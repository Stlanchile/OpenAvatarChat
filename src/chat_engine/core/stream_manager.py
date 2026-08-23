import copy
import weakref
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
from loguru import logger

from chat_engine.contexts.session_clock import SessionClock

from chat_engine.data_models.internal.handler_definition_data import ChatDataConsumeMode, HandlerDataInfo

from chat_engine.data_models.runtime_data.data_bundle import DataBundleDefinition, DataBundle
from chat_engine.data_models.chat_data.chat_data_model import ChatData, StreamableData
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_signal import ChatSignal
from chat_engine.data_models.chat_signal_type import ChatSignalType
from chat_engine.data_models.chat_stream import ChatStreamIdentity, StreamKey
from chat_engine.data_models.chat_stream_config import ChatStreamConfig
from chat_engine.data_models.chat_stream_status import ChatStreamStatus
from chat_engine.core.signal_manager import SignalEmitter, SignalManager
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.dispatch import (
    ProducerAuthorityReferenceV1,
    SecurityEnvelopeReferenceV1,
    SecurityStreamReferenceV1,
    ValidatedDispatchV1,
)
from chat_engine.security.envelope import SecurityClassificationV1
from chat_engine.security.payload_isolation import ChatDataIsolationPlanV1


@dataclass
class StreamDebugConfig:
    """Global configuration for stream lifecycle debug logging."""
    enabled: bool = False

    # Visual symbols for different events
    SYMBOLS = {
        'create': '🆕',
        'start': '▶️',
        'finish': '✅',
        'cancel': '❌',
        'recycle': '🗑️',
        'ref_add': '🔗',
        'ref_remove': '💔',
        'cancel_chain': '⛓️',
        'arrow': '→',
        'tree_branch': '├──',
        'tree_last': '└──',
        'tree_vertical': '│  ',
    }

    def log(self, message: str):
        if self.enabled:
            logger.info(message)

    def log_create(self, stream: "ChatStream"):
        """Log stream creation with visual dependency tree."""
        if not self.enabled:
            return
        if stream._security_log_redacted_v1:
            logger.info("PRIVATE_STREAM_CREATED_V1")
            return
        sym = self.SYMBOLS
        lines = [
            f"{sym['create']} STREAM CREATED: {stream.identity}",
            f"   ┌─ cancelable: {stream.config.cancelable}",
        ]
        
        # Parents section
        parents = list(stream.source_streams.values())
        if parents:
            lines.append(f"   ├─ parents ({len(parents)}):")
            for i, p in enumerate(parents):
                prefix = sym['tree_last'] if i == len(parents) - 1 else sym['tree_branch']
                lines.append(f"   │  {prefix} {p}")
        else:
            lines.append(f"   ├─ parents: (none)")
        
        # Ancestors section (excluding parents)
        ancestors_only = [a for a in stream.ancestor_streams if a.key not in stream.source_streams]
        if ancestors_only:
            lines.append(f"   ├─ ancestors ({len(ancestors_only)}):")
            for i, a in enumerate(ancestors_only):
                prefix = sym['tree_last'] if i == len(ancestors_only) - 1 else sym['tree_branch']
                lines.append(f"   │  {prefix} {a}")
        
        # Cancelable ancestors section
        if stream.cancelable_ancestors:
            lines.append(f"   └─ cancelable chain ({len(stream.cancelable_ancestors)}):")
            for i, c in enumerate(stream.cancelable_ancestors):
                prefix = sym['tree_last'] if i == len(stream.cancelable_ancestors) - 1 else sym['tree_branch']
                lines.append(f"      {prefix} {c}")
        else:
            lines.append(f"   └─ cancelable chain: (none)")
        
        logger.info("\n".join(lines))

    def log_start(self, stream: "ChatStream", timestamp):
        """Log stream start."""
        if not self.enabled:
            return
        if stream._security_log_redacted_v1:
            logger.info("PRIVATE_STREAM_STARTED_V1")
            return
        logger.info(f"{self.SYMBOLS['start']} STREAM STARTED: {stream.identity} @ {timestamp}")

    def log_finish(self, stream: "ChatStream", prev_status, ref_by_list: list):
        """Log stream finish."""
        if not self.enabled:
            return
        if stream._security_log_redacted_v1:
            logger.info("PRIVATE_STREAM_FINISHED_V1")
            return
        ref_info = f"ref_by=[{', '.join(ref_by_list)}]" if ref_by_list else "ref_by=(none)"
        logger.info(
            f"{self.SYMBOLS['finish']} STREAM FINISHED: {stream.identity} | "
            f"{prev_status.name} {self.SYMBOLS['arrow']} ENDED | {ref_info}"
        )

    def log_cancel(self, stream: "ChatStream", prev_status, ref_by_list: list):
        """Log stream cancel."""
        if not self.enabled:
            return
        if stream._security_log_redacted_v1:
            logger.warning("PRIVATE_STREAM_CANCELLED_V1")
            return
        ref_info = f"ref_by=[{', '.join(ref_by_list)}]" if ref_by_list else "ref_by=(none)"
        logger.warning(
            f"{self.SYMBOLS['cancel']} STREAM CANCELLED: {stream.identity} | "
            f"{prev_status.name} {self.SYMBOLS['arrow']} CANCELLED | {ref_info}"
        )

    def log_recycle(self, stream: "ChatStream", ttl: float):
        """Log stream recycle."""
        if not self.enabled:
            return
        if stream._security_log_redacted_v1:
            logger.info("PRIVATE_STREAM_RECYCLED_V1")
            return
        logger.info(
            f"{self.SYMBOLS['recycle']} STREAM RECYCLED: {stream.identity} | "
            f"status={stream.status.name} | lived {ttl}s after finish"
        )

    def log_ref_add(self, refer_by, refer_to, ref_count: int):
        """Log reference added."""
        if not self.enabled:
            return
        logger.info(
            f"{self.SYMBOLS['ref_add']} REF ADD | "
            f"ref_count={ref_count}"
        )

    def log_ref_remove(self, refer_by, refer_to, ref_count: int):
        """Log reference removed."""
        if not self.enabled:
            return
        logger.info(
            f"{self.SYMBOLS['ref_remove']} REF REMOVE | "
            f"ref_count={ref_count}"
        )

    def log_cancel_chain_start(self, stream: "ChatStream"):
        """Log cancel chain start."""
        if not self.enabled:
            return
        if stream._security_log_redacted_v1:
            logger.info("PRIVATE_STREAM_CANCEL_CHAIN_STARTED_V1")
            return
        sym = self.SYMBOLS
        lines = [
            f"{sym['cancel_chain']} CANCEL CHAIN INITIATED from: {stream.identity}",
        ]
        if stream.cancelable_ancestors:
            lines.append(f"   targets ({len(stream.cancelable_ancestors)}):")
            for i, c in enumerate(stream.cancelable_ancestors):
                prefix = sym['tree_last'] if i == len(stream.cancelable_ancestors) - 1 else sym['tree_branch']
                lines.append(f"   {prefix} {c}")
        else:
            lines.append(f"   targets: (none)")
        logger.info("\n".join(lines))

    def log_cancel_chain_complete(
        self,
        cancelled: list,
        *,
        redacted: bool = False,
    ):
        """Log cancel chain completion."""
        if not self.enabled:
            return
        if redacted:
            logger.info("PRIVATE_STREAM_CANCEL_CHAIN_COMPLETED_V1")
            return
        sym = self.SYMBOLS
        if cancelled:
            cancelled_str = ", ".join(str(c) for c in cancelled)
            logger.info(f"{sym['cancel_chain']} CANCEL CHAIN COMPLETE: cancelled {len(cancelled)} streams [{cancelled_str}]")
        else:
            logger.info(f"{sym['cancel_chain']} CANCEL CHAIN COMPLETE: no streams cancelled")


# Global debug config instance - can be enabled/disabled at runtime
stream_debug = StreamDebugConfig()


@dataclass
class InputStreamStats:
    stream_id: ChatStreamIdentity
    start_time: Optional[Tuple[int, int]] = None
    # Keep track of when the upstream stream ended so we can retain it briefly
    # for downstream ref_streams discovery.
    end_mark: Optional[float] = None


@dataclass
class InputSecurityStatsV1:
    stream_ref: SecurityStreamReferenceV1
    envelope_ref: SecurityEnvelopeReferenceV1
    end_mark: Optional[float] = None


class SecurityStreamRejectedV1(RuntimeError):
    """Stable, payload-free secure stream rejection."""


class ChatStream:
    def __init__(self, identity: ChatStreamIdentity,
                 storage: "StreamStorage",
                 config: ChatStreamConfig,
                 source_streams: Optional[List[ChatStreamIdentity]] = None,
                 remove_callback: Optional[Callable[["ChatStream"], None]] = None,
                 signal_emitter: Optional[SignalEmitter] = None,
                 security_stream_ref: Optional[SecurityStreamReferenceV1] = None,
                 security_log_redacted_v1: bool = False):
        self.config: ChatStreamConfig = config
        self.identity: ChatStreamIdentity = identity
        self.status: ChatStreamStatus = ChatStreamStatus.NOT_STARTED
        self.start_time: Optional[Tuple[int, int]] = None
        self.end_time: Optional[Tuple[int, int]] = None
        # Direct parent streams (immediate sources) - dict for fast lookup
        self.source_streams: Dict[StreamKey, ChatStreamIdentity] = {}
        # All ancestor streams in dependency order (parents first, then grandparents, etc.)
        # This is an ordered list for proper interrupt propagation
        self.ancestor_streams: List[ChatStreamIdentity] = []
        # Cancelable ancestors (excludes non-cancelable streams like client audio/video input)
        # Determined at creation time, static and ordered (parents first)
        self.cancelable_ancestors: List[ChatStreamIdentity] = []
        self.ref_by: Dict[StreamKey, ChatStreamIdentity] = {}
        self.weak_storage: weakref.ReferenceType["StreamStorage"] = weakref.ref(storage)
        self.remove_callback: Optional[Callable[["ChatStream"], None]] = remove_callback
        self._signal_emitter = signal_emitter
        self.security_stream_ref = security_stream_ref
        self._security_log_redacted_v1 = security_log_redacted_v1
        self._metadata: Dict[str, Any] = {}
        self._inheritable_metadata: Dict[str, Any] = {}  # Metadata that will be inherited by child streams
        self._should_cancel_on_create: bool = False  # Flag for deferred cancel
        if source_streams is not None:
            seen_keys = set()
            for source_stream in source_streams:
                stream_key = source_stream.key
                if stream_key in seen_keys:
                    continue
                seen_keys.add(stream_key)
                self.source_streams[stream_key] = source_stream
                self.ancestor_streams.append(source_stream)
                # Check if parent is cancelled - if so, we should cancel ourselves
                parent_valid = storage.ref_stream(self.identity, source_stream)
                if not parent_valid:
                    self._should_cancel_on_create = True
            # Collect ancestors from parent streams and build cancelable list
            self._collect_ancestors_and_cancelable(storage, seen_keys)
            # Inherit inheritable metadata from parent streams
            self._inherit_metadata_from_parents(storage)
        
        # Debug logging for stream creation
        self._log_creation()
        
        # If any parent was cancelled, cancel this stream immediately after creation
        if self._should_cancel_on_create and self.config.cancelable:
            if self._security_log_redacted_v1:
                logger.info("PRIVATE_STREAM_AUTO_CANCELLED_V1")
            else:
                logger.info(f"Auto-cancelling stream {self.identity} due to cancelled parent")
            self.cancel(storage)

    def _log_creation(self):
        """Log stream creation with dependency information."""
        stream_debug.log_create(self)

    def _collect_ancestors_and_cancelable(self, storage: "StreamStorage", seen_keys: set):
        """
        Collect all ancestor streams from parent streams and build the cancelable ancestors list.
        Both lists maintain dependency order: direct parents first, then their ancestors.
        """
        # First, add ancestors from all parent streams (in order)
        for source_id in list(self.source_streams.values()):
            parent_stream = storage.find_stream(source_id)
            if parent_stream is None:
                continue
            # Add parent's ancestors (already ordered in parent)
            for ancestor_id in parent_stream.ancestor_streams:
                if ancestor_id.key not in seen_keys:
                    seen_keys.add(ancestor_id.key)
                    self.ancestor_streams.append(ancestor_id)

        # Now build cancelable_ancestors from ancestor_streams (preserving order)
        for ancestor_id in self.ancestor_streams:
            ancestor_stream = storage.find_stream(ancestor_id)
            if ancestor_stream is not None and ancestor_stream.config.cancelable:
                self.cancelable_ancestors.append(ancestor_id)

    def _inherit_metadata_from_parents(self, storage: "StreamStorage"):
        """
        Inherit inheritable metadata from parent streams.
        If multiple parents have the same inheritable metadata key, the first parent's value takes precedence.
        """
        for source_id in list(self.source_streams.values()):
            parent_stream = storage.find_stream(source_id)
            if parent_stream is None:
                continue
            # Inherit from parent's inheritable_metadata
            for key, value in parent_stream._inheritable_metadata.items():
                if key not in self._inheritable_metadata:
                    # Only inherit if not already set (first parent wins)
                    self._inheritable_metadata[key] = value
                    # Also add to regular metadata for easy access
                    self._metadata[key] = value

    def cancel_with_ancestors(self, storage: "StreamStorage") -> List[ChatStreamIdentity]:
        """
        Cancel this stream and all its cancelable ancestors.
        Returns list of cancelled stream identities.
        Cancels from root to leaf order for cleaner signal propagation.
        """
        stream_debug.log_cancel_chain_start(self)
        cancelled = []
        # Cancel ancestors from root to leaf (reverse of dependency order)
        for ancestor_id in reversed(self.cancelable_ancestors):
            ancestor_stream = storage.find_stream(ancestor_id)
            if ancestor_stream is not None:
                if ancestor_stream.status in (ChatStreamStatus.NOT_STARTED, ChatStreamStatus.STARTED):
                    if ancestor_stream.cancel(storage):
                        cancelled.append(ancestor_id)
        # Cancel self if cancelable
        if self.config.cancelable:
            if self.cancel(storage):
                cancelled.append(self.identity)
        stream_debug.log_cancel_chain_complete(
            cancelled,
            redacted=self._security_log_redacted_v1,
        )
        return cancelled

    def __del__(self):
        storage = self.weak_storage()
        if storage is None:
            return
        for source_stream in self.source_streams.values():
            storage.unref_stream(self.identity, source_stream)

    def cancel(self, storage: "StreamStorage"):
        # 已经 cancel 的不能重复 cancel
        if self.status == ChatStreamStatus.CANCELLED:
            return False
        # 允许 cancel 任何非 CANCELLED 状态的 stream
        # 即使 ENDED 且无下游引用，也需要发送 STREAM_CANCEL 信号
        # 因为可能有 handler 正在处理这个 stream（如 LLM 正在处理 HUMAN_TEXT）
        prev_status = self.status
        self.status = ChatStreamStatus.CANCELLED
        ref_by_list = [str(sid) for sid in self.ref_by.values()]
        stream_debug.log_cancel(self, prev_status, ref_by_list)
        stream_cancel_signal = ChatSignal(
            type=ChatSignalType.STREAM_CANCEL,
            source_type=self.config.source_type,
            related_stream=self.identity,
        )
        self._signal_emitter.emit(stream_cancel_signal)
        if self.config.forward_cancel_signal:
            for referer_id in self.ref_by.values():
                referer_stream = storage.find_stream(referer_id)
                if referer_stream is not None:
                    referer_stream.cancel(storage)
        storage.check_stream_status(self)
        if self.remove_callback is not None:
            self.remove_callback(self)
        return True

    def finish(self, storage: "StreamStorage"):
        if self.status not in (ChatStreamStatus.NOT_STARTED, ChatStreamStatus.STARTED):
            return False
        prev_status = self.status
        self.status = ChatStreamStatus.ENDED
        ref_by_list = [str(sid) for sid in self.ref_by.values()]
        stream_debug.log_finish(self, prev_status, ref_by_list)
        stream_end_signal = ChatSignal(
            type=ChatSignalType.STREAM_END,
            source_type=self.config.source_type,
            related_stream=self.identity,
        )
        self._signal_emitter.emit(stream_end_signal)
        storage.check_stream_status(self)
        if self.remove_callback is not None:
            self.remove_callback(self)
        return True

    @property
    def metadata(self) -> Dict[str, Any]:
        """
        Get merged metadata (regular + inheritable).
        Inheritable metadata takes precedence if there are key conflicts.
        This ensures downstream handlers can access inheritable metadata.
        """
        merged = self._metadata.copy()
        merged.update(self._inheritable_metadata)  # Inheritable takes precedence
        return merged

    def update_metadata(self, metadata: Dict[str, Any]):
        """Update regular metadata (not inheritable by child streams)."""
        self._metadata.update(metadata)

    def update_inheritable_metadata(self, metadata: Dict[str, Any], inherit: bool = True):
        """
        Update inheritable metadata that will be automatically inherited by child streams.
        
        Args:
            metadata: Dictionary of metadata to set
            inherit: If True, mark these metadata as inheritable. If False, remove from inheritable.
        """
        if inherit:
            # Add to inheritable_metadata and regular metadata
            self._inheritable_metadata.update(metadata)
            self._metadata.update(metadata)
        else:
            # Remove from inheritable_metadata (but keep in regular metadata)
            for key in metadata.keys():
                self._inheritable_metadata.pop(key, None)


class StreamStorage:
    def __init__(self, 
                 recycle_ttl: float = 10.0,
                 cleanup_interval: float = 1.0):
        """
        Initialize stream storage with configurable lifecycle parameters.
        
        Args:
            recycle_ttl: Time in seconds to keep finished streams alive after ending,
                        even without references. This allows downstream handlers
                        enough time to establish dependencies.
            cleanup_interval: Interval in seconds between periodic cleanup checks.
        """
        self.streams: Dict[StreamKey, ChatStream] = {}
        # recycle pool: keep finished streams for a grace period to avoid
        # dangling ref_stream lookups right after upstream finishes.
        self._finished_at: Dict[StreamKey, float] = {}
        self._recycle_ttl = recycle_ttl
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.monotonic()

    def set_recycle_ttl(self, ttl: float):
        """Set the time-to-live for finished streams before recycling."""
        self._recycle_ttl = ttl

    def set_cleanup_interval(self, interval: float):
        """Set the interval between periodic cleanup checks."""
        self._cleanup_interval = interval

    def _cleanup_recycle(self, force: bool = False):
        """
        Periodic cleanup of expired finished streams.
        
        Args:
            force: If True, run cleanup regardless of interval.
        """
        now = time.monotonic()
        if not force and now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        expired_keys = [
            key for key, ts in self._finished_at.items()
            if now - ts >= self._recycle_ttl
        ]
        for key in expired_keys:
            stream = self.streams.get(key)
            if stream is not None and len(stream.ref_by) == 0 and stream.status in (
                ChatStreamStatus.ENDED, ChatStreamStatus.CANCELLED
            ):
                stream_debug.log_recycle(stream, self._recycle_ttl)
                self.streams.pop(key, None)
            self._finished_at.pop(key, None)

    def add_stream(self, key: StreamKey, stream: ChatStream):
        self._cleanup_recycle()
        if key in self.streams:
            raise ValueError(f"Stream {key} already exists")
        self.streams[key] = stream

    def find_stream(self, stream_id: ChatStreamIdentity) -> Optional[ChatStream]:
        self._cleanup_recycle()
        key = stream_id.key
        result = self.streams.get(key, None)
        return result

    def ref_stream(self, refer_by: ChatStreamIdentity, refer_to: ChatStreamIdentity) -> bool:
        """
        Add a reference from refer_by to refer_to.
        
        Returns:
            bool: True if the target stream is in a valid state (not cancelled),
                  False if the target stream is cancelled (caller should cancel itself)
        """
        self._cleanup_recycle()
        target_stream = self.find_stream(refer_to)
        if target_stream is None:
            logger.error(f"Stream {refer_to} not found")
            return False
        
        referrer_key = refer_by.key
        if referrer_key not in target_stream.ref_by:
            target_stream.ref_by[referrer_key] = refer_by
            stream_debug.log_ref_add(refer_by, refer_to, len(target_stream.ref_by))
        # once referenced again, remove from recycle tracking
        self._finished_at.pop(target_stream.identity.key, None)
        
        # If target stream is already cancelled, the referrer should also be cancelled
        if target_stream.status == ChatStreamStatus.CANCELLED:
            logger.warning(f"Stream {refer_by} references cancelled stream {refer_to}, will propagate cancel")
            return False
        return True

    def unref_stream(self, refer_by: ChatStreamIdentity, refer_to: ChatStreamIdentity):
        self._cleanup_recycle()
        target_stream = self.find_stream(refer_to)
        if target_stream is None:
            logger.error(f"Stream {refer_to} not found")
        else:
            target_stream.ref_by.pop(refer_by.key, None)
            stream_debug.log_ref_remove(refer_by, refer_to, len(target_stream.ref_by))
            self._check_lifespan_(target_stream)

    def check_stream_status(self, stream: ChatStream):
        self._check_lifespan_(stream)

    def _check_lifespan_(self, stream: ChatStream):
        key = stream.identity.key
        # mark finished streams; actual removal deferred to recycle cleanup
        if len(stream.ref_by) == 0 and stream.status in (
            ChatStreamStatus.ENDED, ChatStreamStatus.CANCELLED
        ):
            self._finished_at.setdefault(key, time.monotonic())
        else:
            # still referenced; ensure not in recycle list
            self._finished_at.pop(key, None)
        self._cleanup_recycle()

    def get_all_active_streams(self) -> List[ChatStream]:
        """Get all streams that are currently active (not ended or cancelled)."""
        self._cleanup_recycle()
        return [
            stream for stream in self.streams.values()
            if stream.status in (ChatStreamStatus.NOT_STARTED, ChatStreamStatus.STARTED)
        ]

    def cancel_stream_with_ancestors(self, stream_id: ChatStreamIdentity) -> List[ChatStreamIdentity]:
        """
        Cancel a stream and all its cancelable ancestor streams.
        Used for interrupt functionality.
        
        Args:
            stream_id: Identity of the stream to cancel (typically the leaf/latest stream)
            
        Returns:
            List of cancelled stream identities
        """
        stream = self.find_stream(stream_id)
        if stream is None:
            logger.warning(f"Cannot cancel stream {stream_id}: not found")
            return []
        return stream.cancel_with_ancestors(self)

    def get_stream_ancestry(self, stream_id: ChatStreamIdentity) -> Dict[str, List[ChatStreamIdentity]]:
        """
        Get the complete ancestry information of a stream.
        
        Returns:
            Dict with:
            - 'parents': direct source streams
            - 'ancestors': all ancestors in dependency order (parents first)
            - 'cancelable': cancelable ancestors in dependency order
        """
        stream = self.find_stream(stream_id)
        if stream is None:
            return {'parents': [], 'ancestors': [], 'cancelable': []}
        return {
            'parents': list(stream.source_streams.values()),
            'ancestors': stream.ancestor_streams.copy(),
            'cancelable': stream.cancelable_ancestors.copy()
        }

class ChatStreamer:
    @dataclass
    class StreamHolder:
        stream: Optional[ChatStream] = None

    def __init__(self, storage: StreamStorage, session_clock: SessionClock,
                 data_info: HandlerDataInfo,
                 data_sinks,
                 signal_emitter: SignalEmitter,
                 producer_name: str,
                 data_name: Optional[str] = None,
                 config: Optional[ChatStreamConfig] = None,
                 security_authority: SecurityAuthorityV1 | None = None,
                 producer_authority: ProducerAuthorityReferenceV1 | None = None):
        self._input_stream_ids: Dict[StreamKey, InputStreamStats] = {}
        self._input_security_refs: Dict[str, InputSecurityStatsV1] = {}
        self._streamer_id: int = -1
        self._session_clock: SessionClock = session_clock
        self._data_sinks = data_sinks
        self._producer_name: str = producer_name
        self._data_name: Optional[str] = data_name
        self._data_type: ChatDataType = data_info.type
        self._data_definition: Optional[DataBundleDefinition] = data_info.definition
        self._signal_emitter = signal_emitter
        self._storage = storage
        self._next_id = 0
        self._current_stream = self.StreamHolder()
        self._default_config: ChatStreamConfig = ChatStreamConfig() if config is None else config
        self._security_authority = security_authority
        self._producer_authority = producer_authority
        # Keep ended upstream streams for a short grace period so downstream
        # outputs (e.g., HUMAN_TEXT) can still reference them for ref_streams.
        self._ended_input_retention = 3.0  # seconds

    @property
    def data_type(self):
        return self._data_type

    @property
    def data_name(self):
        return self._data_name

    @property
    def producer_name(self):
        return self._producer_name

    @property
    def auto_link_input(self):
        return self._default_config.auto_link_input

    @property
    def current_stream(self):
        if self._current_stream.stream is None:
            return None
        if self._current_stream.stream.status not in (ChatStreamStatus.NOT_STARTED, ChatStreamStatus.STARTED):
            self._current_stream.stream = None
        return self._current_stream.stream

    @property
    def data_definition(self):
        return self._data_definition

    def update_input_stream(self, chat_data: ChatData):
        self._cleanup_input_streams()
        if chat_data.stream_id is None:
            return
        stream_key = chat_data.stream_id.key
        stream_stats = self._input_stream_ids.setdefault(
            stream_key,
            InputStreamStats(stream_id=chat_data.stream_id)
        )
        if chat_data.is_last_data:
            stream_stats.end_mark = time.monotonic()
        if stream_stats.start_time is None:
            stream_stats.start_time = self._session_clock.get_timestamp()

    def update_input_dispatch_v1(
        self,
        validated_dispatch: ValidatedDispatchV1,
        *,
        link_functional_stream: bool,
    ) -> None:
        """Record trusted ancestry independently from mutable ChatData."""

        stream_ref = validated_dispatch.stream_ref
        security_stats = self._input_security_refs.setdefault(
            stream_ref.stream_authority_id,
            InputSecurityStatsV1(
                stream_ref=stream_ref,
                envelope_ref=validated_dispatch.envelope_ref,
            ),
        )
        payload = validated_dispatch.payload
        if isinstance(payload, ChatData) and payload.is_last_data:
            security_stats.end_mark = time.monotonic()

        if not link_functional_stream:
            return
        trusted_identity = stream_ref.identity
        canonical_stream_id = ChatStreamIdentity(
            data_type=trusted_identity.data_type,
            builder_id=trusted_identity.builder_id,
            stream_id=trusted_identity.stream_id,
            name=trusted_identity.name,
            producer_name=trusted_identity.producer_name,
        )
        stream_key = canonical_stream_id.key
        if stream_key is None:
            return
        stream_stats = self._input_stream_ids.setdefault(
            stream_key,
            InputStreamStats(stream_id=canonical_stream_id),
        )
        if isinstance(payload, ChatData) and payload.is_last_data:
            stream_stats.end_mark = time.monotonic()
        if stream_stats.start_time is None:
            stream_stats.start_time = self._session_clock.get_timestamp()

    def _cleanup_input_streams(self):
        now = time.monotonic()
        to_remove = []
        for key, stats in self._input_stream_ids.items():
            # Remove expired streams (ended and past retention period)
            if (stats.end_mark is not None
                and now - stats.end_mark >= self._ended_input_retention):
                to_remove.append(key)
                continue
            # Remove cancelled streams
            stream = self._storage.find_stream(stats.stream_id)
            if stream is not None and stream.status == ChatStreamStatus.CANCELLED:
                to_remove.append(key)
        for key in to_remove:
            self._input_stream_ids.pop(key, None)

        security_to_remove: list[str] = []
        for authority_id, stats in self._input_security_refs.items():
            if stats.end_mark is None:
                continue
            envelope = (
                self._security_authority.envelope_v1(stats.envelope_ref)
                if self._security_authority is not None
                else None
            )
            if (
                envelope is not None
                and envelope.classification
                is SecurityClassificationV1.CERTIFICATE_PRIVATE
            ):
                # V1 has no declassification API. Retaining private ancestry for
                # the session is a safe fail-closed behavior for late callbacks.
                continue
            if now - stats.end_mark >= self._ended_input_retention:
                security_to_remove.append(authority_id)
        for authority_id in security_to_remove:
            self._input_security_refs.pop(authority_id, None)

    def active_security_parent_refs_v1(
        self,
    ) -> tuple[SecurityEnvelopeReferenceV1, ...]:
        self._cleanup_input_streams()
        if self._security_authority is None:
            return ()
        if self._producer_authority is None:
            self._security_authority._record(
                SecurityAuditEventCodeV1.INVALID_LINEAGE
            )
            raise SecurityStreamRejectedV1(
                "secure producer authority missing"
            )
        refs = self._security_authority.producer_parent_refs_v1(
            self._producer_authority
        )
        if refs is None:
            raise SecurityStreamRejectedV1(
                "secure producer authority invalid"
            )
        return refs

    def find_stream(self, stream_id: ChatStreamIdentity):
        stream = self._storage.find_stream(stream_id)
        if (
            self._security_authority is None
            or stream is None
        ):
            return stream
        if (
            stream.security_stream_ref is None
            or self._producer_authority is None
            or not self._security_authority.producer_can_access_envelope_v1(
                self._producer_authority,
                stream.security_stream_ref.envelope_ref,
            )
        ):
            self._security_authority._record(
                SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                envelope_id=(
                    stream.security_stream_ref.envelope_ref.envelope_id
                    if stream.security_stream_ref is not None
                    else None
                ),
            )
            return None
        return stream

    def _security_parents_for_stream_v1(
        self,
        sources: List[ChatStreamIdentity],
        trusted_root_envelope_ref: SecurityEnvelopeReferenceV1 | None = None,
    ) -> tuple[SecurityEnvelopeReferenceV1, ...]:
        if self._security_authority is None:
            return ()
        refs = list(self.active_security_parent_refs_v1())
        seen = {item.envelope_id for item in refs}
        for source in sources:
            source_stream = self._storage.find_stream(source)
            if (
                source_stream is None
                or source_stream.security_stream_ref is None
            ):
                self._security_authority._record(
                    SecurityAuditEventCodeV1.INVALID_LINEAGE
                )
                raise SecurityStreamRejectedV1("invalid secure stream lineage")
            envelope_ref = source_stream.security_stream_ref.envelope_ref
            if (
                self._producer_authority is None
                or not self._security_authority.producer_can_access_envelope_v1(
                    self._producer_authority,
                    envelope_ref,
                )
            ):
                self._security_authority._record(
                    SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                    envelope_id=envelope_ref.envelope_id,
                )
                raise SecurityStreamRejectedV1(
                    "secure source stream is not authorized"
                )
            if envelope_ref.envelope_id not in seen:
                seen.add(envelope_ref.envelope_id)
                refs.append(envelope_ref)
        if (
            trusted_root_envelope_ref is not None
            and trusted_root_envelope_ref.envelope_id not in seen
        ):
            if (
                self._producer_authority is None
                or not self._security_authority.producer_can_access_envelope_v1(
                    self._producer_authority,
                    trusted_root_envelope_ref,
                )
            ):
                self._security_authority._record(
                    SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                    envelope_id=trusted_root_envelope_ref.envelope_id,
                )
                raise SecurityStreamRejectedV1(
                    "secure root envelope is not authorized"
                )
            refs.append(trusted_root_envelope_ref)
        return tuple(refs)

    def _envelope_for_new_stream_v1(
        self,
        sources: List[ChatStreamIdentity],
        trusted_root_envelope_ref: SecurityEnvelopeReferenceV1 | None = None,
    ) -> SecurityEnvelopeReferenceV1 | None:
        if self._security_authority is None:
            return None
        parents = self._security_parents_for_stream_v1(
            sources,
            trusted_root_envelope_ref,
        )
        if self._producer_authority is None:
            return None
        return self._security_authority.envelope_for_producer_v1(
            self._producer_authority,
            parents,
        )

    def new_stream(
        self,
        sources: List[ChatStreamIdentity],
        name: Optional[str] = None,
        config: Optional[ChatStreamConfig] = None,
        *,
        _trusted_root_envelope_ref: SecurityEnvelopeReferenceV1 | None = None,
    ):
        if self._current_stream.stream is not None:
            self.finish_current()
        new_stream_config = self._default_config
        if config is not None:
            new_stream_config = ChatStreamConfig(**{**new_stream_config.model_dump(), **config.model_dump(exclude_unset=True)})
        new_stream_id = ChatStreamIdentity(
            data_type=self._data_type,
            builder_id=self._streamer_id,
            stream_id=self._next_id,
            name=name,
            producer_name=self._producer_name
        )
        security_stream_ref = None
        security_log_redacted_v1 = False
        if self._security_authority is not None:
            envelope_ref = self._envelope_for_new_stream_v1(
                sources,
                _trusted_root_envelope_ref,
            )
            if envelope_ref is None:
                raise SecurityStreamRejectedV1(
                    "secure stream envelope unavailable"
                )
            envelope = self._security_authority.envelope_v1(
                envelope_ref
            )
            if envelope is None:
                raise SecurityStreamRejectedV1(
                    "secure stream envelope invalid"
                )
            if (
                envelope.classification
                is SecurityClassificationV1.CERTIFICATE_PRIVATE
            ):
                # Handler-supplied stream labels are mutable functional
                # metadata, not trusted lineage, and must never enter generic
                # lifecycle logs for private work.
                new_stream_id.name = None
                security_log_redacted_v1 = True
            security_stream_ref = self._security_authority.bind_stream_v1(
                new_stream_id,
                envelope_ref,
            )
            if security_stream_ref is None:
                raise SecurityStreamRejectedV1(
                    "secure stream binding unavailable"
                )
        stream_holder = self._current_stream
        def stream_remove_callback(stream):
            if (id(stream) == id(stream_holder.stream)
                and stream.status in (ChatStreamStatus.NOT_STARTED, ChatStreamStatus.STARTED)):
                stream_holder.stream = None

        new_stream = ChatStream(
            config=new_stream_config,
            identity=new_stream_id,
            storage=self._storage,
            source_streams=sources,
            remove_callback=stream_remove_callback,
            signal_emitter=self._signal_emitter,
            security_stream_ref=security_stream_ref,
            security_log_redacted_v1=security_log_redacted_v1,
        )
        key = new_stream.identity.key
        self._storage.add_stream(key, new_stream)
        self._next_id += 1
        self._current_stream.stream = new_stream
        return new_stream_id

    def new_stream_from_input(
        self,
        input_stream: ChatStreamIdentity,
        name: Optional[str] = None,
        config: Optional[ChatStreamConfig] = None
    ) -> ChatStreamIdentity:
        """
        Create a new output stream strictly associated with a single input stream.
        
        Unlike new_stream() which auto-associates with all active input streams,
        this method creates an output stream that only references the specified
        input stream. This is useful for handlers that need strict 1:1 input-output
        stream association (e.g., ASR in duplex mode where each audio segment
        must produce a corresponding text segment).
        
        Args:
            input_stream: The specific input stream to associate with
            name: Optional name for the stream
            config: Optional stream configuration override
            
        Returns:
            The identity of the newly created stream
        """
        return self.new_stream(
            sources=[input_stream],
            name=name,
            config=config
        )

    def open_stream(
        self,
        sources: Optional[List[ChatStreamIdentity]] = None,
        name: Optional[str] = None,
        config: Optional[ChatStreamConfig] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[ChatStreamIdentity]:
        """
        Create and immediately start a lifecycle-only stream (no data distribution).
        Emits STREAM_BEGIN signal. Use finish_current() to close it (emits STREAM_END).

        Unlike stream_data(), this does not require data sinks or actual data.
        Useful for virtual streams (e.g., CLIENT_PLAYBACK) that only track lifecycle.

        Args:
            sources: Parent stream identities. If None, uses current active input streams.
            name: Optional stream name.
            config: Optional stream config override.
            meta: Optional metadata to attach to the stream.

        Returns:
            The identity of the newly created and started stream, or None if creation failed.
        """
        if sources is None:
            self._cleanup_input_streams()
            sources = [v.stream_id for v in self._input_stream_ids.values()]
        try:
            stream_id = self.new_stream(sources, name, config)
        except SecurityStreamRejectedV1:
            if self._security_authority is not None:
                self._security_authority._record(
                    SecurityAuditEventCodeV1.DISPATCH_DENIED
                )
                return None
            raise
        stream = self.current_stream
        if stream is None:
            return None
        if meta:
            stream.update_metadata(meta)
        timestamp = self._session_clock.get_timestamp()
        stream.start_time = timestamp
        stream.status = ChatStreamStatus.STARTED
        stream_debug.log_start(stream, timestamp)
        stream_begin_signal = ChatSignal(
            type=ChatSignalType.STREAM_BEGIN,
            source_type=stream.config.source_type,
            related_stream=stream.identity,
        )
        self._signal_emitter.emit(stream_begin_signal)
        return stream_id

    def _ensure_current_stream_authority_v1(
        self,
        sources: List[ChatStreamIdentity],
        trusted_root_envelope_ref: SecurityEnvelopeReferenceV1 | None,
    ) -> None:
        if self._security_authority is None:
            return
        stream = self.current_stream
        if stream is None or stream.security_stream_ref is None:
            self._security_authority._record(
                SecurityAuditEventCodeV1.ENVELOPE_MISSING
            )
            raise SecurityStreamRejectedV1("secure stream authority missing")

        parents = self._security_parents_for_stream_v1(
            sources,
            trusted_root_envelope_ref,
        )
        if not parents or self._security_authority.envelope_covers_parents_v1(
            stream.security_stream_ref.envelope_ref,
            parents,
        ):
            return

        current_envelope = self._security_authority.envelope_v1(
            stream.security_stream_ref.envelope_ref
        )
        derived_ref = self._security_authority.derive_envelope_v1(
            (stream.security_stream_ref.envelope_ref, *parents)
        )
        derived_envelope = (
            self._security_authority.envelope_v1(derived_ref)
            if derived_ref is not None
            else None
        )
        if current_envelope is None or derived_envelope is None:
            raise SecurityStreamRejectedV1("secure lineage derivation failed")

        classification_upgrade = (
            current_envelope.classification
            is SecurityClassificationV1.PUBLIC_CHAT
            and derived_envelope.classification
            is SecurityClassificationV1.CERTIFICATE_PRIVATE
        )
        if classification_upgrade:
            stream._security_log_redacted_v1 = True
        if classification_upgrade and stream.status is ChatStreamStatus.STARTED:
            # A stream whose BEGIN was public cannot carry a private packet.
            # Rotate before fan-out so private BEGIN/data/END share authority.
            self.finish_current()
            self.new_stream(
                sources,
                _trusted_root_envelope_ref=trusted_root_envelope_ref,
            )
            return
        if classification_upgrade:
            stream.identity.name = None

        rebound_ref = self._security_authority.bind_stream_v1(
            stream.identity,
            derived_ref,
        )
        if rebound_ref is None:
            raise SecurityStreamRejectedV1("secure stream rebind failed")
        stream.security_stream_ref = rebound_ref

    def _packet_chat_data(self, data: StreamableData):
        if data is None:
            return None
        timestamp = self._session_clock.get_timestamp()
        if isinstance(data, ChatData):
            if data.type != self._data_type:
                raise ValueError(f"Data type mismatch: {data.type} != {self._data_type}")
            chat_data = data
        elif isinstance(data, DataBundle):
            chat_data = ChatData(
                data=data,
                type=self._data_type,
                timestamp=timestamp,
            )
        elif isinstance(data, np.ndarray):
            data_bundle = DataBundle(definition=self._data_definition)
            data_bundle.set_main_data(data)
            chat_data = ChatData(
                data=data_bundle,
                type=self._data_type,
                timestamp=timestamp,
            )
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")
        if not chat_data.is_timestamp_valid():
            chat_data.timestamp = timestamp
        chat_data.source = self._producer_name
        return chat_data

    def _distribute_chat_data(
        self,
        data: ChatData,
        sinks,
        stream_ref: SecurityStreamReferenceV1 | None,
    ):
        if self._security_authority is None:
            for sink in sinks:
                if sink.owner == data.source:
                    continue
                sink.sink_queue.put(data)
                if sink.consume_info.input_consume_mode == ChatDataConsumeMode.ONCE:
                    break
            return

        if stream_ref is None:
            self._security_authority._record(
                SecurityAuditEventCodeV1.ENVELOPE_MISSING
            )
            return
        try:
            isolation_plan = ChatDataIsolationPlanV1(data)
        except Exception:
            self._security_authority.audit_registry_failure_v1()
            return
        for sink in sinks:
            if sink.owner == data.source:
                continue
            isolated_payload = isolation_plan.clone()
            authorized = self._security_authority.authorize_dispatch_v1(
                stream_ref=stream_ref,
                consumer_capability=sink.consumer_capability,
                trusted_data_type=self._data_type,
                trusted_source=self._producer_name,
                payload=isolated_payload,
            )
            if authorized is None:
                # In particular, an unauthorized ONCE sink must not suppress a
                # later authorized sink.
                continue
            try:
                sink.sink_queue.put(authorized)
            except Exception:
                self._security_authority._record(
                    SecurityAuditEventCodeV1.DISPATCH_DENIED,
                    envelope_id=stream_ref.envelope_ref.envelope_id,
                    consumer_capability_id=(
                        sink.consumer_capability.capability_id
                        if sink.consumer_capability is not None
                        else None
                    ),
                    dispatch_id=authorized.dispatch_id,
                )
                continue
            if (
                sink.consume_info.input_consume_mode
                == ChatDataConsumeMode.ONCE
            ):
                break

    def stream_data(self, data: StreamableData,
                    missing_stream_callback: Optional[Callable[[ChatData], ChatStream]] = None,
                    finish_stream: Optional[bool] = None,
                    stream_meta: Optional[Dict] = None,
                    *,
                    _trusted_root_envelope_ref: SecurityEnvelopeReferenceV1 | None = None):
        self._cleanup_input_streams()
        source_streams = [
            value.stream_id for value in self._input_stream_ids.values()
        ]
        if self.current_stream is None:
            if missing_stream_callback is not None:
                self._current_stream.stream = missing_stream_callback(data)
            else:
                self.new_stream(
                    source_streams,
                    _trusted_root_envelope_ref=_trusted_root_envelope_ref,
                )
        elif self._security_authority is not None:
            self._ensure_current_stream_authority_v1(
                source_streams,
                _trusted_root_envelope_ref,
            )
        stream = self.current_stream
        if stream is None:
            raise ValueError("No current stream")
        if stream_meta is not None:
            stream.update_metadata(stream_meta)
        sinks = self._data_sinks.get(self._data_type, [])
        if len(sinks) == 0:
            if finish_stream:
                self.finish_current()  # Still need to finish the stream even without sinks
            return
        chat_data = self._packet_chat_data(data)
        if isinstance(finish_stream, bool):
            chat_data.is_last_data = finish_stream
        if chat_data is None:
            return
        if stream.status == ChatStreamStatus.NOT_STARTED:
            stream.start_time = chat_data.timestamp
            stream.status = ChatStreamStatus.STARTED
            chat_data.is_first_data = True
            stream_debug.log_start(stream, chat_data.timestamp)
            stream_begin_signal = ChatSignal(
                type=ChatSignalType.STREAM_BEGIN,
                source_type=stream.config.source_type,
                related_stream=stream.identity,
            )
            self._signal_emitter.emit(stream_begin_signal)
        # Production-side cancel guard: check status right before distribution
        # to minimize the TOCTOU window. GIL ensures atomic status read, and the
        # consumer-side guard in _pumper_func catches anything that slips through.
        if stream.status == ChatStreamStatus.CANCELLED:
            return
        chat_data.stream_id = stream.identity
        # Always copy inheritable metadata to ChatData so downstream handlers can access it
        # Regular metadata is only copied on first/last data for performance
        if chat_data.data is not None:
            # Always include inheritable metadata (for POST_END reconnection detection, etc.)
            chat_data.data.metadata.update(stream._inheritable_metadata)
            # Include regular metadata on first/last data
            if chat_data.is_first_data or chat_data.is_last_data:
                chat_data.data.metadata.update(stream._metadata)
        if stream_meta is not None:
            chat_data.data.metadata.update(stream_meta)
        self._distribute_chat_data(
            chat_data,
            sinks,
            stream.security_stream_ref,
        )
        if chat_data.is_last_data:
            self.finish_current()

    def cancel_current(self):
        stream = self.current_stream
        if stream is None:
            return
        stream.cancel(self._storage)

    def cancel_stream(self, stream_id: ChatStreamIdentity) -> bool:
        """Cancel a specific stream by its identity.
        
        Unlike cancel_current(), this can cancel any stream including:
        - Currently active streams
        - Already finished streams (if they still have downstream dependencies)
        
        Args:
            stream_id: Identity of the stream to cancel
            
        Returns:
            True if the stream was cancelled, False otherwise
        """
        stream = self.find_stream(stream_id)
        if stream is None:
            return False
        return stream.cancel(self._storage)

    def finish_current(self):
        stream = self.current_stream
        if stream is None:
            return
        stream.finish(self._storage)


class StreamManager:
    def __init__(self, signal_manager: SignalManager,
                 recycle_ttl: float = 10.0,
                 cleanup_interval: float = 1.0,
                 security_authority: SecurityAuthorityV1 | None = None):
        """
        Initialize stream manager.
        
        Args:
            signal_manager: Signal manager for emitting stream signals
            recycle_ttl: Time in seconds to keep finished streams alive.
                        This gives downstream handlers time to establish dependencies.
            cleanup_interval: Interval in seconds between periodic cleanup checks.
        """
        self._signal_manager = signal_manager
        self._security_authority = security_authority
        self._stream_storage = StreamStorage(
            recycle_ttl=recycle_ttl,
            cleanup_interval=cleanup_interval
        )
        # Use time-based unique base value to ensure stream keys don't conflict
        # across sessions (e.g., when client reconnects and creates a new session).
        # This prevents the issue where a new stream reuses a stream_key that was
        # previously interrupted, causing the client to incorrectly discard audio.
        self._next_streamer_id = int(time.monotonic() * 1000) % 10000000
        if self._security_authority is not None:
            self._signal_manager.set_stream_authority_resolver_v1(
                self._resolve_stream_authority_v1
            )

    def create_streamer(self,
                        data_info: HandlerDataInfo,
                        data_sinks,
                        producer_name: str,
                        data_name: Optional[str] = None,
                        config: Optional[ChatStreamConfig] = None,
                        producer_authority: (
                            ProducerAuthorityReferenceV1 | None
                        ) = None):
        if (
            self._security_authority is not None
            and (
                producer_authority is None
                or not self._security_authority.producer_authority_is_valid_v1(
                    producer_authority
                )
            )
        ):
            self._security_authority._record(
                SecurityAuditEventCodeV1.INVALID_LINEAGE
            )
            raise SecurityStreamRejectedV1(
                "secure producer authority unavailable"
            )
        signal_emitter = self._signal_manager.get_emitter(
            producer_name,
            producer_authority=producer_authority,
        )
        builder = ChatStreamer(
            storage=self._stream_storage,
            session_clock=self._signal_manager.get_clock(),
            data_info=data_info,
            data_sinks=data_sinks,
            signal_emitter=signal_emitter,
            producer_name=producer_name,
            data_name=data_name,
            config=config,
            security_authority=self._security_authority,
            producer_authority=producer_authority,
        )
        builder._streamer_id = self._next_streamer_id
        self._next_streamer_id += 1
        return builder

    def create_lifecycle_streamer(
        self,
        data_type: ChatDataType,
        producer_name: str,
        config: Optional[ChatStreamConfig] = None,
        *,
        _producer_authority: ProducerAuthorityReferenceV1 | None = None,
    ) -> "ChatStreamer":
        """
        Create a streamer for lifecycle-only streams (no data sinks needed).

        The returned streamer uses open_stream() / finish_current() to manage
        stream lifecycle and emit STREAM_BEGIN / STREAM_END signals without
        distributing any data.

        Args:
            data_type: The data type for the lifecycle stream (e.g., CLIENT_PLAYBACK).
            producer_name: Name of the producer handler.
            config: Optional stream configuration.

        Returns:
            A ChatStreamer configured for lifecycle-only use.
        """
        data_info = HandlerDataInfo(type=data_type)
        return self.create_streamer(
            data_info=data_info,
            data_sinks={},
            producer_name=producer_name,
            config=config,
            producer_authority=_producer_authority,
        )

    def create_consumer_view_v1(
        self,
        producer_authority: ProducerAuthorityReferenceV1,
    ) -> "StreamManagerConsumerViewV1":
        return StreamManagerConsumerViewV1(
            self,
            producer_authority,
        )

    def _resolve_stream_authority_v1(
        self,
        stream_id: ChatStreamIdentity,
    ) -> SecurityStreamReferenceV1 | None:
        stream = self.find_stream(stream_id)
        if stream is None:
            return None
        if (
            stream.identity.data_type != stream_id.data_type
            or stream.identity.builder_id != stream_id.builder_id
            or stream.identity.stream_id != stream_id.stream_id
        ):
            return None
        stream_ref = stream.security_stream_ref
        if stream_ref is None:
            return None
        trusted_identity = stream_ref.identity
        if (
            trusted_identity.data_type != stream.identity.data_type
            or trusted_identity.builder_id != stream.identity.builder_id
            or trusted_identity.stream_id != stream.identity.stream_id
            or trusted_identity.name != stream.identity.name
            or trusted_identity.producer_name
            != stream.identity.producer_name
        ):
            return None
        return stream_ref

    def release_secure_state_v1(self) -> None:
        """Release secure stream references and mutable stream metadata."""

        if self._security_authority is None:
            return
        for stream in self._stream_storage.streams.values():
            stream._metadata.clear()
            stream._inheritable_metadata.clear()
            stream.source_streams.clear()
            stream.ancestor_streams.clear()
            stream.cancelable_ancestors.clear()
            stream.ref_by.clear()
            stream.security_stream_ref = None
        self._stream_storage.streams.clear()
        self._stream_storage._finished_at.clear()

    def find_stream(self, stream_id: ChatStreamIdentity):
        if stream_id is None:
            return None
        return self._stream_storage.find_stream(stream_id)

    def set_recycle_ttl(self, ttl: float):
        """Set the time-to-live for finished streams before recycling."""
        self._stream_storage.set_recycle_ttl(ttl)

    def set_cleanup_interval(self, interval: float):
        """Set the interval between periodic cleanup checks."""
        self._stream_storage.set_cleanup_interval(interval)

    def cancel_stream_chain(self, stream_id: ChatStreamIdentity) -> List[ChatStreamIdentity]:
        """
        Cancel a stream and all its cancelable ancestor streams.
        Used for interrupt functionality - cancels the entire processing chain.
        The target stream itself is always cancelled regardless of its cancelable flag.
        
        Args:
            stream_id: Identity of the stream to cancel (typically the leaf/latest stream)
            
        Returns:
            List of cancelled stream identities
        """
        cancelled = self._stream_storage.cancel_stream_with_ancestors(stream_id)
        if stream_id not in cancelled:
            stream = self._stream_storage.find_stream(stream_id)
            if stream is not None and stream.cancel(self._stream_storage):
                cancelled.append(stream_id)
        return cancelled

    def get_stream_ancestry(self, stream_id: ChatStreamIdentity) -> Dict[str, List[ChatStreamIdentity]]:
        """
        Get the complete ancestry information of a stream.
        
        Returns:
            Dict with:
            - 'parents': direct source streams
            - 'ancestors': all ancestors in dependency order (parents first)
            - 'cancelable': cancelable ancestors in dependency order
        """
        return self._stream_storage.get_stream_ancestry(stream_id)

    def get_active_streams(self) -> List[ChatStream]:
        """Get all streams that are currently active (not ended or cancelled)."""
        return self._stream_storage.get_all_active_streams()

    def cancel_streams_by_type(self, data_type: "ChatDataType") -> List[ChatStreamIdentity]:
        """
        Cancel all active streams of the given data type and their cancelable ancestor chains.

        This is the engine-level API for interrupt: call with CLIENT_PLAYBACK to cancel
        all active playback streams and trace back through AVATAR_AUDIO → TTS → LLM.
        Each cancelled stream emits STREAM_CANCEL; forward_cancel_signal cascades
        to downstream referrers.

        Args:
            data_type: The data type of streams to cancel (e.g., ChatDataType.CLIENT_PLAYBACK)

        Returns:
            Deduplicated list of all cancelled stream identities
        """
        active = self.get_active_streams()
        targets = [s for s in active if s.identity.data_type == data_type]
        if not targets:
            return []
        cancelled_set = set()
        cancelled_list = []
        for stream in targets:
            result = self.cancel_stream_chain(stream.identity)
            for sid in result:
                if sid.key not in cancelled_set:
                    cancelled_set.add(sid.key)
                    cancelled_list.append(sid)
        return cancelled_list

    @staticmethod
    def enable_debug_logging(enabled: bool = True):
        """
        Enable or disable stream lifecycle debug logging.
        
        Args:
            enabled: True to enable debug logging, False to disable.
        """
        stream_debug.enabled = enabled
        logger.info(f"Stream debug logging {'enabled' if enabled else 'disabled'}")

    @staticmethod
    def is_debug_logging_enabled() -> bool:
        """Check if stream debug logging is enabled."""
        return stream_debug.enabled


class StreamManagerConsumerViewV1:
    """Handler-bound view that carries core-owned active ancestry."""

    __slots__ = ("__manager", "__producer_authority")

    def __init__(
        self,
        manager: StreamManager,
        producer_authority: ProducerAuthorityReferenceV1,
    ):
        self.__manager = manager
        self.__producer_authority = producer_authority

    def __can_access(self, stream: ChatStream | None) -> bool:
        if stream is None or stream.security_stream_ref is None:
            return False
        authority = self.__manager._security_authority
        return bool(
            authority is not None
            and authority.producer_can_access_envelope_v1(
                self.__producer_authority,
                stream.security_stream_ref.envelope_ref,
            )
        )

    def __view(
        self,
        stream: ChatStream,
    ) -> "ChatStreamConsumerViewV1":
        return ChatStreamConsumerViewV1(
            stream,
            access_check=lambda: self.__can_access(stream),
        )

    def create_lifecycle_streamer(
        self,
        data_type: ChatDataType,
        producer_name: str,
        config: Optional[ChatStreamConfig] = None,
    ) -> "ChatStreamerConsumerViewV1":
        return ChatStreamerConsumerViewV1(
            self.__manager.create_lifecycle_streamer(
                data_type=data_type,
                producer_name=producer_name,
                config=config,
                _producer_authority=self.__producer_authority,
            )
        )

    def find_stream(self, stream_id: ChatStreamIdentity):
        stream = self.__manager.find_stream(stream_id)
        return (
            self.__view(stream)
            if self.__can_access(stream)
            else None
        )

    def get_stream_ancestry(
        self,
        stream_id: ChatStreamIdentity,
    ) -> Dict[str, List[ChatStreamIdentity]]:
        stream = self.__manager.find_stream(stream_id)
        if not self.__can_access(stream):
            return {
                "parents": [],
                "ancestors": [],
                "cancelable": [],
            }
        ancestry = self.__manager.get_stream_ancestry(stream_id)
        return {
            key: [
                identity
                for identity in identities
                if self.__can_access(
                    self.__manager.find_stream(identity)
                )
            ]
            for key, identities in ancestry.items()
        }

    def get_active_streams(self) -> List["ChatStreamConsumerViewV1"]:
        return [
            self.__view(stream)
            for stream in self.__manager.get_active_streams()
            if self.__can_access(stream)
        ]

    def cancel_stream_chain(
        self,
        stream_id: ChatStreamIdentity,
    ) -> List[ChatStreamIdentity]:
        stream = self.__manager.find_stream(stream_id)
        if not self.__can_access(stream):
            return []
        return self.__manager.cancel_stream_chain(stream_id)

    def cancel_streams_by_type(
        self,
        data_type: ChatDataType,
    ) -> List[ChatStreamIdentity]:
        cancelled: list[ChatStreamIdentity] = []
        seen: set[StreamKey] = set()
        for stream in self.__manager.get_active_streams():
            if (
                stream.identity.data_type is not data_type
                or not self.__can_access(stream)
            ):
                continue
            for identity in self.__manager.cancel_stream_chain(
                stream.identity
            ):
                if identity.key in seen:
                    continue
                seen.add(identity.key)
                cancelled.append(identity)
        return cancelled


class ChatStreamConsumerViewV1:
    """Read-mostly handler view with no security-reference surface."""

    __slots__ = ("__access_check", "__stream")

    def __init__(
        self,
        stream: ChatStream,
        access_check: Callable[[], bool] | None = None,
    ):
        self.__stream = stream
        self.__access_check = access_check

    def __allowed(self) -> bool:
        return (
            self.__access_check is None
            or bool(self.__access_check())
        )

    @property
    def identity(self) -> ChatStreamIdentity:
        identity = self.__stream.identity
        return ChatStreamIdentity(
            data_type=identity.data_type,
            builder_id=identity.builder_id,
            stream_id=identity.stream_id,
            name=identity.name,
            producer_name=identity.producer_name,
        )

    @property
    def status(self) -> ChatStreamStatus:
        return self.__stream.status

    @property
    def start_time(self) -> Optional[Tuple[int, int]]:
        return self.__stream.start_time

    @property
    def end_time(self) -> Optional[Tuple[int, int]]:
        return self.__stream.end_time

    @property
    def ancestor_streams(self) -> List[ChatStreamIdentity]:
        if not self.__allowed():
            return []
        return [
            ChatStreamIdentity(
                data_type=identity.data_type,
                builder_id=identity.builder_id,
                stream_id=identity.stream_id,
                name=identity.name,
                producer_name=identity.producer_name,
            )
            for identity in self.__stream.ancestor_streams
        ]

    @property
    def source_streams(self) -> Dict[StreamKey, ChatStreamIdentity]:
        if not self.__allowed():
            return {}
        return {
            key: ChatStreamIdentity(
                data_type=identity.data_type,
                builder_id=identity.builder_id,
                stream_id=identity.stream_id,
                name=identity.name,
                producer_name=identity.producer_name,
            )
            for key, identity in self.__stream.source_streams.items()
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        if not self.__allowed():
            return {}
        return copy.deepcopy(self.__stream.metadata)

    def update_metadata(self, meta: Dict[str, Any]) -> None:
        if not self.__allowed():
            return
        self.__stream.update_metadata(meta)

    def update_inheritable_metadata(
        self,
        meta: Dict[str, Any],
        inherit: bool = True,
    ) -> None:
        if not self.__allowed():
            return
        self.__stream.update_inheritable_metadata(meta, inherit=inherit)


class ChatStreamerConsumerViewV1:
    """Handler output API without mutable lineage or authority registries."""

    __slots__ = ("__streamer",)

    def __init__(self, streamer: ChatStreamer):
        self.__streamer = streamer

    @property
    def data_type(self) -> ChatDataType:
        return self.__streamer.data_type

    @property
    def data_name(self) -> str | None:
        return self.__streamer.data_name

    @property
    def data_definition(self) -> DataBundleDefinition | None:
        return self.__streamer.data_definition

    @property
    def current_stream(self) -> ChatStreamConsumerViewV1 | None:
        stream = self.__streamer.current_stream
        if (
            stream is not None
            and self.__streamer.find_stream(stream.identity) is None
        ):
            return None
        return (
            ChatStreamConsumerViewV1(
                stream,
                access_check=lambda: (
                    self.__streamer.find_stream(stream.identity) is not None
                ),
            )
            if stream is not None
            else None
        )

    def new_stream(
        self,
        sources: List[ChatStreamIdentity],
        name: str | None = None,
        config: ChatStreamConfig | None = None,
    ) -> ChatStreamIdentity:
        return self.__streamer.new_stream(
            sources=sources,
            name=name,
            config=config,
        )

    def new_stream_from_input(
        self,
        input_stream: ChatStreamIdentity,
        name: str | None = None,
        config: ChatStreamConfig | None = None,
    ) -> ChatStreamIdentity:
        return self.__streamer.new_stream_from_input(
            input_stream=input_stream,
            name=name,
            config=config,
        )

    def open_stream(
        self,
        sources: List[ChatStreamIdentity] | None = None,
        name: str | None = None,
        config: ChatStreamConfig | None = None,
        meta: Dict[str, Any] | None = None,
    ) -> ChatStreamIdentity | None:
        return self.__streamer.open_stream(
            sources=sources,
            name=name,
            config=config,
            meta=meta,
        )

    def stream_data(
        self,
        data: StreamableData,
        missing_stream_callback: (
            Callable[[ChatData], ChatStream] | None
        ) = None,
        finish_stream: bool | None = None,
        stream_meta: Dict | None = None,
    ) -> None:
        self.__streamer.stream_data(
            data,
            missing_stream_callback=missing_stream_callback,
            finish_stream=finish_stream,
            stream_meta=stream_meta,
        )

    def cancel_current(self) -> None:
        self.__streamer.cancel_current()

    def cancel_stream(self, stream_id: ChatStreamIdentity) -> bool:
        return self.__streamer.cancel_stream(stream_id)

    def finish_current(self) -> None:
        self.__streamer.finish_current()

    def find_stream(
        self,
        stream_id: ChatStreamIdentity,
    ) -> ChatStreamConsumerViewV1 | None:
        stream = self.__streamer.find_stream(stream_id)
        return (
            ChatStreamConsumerViewV1(
                stream,
                access_check=lambda: (
                    self.__streamer.find_stream(stream.identity) is not None
                ),
            )
            if stream is not None
            else None
        )


class ChatDataSubmitter:
    def __init__(
        self,
        auto_update_input_stream: bool = True,
        security_authority: SecurityAuthorityV1 | None = None,
        producer_authority: ProducerAuthorityReferenceV1 | None = None,
    ):
        self.streamers: Dict[ChatDataType, List[ChatStreamer]] = {}
        self.streamer_name_map: Dict[str, ChatStreamer] = {}
        self.auto_update_input_stream = auto_update_input_stream
        self._security_authority = security_authority
        self._producer_authority = producer_authority
        # Type mapping for override support: original_type -> actual_type
        self._output_type_mapping: Dict[ChatDataType, ChatDataType] = {}

    def set_output_type_mapping(self, mapping: Dict[ChatDataType, ChatDataType]):
        """
        Set the output type mapping for type_override support.
        This allows handler code to use original type names while the framework
        automatically maps to the actual (overridden) types.
        
        Args:
            mapping: Dict mapping original types to actual types
        """
        self._output_type_mapping = mapping

    def _resolve_type(self, data_type: ChatDataType) -> ChatDataType:
        """Resolve original type to actual type using mapping."""
        return self._output_type_mapping.get(data_type, data_type)

    def update_input_stream(self, chat_data: ChatData):
        if not self.auto_update_input_stream:
            return
        for streamer_list in self.streamers.values():
            for streamer in streamer_list:
                if not streamer.auto_link_input:
                    continue
                streamer.update_input_stream(chat_data)

    def update_input_dispatch_v1(
        self,
        validated_dispatch: ValidatedDispatchV1,
    ) -> None:
        if self._security_authority is None:
            return
        for streamer_list in self.streamers.values():
            for streamer in streamer_list:
                streamer.update_input_dispatch_v1(
                    validated_dispatch,
                    link_functional_stream=(
                        self.auto_update_input_stream
                        and streamer.auto_link_input
                    ),
                )

    def active_security_parent_refs_v1(
        self,
    ) -> tuple[SecurityEnvelopeReferenceV1, ...]:
        if self._security_authority is None:
            return ()
        if self._producer_authority is None:
            self._security_authority._record(
                SecurityAuditEventCodeV1.INVALID_LINEAGE
            )
            raise SecurityStreamRejectedV1(
                "secure producer authority missing"
            )
        refs = self._security_authority.producer_parent_refs_v1(
            self._producer_authority
        )
        if refs is None:
            raise SecurityStreamRejectedV1(
                "secure producer authority invalid"
            )
        return refs

    def register_streamer(self, streamer: ChatStreamer):
        streamer_list = self.streamers.setdefault(streamer.data_type, [])
        streamer_list.append(streamer)
        if streamer.data_name is not None:
            self.streamer_name_map[streamer.data_name] = streamer

    def get_streamers(self, data_type: ChatDataType):
        actual_type = self._resolve_type(data_type)
        return self.streamers.get(actual_type, [])

    def get_streamer(self, data_type: ChatDataType):
        streamers = self.get_streamers(data_type)
        if len(streamers) == 0:
            return None
        if len(streamers) > 1:
            logger.warning(f"More than one streamer for data type {data_type}, using the first one.")
        return streamers[0]

    def get_streamer_by_name(self, name: str):
        return self.streamer_name_map.get(name, None)

    def submit(self, data: Union[StreamableData, Tuple[ChatDataType, StreamableData]],
               finish_stream: Optional[bool] = None):
        if data is None:
            return
        trusted_submission_envelope_ref = None
        if self._security_authority is not None:
            trusted_parents = self.active_security_parent_refs_v1()
            trusted_submission_envelope_ref = (
                self._security_authority.envelope_for_producer_v1(
                    self._producer_authority,
                    trusted_parents,
                )
            )
            if trusted_submission_envelope_ref is None:
                return
        data_type = None
        streamers = None
        stream_data = data  # 实际要流式传输的数据
        if len(self.streamers) == 1:
            data_type = list(self.streamers.keys())[0]
            streamers = self.get_streamers(data_type)
        if isinstance(data, ChatData):
            data_type = data.type
            streamers = self.get_streamers(data_type)
        elif isinstance(data, (DataBundle, np.ndarray)):
            if data_type is None:
                msg = f"Bare DataBundle is supported only if handler outputs single chat data type."
                raise ValueError(msg)
        elif isinstance(data, tuple) and len(data) == 2:
            chat_data_type, raw_data = data
            if not isinstance(chat_data_type, ChatDataType) or not isinstance(raw_data, (DataBundle, np.ndarray)):
                msg = f"Unsupported handler output type {type(data)}"
                raise ValueError(msg)
            if chat_data_type not in self.streamers:
                msg = f"Handler output type {chat_data_type} is not configured."
                raise ValueError(msg)
            data_type = chat_data_type
            streamers = self.get_streamers(data_type)
            stream_data = raw_data  # 使用提取的原始数据
        else:
            msg = f"Unsupported chat data with type {type(data)}"
            raise ValueError(msg)
        if streamers is None or len(streamers) == 0:
            logger.warning(f"No streamer for data type {data_type}")
            return
        for streamer in streamers:
            try:
                streamer.stream_data(
                    stream_data,
                    finish_stream=finish_stream,
                    _trusted_root_envelope_ref=(
                        trusted_submission_envelope_ref
                    ),
                )
            except SecurityStreamRejectedV1:
                if self._security_authority is not None:
                    self._security_authority._record(
                        SecurityAuditEventCodeV1.DISPATCH_DENIED
                    )
                    continue
                raise


class ChatDataSubmitterConsumerViewV1:
    """Handler-facing output API without registry mutation methods."""

    __slots__ = ("__submitter",)

    def __init__(self, submitter: ChatDataSubmitter):
        self.__submitter = submitter

    def submit(
        self,
        data: Union[
            StreamableData,
            Tuple[ChatDataType, StreamableData],
        ],
        finish_stream: bool | None = None,
    ) -> None:
        self.__submitter.submit(data, finish_stream=finish_stream)

    def get_streamers(
        self,
        data_type: ChatDataType,
    ) -> List[ChatStreamerConsumerViewV1]:
        return [
            ChatStreamerConsumerViewV1(streamer)
            for streamer in self.__submitter.get_streamers(data_type)
        ]

    def get_streamer(
        self,
        data_type: ChatDataType,
    ) -> ChatStreamerConsumerViewV1 | None:
        streamer = self.__submitter.get_streamer(data_type)
        return (
            ChatStreamerConsumerViewV1(streamer)
            if streamer is not None
            else None
        )

    def get_streamer_by_name(
        self,
        name: str,
    ) -> ChatStreamerConsumerViewV1 | None:
        streamer = self.__submitter.get_streamer_by_name(name)
        return (
            ChatStreamerConsumerViewV1(streamer)
            if streamer is not None
            else None
        )
