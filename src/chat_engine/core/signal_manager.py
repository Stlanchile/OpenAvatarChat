import queue
import threading
from dataclasses import dataclass, replace
from typing import Callable, Dict, List, Optional

from chat_engine.contexts.session_clock import SessionClock
from chat_engine.data_models.chat_signal import ChatSignal, SignalFilterRule
from chat_engine.data_models.chat_stream import ChatStreamIdentity
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.dispatch import (
    ConsumerCapabilityV1,
    ProducerAuthorityReferenceV1,
    SecurityEnvelopeReferenceV1,
    SecurityStreamReferenceV1,
)
from chat_engine.security.payload_isolation import isolate_signal_for_consumer_v1
from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)

_SIGNAL_SHUTDOWN_SENTINEL_V1 = object()


@dataclass(frozen=True, slots=True)
class _SignalListenerRegistrationV1:
    listener: Callable[[ChatSignal], None]
    consumer_capability: ConsumerCapabilityV1 | None
    producer_authority: ProducerAuthorityReferenceV1 | None


class SignalEmitter:
    def __init__(
        self,
        manager: "SignalManager",
        session_clock: SessionClock,
        source_name: Optional[str] = None,
        producer_authority: ProducerAuthorityReferenceV1 | None = None,
    ):
        self._manager = manager
        self.source_name = source_name
        self.session_clock = session_clock
        self._producer_authority = producer_authority

    def emit(self, signal: ChatSignal):
        self._manager.enqueue_signal_v1(
            signal,
            source_name=self.source_name,
            producer_authority=self._producer_authority,
        )


class SignalManager:
    def __init__(
        self,
        session_clock: SessionClock,
        security_authority: SecurityAuthorityV1 | None = None,
        work_runtime_v1: SessionWorkRuntimeV1 | None = None,
    ):
        self.session_clock = session_clock
        self._security_authority = security_authority
        self._work_runtime_v1 = work_runtime_v1
        self.running_flags = [False]
        self.signal_queue = queue.Queue()
        self.signal_distribute_thread: Optional[threading.Thread] = None
        self.signal_listeners: Dict[
            SignalFilterRule,
            List[_SignalListenerRegistrationV1],
        ] = {}
        self._stream_authority_resolver: Optional[
            Callable[[ChatStreamIdentity], SecurityStreamReferenceV1 | None]
        ] = None

    def get_clock(self):
        return self.session_clock

    def set_stream_authority_resolver_v1(
        self,
        resolver: Callable[
            [ChatStreamIdentity],
            SecurityStreamReferenceV1 | None,
        ],
    ) -> None:
        self._stream_authority_resolver = resolver

    def init(self):
        if self.signal_distribute_thread is not None:
            raise RuntimeError("SignalManager has been initialized")
        self.running_flags[0] = True
        self.signal_distribute_thread = threading.Thread(
            target=self.signal_distribute_thread_func,
            args=(self.running_flags, self.signal_queue, self.signal_listeners))
        self.signal_distribute_thread.start()

    def shutdown(self, timeout: float | None = None) -> bool:
        self.running_flags[0] = False
        self.signal_queue.put(_SIGNAL_SHUTDOWN_SENTINEL_V1)
        if self.signal_distribute_thread is not None:
            try:
                self.signal_distribute_thread.join(timeout=timeout)
            except RuntimeError:
                pass
            if self.signal_distribute_thread.is_alive():
                return False
        return self.finalize_shutdown_v1()

    def finalize_shutdown_v1(self) -> bool:
        thread = self.signal_distribute_thread
        if thread is not None and thread.is_alive():
            return False
        self.signal_distribute_thread = None
        self.drain_registered_work_v1()
        self.clear_listeners()
        return True

    def drain_registered_work_v1(self) -> None:
        """Discard queued signals while releasing their work-owned leases."""

        while True:
            try:
                queued_signal = self.signal_queue.get_nowait()
            except queue.Empty:
                break
            if self._work_runtime_v1 is None:
                continue
            work_item = (
                queued_signal
                if isinstance(queued_signal, WorkBoundItemV1)
                else getattr(queued_signal, "work_item_v1", None)
            )
            if isinstance(work_item, WorkBoundItemV1):
                work_item.release_once_v1(self._work_runtime_v1)

    def get_emitter(
        self,
        source_name: Optional[str] = None,
        producer_authority: ProducerAuthorityReferenceV1 | None = None,
    ):
        emitter = SignalEmitter(
            self,
            self.session_clock,
            source_name,
            producer_authority,
        )
        return emitter

    def register_listener(
        self,
        listener: Callable[[ChatSignal], None],
        signal_filter: SignalFilterRule = SignalFilterRule(None, None, None),
        consumer_capability: ConsumerCapabilityV1 | None = None,
        producer_authority: ProducerAuthorityReferenceV1 | None = None,
    ):
        if (
            self._security_authority is not None
            and consumer_capability is None
        ):
            self._security_authority._record(
                SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED
            )
            return
        listener_list = self.signal_listeners.setdefault(signal_filter, [])
        registration = _SignalListenerRegistrationV1(
            listener=listener,
            consumer_capability=consumer_capability,
            producer_authority=producer_authority,
        )
        if registration not in listener_list:
            listener_list.append(registration)

    def clear_listeners(self):
        self.signal_listeners.clear()

    def enqueue_signal_v1(
        self,
        signal: ChatSignal,
        *,
        source_name: str | None,
        producer_authority: ProducerAuthorityReferenceV1 | None,
    ) -> None:
        runtime = self._work_runtime_v1
        if runtime is not None and runtime.current_work_v1() is None:
            try:
                ingress = runtime.register_root_work_v1(
                    WorkOperationKindV1.GENERIC_ASYNC
                )
            except WorkAdmissionDeniedV1:
                return
            try:
                with runtime.activate_work_v1(ingress):
                    self._enqueue_signal_in_scope_v1(
                        signal,
                        source_name=source_name,
                        producer_authority=producer_authority,
                    )
            finally:
                runtime.release_work_v1(ingress)
            return
        self._enqueue_signal_in_scope_v1(
            signal,
            source_name=source_name,
            producer_authority=producer_authority,
        )

    def _enqueue_signal_in_scope_v1(
        self,
        signal: ChatSignal,
        *,
        source_name: str | None,
        producer_authority: ProducerAuthorityReferenceV1 | None,
    ) -> None:
        if self._security_authority is None:
            signal.source_name = source_name
            self.signal_queue.put_nowait(signal)
            return

        authority = self._security_authority
        signal_snapshot = isolate_signal_for_consumer_v1(signal)
        signal_snapshot.source_name = source_name
        stream_ref = None
        parent_refs: list[SecurityEnvelopeReferenceV1] = []

        if signal_snapshot.related_stream is not None:
            resolver = self._stream_authority_resolver
            if resolver is None:
                authority._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                return
            stream_ref = resolver(signal_snapshot.related_stream)
            if stream_ref is None:
                authority._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                return
            if (
                producer_authority is None
                or not authority.producer_can_access_envelope_v1(
                    producer_authority,
                    stream_ref.envelope_ref,
                )
            ):
                authority._record(
                    SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                    envelope_id=stream_ref.envelope_ref.envelope_id,
                )
                return
            parent_refs.append(stream_ref.envelope_ref)

        if producer_authority is not None:
            producer_parent_refs = authority.producer_parent_refs_v1(
                producer_authority
            )
            if producer_parent_refs is None:
                authority.audit_registry_failure_v1()
                return
            parent_refs.extend(producer_parent_refs)

        unique_parent_refs: list[SecurityEnvelopeReferenceV1] = []
        seen_parent_ids: set[str] = set()
        for parent_ref in parent_refs:
            if parent_ref.envelope_id in seen_parent_ids:
                continue
            seen_parent_ids.add(parent_ref.envelope_id)
            unique_parent_refs.append(parent_ref)

        if not unique_parent_refs:
            if producer_authority is None:
                authority._record(
                    SecurityAuditEventCodeV1.INVALID_LINEAGE
                )
                return
            envelope_ref = authority.envelope_for_producer_v1(
                producer_authority
            )
        elif (
            len(unique_parent_refs) == 1
            and stream_ref is not None
            and unique_parent_refs[0].envelope_id
            == stream_ref.envelope_ref.envelope_id
        ):
            envelope_ref = stream_ref.envelope_ref
        else:
            envelope_ref = authority.derive_envelope_v1(unique_parent_refs)
        if envelope_ref is None:
            return

        authorized = authority.authorize_signal_emission_v1(
            envelope_ref=envelope_ref,
            stream_ref=stream_ref,
            trusted_signal_type=signal_snapshot.type,
            trusted_source_type=signal_snapshot.source_type,
            trusted_source_name=source_name,
            payload=signal_snapshot,
        )
        if authorized is not None:
            runtime = self._work_runtime_v1
            if runtime is None:
                self.signal_queue.put_nowait(authorized)
                return
            scope = runtime.current_scope_v1()
            if scope is None:
                return
            try:
                item = runtime.make_child_item_v1(
                    authorized,
                    WorkOperationKindV1.GENERIC_ASYNC,
                    parent=scope.registered_work,
                    envelope_ref=envelope_ref,
                )
            except WorkAdmissionDeniedV1:
                return
            authorized = replace(
                authorized,
                work_item_v1=item,
            )
            try:
                if not runtime.perform_if_live_v1(
                    item.registered_work,
                    WorkValidationBoundaryV1.BEFORE_EGRESS,
                    lambda: self.signal_queue.put_nowait(authorized),
                ):
                    item.release_once_v1(runtime)
            except Exception:
                item.release_once_v1(runtime)
                raise

    def signal_distribute_thread_func(
        self,
        running_flags,
        signal_queue: queue.Queue,
        signal_listeners: Dict[
            SignalFilterRule,
            List[_SignalListenerRegistrationV1],
        ],
    ):
        while running_flags[0]:
            try:
                queued_item = signal_queue.get(block=True, timeout=0.5)
            except queue.Empty:
                continue
            if queued_item is _SIGNAL_SHUTDOWN_SENTINEL_V1:
                continue
            runtime = self._work_runtime_v1
            if runtime is None:
                self._distribute_signal_item_v1(
                    queued_item,
                    signal_listeners,
                )
                continue
            item = getattr(queued_item, "work_item_v1", None)
            if not isinstance(item, WorkBoundItemV1):
                self._distribute_signal_item_v1(
                    queued_item,
                    signal_listeners,
                )
                continue
            try:
                if not runtime.validate_work_v1(
                    item.registered_work,
                    WorkValidationBoundaryV1.QUEUE_DEQUEUE,
                ):
                    runtime.log_late_drop_v1(
                        item.registered_work,
                        "QUEUE_DEQUEUE",
                    )
                    continue
                with runtime.activate_work_v1(
                    item.registered_work,
                    item.envelope_ref,
                ):
                    self._distribute_signal_item_v1(
                        queued_item,
                        signal_listeners,
                    )
            finally:
                item.release_once_v1(runtime)

    def _distribute_signal_item_v1(
        self,
        queued_item,
        signal_listeners: Dict[
            SignalFilterRule,
            List[_SignalListenerRegistrationV1],
        ],
    ) -> None:
        validated_emission = None
        if self._security_authority is not None:
            # M3 dequeue validation happens before this method.  M2
            # authentication remains the first payload-relevant action.
            validated_emission = (
                self._security_authority
                .validate_dequeued_signal_emission_v1(queued_item)
            )
            if validated_emission is None:
                return
            if (
                self._work_runtime_v1 is not None
                and self._work_runtime_v1.current_work_v1() is None
            ):
                self._security_authority._record(
                    SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED,
                    dispatch_id=validated_emission.emission_id,
                )
                return
            if self._work_runtime_v1 is not None:
                scope = self._work_runtime_v1.current_scope_v1()
                if (
                    scope is None
                    or scope.envelope_ref
                    != validated_emission.envelope_ref
                ):
                    self._security_authority._record(
                        SecurityAuditEventCodeV1.DISPATCH_DENIED,
                        dispatch_id=validated_emission.emission_id,
                    )
                    return
            signal = validated_emission.payload
            if not isinstance(signal, ChatSignal):
                self._security_authority._record(
                    SecurityAuditEventCodeV1.DISPATCH_DENIED,
                    dispatch_id=validated_emission.emission_id,
                )
                return
            signal.type = validated_emission.trusted_signal_type
            signal.source_type = validated_emission.trusted_source_type
            signal.source_name = validated_emission.trusted_source_name
            if validated_emission.stream_ref is not None:
                trusted_identity = validated_emission.stream_ref.identity
                signal.related_stream = ChatStreamIdentity(
                    data_type=trusted_identity.data_type,
                    builder_id=trusted_identity.builder_id,
                    stream_id=trusted_identity.stream_id,
                    name=trusted_identity.name,
                    producer_name=trusted_identity.producer_name,
                )
            else:
                signal.related_stream = None
        else:
            signal = queued_item

        signal_stream_type = (
            signal.related_stream.data_type
            if signal.related_stream is not None
            else None
        )
        filter_keys = [
            SignalFilterRule(signal.type, signal.source_type, None),
            SignalFilterRule(None, signal.source_type, None),
            SignalFilterRule(signal.type, None, None),
            SignalFilterRule(None, None, None),
        ]
        if signal_stream_type is not None:
            filter_keys += [
                SignalFilterRule(
                    signal.type,
                    signal.source_type,
                    signal_stream_type,
                ),
                SignalFilterRule(
                    None,
                    signal.source_type,
                    signal_stream_type,
                ),
                SignalFilterRule(
                    signal.type,
                    None,
                    signal_stream_type,
                ),
                SignalFilterRule(None, None, signal_stream_type),
            ]
        for filter_key in filter_keys:
            for registration in signal_listeners.get(filter_key, []):
                if self._security_authority is not None:
                    capability = registration.consumer_capability
                    if capability is None or not (
                        self._security_authority.consumer_is_authorized_v1(
                            validated_emission.envelope_ref,
                            capability,
                        )
                    ):
                        continue
                    producer_authority = registration.producer_authority
                    if (
                        producer_authority is not None
                        and not self._security_authority
                        .record_signal_for_producer_v1(
                            producer_authority,
                            capability,
                            validated_emission.envelope_ref,
                            dispatch_id=validated_emission.emission_id,
                        )
                    ):
                        continue
                    listener_signal = isolate_signal_for_consumer_v1(
                        signal
                    )
                    try:
                        registration.listener(listener_signal)
                    except Exception:
                        # Never log a private signal or exception text.
                        self._security_authority._record(
                            SecurityAuditEventCodeV1.DISPATCH_DENIED,
                            envelope_id=(
                                validated_emission
                                .envelope_ref.envelope_id
                            ),
                            consumer_capability_id=(
                                capability.capability_id
                            ),
                            dispatch_id=validated_emission.emission_id,
                        )
                else:
                    registration.listener(signal)
