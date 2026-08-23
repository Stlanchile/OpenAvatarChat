"""Per-consumer mutable payload isolation for secure dispatch."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

import numpy as np

from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.runtime_data.data_bundle import (
    DataBundle,
    DataBundleDefinition,
)
from chat_engine.data_models.runtime_data.data_store import DataStore, DataStoreType


@dataclass(frozen=True, slots=True)
class _ImmutableArraySnapshotV1:
    buffer: bytes
    dtype: np.dtype
    shape: tuple[int, ...]

    @classmethod
    def from_array(cls, value: np.ndarray) -> _ImmutableArraySnapshotV1:
        contiguous = np.ascontiguousarray(value)
        return cls(
            buffer=contiguous.tobytes(order="C"),
            dtype=contiguous.dtype,
            shape=tuple(contiguous.shape),
        )

    def consumer_view(self) -> np.ndarray:
        # bytes owns immutable storage; numpy cannot make this view writeable.
        return np.frombuffer(self.buffer, dtype=self.dtype).reshape(self.shape)


@dataclass(frozen=True, slots=True)
class _DataStoreSnapshotV1:
    value: Any
    storage: DataStoreType
    immutable_array: bool = False

    def clone(self) -> DataStore:
        if self.immutable_array:
            value = self.value.consumer_view()
        elif isinstance(self.value, str) or self.value is None:
            value = self.value
        else:
            value = copy.deepcopy(self.value)
        return DataStore(value, self.storage)


class ChatDataIsolationPlanV1:
    """Capture one stable packet snapshot, then create isolated sink views."""

    def __init__(self, chat_data: ChatData):
        self._stream_id = copy.copy(chat_data.stream_id)
        self._source = chat_data.source
        self._type = chat_data.type
        self._timestamp = tuple(chat_data.timestamp)
        self._is_first_data = chat_data.is_first_data
        self._is_last_data = chat_data.is_last_data
        self._bundle_definition = None
        self._bundle_metadata = None
        self._bundle_events = None
        self._data_stores: tuple[_DataStoreSnapshotV1, ...] = ()

        if chat_data.data is not None:
            self._bundle_definition = chat_data.data.definition
            self._bundle_metadata = copy.deepcopy(chat_data.data.metadata)
            self._bundle_events = copy.deepcopy(chat_data.data.events)
            snapshots: list[_DataStoreSnapshotV1] = []
            for store in chat_data.data.data:
                if isinstance(store.data, np.ndarray):
                    snapshots.append(
                        _DataStoreSnapshotV1(
                            value=_ImmutableArraySnapshotV1.from_array(store.data),
                            storage=store.storage,
                            immutable_array=True,
                        )
                    )
                else:
                    snapshots.append(
                        _DataStoreSnapshotV1(
                            value=store.data,
                            storage=store.storage,
                        )
                    )
            self._data_stores = tuple(snapshots)

    def clone(self) -> ChatData:
        bundle = None
        if self._bundle_definition is not None:
            definition = DataBundleDefinition()
            for entry in self._bundle_definition.entries.values():
                definition.add_entry(copy.deepcopy(entry))
            if self._bundle_definition.main_entry_name is not None:
                definition.set_main_entry(self._bundle_definition.main_entry_name)
            bundle = DataBundle(definition)
            bundle.metadata = copy.deepcopy(self._bundle_metadata)
            bundle.events = copy.deepcopy(self._bundle_events)
            bundle.data = [snapshot.clone() for snapshot in self._data_stores]

        return ChatData(
            stream_id=copy.copy(self._stream_id),
            source=self._source,
            type=self._type,
            timestamp=self._timestamp,
            data=bundle,
            is_first_data=self._is_first_data,
            is_last_data=self._is_last_data,
        )


def isolate_signal_for_consumer_v1(signal: Any) -> Any:
    """Deep-clone mutable signal fields before delivery to each listener."""

    model_copy = getattr(signal, "model_copy", None)
    if callable(model_copy):
        return model_copy(deep=True)
    return copy.deepcopy(signal)
