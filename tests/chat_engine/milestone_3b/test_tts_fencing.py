from __future__ import annotations

import importlib
import sys
import threading
import time
from collections import deque
from types import ModuleType, SimpleNamespace

import numpy as np

from chat_engine.common.handler_base import HandlerDataInfo
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_stream import ChatStreamIdentity
from chat_engine.data_models.runtime_data.data_bundle import (
    DataBundleDefinition,
    DataBundleEntry,
)
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import (
    WorkFenceV1,
    WorkOperationKindV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)
from handlers.tts.bailian_tts.tts_handler_cosyvoice_bailian import (
    BailianTTSSession,
    CosyvoiceCallBack,
)
from handlers.tts.bailian_tts.tts_handler_cosyvoice_bailian import (
    HandlerTTS as BailianHandler,
)
from handlers.tts.bailian_tts.tts_handler_cosyvoice_bailian import (
    TTSContext as BailianContext,
)
from handlers.tts.cosyvoice import (
    cosyvoice_processor as cosyvoice_processor_module,
)
from handlers.tts.cosyvoice.cosyvoice_processor import (
    TTSCosyVoiceProcessor,
)
from handlers.tts.cosyvoice.tts_handler_cosyvoice import (
    HandlerTTS as LocalCosyVoiceHandler,
)
from handlers.tts.cosyvoice.tts_handler_cosyvoice import (
    TTSContext as LocalCosyVoiceContext,
)

if "edge_tts" not in sys.modules:
    edge_tts_stub = ModuleType("edge_tts")
    edge_tts_stub.Communicate = object
    sys.modules["edge_tts"] = edge_tts_stub

edge_module = importlib.import_module(
    "handlers.tts.edgetts.tts_handler_edgetts"
)


class _Submitter:
    def __init__(self) -> None:
        self.outputs: list[tuple[object, bool | None]] = []

    def submit(self, output, finish_stream=None):
        self.outputs.append((output, finish_stream))


class _RaisingSubmitter:
    @staticmethod
    def submit(*_args, **_kwargs):
        raise RuntimeError("OWNER_CALLBACK_CANARY")


class _BlockingCommunicate:
    started = threading.Event()
    release = threading.Event()

    def __init__(self, text, voice) -> None:
        del text, voice

    def stream_sync(self):
        self.started.set()
        self.release.wait(timeout=5)
        yield {"type": "audio", "data": b"\0\0" * 100}


class _ImmediateCommunicate:
    def __init__(self, text, voice) -> None:
        del text, voice

    def stream_sync(self):
        yield {"type": "audio", "data": b"\0\0" * 100}


class _InputData:
    def __init__(self, text: str, *, terminal: bool) -> None:
        self._text = text
        self._terminal = terminal

    def get_main_data(self):
        return self._text

    def get_meta(self, name, default=None):
        if name == "avatar_text_end":
            return self._terminal
        return default


class _FakeInput:
    def __init__(self, text: str, *, terminal: bool) -> None:
        self.type = ChatDataType.AVATAR_TEXT
        self.data = _InputData(text, terminal=terminal)
        self.is_last_data = terminal


class _Queue:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def put_nowait(self, item) -> None:
        self.items.append(item)

    def put(self, item) -> None:
        self.items.append(item)


class _CancellingSynthesizer:
    def __init__(self) -> None:
        self.cancel_calls = 0

    def streaming_cancel(self) -> None:
        self.cancel_calls += 1


def _audio_definition() -> DataBundleDefinition:
    definition = DataBundleDefinition()
    definition.add_entry(
        DataBundleEntry.create_audio_entry(
            "avatar_audio",
            1,
            24000,
        )
    )
    definition.lockdown()
    return definition


def _runtime_parent():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC
    )
    return controller, runtime, parent


def test_edgetts_retirement_during_synthesis_drops_audio(
    monkeypatch,
):
    _BlockingCommunicate.started.clear()
    _BlockingCommunicate.release.clear()
    monkeypatch.setattr(
        edge_module.edge_tts,
        "Communicate",
        _BlockingCommunicate,
    )
    monkeypatch.setattr(
        edge_module.librosa,
        "load",
        lambda *_args, **_kwargs: (
            np.ones(100, dtype=np.float32),
            24000,
        ),
    )
    controller, runtime, parent = _runtime_parent()
    handler = edge_module.HandlerTTS()
    handler.voice = "synthetic"
    context = edge_module.TTSContext("session")
    context.work_runtime_v1 = runtime
    submitter = _Submitter()
    context.data_submitter = submitter

    def synthesize() -> None:
        with runtime.activate_work_v1(parent):
            handler._handle_fenced_v1(
                context,
                _FakeInput("hello.", terminal=True),
                "hello.",
                _audio_definition(),
            )

    thread = threading.Thread(target=synthesize)
    thread.start()
    assert _BlockingCommunicate.started.wait(timeout=2)
    retirement = controller.retire_generation_v1()
    _BlockingCommunicate.release.set()
    thread.join(timeout=3)

    assert not thread.is_alive()
    assert submitter.outputs == []
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_edgetts_disabled_mode_preserves_legacy_output(monkeypatch):
    monkeypatch.setattr(
        edge_module.edge_tts,
        "Communicate",
        _ImmediateCommunicate,
    )
    monkeypatch.setattr(
        edge_module.librosa,
        "load",
        lambda *_args, **_kwargs: (
            np.ones(100, dtype=np.float32),
            24000,
        ),
    )
    handler = edge_module.HandlerTTS()
    handler.voice = "synthetic"
    context = edge_module.TTSContext("legacy")
    submitter = _Submitter()
    context.data_submitter = submitter
    output_info = HandlerDataInfo(
        type=ChatDataType.AVATAR_AUDIO,
        definition=_audio_definition(),
    )

    handler.handle(
        context,
        _FakeInput("hello", terminal=True),
        {ChatDataType.AVATAR_AUDIO: output_info},
    )

    assert len(submitter.outputs) == 2
    assert submitter.outputs[-1][1] is True


def test_bailian_late_callback_cannot_emit_or_mutate_current_state():
    controller, runtime, parent = _runtime_parent()
    child = runtime.register_child_work_v1(
        parent,
        WorkOperationKindV1.TTS_SYNTHESIS,
    )
    item = WorkBoundItemV1(payload=None, registered_work=child)
    context = BailianContext("session")
    context.work_runtime_v1 = runtime
    submitter = _Submitter()
    context.data_submitter = submitter
    stream_id = ChatStreamIdentity(
        data_type=ChatDataType.AVATAR_TEXT,
        builder_id=1,
        stream_id=1,
    )
    session = BailianTTSSession(
        input_stream_id=stream_id,
        work_item_v1=item,
        work_runtime_v1=runtime,
    )
    context.api_links[stream_id.key] = session
    callback = CosyvoiceCallBack(
        context,
        _audio_definition(),
        session,
    )
    retirement = controller.retire_generation_v1()

    callback.on_data(b"\0\0" * 13000)
    callback.on_complete()

    assert submitter.outputs == []
    assert context.api_links[stream_id.key] is session
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_bailian_precleanup_cancel_holds_lease_until_terminal_callback():
    controller, runtime, parent = _runtime_parent()
    child = runtime.register_child_work_v1(
        parent,
        WorkOperationKindV1.TTS_SYNTHESIS,
    )
    item = WorkBoundItemV1(payload=None, registered_work=child)
    context = BailianContext("session")
    context.work_runtime_v1 = runtime
    stream_id = ChatStreamIdentity(
        data_type=ChatDataType.AVATAR_TEXT,
        builder_id=1,
        stream_id=1,
    )
    synthesizer = _CancellingSynthesizer()
    session = BailianTTSSession(
        input_stream_id=stream_id,
        synthesizer=synthesizer,
        work_item_v1=item,
        work_runtime_v1=runtime,
    )
    context.api_links[stream_id.key] = session
    callback = CosyvoiceCallBack(
        context,
        _audio_definition(),
        session,
    )
    handler = BailianHandler()
    retirement = controller.retire_generation_v1()

    handler.drain_registered_work_v1(context)

    assert synthesizer.cancel_calls == 1
    assert controller.snapshot_v1().unreleased_work_by_generation == ((1, 2),)
    callback.on_close()
    assert controller.snapshot_v1().unreleased_work_by_generation == ((1, 1),)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(
        retirement.cleanup_fence
    )
    assert controller.shutdown()


def test_bailian_live_callbacks_emit_terminal_and_release():
    controller, runtime, parent = _runtime_parent()
    child = runtime.register_child_work_v1(
        parent,
        WorkOperationKindV1.TTS_SYNTHESIS,
    )
    item = WorkBoundItemV1(payload=None, registered_work=child)
    context = BailianContext("session")
    context.work_runtime_v1 = runtime
    submitter = _Submitter()
    context.data_submitter = submitter
    stream_id = ChatStreamIdentity(
        data_type=ChatDataType.AVATAR_TEXT,
        builder_id=1,
        stream_id=1,
    )
    session = BailianTTSSession(
        input_stream_id=stream_id,
        work_item_v1=item,
        work_runtime_v1=runtime,
    )
    context.api_links[stream_id.key] = session
    callback = CosyvoiceCallBack(
        context,
        _audio_definition(),
        session,
    )

    callback.on_data(b"\0\0" * 13000)
    callback.on_complete()

    assert len(submitter.outputs) == 2
    assert submitter.outputs[-1][1] is True
    assert stream_id.key not in context.api_links
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


def test_local_cosyvoice_owner_revalidates_process_result_and_ref_is_opaque():
    controller, runtime, parent = _runtime_parent()
    handler = object.__new__(LocalCosyVoiceHandler)
    handler.sample_rate = 24000
    handler.cancelled_work_v1 = {}
    handler.task_queue_map = {}
    handler.tts_input_queue = _Queue()
    context = LocalCosyVoiceContext("session")
    context.task_queue = deque()
    context.work_runtime_v1 = runtime
    submitter = _Submitter()
    context.data_submitter = submitter
    handler.start_context(SimpleNamespace(), context)

    with runtime.activate_work_v1(parent):
        handler._handle_fenced_v1(
            context,
            _FakeInput("hello.", terminal=False),
            "hello.",
        )

    assert len(handler.tts_input_queue.items) == 1
    worker_item = handler.tts_input_queue.items[0]
    assert isinstance(worker_item["work_ref_v1"], str)
    assert not any(
        isinstance(value, WorkFenceV1)
        for value in worker_item.values()
    )
    task = context.task_queue[0]
    retirement = controller.retire_generation_v1()
    task.result_queue.put(np.ones((1, 100), dtype=np.float32))
    task.result_queue.put(None)

    deadline = time.monotonic() + 3
    while context.task_queue and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not context.task_queue
    assert submitter.outputs == []
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    context.task_queue.append(None)
    context.task_consume_thread.join(timeout=2)
    assert not context.task_consume_thread.is_alive()
    assert controller.shutdown()


def _remote_processor_for_test(output_queue: _Queue):
    processor = object.__new__(TTSCosyVoiceProcessor)
    processor.model = None
    processor.api_url = "https://synthetic.invalid"
    processor.spk_id = "synthetic"
    processor.sample_rate = 24000
    processor.cancelled_work_v1 = {}
    processor.output_queue = output_queue
    processor.ref_audio_buffer = None
    processor.ref_audio_text = None
    processor.dump_audio = False
    return processor


def test_local_cosyvoice_remote_non_200_always_returns_terminal(
    monkeypatch,
):
    output_queue = _Queue()
    processor = _remote_processor_for_test(output_queue)
    monkeypatch.setattr(
        cosyvoice_processor_module.requests,
        "get",
        lambda *_args, **_kwargs: SimpleNamespace(
            status_code=503,
        ),
    )

    processor._process_task_v1({
        "text": "public",
        "key": "task",
        "session_id": "session",
        "work_ref_v1": "opaque",
    })

    assert output_queue.items == [{
        "key": "task",
        "tts_speech": None,
        "session_id": "session",
    }]


def test_local_cosyvoice_worker_exception_always_returns_terminal(
    monkeypatch,
):
    output_queue = _Queue()
    processor = _remote_processor_for_test(output_queue)

    def fail_request(*_args, **_kwargs):
        raise RuntimeError("WORKER_EXCEPTION_CANARY")

    monkeypatch.setattr(
        cosyvoice_processor_module.requests,
        "get",
        fail_request,
    )

    processor._process_task_v1({
        "text": "public",
        "key": "task",
        "session_id": "session",
        "work_ref_v1": "opaque",
    })

    assert output_queue.items == [{
        "key": "task",
        "tts_speech": None,
        "session_id": "session",
    }]


def test_local_cosyvoice_owner_callback_exception_releases_and_advances():
    controller, runtime, parent = _runtime_parent()
    handler = object.__new__(LocalCosyVoiceHandler)
    handler.sample_rate = 24000
    handler.cancelled_work_v1 = {}
    handler.task_queue_map = {}
    handler.tts_input_queue = _Queue()
    context = LocalCosyVoiceContext("session")
    context.task_queue = deque()
    context.work_runtime_v1 = runtime
    context.data_submitter = _RaisingSubmitter()
    handler.start_context(SimpleNamespace(), context)

    with runtime.activate_work_v1(parent):
        handler._handle_fenced_v1(
            context,
            _FakeInput("hello.", terminal=False),
            "hello.",
        )
    task = context.task_queue[0]
    item = task.work_item_v1
    task.result_queue.put(
        np.ones((1, 100), dtype=np.float32)
    )

    deadline = time.monotonic() + 3
    while context.task_queue and time.monotonic() < deadline:
        time.sleep(0.01)

    assert not context.task_queue
    assert item is not None
    assert not item.release_once_v1(runtime)
    context.task_queue.append(None)
    context.task_consume_thread.join(timeout=2)
    assert not context.task_consume_thread.is_alive()
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()
