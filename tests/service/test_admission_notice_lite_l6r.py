from __future__ import annotations

import asyncio
import io
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from PIL import Image

from chat_engine.contexts.session_history import SessionHistory
from chat_engine.core.chat_session import ChatSession
from handlers.agent.chat_agent_handler import ChatAgentContext, ChatAgentHandler
from handlers.agent.memory.session_memory_manager import SessionMemoryManager
from handlers.agent.oc_bridge.pending_confirmations import PendingConfirmationsManager
from handlers.agent.oc_bridge.task_notification_queue import (
    TaskNotification,
    TaskNotificationQueue,
)
from service.admission_notice_lite_chat_context import AdmissionContextV1
from service.admission_notice_lite_contracts import (
    RecognitionJobContextLiteV1,
    RecognitionStateLiteV1,
    ValidatedAdmissionFrameLiteV1,
)
from service.admission_notice_lite_routes import (
    _status_content,
    register_admission_notice_lite_routes,
)
from service.admission_notice_lite_service import AdmissionNoticeLiteService
from service.conversation_reset import reset_exact_chat_session_conversation
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _context(
    *,
    name: str | None = "李明",
    source_province: str | None = "湖北",
) -> AdmissionContextV1:
    return AdmissionContextV1(
        schema_version="admission_context_v1",
        institution_name="湖北交通职业技术学院",
        college="交通信息学院",
        name=name,
        source_province=source_province,
        major="智能交通技术(专本联合培养)",
    )


@pytest.mark.parametrize(
    ("name", "source_province", "expected_keys"),
    (
        (
            "李明",
            "湖北",
            {
                "schema_version",
                "institution_name",
                "college",
                "name",
                "source_province",
                "major",
            },
        ),
        (
            None,
            "湖北",
            {
                "schema_version",
                "institution_name",
                "college",
                "source_province",
                "major",
            },
        ),
        (
            "李明",
            None,
            {
                "schema_version",
                "institution_name",
                "college",
                "name",
                "major",
            },
        ),
        (
            None,
            None,
            {
                "schema_version",
                "institution_name",
                "college",
                "major",
            },
        ),
    ),
)
def test_public_context_omits_unavailable_optional_fields(
    name: str | None,
    source_province: str | None,
    expected_keys: set[str],
) -> None:
    public = _context(name=name, source_province=source_province).to_public_dict()
    assert set(public) == expected_keys
    assert None not in public.values()
    assert "未识别" not in public.values()


def test_public_context_rejects_unsupported_major_and_wrong_constants() -> None:
    with pytest.raises(ValueError, match="major"):
        AdmissionContextV1(
            schema_version="admission_context_v1",
            institution_name="湖北交通职业技术学院",
            college="交通信息学院",
            name=None,
            source_province=None,
            major="不存在的专业",  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="institution"):
        AdmissionContextV1(
            schema_version="admission_context_v1",
            institution_name="其他学校",
            college="交通信息学院",
            name=None,
            source_province=None,
            major="智能交通技术",
        )


class _ContextProcessor:
    def __init__(self, admission_context: AdmissionContextV1 | None = None) -> None:
        self.admission_context = admission_context or _context()

    async def prepare_for_ingestion(self) -> bool:
        return True

    async def process(
        self,
        context: RecognitionJobContextLiteV1,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
    ) -> AdmissionContextV1:
        assert context.session_is_current()
        assert frames
        return self.admission_context


def _jpeg() -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(output, format="JPEG")
    return output.getvalue()


@pytest.mark.parametrize(
    ("name", "source_province"),
    (("李明", "湖北"), (None, "湖北"), ("李明", None), (None, None)),
)
@pytest.mark.asyncio
async def test_owner_get_exposes_only_completed_sanitized_context(
    name: str | None,
    source_province: str | None,
) -> None:
    owner = object()

    class Engine:
        def __init__(self) -> None:
            self.sessions = {"owner": owner}

        @staticmethod
        def add_session_stop_observer(observer) -> None:
            assert callable(observer)

    app = FastAPI()
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=Engine(),
        config=AdmissionNoticeLiteFeatureConfigV1(enabled=True),
        processor=_ContextProcessor(
            _context(name=name, source_province=source_province)
        ),
    )
    assert service is not None
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            created = await client.post(
                "/api/v1/sessions/owner/admission-notice/recognitions",
                files={"frame_1": ("frame.jpg", _jpeg(), "image/jpeg")},
            )
            recognition_id = created.json()["recognition_id"]
            for _ in range(100):
                response = await client.get(
                    "/api/v1/sessions/owner/admission-notice/recognitions/"
                    f"{recognition_id}"
                )
                if response.json()["status"] == "completed":
                    break
                await asyncio.sleep(0)
        public = response.json()
        assert public == {
            "recognition_id": recognition_id,
            "status": "completed",
            "admission_context": _context(
                name=name,
                source_province=source_province,
            ).to_public_dict(),
        }
        public_repr = repr(public).lower()
        assert all(
            forbidden not in public_repr
            for forbidden in (
                "ocr",
                "spans",
                "polygon",
                "score",
                "frame_id",
                "candidates",
                "provenance",
                "model_identity",
            )
        )
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_completed_job_retains_only_sanitized_context_for_terminal_record() -> None:
    owner = object()
    service = AdmissionNoticeLiteService(
        config=AdmissionNoticeLiteFeatureConfigV1(enabled=True),
        session_lookup=lambda session_id: owner if session_id == "owner" else None,
        processor=_ContextProcessor(),
    )
    permit = await service.begin_ingestion("owner")
    frame = ValidatedAdmissionFrameLiteV1(
        frame_index=1,
        jpeg_bytes=b"\xff\xd8\xff\xd9",
        encoded_size=4,
        width=1,
        height=1,
        exif_orientation=1,
    )
    try:
        created = await service.create_recognition(permit, (frame,))
    finally:
        service.release_ingestion(permit)
    try:
        for _ in range(100):
            job, admission_context = await service.get_recognition_with_context(
                "owner",
                created.recognition_id,
            )
            if job.state is RecognitionStateLiteV1.COMPLETED:
                break
            await asyncio.sleep(0)
        assert job.state is RecognitionStateLiteV1.COMPLETED
        assert admission_context == _context()
        assert service.retained_frame_count == 0
        assert _status_content(job, admission_context) == {
            "recognition_id": created.recognition_id,
            "status": "completed",
            "admission_context": _context().to_public_dict(),
        }
        runtime = service._jobs[created.recognition_id]
        assert not hasattr(runtime, "ocr")
        assert not hasattr(runtime, "result")
    finally:
        await service.shutdown()


def test_recognition_production_path_has_no_automatic_chatagent_bridge() -> None:
    processor_source = (
        PROJECT_ROOT / "src/service/admission_notice_lite_processor.py"
    ).read_text(encoding="utf-8")
    demo_source = (PROJECT_ROOT / "src/demo.py").read_text(encoding="utf-8")
    chat_source = (
        PROJECT_ROOT / "src/handlers/agent/chat_agent_handler.py"
    ).read_text(encoding="utf-8")
    combined = f"{processor_source}\n{demo_source}\n{chat_source}"
    assert "personalize_admission_notice_lite_v1" not in combined
    assert "AdmissionNoticeChatPersonalizerLiteV1" not in combined
    assert "ChatAgentTurnContextLiteV1" not in combined
    assert "use_tools = False" not in combined
    assert "max_rounds = 1" not in combined


def test_bound_conversation_reset_clears_semantics_but_keeps_session_alive() -> None:
    context = ChatAgentContext("owner")
    context.memory = SessionMemoryManager()
    context.memory.record_user_input("<admission-context>old</admission-context>")
    context.memory.record_assistant_response("old reply")
    context.input_buffer = "partial"
    context.responded_events["event"] = 1.0
    context.pending_confirmations = PendingConfirmationsManager()
    context.pending_confirmations.upsert([{"id": "old", "text": "old"}])
    context.task_queue = TaskNotificationQueue()
    context.task_queue.push(TaskNotification(task_id="old", status="completed"))

    session = object.__new__(ChatSession)
    handler = ChatAgentHandler()
    session.handlers = {
        "chat_agent": SimpleNamespace(
            env=SimpleNamespace(handler=handler, context=context)
        )
    }
    history = SessionHistory()
    history.create_and_add_event(data="old")
    session.session_context = SimpleNamespace(session_history=history)
    session._playback_begin_event_ids = {"stream": "event"}

    assert reset_exact_chat_session_conversation(session)
    assert context.memory.get_dialogue_for_llm() == []
    assert context.memory.turn_count == 0
    assert context.input_buffer == ""
    assert context.responded_events == {}
    assert context.pending_confirmations.to_serializable() == []
    assert context.task_queue.size == 0
    assert history.get_recent_events() == []
    assert session._playback_begin_event_ids == {}
    assert session.handlers["chat_agent"].env.context is context
