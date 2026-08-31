#!/usr/bin/env python3
"""Positive source projection for the historically approved Lite L3 boundary."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from collections.abc import Mapping

HISTORICAL_L3_COMMIT = "56ad0a362e48cf35a1dea558b134c130da1467c9"
HISTORICAL_L3_QUALIFICATION_SOURCE_SHA256 = (
    "b9c9ee00e78e0bcf318b47618145b052d4b29d9cd79ae1211688f683620d163f"
)
APPROVED_MODEL_MANIFEST_SHA256_LITE_V1 = (
    "1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b"
)

_CONTRACTS_PATH = "src/service/admission_notice_lite_contracts.py"
_OCR_PATH = "src/service/admission_notice_lite_ocr.py"
_GATE_PATH = "src/service/admission_notice_lite_ocr_qualification.py"
_SERVICE_PATH = "src/service/admission_notice_lite_service.py"

L3_SIDECAR_SOURCE_PATHS = (
    "services/admission_notice_ocr/model_manifest.json",
    "services/admission_notice_ocr/pyproject.toml",
    "services/admission_notice_ocr/uv.lock",
    "services/admission_notice_ocr/src/admission_notice_ocr/__init__.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/app.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/manifest.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/pipeline.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/protocol.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/qualify.py",
    "services/admission_notice_ocr/src/admission_notice_ocr/sidecar_qualify.py",
)
L3_MAIN_SOURCE_PATHS = (
    "scripts/admission_notice_lite_l3_qualify.py",
    "src/service/__init__.py",
    _CONTRACTS_PATH,
    "src/service/admission_notice_lite_ingestion.py",
    _OCR_PATH,
    _GATE_PATH,
    _SERVICE_PATH,
    "src/service/service_data_models/__init__.py",
    "src/service/service_data_models/admission_notice_lite_config.py",
)
L3_QUALIFICATION_SOURCE_PATHS = L3_SIDECAR_SOURCE_PATHS + L3_MAIN_SOURCE_PATHS

L4_DOWNSTREAM_SOURCE_PATHS = (
    "src/service/admission_notice_lite_major_catalog.py",
    "src/service/admission_notice_lite_processor.py",
    "src/service/admission_notice_lite_semantics.py",
)
L5_DOWNSTREAM_SOURCE_PATHS = (
    "src/demo.py",
    "src/handlers/agent/chat_agent_handler.py",
    "src/handlers/agent/prompt/prompt_compiler.py",
    "src/service/admission_notice_lite_chat_context.py",
    "src/service/admission_notice_lite_personalization.py",
)

_HISTORICAL_DISABLED_GATE_SOURCE = (
    b'"""Reviewed real-runtime qualification gate for Admission Notice Lite L3."""\n'
    b"\n"
    b"QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1: str | None = None\n"
)

_CONTRACT_ASSIGNMENTS = (
    "MAX_OCR_SPANS_PER_FRAME_LITE_V1",
    "MAX_OCR_CHARACTERS_PER_SPAN_LITE_V1",
    "MAX_OCR_UTF8_BYTES_PER_SPAN_LITE_V1",
    "MAX_OCR_AGGREGATE_CHARACTERS_PER_FRAME_LITE_V1",
    "MAX_OCR_AGGREGATE_UTF8_BYTES_PER_FRAME_LITE_V1",
    "_SHA256_PATTERN",
)
_CONTRACT_CLASSES = (
    "RecognitionStateLiteV1",
    "RecognitionErrorReasonLiteV1",
    "RecognitionJobContextLiteV1",
    "ValidatedAdmissionFrameLiteV1",
    "OcrSpanLiteV1",
    "OcrFrameLiteV1",
    "OcrBatchLiteV1",
    "OcrRuntimeIdentityLiteV1",
    "RecognitionProcessorLiteV1",
    "RecognitionJobLiteV1",
    "AdmissionNoticeLiteError",
)
_L3_ERROR_REASON_MEMBERS = (
    "INVALID_REQUEST",
    "INVALID_IMAGE",
    "IMAGE_TOO_LARGE",
    "IMAGE_DIMENSIONS_UNSUPPORTED",
    "TOO_MANY_FRAMES",
    "UNSUPPORTED_MEDIA_TYPE",
    "SERVICE_UNAVAILABLE",
    "SERVICE_BUSY",
    "RECOGNITION_ALREADY_ACTIVE",
    "RECOGNITION_NOT_FOUND",
    "RECOGNITION_CANCELLED",
    "RECOGNITION_EXPIRED",
    "INTERNAL_ERROR",
)
_REVIEWED_L4_SEMANTIC_FAILURE_MEMBERS = frozenset(
    {
        "UNSUPPORTED_NOTICE",
        "INSUFFICIENT_NOTICE",
        "MAJOR_NOT_RECOGNIZED",
        "AMBIGUOUS_NOTICE",
    }
)

_OCR_ASSIGNMENTS = (
    "OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1",
    "MAX_OCR_REQUEST_METADATA_BYTES_LITE_V1",
    "MAX_OCR_RESPONSE_BYTES_LITE_V1",
    "MAX_OCR_REQUEST_JPEG_BYTES_LITE_V1",
    "MAX_OCR_REQUEST_TOTAL_BYTES_LITE_V1",
    "OCR_REQUEST_MAGIC_LITE_V1",
    "OCR_RESPONSE_MAGIC_LITE_V1",
    "_FRAME_PREFIX",
    "_MESSAGE_PREFIX",
    "QUALIFIED_OCR_BACKEND_LITE_V1",
    "QUALIFIED_OCR_DEVICE_LITE_V1",
    "QUALIFIED_OCR_THREAD_COUNT_LITE_V1",
    "QUALIFIED_PADDLE_VERSION_LITE_V1",
    "QUALIFIED_PADDLEOCR_VERSION_LITE_V1",
    "QUALIFIED_PADDLEX_VERSION_LITE_V1",
)
_OCR_DEFINITIONS = (
    "OcrFailureCodeLiteV1",
    "AdmissionNoticeOcrErrorLiteV1",
    "_error",
    "_reject_json_constant",
    "_reject_duplicate_json_object",
    "_decode_json_object",
    "_has_exact_keys",
    "_encode_header",
    "_validate_request_frames",
    "_encode_ping_request",
    "_encode_ocr_request",
    "_parse_runtime_identity",
    "_parse_error_response",
    "_parse_ping_response",
    "_parse_span",
    "_parse_ocr_response",
    "_parse_response_prefix",
    "_close_writer",
    "AdmissionNoticeOcrClientLiteV1",
    "AdmissionNoticeOcrProcessorLiteV1",
    "_identity_is_qualified",
    "build_qualified_admission_notice_ocr_processor_lite_v1",
)
_OCR_CLIENT_METHODS = (
    "ping",
    "ping_sync",
    "recognize",
    "_exchange",
    "_recv_exact",
)
_OCR_PROCESSOR_HISTORICAL_METHODS = (
    "prepare_for_ingestion",
    "process",
)
_OCR_PROCESSOR_CURRENT_METHODS = (
    "prepare_for_ingestion",
    "process",
    "recognize_batch",
)

_SERVICE_ASSIGNMENTS = (
    "_ACTIVE_STATES",
    "_TERMINAL_RETENTION_SECONDS",
    "_MAX_RETAINED_TERMINAL_JOBS",
    "_SHUTDOWN_WAIT_SECONDS",
)
_SERVICE_CLASSES = (
    "_RecognitionIngestionPermitLiteV1",
    "_RecognitionJobRuntimeLiteV1",
    "AdmissionNoticeLiteService",
)
_SERVICE_METHODS = (
    "__init__",
    "accepting",
    "active_job_count",
    "retained_job_count",
    "active_ingestion_count",
    "resource_slot_count",
    "retained_frame_count",
    "owned_task_count",
    "_bind_event_loop",
    "_track_task",
    "_track_job_task",
    "_on_task_done",
    "_on_job_task_done",
    "_release_resource_permit",
    "_maybe_release_job_resources",
    "_discard_job_locked",
    "_schedule_terminal_retention_locked",
    "_terminal_retention_timer_fired",
    "_purge_retained_job",
    "_new_recognition_id_locked",
    "_release_active_slot_locked",
    "_owner_is_current_locked",
    "_transition_terminal_locked",
    "_trim_terminal_jobs_locked",
    "_purge_terminal_jobs_locked",
    "_transition_processor_result_locked",
    "_expire_due_jobs_locked",
    "_cancel_tasks",
    "_processor_ready_for_ingestion",
    "begin_ingestion",
    "release_ingestion",
    "ingestion_cancel_reason",
    "create_recognition",
    "_run_job",
    "_finish_completed",
    "_finish_failed",
    "_expire_job",
    "_cancel_if_active",
    "get_recognition",
    "cancel_recognition",
    "notify_session_stopped",
    "_cancel_stopped_session",
    "shutdown",
)


class L3SourceProjectionError(ValueError):
    """The current source cannot be represented by the approved L3 boundary."""


class L3SourceProjectionMismatch(AssertionError):
    """The current positive L3 projection differs from the historical one."""


def _parse_source(path: str, source: bytes) -> ast.Module:
    try:
        return ast.parse(source, filename=path)
    except (SyntaxError, UnicodeDecodeError):
        raise L3SourceProjectionError(f"{path}: source is not valid Python") from None


def _dump(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _assignment_name(node: ast.Assign | ast.AnnAssign) -> str:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        raise L3SourceProjectionError("qualification projection requires simple names")
    return targets[0].id


def _module_inventory(
    path: str,
    tree: ast.Module,
) -> tuple[
    tuple[ast.Import | ast.ImportFrom, ...],
    dict[str, ast.Assign | ast.AnnAssign],
    dict[str, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef],
]:
    imports: list[ast.Import | ast.ImportFrom] = []
    assignments: dict[str, ast.Assign | ast.AnnAssign] = {}
    definitions: dict[str, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            name = _assignment_name(node)
            if name in assignments:
                raise L3SourceProjectionError(f"{path}: duplicate assignment {name}")
            assignments[name] = node
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in definitions:
                raise L3SourceProjectionError(
                    f"{path}: duplicate definition {node.name}"
                )
            definitions[node.name] = node
        elif not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            raise L3SourceProjectionError(
                f"{path}: unsupported top-level source statement"
            )
    return tuple(imports), assignments, definitions


def _enum_members(node: ast.ClassDef) -> dict[str, ast.Assign]:
    members: dict[str, ast.Assign] = {}
    for item in node.body:
        if not isinstance(item, ast.Assign):
            raise L3SourceProjectionError(
                f"{node.name}: enum contains a non-assignment statement"
            )
        name = _assignment_name(item)
        if (
            not isinstance(item.value, ast.Constant)
            or item.value.value != name
            or name in members
        ):
            raise L3SourceProjectionError(
                f"{node.name}: enum member must map exactly to its own name"
            )
        members[name] = item
    return members


def _semantic_failure_names(
    service_assignments: Mapping[str, ast.Assign | ast.AnnAssign],
) -> frozenset[str]:
    node = service_assignments.get("_SEMANTIC_FAILURE_REASONS")
    if node is None:
        return frozenset()
    value = node.value
    if (
        not isinstance(value, ast.Call)
        or not isinstance(value.func, ast.Name)
        or value.func.id != "frozenset"
        or len(value.args) != 1
        or value.keywords
        or not isinstance(value.args[0], ast.Set)
    ):
        raise L3SourceProjectionError(
            "_SEMANTIC_FAILURE_REASONS must be one closed frozenset"
        )
    names: set[str] = set()
    for item in value.args[0].elts:
        if (
            not isinstance(item, ast.Attribute)
            or not isinstance(item.value, ast.Name)
            or item.value.id != "RecognitionErrorReasonLiteV1"
            or item.attr in names
        ):
            raise L3SourceProjectionError(
                "_SEMANTIC_FAILURE_REASONS contains an invalid member"
            )
        names.add(item.attr)
    if not names:
        raise L3SourceProjectionError(
            "_SEMANTIC_FAILURE_REASONS must not be empty when present"
        )
    if names != _REVIEWED_L4_SEMANTIC_FAILURE_MEMBERS:
        raise L3SourceProjectionError(
            "_SEMANTIC_FAILURE_REASONS exceeds the reviewed L4 boundary"
        )
    return frozenset(names)


def _project_contracts(
    source: bytes,
    semantic_failure_names: frozenset[str],
) -> bytes:
    tree = _parse_source(_CONTRACTS_PATH, source)
    imports, assignments, definitions = _module_inventory(_CONTRACTS_PATH, tree)
    if tuple(assignments) != _CONTRACT_ASSIGNMENTS:
        raise L3SourceProjectionError("contracts assignment inventory changed")
    if tuple(definitions) != _CONTRACT_CLASSES:
        raise L3SourceProjectionError("contracts definition inventory changed")

    projected_imports = [copy.deepcopy(node) for node in imports]
    threading_imports = [
        node
        for node in projected_imports
        if isinstance(node, ast.Import)
        and tuple(alias.name for alias in node.names) == ("threading",)
    ]
    if len(threading_imports) not in {0, 1}:
        raise L3SourceProjectionError("contracts L5 threading import changed")
    projected_imports = [
        node for node in projected_imports if node not in threading_imports
    ]
    callable_imports = [
        node
        for node in projected_imports
        if isinstance(node, ast.ImportFrom)
        and node.module == "collections.abc"
        and tuple(alias.name for alias in node.names) == ("Callable",)
    ]
    if len(callable_imports) not in {0, 1}:
        raise L3SourceProjectionError("contracts L5 callable import changed")
    projected_imports = [
        node for node in projected_imports if node not in callable_imports
    ]
    typing_imports = [
        node
        for node in projected_imports
        if isinstance(node, ast.ImportFrom) and node.module == "typing"
    ]
    if len(typing_imports) != 1 or tuple(
        alias.name for alias in typing_imports[0].names
    ) != ("Protocol",):
        raise L3SourceProjectionError("contracts L5 typing import changed")
    entries: list[tuple[str, str]] = [
        (f"import:{index}", _dump(node)) for index, node in enumerate(projected_imports)
    ]
    entries.extend(
        (f"assignment:{name}", _dump(assignments[name]))
        for name in _CONTRACT_ASSIGNMENTS
    )
    for name in _CONTRACT_CLASSES:
        node = definitions[name]
        if not isinstance(node, ast.ClassDef):
            raise L3SourceProjectionError(f"contracts definition {name} is not a class")
        if name == "RecognitionJobContextLiteV1":
            projected = copy.deepcopy(node)
            l5_fields = [
                item
                for item in projected.body
                if isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.target.id
                in {"publication_lock", "owning_session", "session_is_current"}
            ]
            if len(l5_fields) not in {0, 3}:
                raise L3SourceProjectionError(
                    "contracts L5 recognition context fields changed"
                )
            projected.body = [item for item in projected.body if item not in l5_fields]
            entries.append((f"class:{name}", _dump(projected)))
            continue
        if name != "RecognitionErrorReasonLiteV1":
            entries.append((f"class:{name}", _dump(node)))
            continue
        members = _enum_members(node)
        missing = set(_L3_ERROR_REASON_MEMBERS) - set(members)
        extras = set(members) - set(_L3_ERROR_REASON_MEMBERS)
        if missing or extras != set(semantic_failure_names):
            raise L3SourceProjectionError(
                "contracts L3/semantic failure boundary changed"
            )
        projected = copy.deepcopy(node)
        projected.body = [
            copy.deepcopy(members[name]) for name in _L3_ERROR_REASON_MEMBERS
        ]
        entries.append((f"class:{name}", _dump(projected)))
    return _serialize(entries)


def _class_method_inventory(node: ast.ClassDef) -> tuple[str, ...]:
    return tuple(
        item.name
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _processor_projection(node: ast.ClassDef) -> str:
    method_inventory = _class_method_inventory(node)
    methods = {
        item.name: item
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    fields = [
        item for item in node.body if isinstance(item, (ast.Assign, ast.AnnAssign))
    ]
    if method_inventory == _OCR_PROCESSOR_HISTORICAL_METHODS:
        stage = methods["process"]
        if not isinstance(stage, ast.AsyncFunctionDef):
            raise L3SourceProjectionError("historical OCR stage must be async")
        if (
            len(stage.body) < 2
            or not isinstance(stage.body[-2], ast.Delete)
            or ast.unparse(stage.body[-2]) != "del batch"
        ):
            raise L3SourceProjectionError(
                "historical OCR stage terminal discard changed"
            )
        stage_statements = stage.body[:-2] + stage.body[-1:]
    elif method_inventory == _OCR_PROCESSOR_CURRENT_METHODS:
        wrapper = methods["process"]
        stage = methods["recognize_batch"]
        if not isinstance(wrapper, ast.AsyncFunctionDef) or not isinstance(
            stage, ast.AsyncFunctionDef
        ):
            raise L3SourceProjectionError("current OCR stage methods must be async")
        if tuple(ast.unparse(item) for item in wrapper.body) != (
            "batch = await self.recognize_batch(context, frames)",
            "del batch",
        ):
            raise L3SourceProjectionError("L4 OCR wrapper boundary changed")
        if (
            len(stage.body) < 3
            or not (
                isinstance(stage.body[0], ast.Expr)
                and isinstance(stage.body[0].value, ast.Constant)
                and stage.body[0].value.value
                == "Return one validated transient batch for immediate in-call "
                "consumption."
            )
            or not isinstance(stage.body[-1], ast.Return)
            or not isinstance(stage.body[-1].value, ast.Name)
            or stage.body[-1].value.id != "batch"
        ):
            raise L3SourceProjectionError("L4 typed OCR batch handoff changed")
        stage_statements = stage.body[1:-1]
    else:
        raise L3SourceProjectionError("OCR processor method inventory changed")

    prepare = methods.get("prepare_for_ingestion")
    if not isinstance(prepare, ast.AsyncFunctionDef):
        raise L3SourceProjectionError("OCR readiness method changed")
    if not isinstance(stage, ast.AsyncFunctionDef):
        raise L3SourceProjectionError("OCR stage changed")
    entries = {
        "bases": tuple(_dump(item) for item in node.bases),
        "decorators": tuple(_dump(item) for item in node.decorator_list),
        "fields": tuple(_dump(item) for item in fields),
        "keywords": tuple(_dump(item) for item in node.keywords),
        "prepare_for_ingestion": _dump(prepare),
        "stage_arguments": _dump(stage.args),
        "stage_statements": tuple(_dump(item) for item in stage_statements),
    }
    return json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _project_ocr(source: bytes) -> bytes:
    tree = _parse_source(_OCR_PATH, source)
    imports, assignments, definitions = _module_inventory(_OCR_PATH, tree)
    if tuple(assignments) != _OCR_ASSIGNMENTS:
        raise L3SourceProjectionError("OCR assignment inventory changed")
    if tuple(definitions) != _OCR_DEFINITIONS:
        raise L3SourceProjectionError("OCR definition inventory changed")
    client = definitions["AdmissionNoticeOcrClientLiteV1"]
    processor = definitions["AdmissionNoticeOcrProcessorLiteV1"]
    if not isinstance(client, ast.ClassDef) or not isinstance(processor, ast.ClassDef):
        raise L3SourceProjectionError("OCR processor/client definitions changed kind")
    if _class_method_inventory(client) != _OCR_CLIENT_METHODS:
        raise L3SourceProjectionError("OCR client method inventory changed")

    entries: list[tuple[str, str]] = [
        (f"import:{index}", _dump(node)) for index, node in enumerate(imports)
    ]
    entries.extend(
        (f"assignment:{name}", _dump(assignments[name])) for name in _OCR_ASSIGNMENTS
    )
    for name in _OCR_DEFINITIONS:
        node = definitions[name]
        value = (
            _processor_projection(node)
            if name == "AdmissionNoticeOcrProcessorLiteV1"
            and isinstance(node, ast.ClassDef)
            else _dump(node)
        )
        entries.append((f"definition:{name}", value))
    return _serialize(entries)


_REVIEWED_SEMANTIC_HANDLER_SOURCE = (
    "except AdmissionNoticeLiteError as error:\n"
    "    reason = error.reason if error.reason in _SEMANTIC_FAILURE_REASONS "
    "else RecognitionErrorReasonLiteV1.INTERNAL_ERROR\n"
    "    logger.info('Admission Notice Lite processor failed recognition_id={} "
    "reason={}', job.recognition_id, reason.value)\n"
    "    await self._finish_failed(job, reason)"
)


def _remove_reviewed_semantic_handler(
    service: ast.ClassDef,
    *,
    expected: bool,
) -> None:
    all_handlers = [
        node
        for node in ast.walk(service)
        if isinstance(node, ast.ExceptHandler)
        and isinstance(node.type, ast.Name)
        and node.type.id == "AdmissionNoticeLiteError"
    ]
    run_job = next(
        (
            item
            for item in service.body
            if isinstance(item, ast.AsyncFunctionDef) and item.name == "_run_job"
        ),
        None,
    )
    if run_job is None:
        raise L3SourceProjectionError("service _run_job is missing")
    located: list[tuple[ast.Try, int, ast.ExceptHandler]] = []
    for node in ast.walk(run_job):
        if not isinstance(node, ast.Try):
            continue
        for index, handler in enumerate(node.handlers):
            if (
                isinstance(handler.type, ast.Name)
                and handler.type.id == "AdmissionNoticeLiteError"
            ):
                located.append((node, index, handler))
    if not expected:
        if all_handlers or located:
            raise L3SourceProjectionError(
                "historical service unexpectedly contains a semantic handler"
            )
        return
    if len(all_handlers) != 1 or len(located) != 1:
        raise L3SourceProjectionError(
            "semantic failure handler must occur exactly once in _run_job"
        )
    parent, index, handler = located[0]
    if (
        index + 1 >= len(parent.handlers)
        or not isinstance(parent.handlers[index + 1].type, ast.Name)
        or parent.handlers[index + 1].type.id != "Exception"
        or ast.unparse(handler) != _REVIEWED_SEMANTIC_HANDLER_SOURCE
    ):
        raise L3SourceProjectionError("reviewed semantic failure handler shape changed")
    del parent.handlers[index]


def _remove_l5_job_context_attachment(service: ast.ClassDef) -> None:
    calls = [
        node
        for node in ast.walk(service)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "RecognitionJobContextLiteV1"
    ]
    if len(calls) != 1:
        raise L3SourceProjectionError(
            "service L5 recognition context attachment changed"
        )
    call = calls[0]
    l5_keywords = {
        keyword.arg: keyword
        for keyword in call.keywords
        if keyword.arg in {"owning_session", "session_is_current", "publication_lock"}
    }
    if not l5_keywords:
        return
    if set(l5_keywords) != {
        "owning_session",
        "session_is_current",
        "publication_lock",
    }:
        raise L3SourceProjectionError("service L5 recognition context keywords changed")
    if ast.unparse(l5_keywords["owning_session"].value) != "job.owning_session":
        raise L3SourceProjectionError(
            "service L5 exact owning session attachment changed"
        )
    session_is_current = ast.unparse(l5_keywords["session_is_current"].value)
    if session_is_current != (
        "lambda: self._session_lookup(job.owning_session_id) is "
        "job.owning_session and id(job.owning_session) not in "
        "self._invalidated_owner_keys"
    ):
        raise L3SourceProjectionError("service L5 current-session check changed")
    if ast.unparse(l5_keywords["publication_lock"].value) != "job.publication_lock":
        raise L3SourceProjectionError("service L5 publication fence changed")
    call.keywords = [
        keyword for keyword in call.keywords if keyword.arg not in l5_keywords
    ]


def _remove_l5_publication_fence(
    runtime: ast.ClassDef,
    service: ast.ClassDef,
) -> None:
    fields = [
        item
        for item in runtime.body
        if isinstance(item, ast.AnnAssign)
        and isinstance(item.target, ast.Name)
        and item.target.id == "publication_lock"
    ]
    if not fields:
        if any(
            isinstance(node, ast.keyword) and node.arg == "publication_lock"
            for node in ast.walk(service)
        ):
            raise L3SourceProjectionError(
                "historical service has a partial L5 publication fence"
            )
        transition = next(
            (
                item
                for item in service.body
                if isinstance(item, ast.FunctionDef)
                and item.name == "_transition_terminal_locked"
            ),
            None,
        )
        if transition is None or any(
            isinstance(node, ast.With)
            and any(
                ast.unparse(item.context_expr) == "job.publication_lock"
                for item in node.items
            )
            for node in ast.walk(transition)
        ):
            raise L3SourceProjectionError(
                "historical service has a partial L5 terminal fence"
            )
        return
    if len(fields) != 1:
        raise L3SourceProjectionError("service L5 runtime publication lock changed")
    runtime.body.remove(fields[0])

    runtime_calls = [
        node
        for node in ast.walk(service)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_RecognitionJobRuntimeLiteV1"
    ]
    if len(runtime_calls) != 1:
        raise L3SourceProjectionError("service L5 runtime construction changed")
    runtime_call = runtime_calls[0]
    keywords = [
        keyword
        for keyword in runtime_call.keywords
        if keyword.arg == "publication_lock"
    ]
    if len(keywords) != 1 or ast.unparse(keywords[0].value) != "threading.Lock()":
        raise L3SourceProjectionError("service L5 runtime lock construction changed")
    runtime_call.keywords.remove(keywords[0])

    transition = next(
        (
            item
            for item in service.body
            if isinstance(item, ast.FunctionDef)
            and item.name == "_transition_terminal_locked"
        ),
        None,
    )
    if (
        transition is None
        or len(transition.body) != 1
        or not isinstance(transition.body[0], ast.With)
        or len(transition.body[0].items) != 1
        or ast.unparse(transition.body[0].items[0].context_expr)
        != "job.publication_lock"
    ):
        raise L3SourceProjectionError("service L5 terminal publication fence changed")
    body = transition.body[0].body
    cancel_sets = [
        item
        for item in body
        if isinstance(item, ast.If)
        and ast.unparse(item.test)
        == "state in {RecognitionStateLiteV1.CANCELLED, RecognitionStateLiteV1.EXPIRED}"
    ]
    if (
        len(cancel_sets) != 1
        or tuple(ast.unparse(item) for item in cancel_sets[0].body)
        != ("job.cancel_event.set()",)
        or cancel_sets[0].orelse
    ):
        raise L3SourceProjectionError("service L5 terminal cancellation fence changed")
    transition.body = [item for item in body if item not in cancel_sets]


def _project_service(
    source: bytes,
    semantic_failure_names: frozenset[str],
) -> bytes:
    tree = _parse_source(_SERVICE_PATH, source)
    imports, assignments, definitions = _module_inventory(_SERVICE_PATH, tree)
    expected_assignments = list(_SERVICE_ASSIGNMENTS)
    if semantic_failure_names:
        expected_assignments.insert(1, "_SEMANTIC_FAILURE_REASONS")
    if tuple(assignments) != tuple(expected_assignments):
        raise L3SourceProjectionError("service assignment inventory changed")
    if tuple(definitions) != _SERVICE_CLASSES:
        raise L3SourceProjectionError("service definition inventory changed")
    service = definitions["AdmissionNoticeLiteService"]
    if not isinstance(service, ast.ClassDef):
        raise L3SourceProjectionError("AdmissionNoticeLiteService changed kind")
    if _class_method_inventory(service) != _SERVICE_METHODS:
        raise L3SourceProjectionError("service method inventory changed")

    projected_imports = [copy.deepcopy(node) for node in imports]
    threading_imports = [
        node
        for node in projected_imports
        if isinstance(node, ast.Import)
        and tuple(alias.name for alias in node.names) == ("threading",)
    ]
    if len(threading_imports) not in {0, 1}:
        raise L3SourceProjectionError("service L5 threading import changed")
    projected_imports = [
        node for node in projected_imports if node not in threading_imports
    ]
    projected_runtime = copy.deepcopy(definitions["_RecognitionJobRuntimeLiteV1"])
    if not isinstance(projected_runtime, ast.ClassDef):
        raise L3SourceProjectionError("service runtime changed kind")
    projected_service = copy.deepcopy(service)
    _remove_reviewed_semantic_handler(
        projected_service,
        expected=bool(semantic_failure_names),
    )
    _remove_l5_job_context_attachment(projected_service)
    _remove_l5_publication_fence(projected_runtime, projected_service)
    ast.fix_missing_locations(projected_service)
    ast.fix_missing_locations(projected_runtime)

    entries: list[tuple[str, str]] = [
        (f"import:{index}", _dump(node)) for index, node in enumerate(projected_imports)
    ]
    entries.extend(
        (f"assignment:{name}", _dump(assignments[name]))
        for name in _SERVICE_ASSIGNMENTS
    )
    entries.extend(
        (
            f"class:{name}",
            _dump(projected_service)
            if name == "AdmissionNoticeLiteService"
            else _dump(projected_runtime)
            if name == "_RecognitionJobRuntimeLiteV1"
            else _dump(definitions[name]),
        )
        for name in _SERVICE_CLASSES
    )
    return _serialize(entries)


def _serialize(entries: list[tuple[str, str]]) -> bytes:
    return json.dumps(
        entries,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()


def l3_source_projection(
    sources: Mapping[str, bytes],
) -> dict[str, bytes]:
    """Return the exact positive L3 view for every historically hashed path."""

    if set(sources) != set(L3_QUALIFICATION_SOURCE_PATHS):
        raise L3SourceProjectionError("qualification source path inventory changed")
    contract_tree = _parse_source(_CONTRACTS_PATH, sources[_CONTRACTS_PATH])
    _, _, contract_definitions = _module_inventory(_CONTRACTS_PATH, contract_tree)
    error_enum = contract_definitions.get("RecognitionErrorReasonLiteV1")
    if not isinstance(error_enum, ast.ClassDef):
        raise L3SourceProjectionError("RecognitionErrorReasonLiteV1 is missing")
    error_members = _enum_members(error_enum)

    service_tree = _parse_source(_SERVICE_PATH, sources[_SERVICE_PATH])
    _, service_assignments, _ = _module_inventory(_SERVICE_PATH, service_tree)
    semantic_failure_names = _semantic_failure_names(service_assignments)
    if set(error_members) - set(_L3_ERROR_REASON_MEMBERS) != set(
        semantic_failure_names
    ):
        raise L3SourceProjectionError(
            "semantic failure enum and service boundary disagree"
        )

    projection: dict[str, bytes] = {}
    for path in L3_QUALIFICATION_SOURCE_PATHS:
        source = sources[path]
        if path == _CONTRACTS_PATH:
            value = _project_contracts(source, semantic_failure_names)
        elif path == _OCR_PATH:
            value = _project_ocr(source)
        elif path == _SERVICE_PATH:
            value = _project_service(source, semantic_failure_names)
        else:
            value = source
        projection[path] = value
    return projection


def l3_projection_sha256(sources: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    projection = l3_source_projection(sources)
    for path in L3_QUALIFICATION_SOURCE_PATHS:
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(projection[path])
        digest.update(b"\0")
    return digest.hexdigest()


def reconstruct_historical_l3_qualified_sources(
    *,
    current_sources: Mapping[str, bytes],
    historical_sources: Mapping[str, bytes],
) -> dict[str, bytes]:
    """Gate the exact historical representation on positive projection equality."""

    current_projection = l3_source_projection(current_sources)
    historical_projection = l3_source_projection(historical_sources)
    mismatched = tuple(
        path
        for path in L3_QUALIFICATION_SOURCE_PATHS
        if current_projection[path] != historical_projection[path]
    )
    if mismatched:
        raise L3SourceProjectionMismatch(
            "L3 qualification projection changed: " + ", ".join(mismatched)
        )
    reconstructed = dict(historical_sources)
    reconstructed[_GATE_PATH] = _HISTORICAL_DISABLED_GATE_SOURCE
    return reconstructed


def historical_l3_qualification_source_sha256(
    reconstructed_sources: Mapping[str, bytes],
) -> str:
    if set(reconstructed_sources) != set(L3_QUALIFICATION_SOURCE_PATHS):
        raise L3SourceProjectionError("historical source path inventory changed")
    digest = hashlib.sha256()
    for path in L3_QUALIFICATION_SOURCE_PATHS:
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(reconstructed_sources[path])
        digest.update(b"\0")
    return digest.hexdigest()


__all__ = [
    "APPROVED_MODEL_MANIFEST_SHA256_LITE_V1",
    "HISTORICAL_L3_COMMIT",
    "HISTORICAL_L3_QUALIFICATION_SOURCE_SHA256",
    "L3_MAIN_SOURCE_PATHS",
    "L3_QUALIFICATION_SOURCE_PATHS",
    "L3_SIDECAR_SOURCE_PATHS",
    "L4_DOWNSTREAM_SOURCE_PATHS",
    "L5_DOWNSTREAM_SOURCE_PATHS",
    "L3SourceProjectionError",
    "L3SourceProjectionMismatch",
    "historical_l3_qualification_source_sha256",
    "l3_projection_sha256",
    "l3_source_projection",
    "reconstruct_historical_l3_qualified_sources",
]
