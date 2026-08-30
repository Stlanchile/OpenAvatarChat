from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import logging
import os
import queue
import signal
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any

from admission_notice_ocr.manifest import (
    VerifiedManifest,
    load_and_verify_manifest,
)
from admission_notice_ocr.protocol import (
    ErrorCode,
    ProtocolError,
    Request,
    encode_error,
    encode_ocr,
    encode_ping,
    read_request,
)

DEFAULT_SOCKET_PATH = Path("/run/openavatarchat-admission-lite/ocr.sock")
SOCKET_MODE = 0o660
SOCKET_BACKLOG = 4
MAX_CONNECTIONS = 4
SHUTDOWN_WAIT_SECONDS = 5.0
_UNSAFE_SOCKET_PARENT_MODE = stat.S_IWGRP | stat.S_IWOTH


class SidecarStartupError(Exception):
    def __init__(self) -> None:
        super().__init__("OCR_SIDECAR_STARTUP_FAILED")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _prepare_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        directory_stat = path.lstat()
    except OSError:
        raise SidecarStartupError() from None
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or path.is_symlink()
        or directory_stat.st_uid != os.geteuid()
        or directory_stat.st_mode & 0o077
    ):
        raise SidecarStartupError()


def _runtime_environment(runtime_cache: Path) -> dict[str, str]:
    return {
        "HOME": str(runtime_cache / "home"),
        "XDG_CACHE_HOME": str(runtime_cache / "xdg-cache"),
        "PADDLE_HOME": str(runtime_cache / "paddle"),
        "PADDLE_PDX_CACHE_HOME": str(runtime_cache / "paddlex"),
        "HF_HOME": str(runtime_cache / "huggingface"),
        "HUGGINGFACE_HUB_CACHE": str(runtime_cache / "huggingface" / "hub"),
        "MODELSCOPE_CACHE": str(runtime_cache / "modelscope"),
    }


def _configure_cpu_runtime(thread_count: int, runtime_cache: Path) -> None:
    _prepare_private_directory(runtime_cache)
    for cache_path in {
        Path(value)
        for value in _runtime_environment(runtime_cache).values()
        if Path(value).parent == runtime_cache
    }:
        _prepare_private_directory(cache_path)

    thread_value = str(thread_count)
    for name in (
        "OMP_NUM_THREADS",
        "MKL_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "FLAGS_paddle_num_threads",
    ):
        os.environ[name] = thread_value
    os.environ.update(_runtime_environment(runtime_cache))
    os.environ["OMP_DYNAMIC"] = "FALSE"
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    os.environ["PADDLE_PDX_DISABLE_DEVICE_FALLBACK"] = "True"
    os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "True"
    os.environ["PADDLE_PDX_ENABLE_MKLDNN_BYDEFAULT"] = "False"
    os.environ["PADDLE_PDX_USE_PIR_TRT"] = "False"


def _validate_socket_parent(socket_path: Path) -> None:
    if (
        not socket_path.is_absolute()
        or "\x00" in str(socket_path)
        or len(os.fsencode(socket_path)) > 100
    ):
        raise SidecarStartupError()
    parent = socket_path.parent
    try:
        parent_stat = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError:
        raise SidecarStartupError() from None
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent.is_symlink()
        or resolved_parent != parent
        or parent_stat.st_uid != os.geteuid()
        or parent_stat.st_mode & _UNSAFE_SOCKET_PARENT_MODE
    ):
        raise SidecarStartupError()


def _remove_owned_stale_socket(socket_path: Path) -> None:
    try:
        original = socket_path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise SidecarStartupError() from None
    if not stat.S_ISSOCK(original.st_mode) or original.st_uid != os.geteuid():
        raise SidecarStartupError()

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.2)
        probe.connect(str(socket_path))
    except ConnectionRefusedError:
        pass
    except FileNotFoundError:
        return
    except OSError:
        raise SidecarStartupError() from None
    else:
        raise SidecarStartupError()
    finally:
        probe.close()

    try:
        current = socket_path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise SidecarStartupError() from None
    if (
        not stat.S_ISSOCK(current.st_mode)
        or current.st_uid != os.geteuid()
        or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)
    ):
        raise SidecarStartupError()
    try:
        socket_path.unlink()
    except OSError:
        raise SidecarStartupError() from None


class _InferenceWorker:
    """One daemon worker for the one warmed, serialized Paddle pipeline."""

    def __init__(self, pipeline: Any):
        self._pipeline = pipeline
        self._queue: queue.Queue[
            tuple[
                tuple[Any, ...],
                concurrent.futures.Future[list[dict[str, Any]]],
            ]
            | None
        ] = queue.Queue(maxsize=1)
        self._state_lock = threading.Lock()
        self._closed = False
        self._busy = False
        self._thread = threading.Thread(
            target=self._serve,
            name="admission-notice-ocr-inference",
            daemon=True,
        )
        self._thread.start()

    async def recognize(self, frames: tuple[Any, ...]) -> list[dict[str, Any]]:
        future: concurrent.futures.Future[list[dict[str, Any]]] = (
            concurrent.futures.Future()
        )
        with self._state_lock:
            if self._closed or self._busy:
                raise RuntimeError("OCR worker is unavailable")
            self._busy = True
            try:
                self._queue.put_nowait((frames, future))
            except queue.Full:
                self._busy = False
                raise RuntimeError("OCR worker queue is full") from None
        return await asyncio.wrap_future(future)

    @property
    def ready(self) -> bool:
        with self._state_lock:
            return not self._closed and not self._busy

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass

    def _serve(self) -> None:
        while True:
            work = self._queue.get()
            if work is None:
                return
            frames, future = work
            if not future.set_running_or_notify_cancel():
                with self._state_lock:
                    self._busy = False
                    closed = self._closed
                if closed:
                    return
                continue
            try:
                result = self._pipeline.recognize(frames)
            except Exception as error:
                future.set_exception(error)
            else:
                future.set_result(result)
            finally:
                with self._state_lock:
                    self._busy = False
                    closed = self._closed
            if closed:
                return


class OcrSidecarServer:
    def __init__(
        self,
        *,
        socket_path: Path,
        pipeline: Any,
        runtime_identity: dict[str, str | int],
        shutdown_wait_seconds: float = SHUTDOWN_WAIT_SECONDS,
    ):
        self._socket_path = socket_path
        self._pipeline = pipeline
        self._runtime_identity = runtime_identity
        self._shutdown_wait_seconds = shutdown_wait_seconds
        self._inference_lock = asyncio.Lock()
        self._inference_worker: _InferenceWorker | None = None
        self._connection_slots = asyncio.BoundedSemaphore(MAX_CONNECTIONS)
        self._client_tasks: set[asyncio.Task[Any]] = set()
        self._server: asyncio.AbstractServer | None = None
        self._socket_identity: tuple[int, int] | None = None

    async def start(self) -> None:
        _validate_socket_parent(self._socket_path)
        _remove_owned_stale_socket(self._socket_path)
        self._inference_worker = _InferenceWorker(self._pipeline)
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_client,
                path=str(self._socket_path),
                backlog=SOCKET_BACKLOG,
            )
            os.chmod(self._socket_path, SOCKET_MODE)
            socket_stat = self._socket_path.lstat()
        except Exception:
            await self.close()
            raise SidecarStartupError() from None
        if not stat.S_ISSOCK(socket_stat.st_mode):
            await self.close()
            raise SidecarStartupError()
        self._socket_identity = (socket_stat.st_dev, socket_stat.st_ino)

    async def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        inference_worker = self._inference_worker
        self._inference_worker = None
        if inference_worker is not None:
            inference_worker.close()
        pending = tuple(task for task in self._client_tasks if not task.done())
        if pending:
            _, unfinished = await asyncio.wait(
                pending,
                timeout=self._shutdown_wait_seconds,
            )
            for task in unfinished:
                task.cancel()
            if unfinished:
                await asyncio.gather(*unfinished, return_exceptions=True)
        self._remove_socket_if_owned()

    def _remove_socket_if_owned(self) -> None:
        expected = self._socket_identity
        self._socket_identity = None
        if expected is None:
            return
        try:
            current = self._socket_path.lstat()
        except OSError:
            return
        if (
            stat.S_ISSOCK(current.st_mode)
            and current.st_uid == os.geteuid()
            and (current.st_dev, current.st_ino) == expected
        ):
            try:
                self._socket_path.unlink()
            except OSError:
                pass

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        response = encode_error(ErrorCode.OCR_SERVICE_UNAVAILABLE)
        request: Request | None = None
        try:
            if self._connection_slots.locked():
                return
            async with self._connection_slots:
                try:
                    request = await read_request(reader)
                    if request.operation == "ping":
                        inference_worker = self._inference_worker
                        if inference_worker is None or not inference_worker.ready:
                            response = encode_error(ErrorCode.OCR_SERVICE_UNAVAILABLE)
                        else:
                            response = encode_ping(self._runtime_identity)
                    else:
                        started_at = time.monotonic()
                        async with self._inference_lock:
                            inference_worker = self._inference_worker
                            if inference_worker is None:
                                raise RuntimeError("OCR worker is unavailable")
                            frames = await inference_worker.recognize(request.frames)
                        response = encode_ocr(frames)
                        logging.info(
                            "OCR inference completed frame_count=%d duration_ms=%.1f",
                            len(request.frames),
                            (time.monotonic() - started_at) * 1000.0,
                        )
                except ProtocolError as error:
                    response = encode_error(error.code)
                except Exception:
                    response = encode_error(ErrorCode.OCR_RUNTIME_ERROR)
                    logging.warning("OCR inference failed reason=OCR_RUNTIME_ERROR")
        finally:
            request = None
            try:
                writer.write(response)
                await writer.drain()
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            if task is not None:
                self._client_tasks.discard(task)


def _write_ready_file(
    ready_file: Path | None,
    *,
    model_init_ms: float,
    startup_ms: float,
    thread_count: int,
    runtime_cache: Path,
) -> None:
    if ready_file is None:
        return
    temporary = ready_file.with_name(f".{ready_file.name}.{os.getpid()}.tmp")
    try:
        payload = json.dumps(
            {
                "model_init_ms": round(model_init_ms, 3),
                "pid": os.getpid(),
                "startup_ms": round(startup_ms, 3),
                "cache_environment_match": all(
                    os.environ.get(name) == expected
                    for name, expected in _runtime_environment(runtime_cache).items()
                ),
                "thread_environment_match": all(
                    os.environ.get(name) == str(thread_count)
                    for name in (
                        "OMP_NUM_THREADS",
                        "MKL_NUM_THREADS",
                        "OPENBLAS_NUM_THREADS",
                        "NUMEXPR_NUM_THREADS",
                        "FLAGS_paddle_num_threads",
                    )
                ),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            destination.write(payload + "\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.link(temporary, ready_file, follow_symlinks=False)
    except (OSError, TypeError, ValueError):
        raise SidecarStartupError() from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


async def _run(
    *,
    socket_path: Path,
    manifest: VerifiedManifest,
    ready_file: Path | None,
    process_started_at: float,
) -> None:
    runtime_cache = socket_path.parent / "ocr-runtime"
    _configure_cpu_runtime(manifest.thread_count, runtime_cache)
    model_started_at = time.monotonic()
    from admission_notice_ocr.pipeline import PaddleOcrPipeline

    pipeline = PaddleOcrPipeline(manifest)
    model_init_ms = (time.monotonic() - model_started_at) * 1000.0
    server = OcrSidecarServer(
        socket_path=socket_path,
        pipeline=pipeline,
        runtime_identity=manifest.runtime_identity(),
    )
    await server.start()
    startup_ms = (time.monotonic() - process_started_at) * 1000.0
    _write_ready_file(
        ready_file,
        model_init_ms=model_init_ms,
        startup_ms=startup_ms,
        thread_count=manifest.thread_count,
        runtime_cache=runtime_cache,
    )
    logging.info(
        "OCR sidecar ready backend=paddle_static device=cpu threads=%d "
        "manifest_sha256=%s",
        manifest.thread_count,
        manifest.manifest_sha256,
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop_event.set)
        except NotImplementedError:
            pass
    try:
        await stop_event.wait()
    finally:
        await server.close()
        logging.info("OCR sidecar stopped")


def _parse_args() -> argparse.Namespace:
    project_root = _project_root()
    parser = argparse.ArgumentParser(
        description="Admission Notice Lite CPU OCR sidecar"
    )
    parser.add_argument("--socket-path", type=Path, default=DEFAULT_SOCKET_PATH)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=project_root / "model_manifest.json",
    )
    parser.add_argument(
        "--models-root",
        type=Path,
        default=project_root / "models",
    )
    parser.add_argument("--ready-file", type=Path)
    return parser.parse_args()


def main() -> None:
    process_started_at = time.monotonic()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    args = _parse_args()
    try:
        manifest = load_and_verify_manifest(args.manifest, args.models_root)
        asyncio.run(
            _run(
                socket_path=args.socket_path,
                manifest=manifest,
                ready_file=args.ready_file,
                process_started_at=process_started_at,
            )
        )
    except Exception:
        logging.error("OCR sidecar failed reason=OCR_SIDECAR_STARTUP_FAILED")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
