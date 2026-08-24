"""
OC Channel Client — sends messages to OC via the oac-bridge channel webhook
and receives replies via an HTTP callback server.

Flow:
  OAC ──POST /webhook/oac-bridge──▶ OC Gateway
       ◀──POST /oc-reply──────────  OC (callback)
"""

import json
import threading
import time
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional

import requests
from loguru import logger


class OcReplyMessage:
    """A single reply from OC delivered via callback."""

    def __init__(
        self,
        oac_session_id: str,
        text: str,
        timestamp: float,
        correlation_id: str | None = None,
        status: str | None = None,
    ):
        self.oac_session_id = oac_session_id
        self.text = text
        self.timestamp = timestamp
        self.correlation_id = correlation_id
        self.status = status


class OcReplyQueue:
    """Thread-safe reply queue indexed by oac_session_id."""

    def __init__(self):
        self._lock = threading.Lock()
        self._queues: Dict[str, List[OcReplyMessage]] = defaultdict(list)
        self._events: Dict[str, threading.Event] = {}
        self._callbacks: Dict[
            str, Callable[[OcReplyMessage], bool | None]
        ] = {}
        self._require_registered_correlation_v1 = False

    def push(self, msg: OcReplyMessage):
        reply_key = msg.correlation_id or msg.oac_session_id
        with self._lock:
            cb = self._callbacks.get(reply_key)
            strict = self._require_registered_correlation_v1
        if cb:
            try:
                if cb(msg):
                    return
            except Exception:
                logger.warning("OC_REPLY_CALLBACK_FAILED_V1")
                if strict:
                    return
        elif strict:
            logger.info("LATE_CALLBACK_DROPPED OC_REPLY_UNKNOWN")
            return
        with self._lock:
            self._queues[reply_key].append(msg)
            evt = self._events.get(reply_key)
        if evt:
            evt.set()

    def wait_for_reply(
        self, reply_key: str, timeout: float = 60.0
    ) -> Optional[OcReplyMessage]:
        """Block until a reply arrives for this session, or timeout."""
        evt = threading.Event()
        with self._lock:
            pending = self._queues.get(reply_key)
            if pending:
                return pending.pop(0)
            self._events[reply_key] = evt

        evt.wait(timeout=timeout)

        with self._lock:
            self._events.pop(reply_key, None)
            pending = self._queues.get(reply_key)
            if pending:
                return pending.pop(0)
        return None

    def register_callback(
        self,
        reply_key: str,
        cb: Callable[[OcReplyMessage], bool | None],
    ):
        with self._lock:
            self._callbacks[reply_key] = cb

    def unregister_callback(self, reply_key: str):
        with self._lock:
            self._callbacks.pop(reply_key, None)

    def require_registered_correlation_v1(self) -> None:
        with self._lock:
            self._require_registered_correlation_v1 = True


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that receives OC replies at /oc-reply."""

    reply_queue: Optional[OcReplyQueue] = None
    expected_token: str = ""

    def do_POST(self):
        if self.path != "/oc-reply":
            self.send_response(404)
            self.end_headers()
            return

        if self.expected_token:
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] != self.expected_token:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')
                return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 256 * 1024:
            self.send_response(413)
            self.end_headers()
            return

        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid json"}')
            return

        oac_session_id = data.get("oac_session_id", "")
        text = data.get("text", "")
        if not oac_session_id or not text:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"missing oac_session_id or text"}')
            return

        msg = OcReplyMessage(
            oac_session_id=oac_session_id,
            text=text,
            timestamp=data.get("timestamp", time.time()),
            correlation_id=data.get("correlation_id"),
            status=data.get("status"),
        )
        logger.info("OC_REPLY_RECEIVED_V1")
        if self.reply_queue:
            self.reply_queue.push(msg)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        del format, args
        logger.debug("OC_CALLBACK_HTTP_REQUEST_V1")


class OcChannelClient:
    """
    Manages bidirectional communication with OC via the oac-bridge channel.

    - Sends: HTTP POST to OC gateway's /webhook/oac-bridge
    - Receives: HTTP callback server on a local port
    """

    def __init__(
        self,
        gateway_url: str = "http://localhost:18789",
        webhook_path: str = "/webhook/oac-bridge",
        token: str = "",
        callback_port: int = 8011,
        callback_host: str = "0.0.0.0",
    ):
        self._gateway_url = gateway_url.rstrip("/")
        self._webhook_path = webhook_path
        self._token = token
        self._callback_port = callback_port
        self._callback_host = callback_host
        self._reply_queue = OcReplyQueue()
        self._server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._started = False

    @property
    def reply_queue(self) -> OcReplyQueue:
        return self._reply_queue

    @property
    def callback_url(self) -> str:
        return f"http://localhost:{self._callback_port}/oc-reply"

    def start(self) -> bool:
        """Start the callback HTTP server in a background thread."""
        if self._started:
            return True
        try:
            handler_class = type(
                "_OacCallbackHandler",
                (_CallbackHandler,),
                {
                    "reply_queue": self._reply_queue,
                    "expected_token": self._token,
                },
            )
            self._server = HTTPServer(
                (self._callback_host, self._callback_port), handler_class
            )
            self._server_thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
                name="oc-callback-server",
            )
            self._server_thread.start()
            self._started = True
            logger.info(
                f"[OcChannelClient] Callback server started on "
                f"{self._callback_host}:{self._callback_port}"
            )
            return True
        except Exception:
            logger.error("OC_CALLBACK_SERVER_START_FAILED_V1")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None
        self._started = False
        logger.info("[OcChannelClient] Callback server stopped")

    def send_message(
        self,
        oac_session_id: str,
        text: str,
        sender_name: str = "OAC User",
        timeout: float = 10.0,
        correlation_id: str | None = None,
    ) -> Dict[str, Any]:
        """Send a message to OC via the oac-bridge webhook."""
        url = f"{self._gateway_url}{self._webhook_path}"
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        payload = {
            "oac_session_id": oac_session_id,
            "text": text,
            "sender_name": sender_name,
        }
        if correlation_id:
            payload["correlation_id"] = correlation_id

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            logger.error("OC_CHANNEL_SEND_FAILED_V1")
            return {"error": "OC channel request failed"}

    def send_and_wait(
        self,
        oac_session_id: str,
        text: str,
        sender_name: str = "OAC User",
        wait_timeout: float = 60.0,
        correlation_id: str | None = None,
    ) -> Optional[str]:
        """Send a message and wait for the reply."""
        result = self.send_message(
            oac_session_id,
            text,
            sender_name,
            correlation_id=correlation_id,
        )
        if "error" in result:
            return None

        reply = self._reply_queue.wait_for_reply(
            correlation_id or oac_session_id,
            timeout=wait_timeout,
        )
        return reply.text if reply else None
