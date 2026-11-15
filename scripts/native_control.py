"""Encrypted, session-bound UI control for a disposable signed-out iOS Simulator.

Requires cryptography (compatible with wheel pin 46.0.3). Run this module on the
runner; call ControlClient from the office process. Never pass keys as CLI args.
"""

import base64
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import re
import secrets
import socket
from socketserver import ThreadingMixIn
import threading
import time
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_REQUEST = 64 * 1024
MAX_UPSTREAM = 12 * 1024 * 1024
MAX_RESPONSE = 17 * 1024 * 1024
ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"
IDENTIFIER = re.compile(r"[A-Za-z0-9:-]{1,128}\Z")


class TransportError(Exception):
    """An unauthenticated or replayed message; contains no upstream details."""

    def __init__(self, status: int):
        super().__init__("Control message rejected")
        self.status = status


class OperationError(Exception):
    """A fixed public error code, encrypted before leaving the runner."""


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Invalid encoding")
    decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    if _encode(decoded) != value:
        raise ValueError("Invalid encoding")
    return decoded


def _shutdown_socket(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def key_from_environment() -> bytes:
    """Read the base64-encoded shared 32-byte key without displaying it."""
    key = _decode(os.environ["QA_CONTROL_KEY"])
    if len(key) != 32:
        raise ValueError("Invalid control key")
    return key


class Protocol:
    """Directional AES-GCM keys and AAD bind sequence, session, and request."""

    def __init__(self, key: bytes, session_id: str):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("Invalid control key")
        if not isinstance(session_id, str) or not IDENTIFIER.fullmatch(session_id):
            raise ValueError("Invalid session")
        self.session_id = session_id
        context = b"native-control/v1/" + session_id.encode("ascii")
        self._keys = {
            direction: AESGCM(hmac.digest(key, context + b"/" + direction.encode(), "sha256"))
            for direction in ("request", "response")
        }
        self.authorization = "Bearer " + hmac.digest(key, context + b"/authorization", "sha256").hex()

    def _aad(self, direction: str, sequence: int, request_nonce: str) -> bytes:
        return json.dumps(
            ["native-control/v1", self.session_id, direction, sequence, request_nonce],
            separators=(",", ":"),
        ).encode("ascii")

    def seal(self, direction: str, sequence: int, payload: dict, request_nonce: str = "") -> bytes:
        """Encrypt one message; response AAD includes its request's nonce."""
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(payload, separators=(",", ":"), allow_nan=False, ensure_ascii=False).encode("utf-8")
        if len(plaintext) > (MAX_UPSTREAM if direction == "response" else MAX_REQUEST):
            raise ValueError("Message too large")
        ciphertext = self._keys[direction].encrypt(
            nonce,
            plaintext,
            self._aad(direction, sequence, request_nonce),
        )
        return json.dumps({"seq": sequence, "nonce": _encode(nonce), "data": _encode(ciphertext)}, separators=(",", ":")).encode("ascii")

    def open(self, direction: str, body: bytes, request_nonce: str = "") -> tuple[int, str, dict]:
        """Validate envelope and tag before interpreting any UI operation."""
        try:
            envelope = json.loads(body)
            if not isinstance(envelope, dict) or set(envelope) != {"seq", "nonce", "data"}:
                raise ValueError("Invalid envelope")
            sequence = envelope["seq"]
            if type(sequence) is not int or not 1 <= sequence < 2**63:
                raise ValueError("Invalid sequence")
            nonce = _decode(envelope["nonce"])
            if len(nonce) != 12:
                raise ValueError("Invalid nonce")
            plaintext = self._keys[direction].decrypt(
                nonce, _decode(envelope["data"]), self._aad(direction, sequence, request_nonce)
            )
            payload = json.loads(plaintext)
            if not isinstance(payload, dict):
                raise ValueError("Invalid payload")
            return sequence, envelope["nonce"], payload
        except (ValueError, TypeError, KeyError, UnicodeError, InvalidTag, RecursionError):
            raise TransportError(401) from None


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OperationError("invalid_request")
    return value


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise OperationError("invalid_request")
    return value


class AppiumSession:
    """Only a fixed localhost Appium session; no general HTTP proxy or scripts."""

    def __init__(self, session_id: str):
        if not isinstance(session_id, str) or not IDENTIFIER.fullmatch(session_id):
            raise ValueError("Invalid session")
        self._prefix = "/session/" + session_id

    def _request(self, method: str, suffix: str, payload: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", 4723, timeout=20)
        timer = None
        deadline = time.monotonic() + 20
        try:
            connection.connect()
            # A peer sending occasional bytes cannot extend the absolute deadline.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OperationError("upstream_failed")
            timer = threading.Timer(remaining, _shutdown_socket, args=(connection.sock,))
            timer.daemon = True
            timer.start()
            body = None if payload is None else json.dumps(payload, allow_nan=False).encode("utf-8")
            connection.request(method, self._prefix + suffix, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(MAX_UPSTREAM + 1)
            if response.status != 200 or len(raw) > MAX_UPSTREAM:
                raise OperationError("upstream_failed")
            result = json.loads(raw)
            if not isinstance(result, dict) or "value" not in result:
                raise OperationError("upstream_failed")
            value = result["value"]
            if isinstance(value, dict) and "error" in value:
                raise OperationError("upstream_failed")
            return value
        except (OSError, http.client.HTTPException, ValueError, RecursionError):
            raise OperationError("upstream_failed") from None
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()

    def perform(self, request: dict):
        """Map a closed set of validated UI operations to fixed W3C endpoints."""
        operation = request.get("op")
        fields = {
            "source": set(), "screenshot": set(), "window": set(),
            "find": {"using", "value"}, "click": {"element_id"},
            "clear": {"element_id"}, "value": {"element_id", "text"},
            "tap": {"x", "y"}, "swipe": {"x", "y", "end_x", "end_y", "duration_ms"},
        }
        if not isinstance(operation, str) or operation not in fields:
            raise OperationError("operation_not_allowed")
        if set(request) != fields[operation] | {"op"}:
            raise OperationError("invalid_request")
        if operation in ("source", "screenshot", "window"):
            suffix = "/window/rect" if operation == "window" else "/" + operation
            return self._request("GET", suffix)
        if operation == "find":
            using = request["using"]
            if using not in ("accessibility id", "-ios predicate string"):
                raise OperationError("operation_not_allowed")
            value = self._request("POST", "/element", {"using": using, "value": _text(request["value"], 2048)})
            if not isinstance(value, dict) or not isinstance(value.get(ELEMENT_KEY), str) or not IDENTIFIER.fullmatch(value[ELEMENT_KEY]):
                raise OperationError("upstream_failed")
            return {"element_id": value[ELEMENT_KEY]}
        if operation in ("click", "value", "clear"):
            element_id = request["element_id"]
            if not isinstance(element_id, str) or not IDENTIFIER.fullmatch(element_id):
                raise OperationError("invalid_request")
            payload = {"text": _text(request["text"], 10000)} if operation == "value" else {}
            return self._request("POST", "/element/" + element_id + "/" + operation, payload)
        x = _integer(request["x"], 0, 8192)
        y = _integer(request["y"], 0, 8192)
        actions = [{"type": "pointerMove", "duration": 0, "x": x, "y": y}, {"type": "pointerDown", "button": 0}]
        if operation == "swipe":
            actions.append({"type": "pointerMove", "duration": _integer(request["duration_ms"], 50, 2000), "x": _integer(request["end_x"], 0, 8192), "y": _integer(request["end_y"], 0, 8192)})
        actions.append({"type": "pointerUp", "button": 0})
        return self._request("POST", "/actions", {"actions": [{"type": "pointer", "id": "qa-touch", "parameters": {"pointerType": "touch"}, "actions": actions}]})


class ControlEngine:
    """Serialize requests and consume authenticated sequences exactly once."""

    def __init__(self, protocol: Protocol, session: AppiumSession, lifetime: int = 900):
        self.protocol = protocol
        self.session = session
        self.deadline = time.monotonic() + _integer(lifetime, 30, 3600)
        self._sequence = 0
        self._lock = threading.Lock()
        self.finish_requested = threading.Event()
        self.completed = threading.Event()
        self._finish_response = None

    def response_delivered(self, response: bytes) -> None:
        """Allow CLI shutdown only after the exact finish reply was written."""
        with self._lock:
            if self._finish_response is not None and hmac.compare_digest(response, self._finish_response):
                self.completed.set()

    def handle(self, authorization: str, body: bytes) -> bytes:
        """Return encrypted success/error; reject bad auth, tag, or sequence."""
        if not isinstance(authorization, str) or not authorization.isascii() or not hmac.compare_digest(authorization, self.protocol.authorization):
            raise TransportError(401)
        if not isinstance(body, bytes) or not 0 < len(body) <= MAX_REQUEST:
            raise TransportError(401)
        with self._lock:
            sequence, nonce, request = self.protocol.open("request", body)
            if sequence != self._sequence + 1:
                raise TransportError(409)
            self._sequence = sequence
            finishing = False
            if self.finish_requested.is_set() or time.monotonic() >= self.deadline:
                payload = {"ok": False, "error": "expired"}
            elif request == {"op": "finish"}:
                self.finish_requested.set()
                finishing = True
                payload = {"ok": True, "value": None}
            else:
                try:
                    payload = {"ok": True, "value": self.session.perform(request)}
                except OperationError as error:
                    code = str(error)
                    payload = {"ok": False, "error": code if code in {"invalid_request", "operation_not_allowed", "upstream_failed"} else "upstream_failed"}
                except Exception:
                    # Neither Appium exception text nor user-entered values leave in errors.
                    payload = {"ok": False, "error": "upstream_failed"}
            try:
                response = self.protocol.seal("response", sequence, payload, nonce)
            except (ValueError, TypeError, UnicodeError):
                response = self.protocol.seal("response", sequence, {"ok": False, "error": "upstream_failed"}, nonce)
            if finishing:
                self._finish_response = response
            return response


class ControlHandler(BaseHTTPRequestHandler):
    """One bounded HTTP endpoint; transport never logs bodies or headers."""

    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def handle(self):
        # Unauthenticated headers get only five seconds, independent of traffic.
        self._request_timer = None
        self._arm_deadline(5)
        try:
            super().handle()
        finally:
            self._request_timer.cancel()

    def _arm_deadline(self, limit: int):
        if self._request_timer is not None:
            self._request_timer.cancel()
        remaining = max(0.1, min(limit, self.server.engine.deadline - time.monotonic()))
        self._request_timer = threading.Timer(remaining, _shutdown_socket, args=(self.connection,))
        self._request_timer.daemon = True
        self._request_timer.start()

    def log_message(self, format, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self._respond(401, b"")

    def _respond(self, status: int, body: bytes):
        self.send_response_only(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        try:
            if self.path != "/control" or self.headers.get("Transfer-Encoding") is not None:
                raise TransportError(401)
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise TransportError(401)
            length = int(lengths[0])
            if not 0 < length <= MAX_REQUEST:
                raise TransportError(401)
            authorizations = self.headers.get_all("Authorization", [])
            if len(authorizations) != 1 or not authorizations[0].isascii() or not hmac.compare_digest(authorizations[0], self.server.engine.protocol.authorization):
                raise TransportError(401)
            self._arm_deadline(40)
            self.connection.settimeout(10)
            body = self.rfile.read(length)
            if len(body) != length:
                raise TransportError(401)
            encrypted = self.server.engine.handle(authorizations[0], body)
            self._respond(200, encrypted)
            self.server.engine.response_delivered(encrypted)
        except TransportError as error:
            self._respond(error.status, b"")
        except (OSError, ValueError, OverflowError):
            self.close_connection = True


class ControlServer(ThreadingMixIn, HTTPServer):
    """At most eight daemon handlers; slow unauthenticated peers cannot queue work."""

    daemon_threads = True
    block_on_close = False
    MAX_HANDLERS = 8

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(self.MAX_HANDLERS)
        self._active_lock = threading.Lock()
        self._active_handlers = 0
        super().__init__(*args, **kwargs)

    @property
    def active_handlers(self) -> int:
        """Non-sensitive concurrency count for readiness and resource checks."""
        with self._active_lock:
            return self._active_handlers

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            # Never spawn or queue a ninth handler. Rejection is itself bounded.
            try:
                request.settimeout(0.1)
                request.sendall(b"HTTP/1.0 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        with self._active_lock:
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release_slot()
            raise

    def _release_slot(self):
        with self._active_lock:
            self._active_handlers -= 1
        self._slots.release()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_slot()

    def handle_error(self, request, client_address):
        pass


def create_server(key: bytes, session_id: str, lifetime: int = 900) -> ControlServer:
    """Create the sole runner endpoint, always bound to 127.0.0.1:4781."""
    protocol = Protocol(key, session_id)
    engine = ControlEngine(protocol, AppiumSession(session_id), lifetime)
    server = ControlServer(("127.0.0.1", 4781), ControlHandler)
    server.engine = engine
    server.timeout = 1
    return server


def serve_from_environment() -> None:
    """Run on the runner loopback only, for at most the configured lifetime."""
    with create_server(key_from_environment(), os.environ["QA_APPIUM_SESSION_ID"], int(os.environ.get("QA_CONTROL_LIFETIME_SECONDS", "900"))) as server:
        while time.monotonic() < server.engine.deadline and not server.engine.completed.is_set():
            server.handle_request()


class ControlClient:
    """Office-side callable API. Any ambiguous failure requires a new session."""

    def __init__(self, endpoint: str, key: bytes, session_id: str, initial_sequence: int = 0):
        parsed = urlsplit(endpoint)
        local = parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
        tunnel = parsed.scheme == "https" and parsed.hostname and parsed.hostname.endswith(".trycloudflare.com") and parsed.port in (None, 443)
        if not (local or tunnel) or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("Invalid control endpoint")
        self._hostname = parsed.hostname
        self._port = parsed.port
        self._local = local
        self.protocol = Protocol(key, session_id)
        self._sequence = _integer(initial_sequence, 0, 2**63 - 1)
        self._failed = False
        self._lock = threading.Lock()

    @property
    def sequence(self) -> int:
        """Last allocated sequence; resume only after a verified successful reply."""
        return self._sequence

    def call(self, operation: str, **parameters) -> dict:
        """Perform one UI command; never include values or server text in errors."""
        with self._lock:
            if self._failed:
                raise RuntimeError("Control client unavailable")
            self._sequence += 1
            body = self.protocol.seal("request", self._sequence, {"op": operation, **parameters})
            if len(body) > MAX_REQUEST:
                self._failed = True
                raise RuntimeError("Control request too large")
            nonce = json.loads(body)["nonce"]
            connection_type = http.client.HTTPConnection if self._local else http.client.HTTPSConnection
            connection = connection_type(self._hostname, self._port, timeout=35)
            timer = None
            deadline = time.monotonic() + 35
            try:
                connection.connect()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Control request expired")
                timer = threading.Timer(remaining, _shutdown_socket, args=(connection.sock,))
                timer.daemon = True
                timer.start()
                connection.request("POST", "/control", body, {"Authorization": self.protocol.authorization, "Content-Type": "application/octet-stream"})
                response = connection.getresponse()
                encrypted = response.read(MAX_RESPONSE + 1)
                if response.status != 200 or len(encrypted) > MAX_RESPONSE:
                    raise RuntimeError("Control message rejected")
                sequence, _, payload = self.protocol.open("response", encrypted, nonce)
                if sequence != self._sequence:
                    raise RuntimeError("Control message rejected")
                return payload
            except Exception:
                self._failed = True
                raise RuntimeError("Control request failed; session must be renewed") from None
            finally:
                if timer is not None:
                    timer.cancel()
                connection.close()


if __name__ == "__main__":
    try:
        serve_from_environment()
    except Exception:
        # Startup errors must not dump environment, credentials, or upstream details.
        raise SystemExit(1) from None
