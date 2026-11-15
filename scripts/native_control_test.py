"""No accounts or Simulator needed: exercise the control security boundary."""

import contextlib
import io
import json
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

import native_control as control


KEY = bytes(range(32))  # Public test fixture, never an operational key.
SESSION = "fake-session-123"
PRIVATE_VALUE = "private-entered-value-fixture"


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.protocol = control.Protocol(KEY, SESSION)
        self.session = Mock()
        self.session.perform.return_value = PRIVATE_VALUE
        self.engine = control.ControlEngine(self.protocol, self.session)

    def request(self, sequence=1, payload=None):
        return self.protocol.seal("request", sequence, payload or {"op": "source"})

    def response(self, request, response):
        sequence, _, payload = self.protocol.open("response", response, json.loads(request)["nonce"])
        self.assertEqual(sequence, json.loads(request)["seq"])
        return payload

    def rejected(self, body, status=401, authorization=None):
        with self.assertRaises(control.TransportError) as caught:
            self.engine.handle(self.protocol.authorization if authorization is None else authorization, body)
        self.assertEqual(caught.exception.status, status)

    def test_key_and_session_validation(self):
        for key, session in [(b"short", SESSION), (KEY, "../session"), (KEY, "session/path")]:
            with self.assertRaises(ValueError):
                control.Protocol(key, session)

    def test_wrong_auth_never_runs_appium_or_consumes_sequence(self):
        request = self.request()
        self.rejected(request, authorization="Bearer wrong")
        self.rejected(request, authorization="non-ascii-\u043a")
        self.session.perform.assert_not_called()
        self.assertTrue(self.response(request, self.engine.handle(self.protocol.authorization, request))["ok"])

    def test_ciphertext_tamper_is_denied_without_consuming_sequence(self):
        request = self.request()
        envelope = json.loads(request)
        data = bytearray(control._decode(envelope["data"]))
        data[-1] ^= 1
        envelope["data"] = control._encode(bytes(data))
        self.rejected(json.dumps(envelope).encode())
        self.session.perform.assert_not_called()
        self.engine.handle(self.protocol.authorization, request)
        self.session.perform.assert_called_once()

    def test_replay_and_out_of_order_sequence_do_not_repeat_action(self):
        self.rejected(self.request(2), 409)
        request = self.request()
        self.engine.handle(self.protocol.authorization, request)
        self.rejected(request, 409)
        self.session.perform.assert_called_once()

    def test_sequence_is_authenticated(self):
        envelope = json.loads(self.request())
        envelope["seq"] = 2
        self.rejected(json.dumps(envelope).encode())
        self.session.perform.assert_not_called()

    def test_session_and_direction_binding(self):
        other = control.Protocol(KEY, "different-session")
        self.rejected(other.seal("request", 1, {"op": "source"}))
        self.rejected(self.protocol.seal("response", 1, {"op": "source"}))
        self.session.perform.assert_not_called()

    def test_response_is_bound_to_the_exact_request_nonce(self):
        request = self.request()
        response = self.engine.handle(self.protocol.authorization, request)
        unrelated_nonce = json.loads(self.request())["nonce"]
        with self.assertRaises(control.TransportError):
            self.protocol.open("response", response, unrelated_nonce)
        self.assertTrue(self.response(request, response)["ok"])

    def test_values_and_results_are_not_visible_in_transport(self):
        request = self.request(payload={"op": "value", "element_id": "fake-element", "text": PRIVATE_VALUE})
        response = self.engine.handle(self.protocol.authorization, request)
        self.assertNotIn(PRIVATE_VALUE.encode(), request)
        self.assertNotIn(PRIVATE_VALUE.encode(), response)
        self.assertEqual(self.response(request, response)["value"], PRIVATE_VALUE)

    def test_upstream_exception_text_is_not_disclosed(self):
        self.session.perform.side_effect = RuntimeError(PRIVATE_VALUE)
        request = self.request()
        response = self.engine.handle(self.protocol.authorization, request)
        self.assertNotIn(PRIVATE_VALUE.encode(), response)
        self.assertEqual(self.response(request, response), {"ok": False, "error": "upstream_failed"})

    def test_expired_engine_does_not_run_appium(self):
        self.engine.deadline = time.monotonic() - 1
        request = self.request()
        self.assertEqual(self.response(request, self.engine.handle(self.protocol.authorization, request)), {"ok": False, "error": "expired"})
        self.session.perform.assert_not_called()

    def test_finish_is_authenticated_and_never_changes_appium(self):
        request = self.request(payload={"op": "finish"})
        self.rejected(request, authorization="wrong")
        self.assertFalse(self.engine.completed.is_set())
        response = self.engine.handle(self.protocol.authorization, request)
        self.assertTrue(self.response(request, response)["ok"])
        self.assertTrue(self.engine.finish_requested.is_set())
        self.assertFalse(self.engine.completed.is_set())
        later_request = self.request(2)
        later_response = self.engine.handle(self.protocol.authorization, later_request)
        self.assertEqual(self.response(later_request, later_response), {"ok": False, "error": "expired"})
        self.engine.response_delivered(later_response)
        self.assertFalse(self.engine.completed.is_set())
        self.engine.response_delivered(response)
        self.assertTrue(self.engine.completed.is_set())
        self.session.perform.assert_not_called()

    def test_oversize_and_malformed_payloads_are_denied(self):
        for body in [b"x" * (control.MAX_REQUEST + 1), b"null", b"{}", b"[]", b'{"seq":true,"nonce":"","data":""}']:
            self.rejected(body)
        self.session.perform.assert_not_called()

    def test_non_json_upstream_result_is_encrypted_generic_error(self):
        self.session.perform.return_value = float("inf")
        request = self.request()
        response = self.engine.handle(self.protocol.authorization, request)
        self.assertEqual(self.response(request, response), {"ok": False, "error": "upstream_failed"})


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.session = control.AppiumSession(SESSION)
        self.session._request = Mock(return_value=None)

    def test_arbitrary_operations_and_path_traversal_are_rejected(self):
        requests = [
            {"op": "execute", "script": "anything"}, {"op": "session"},
            {"op": "source", "url": "http://remote.invalid"},
            {"op": "click", "element_id": "../../session"},
            {"op": "find", "using": "xpath", "value": "//any"},
            {"op": "tap", "x": True, "y": 0},
            {"op": "swipe", "x": 0, "y": 0, "end_x": 10, "end_y": 20, "duration_ms": 100000},
        ]
        for request in requests:
            with self.subTest(operation=request["op"]), self.assertRaises(control.OperationError):
                self.session.perform(request)
        self.session._request.assert_not_called()

    def test_value_uses_fixed_session_element_endpoint(self):
        self.session.perform({"op": "value", "element_id": "fake-element", "text": PRIVATE_VALUE})
        self.session._request.assert_called_once_with("POST", "/element/fake-element/value", {"text": PRIVATE_VALUE})

    def test_find_allows_only_supported_locator_and_returns_element_id(self):
        self.session._request.return_value = {control.ELEMENT_KEY: "fake-element"}
        self.assertEqual(self.session.perform({"op": "find", "using": "accessibility id", "value": "button"}), {"element_id": "fake-element"})

    def test_swipe_is_bounded_w3c_touch_action(self):
        self.session.perform({"op": "swipe", "x": 1, "y": 2, "end_x": 3, "end_y": 4, "duration_ms": 100})
        method, path, payload = self.session._request.call_args.args
        self.assertEqual((method, path), ("POST", "/actions"))
        self.assertEqual(payload["actions"][0]["parameters"], {"pointerType": "touch"})
        self.assertEqual(payload["actions"][0]["actions"][2]["duration"], 100)

    def test_upstream_redirect_or_error_is_not_followed_or_disclosed(self):
        response = Mock(status=302)
        response.read.return_value = PRIVATE_VALUE.encode()
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(control.http.client, "HTTPConnection", return_value=connection) as factory:
            with self.assertRaises(control.OperationError) as caught:
                control.AppiumSession(SESSION)._request("GET", "/source")
        self.assertEqual(str(caught.exception), "upstream_failed")
        factory.assert_called_once_with("127.0.0.1", 4723, timeout=20)
        connection.request.assert_called_once()
        connection.close.assert_called_once()


class HttpBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.protocol = control.Protocol(KEY, SESSION)
        self.session = Mock()
        self.session.perform.return_value = PRIVATE_VALUE
        self.server = control.ControlServer(("127.0.0.1", 0), control.ControlHandler)
        self.server.engine = control.ControlEngine(self.protocol, self.session)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.endpoint = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_real_http_roundtrip_and_generic_auth_denial_without_logs(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            connection = control.http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
            connection.request("POST", "/control", PRIVATE_VALUE.encode())
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            self.assertEqual(response.read(), b"")
            connection.close()
            self.assertEqual(control.ControlClient(self.endpoint, KEY, SESSION).call("source"), {"ok": True, "value": PRIVATE_VALUE})
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")

    def wait_for_handlers(self, expected):
        deadline = time.monotonic() + 2
        while self.server.active_handlers != expected and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.server.active_handlers, expected)

    def test_incomplete_unauthenticated_header_does_not_block_valid_control(self):
        slow = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)
        try:
            slow.sendall(b"POST /control HTTP/1.1\r\nHost: unfinished")
            self.wait_for_handlers(1)
            started = time.monotonic()
            result = control.ControlClient(self.endpoint, KEY, SESSION).call("source")
            self.assertTrue(result["ok"])
            self.assertLess(time.monotonic() - started, 2)
        finally:
            slow.close()
        self.wait_for_handlers(0)

    def test_concurrent_handler_limit_rejects_excess_without_spawning(self):
        slow = []
        try:
            for _ in range(self.server.MAX_HANDLERS):
                connection = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)
                connection.sendall(b"POST /control HTTP/1.1\r\nHost: unfinished")
                slow.append(connection)
            self.wait_for_handlers(self.server.MAX_HANDLERS)
            excess = control.http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
            try:
                try:
                    excess.request("POST", "/control", b"{}")
                    response = excess.getresponse()
                    self.assertEqual(response.status, 401)
                    self.assertEqual(response.read(), b"")
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, control.http.client.RemoteDisconnected):
                    # A rejected socket may close before the request body is sent.
                    pass
            finally:
                excess.close()
            self.assertEqual(self.server.active_handlers, self.server.MAX_HANDLERS)
            self.session.perform.assert_not_called()
        finally:
            for connection in slow:
                connection.close()
        self.wait_for_handlers(0)

    def test_forbidden_operation_is_encrypted_and_session_can_continue(self):
        self.server.engine.session = control.AppiumSession(SESSION)
        client = control.ControlClient(self.endpoint, KEY, SESSION)
        self.assertEqual(client.call("execute"), {"ok": False, "error": "operation_not_allowed"})
        self.assertEqual(client.call("finish"), {"ok": True, "value": None})

    def test_sequence_handoff_resumes_after_verified_self_test(self):
        first = control.ControlClient(self.endpoint, KEY, SESSION)
        self.assertTrue(first.call("window")["ok"])
        self.assertEqual(first.sequence, 1)
        resumed = control.ControlClient(self.endpoint, KEY, SESSION, initial_sequence=first.sequence)
        self.assertTrue(resumed.call("source")["ok"])
        self.assertEqual(resumed.sequence, 2)

    def test_transport_replay_has_generic_empty_409(self):
        request = self.protocol.seal("request", 1, {"op": "source"})
        for expected in (200, 409):
            connection = control.http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
            connection.request("POST", "/control", request, {"Authorization": self.protocol.authorization})
            response = connection.getresponse()
            self.assertEqual(response.status, expected)
            body = response.read()
            if expected == 409:
                self.assertEqual(body, b"")
            connection.close()
        self.session.perform.assert_called_once()

    def test_client_fails_closed_on_replayed_wrong_bound_response(self):
        client = control.ControlClient(self.endpoint, KEY, SESSION)
        response = Mock(status=200)
        response.read.return_value = self.protocol.seal("response", 1, {"ok": True}, "wrong-request-nonce")
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(control.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "session must be renewed"):
                client.call("source")
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                client.call("source")
        connection.request.assert_called_once()


class LifecycleTests(unittest.TestCase):
    def test_threaded_cli_waits_until_encrypted_finish_reply_is_written(self):
        reply_pending = threading.Event()
        allow_reply = threading.Event()

        class GatedHandler(control.ControlHandler):
            def _respond(self, status, body):
                if status == 200:
                    reply_pending.set()
                    if not allow_reply.wait(timeout=2):
                        raise TimeoutError("Test reply was not released")
                super()._respond(status, body)

        server = control.ControlServer(("127.0.0.1", 0), GatedHandler)
        server.timeout = 0.02
        session = Mock()
        server.engine = control.ControlEngine(control.Protocol(KEY, SESSION), session)
        cli_errors, client_errors, replies = [], [], []

        def run_cli():
            try:
                control.serve_from_environment()
            except Exception as error:
                cli_errors.append(type(error).__name__)

        def run_client():
            try:
                replies.append(control.ControlClient("http://127.0.0.1:" + str(server.server_port), KEY, SESSION).call("finish"))
            except Exception as error:
                client_errors.append(type(error).__name__)

        cli = threading.Thread(target=run_cli, daemon=True)
        client = threading.Thread(target=run_client, daemon=True)
        with patch.object(control, "create_server", return_value=server), patch.dict(control.os.environ, {"QA_CONTROL_KEY": control._encode(KEY), "QA_APPIUM_SESSION_ID": SESSION}):
            try:
                cli.start()
                client.start()
                self.assertTrue(reply_pending.wait(timeout=2))
                self.assertTrue(server.engine.finish_requested.is_set())
                self.assertFalse(server.engine.completed.is_set())
                cli.join(timeout=0.15)
                self.assertTrue(cli.is_alive(), "CLI exited before its daemon handler wrote the finish reply")
                allow_reply.set()
                client.join(timeout=2)
                cli.join(timeout=2)
                self.assertFalse(client.is_alive())
                self.assertFalse(cli.is_alive())
                self.assertEqual(replies, [{"ok": True, "value": None}])
                self.assertEqual(client_errors, [])
                self.assertEqual(cli_errors, [])
                self.assertTrue(server.engine.completed.is_set())
                session.perform.assert_not_called()
            finally:
                allow_reply.set()
                server.engine.deadline = time.monotonic()
                client.join(timeout=2)
                cli.join(timeout=2)
                server.server_close()


if __name__ == "__main__":
    unittest.main()
