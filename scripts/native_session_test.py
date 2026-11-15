"""Regression tests for the anonymous-only diagnostic publication boundary."""

import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


SOURCE = Path(__file__).resolve().with_name("native_session.py")
CONTROL_KEY = "PUBLIC-TEST-ONLY-CONTROL-KEY-FIXTURE"
PRIVATE_MARKER = "private-cookie-session-fixture"


class TrackedBody(io.BytesIO):
    def __init__(self, body):
        super().__init__(body)
        self.read_calls = 0

    def read(self, *args):
        self.read_calls += 1
        return super().read(*args)


class DiagnosticPrivacyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        runner = root / "runner"
        workspace = root / "workspace"
        runner.mkdir()
        workspace.mkdir()
        original_cwd = Path.cwd()
        os.chdir(workspace)
        self.addCleanup(os.chdir, original_cwd)
        environment = patch.dict(os.environ, {"RUNNER_TEMP": str(runner), "QA_NATIVE_TARGET": "settings", "QA_CONTROL_KEY": CONTROL_KEY})
        environment.start()
        self.addCleanup(environment.stop)
        spec = importlib.util.spec_from_file_location("isolated_native_session", SOURCE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.PHASE = "xcuitest-session"
        self.output = Path("artifacts/settings-startup-diagnostic.json")
        self.log = runner / "appium-private.log"

    def error(self, message):
        body = TrackedBody(json.dumps({"value": {"error": "session not created", "message": message}}).encode())
        error = urllib.error.HTTPError("http://127.0.0.1:4723/session", 500, "fixture failure", {}, body)
        self.addCleanup(error.close)
        return error, body

    def assert_blocked(self, error, body):
        with patch.object(Path, "open", side_effect=AssertionError("Forbidden diagnostic touched a file")):
            self.module.settings_startup_diagnostic(error)
        self.assertEqual(body.read_calls, 0)
        self.assertFalse(self.output.exists())
        self.assertFalse(Path("artifacts").exists())

    def test_telegram_target_never_reads_or_publishes_sensitive_diagnostics(self):
        os.environ["QA_NATIVE_TARGET"] = "telegram"
        self.log.write_text("Cookie: " + PRIVATE_MARKER + " secret=" + CONTROL_KEY)
        error, body = self.error("Cookie: " + PRIVATE_MARKER + " password=" + CONTROL_KEY)
        self.assert_blocked(error, body)

    def test_any_settings_phase_after_endpoint_publication_is_blocked(self):
        self.module.ENDPOINT.parent.mkdir()
        self.module.ENDPOINT.write_text("{}")
        error, body = self.error(PRIVATE_MARKER)
        with patch.object(Path, "open", side_effect=AssertionError("Post-endpoint diagnostic touched a file")):
            self.module.settings_startup_diagnostic(error)
        self.assertEqual(body.read_calls, 0)
        self.assertFalse(self.output.exists())

    def test_other_phases_and_unspecified_target_never_publish(self):
        error, body = self.error(PRIVATE_MARKER)
        for phase in ("starting", "simulator", "appium-server", "encrypted-control", "temporary-tunnel"):
            with self.subTest(phase=phase):
                self.module.PHASE = phase
                self.assert_blocked(error, body)
        self.module.PHASE = "xcuitest-session"
        os.environ.pop("QA_NATIVE_TARGET")
        self.assert_blocked(error, body)

    def test_anonymous_settings_bootstrap_diagnostic_is_bounded_and_filtered(self):
        self.log.write_text("discarded-prefix" * 5000 + "\n" + CONTROL_KEY + "\ntoken=private-token-fixture password=private-password-fixture safe-tail\n")
        error, body = self.error(CONTROL_KEY + " " + "m" * 7000)
        self.module.settings_startup_diagnostic(error)
        raw = self.output.read_text()
        diagnostic = json.loads(raw)
        self.assertEqual(body.read_calls, 1)
        self.assertEqual(diagnostic["phase"], "xcuitest-session")
        self.assertEqual(diagnostic["http_status"], 500)
        self.assertEqual(diagnostic["driver_error"], "session not created")
        self.assertNotIn(CONTROL_KEY, raw)
        self.assertNotIn("private-token-fixture", raw)
        self.assertNotIn("private-password-fixture", raw)
        self.assertIn("[redacted]", raw)
        self.assertIn("safe-tail", diagnostic["settings_bootstrap_tail"])
        self.assertLess(len(raw), 32000)
        self.assertLessEqual(len(diagnostic["driver_message"]), 6000)
        self.assertLessEqual(len(diagnostic["settings_bootstrap_tail"]), 24000)

    def test_filtering_last_log_value_preserves_valid_json(self):
        self.log.write_text("anonymous startup token=private-final-token-fixture")
        error, _ = self.error("anonymous startup failed")
        self.module.settings_startup_diagnostic(error)
        raw = self.output.read_text()
        self.assertNotIn("private-final-token-fixture", raw)
        self.assertEqual(json.loads(raw)["http_status"], 500)

    def test_bearer_and_quoted_json_credentials_are_filtered_in_both_sources(self):
        markers = ["private-log-bearer-fixture", "private-log-json-token-fixture", "private-http-bearer-fixture", "private-http-json-token-fixture"]
        self.log.write_text('Authorization: Bearer ' + markers[0] + '\n{"token": "' + markers[1] + '"}\n')
        error, _ = self.error('Authorization: Bearer ' + markers[2] + '\n{"token": "' + markers[3] + '"}')
        self.module.settings_startup_diagnostic(error)
        raw = self.output.read_text()
        for marker in markers:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, raw)
        self.assertEqual(json.loads(raw)["http_status"], 500)


if __name__ == "__main__":
    unittest.main()
