"""Synthetic-only persistence, ambiguity and interprocess exclusion tests."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import office_control as office


PRIVATE_VALUE = "synthetic-private-ui-fixture"
RAW_KEY = bytes(range(32))


class OfficeControlTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.metadata = root / "endpoint.json"
        self.key = root / "control.key"
        self.state = root / "state.json"
        self.lock = root / "state.json.lock"
        self.receipt = {"endpoint": "https://synthetic.trycloudflare.com", "session": "synthetic-session", "run": "12345", "initial_sequence": 3}
        self.metadata.write_text(json.dumps(self.receipt))
        self.key.write_bytes(RAW_KEY)
        self.dispatches = []
        self.reply = {"ok": True, "value": PRIVATE_VALUE}
        self.transport_error = None
        self.factory = Mock(side_effect=self.new_client)
        patched = patch.object(office, "ControlClient", self.factory)
        patched.start()
        self.addCleanup(patched.stop)

    def driver(self):
        return office.OfficeControl(self.metadata, self.key, self.state)

    def read_state(self):
        return json.loads(self.state.read_text())

    def new_client(self, endpoint, key, session, initial_sequence):
        self.assertEqual(key, RAW_KEY)
        client = SimpleNamespace(sequence=initial_sequence)

        def call(operation, **parameters):
            before = self.read_state()
            self.assertTrue(before["inflight"])
            self.assertEqual(before["last_verified_sequence"], initial_sequence)
            self.assertTrue(self.lock.exists())
            self.dispatches.append((operation, parameters, initial_sequence))
            if self.transport_error is not None:
                raise self.transport_error
            client.sequence += 1
            return self.reply

        client.call = call
        return client

    def assert_poisoned(self):
        self.assertTrue(self.lock.exists())
        prior = len(self.dispatches)
        with self.assertRaises(office.OfficeControlLocked):
            self.driver().call("source")
        self.assertEqual(len(self.dispatches), prior)

    def test_fresh_instances_resume_only_last_verified_sequence(self):
        self.assertEqual(self.driver().call("value", element_id="fake-element", text=PRIVATE_VALUE), self.reply)
        self.assertEqual(self.read_state()["last_verified_sequence"], 4)
        self.assertFalse(self.read_state()["inflight"])
        self.assertFalse(self.lock.exists())
        self.driver().call("source")
        self.assertEqual([entry[2] for entry in self.dispatches], [3, 4])
        self.assertEqual(self.read_state()["last_verified_sequence"], 5)
        self.assertNotIn(PRIVATE_VALUE, self.state.read_text())
        self.assertEqual(set(self.state.parent.iterdir()), {self.metadata, self.key, self.state})

    def test_verified_operational_error_advances_and_does_not_retry(self):
        self.reply = {"ok": False, "error": "upstream_failed"}
        self.assertEqual(self.driver().call("find", using="accessibility id", value=PRIVATE_VALUE), self.reply)
        self.assertEqual(len(self.dispatches), 1)
        self.assertEqual(self.read_state()["last_verified_sequence"], 4)
        self.assertFalse(self.lock.exists())
        self.reply = {"ok": True, "value": PRIVATE_VALUE}
        self.driver().call("source")
        self.assertEqual([entry[0] for entry in self.dispatches], ["find", "source"])

    def test_transport_failure_leaves_inflight_and_cannot_be_retried(self):
        self.transport_error = RuntimeError(PRIVATE_VALUE)
        with self.assertRaises(office.OfficeControlError) as caught:
            self.driver().call("tap", x=1, y=2)
        self.assertNotIn(PRIVATE_VALUE, str(caught.exception))
        self.assertEqual(self.read_state()["last_verified_sequence"], 3)
        self.assertTrue(self.read_state()["inflight"])
        self.assert_poisoned()

    def test_failure_to_write_inflight_never_dispatches_and_retains_lock(self):
        with patch.object(office, "_write_state", side_effect=OSError(PRIVATE_VALUE)):
            with self.assertRaises(office.OfficeControlError) as caught:
                self.driver().call("tap", x=1, y=2)
        self.assertNotIn(PRIVATE_VALUE, str(caught.exception))
        self.assertEqual(self.dispatches, [])
        self.assertFalse(self.state.exists())
        self.assert_poisoned()

    def test_failure_to_commit_verified_response_never_replays_command(self):
        real_write = office._write_state
        writes = 0

        def fail_commit(path, state):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError(PRIVATE_VALUE)
            real_write(path, state)

        with patch.object(office, "_write_state", side_effect=fail_commit):
            with self.assertRaises(office.OfficeControlError):
                self.driver().call("tap", x=1, y=2)
        self.assertEqual(len(self.dispatches), 1)
        self.assertTrue(self.read_state()["inflight"])
        self.assertEqual(self.read_state()["last_verified_sequence"], 3)
        self.assert_poisoned()

    def test_failed_atomic_replace_preserves_previous_state_and_poison_lock(self):
        self.driver().call("source")
        saved = self.state.read_bytes()
        with patch.object(office.os, "replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(office.OfficeControlError):
                self.driver().call("click", element_id="fake-element")
        self.assertEqual(self.state.read_bytes(), saved)
        self.assertEqual(len(self.dispatches), 1)
        self.assert_poisoned()

    def test_inflight_marker_without_lock_is_still_fail_closed(self):
        self.driver().call("source")
        state = self.read_state()
        state["inflight"] = True
        self.state.write_text(json.dumps(state))
        self.factory.reset_mock()
        with self.assertRaises(office.OfficeControlLocked):
            self.driver().call("source")
        self.factory.assert_not_called()
        self.assert_poisoned()

    def test_metadata_session_run_endpoint_and_initial_sequence_mismatch_refuse_resume(self):
        for field, replacement in [("session", "other-session"), ("run", "99999"), ("endpoint", "https://other.trycloudflare.com"), ("initial_sequence", 8)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                state = Path(directory) / "state.json"
                office._write_state(state, {"version": 1, "binding": self.receipt, "last_verified_sequence": 4, "inflight": False})
                receipt = {**self.receipt, field: replacement}
                self.metadata.write_text(json.dumps(receipt))
                self.factory.reset_mock()
                with self.assertRaisesRegex(office.OfficeControlError, "does not match"):
                    office.OfficeControl(self.metadata, self.key, state).call("source")
                self.factory.assert_not_called()
                self.assertEqual(json.loads(state.read_text())["last_verified_sequence"], 4)

    def test_another_process_holds_lock_for_entire_dispatch(self):
        script = '''
import json, sys
from types import SimpleNamespace
import office_control as office
def factory(endpoint, key, session, initial_sequence):
    client = SimpleNamespace(sequence=initial_sequence)
    def call(operation, **parameters):
        print("ready", flush=True)
        sys.stdin.readline()
        client.sequence += 1
        return {"ok": True, "value": None}
    client.call = call
    return client
office.ControlClient = factory
office.OfficeControl(*sys.argv[1:]).call("source")
'''
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(office.__file__).resolve().parent)
        process = subprocess.Popen([sys.executable, "-c", script, str(self.metadata), str(self.key), str(self.state)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        try:
            deadline = time.monotonic() + 5
            while not self.state.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.state.exists(), "Synthetic child never entered dispatch")
            self.assertTrue(self.read_state()["inflight"])
            with self.assertRaises(office.OfficeControlLocked):
                self.driver().call("tap", x=1, y=2)
            self.factory.assert_not_called()
            process.stdin.write("continue\n")
            process.stdin.flush()
            output, errors = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, errors)
            self.assertEqual(output.strip(), "ready")
            self.assertFalse(self.lock.exists())
            self.assertFalse(self.read_state()["inflight"])
            self.assertEqual(self.read_state()["last_verified_sequence"], 4)
            self.driver().call("source")
            self.assertEqual(self.dispatches[0][2], 4)
            self.assertEqual(self.read_state()["last_verified_sequence"], 5)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
