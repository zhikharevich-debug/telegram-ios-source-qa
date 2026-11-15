"""Disposable Appium orchestration. Never upload private logs or logged-in images."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import hashlib

TEMP = Path(os.environ["RUNNER_TEMP"])
STATE = TEMP / "native-session.json"
ENDPOINT = Path("artifacts/control-endpoint.json")
DEVICE_PATTERN = re.compile(r"[0-9A-Fa-f-]{36}\Z")


def capture(*args):
    return subprocess.check_output(args, text=True, timeout=90).strip()


def local_request(path, body=None, timeout=15):
    request = urllib.request.Request("http://127.0.0.1:4723" + path, data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def write_state(state):
    STATE.write_text(json.dumps(state))
    STATE.chmod(0o600)


def background(args, name, env):
    with (TEMP / (name + "-private.log")).open("w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, env=env)
    return process.pid


def prepare():
    from native_control import ControlClient, key_from_environment

    state = {"pids": []}
    write_state(state)
    source_state = TEMP / "native-build-state.json"
    if os.environ.get("QA_NATIVE_TARGET") == "telegram":
        state.update(json.loads(source_state.read_text()))
        assert state["bundle"] == "org.sodstr.qa.Telegram"
    else:
        runtime = next(r for r in json.loads(capture("xcrun", "simctl", "list", "runtimes", "--json"))["runtimes"] if r.get("isAvailable") and r["name"] == "iOS 26.5")
        devices = json.loads(capture("xcrun", "simctl", "list", "devices", "available", "--json"))["devices"]
        candidates = {d["deviceTypeIdentifier"] for d in devices.get(runtime["identifier"], []) if d.get("isAvailable")}
        candidates.update(d["identifier"] for d in runtime.get("supportedDeviceTypes", []))
        types = json.loads(capture("xcrun", "simctl", "list", "devicetypes", "--json"))["devicetypes"]
        phone = next(t for t in types if t["identifier"] in candidates and t["name"].startswith("iPhone"))
        state.update(device=capture("xcrun", "simctl", "create", "Native-Control-QA", phone["identifier"], runtime["identifier"]), bundle="com.apple.Preferences")
        write_state(state)
        subprocess.run(["xcrun", "simctl", "boot", state["device"]], check=True, timeout=90)
        simulator = str(Path(os.environ["DEVELOPER_DIR"]) / "Applications/Simulator.app")
        subprocess.run(["open", "-a", simulator, "--args", "-CurrentDeviceUDID", state["device"]], check=True, timeout=60)
        subprocess.run(["xcrun", "simctl", "bootstatus", state["device"], "-b"], check=True, timeout=480)
    assert DEVICE_PATTERN.fullmatch(state["device"])
    write_state(state)
    child_env = {k: v for k, v in os.environ.items() if k != "QA_CONTROL_KEY"}
    appium = str(TEMP / "appium/node_modules/.bin/appium")
    state["pids"].append(background([appium, "--address", "127.0.0.1", "--port", "4723", "--use-drivers", "xcuitest", "--log-level", "error"], "appium", child_env))
    write_state(state)
    for _ in range(60):
        try:
            if local_request("/status")["value"]["ready"]:
                break
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)
    else:
        raise RuntimeError("Appium did not become ready; private log retained only on runner")
    caps = {"platformName": "iOS", "appium:automationName": "XCUITest", "appium:udid": state["device"], "appium:bundleId": state["bundle"], "appium:noReset": True, "appium:newCommandTimeout": 3600, "appium:showXcodeLog": False, "appium:showIOSLog": False, "appium:skipLogCapture": True, "appium:printPageSourceOnFindFailure": False}
    session = local_request("/session", {"capabilities": {"alwaysMatch": caps}}, timeout=600)["value"]["sessionId"]
    state["session"] = session
    control_env = os.environ.copy()
    control_env.update(QA_APPIUM_SESSION_ID=session, QA_CONTROL_LIFETIME_SECONDS="3600")
    state["control_pid"] = background([sys.executable, "scripts/native_control.py"], "control", control_env)
    state["pids"].append(state["control_pid"])
    write_state(state)
    for _ in range(30):
        try:
            urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:4781/control", data=b"{}"), timeout=3)
        except urllib.error.HTTPError as error:
            if error.code == 401:
                break
            raise
        except OSError:
            time.sleep(1)
    else:
        raise RuntimeError("Private control did not become ready")
    for header in ({}, {"Authorization": "Bearer invalid"}):
        try:
            urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:4781/control", data=b"{}", headers=header), timeout=10)
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise RuntimeError("Unauthenticated control unexpectedly accepted")
    client = ControlClient("http://127.0.0.1:4781", key_from_environment(), session)
    window = client.call("window")
    assert window.get("ok"), "Authenticated window request failed"
    archive_path = TEMP / "cloudflared.tgz"
    urllib.request.urlretrieve("https://github.com/cloudflare/cloudflared/releases/download/2026.11.0/cloudflared-darwin-arm64.tgz", archive_path)
    with archive_path.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == "8c2f90277ef06a6080bb40b964d33f09f1188102f8798f2e344174b6cf41accf"
    tunnel = TEMP / "cloudflared"
    with tarfile.open(archive_path) as archive:
        member = next(m for m in archive if m.isfile() and Path(m.name).name == "cloudflared")
        with archive.extractfile(member) as source, tunnel.open("wb") as destination:
            shutil.copyfileobj(source, destination)
    tunnel.chmod(0o700)
    state["pids"].append(background([str(tunnel), "tunnel", "--url", "http://127.0.0.1:4781", "--no-autoupdate"], "tunnel", child_env))
    write_state(state)
    for _ in range(60):
        text = (TEMP / "tunnel-private.log").read_text(errors="replace")
        match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", text)
        if match:
            break
        time.sleep(1)
    else:
        raise RuntimeError("Temporary tunnel did not become ready")
    ENDPOINT.parent.mkdir(exist_ok=True)
    ENDPOINT.write_text(json.dumps({"endpoint": match[0], "session": session, "initial_sequence": client.sequence, "target": state["bundle"], "run": os.environ.get("GITHUB_RUN_ID"), "expires": int(time.time()) + 3500, "local_denials": "passed"}))
    print("Encrypted native control ready. Only non-secret endpoint metadata is published.")


def cleanup():
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    build_state = TEMP / "native-build-state.json"
    if not state.get("device") and build_state.exists():
        state.update(json.loads(build_state.read_text()))
    import signal
    for pid in reversed(state.get("pids", [])):
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    device = state.get("device")
    if device and DEVICE_PATTERN.fullmatch(device):
        deletion_failed = False
        for action in ("shutdown", "delete"):
            try:
                subprocess.run(["xcrun", "simctl", action, device], timeout=60, check=action == "delete", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (subprocess.SubprocessError, OSError):
                if action == "delete":
                    deletion_failed = True
        if deletion_failed:
            raise RuntimeError("Simulator deletion failed; ephemeral runner teardown remains mandatory")


if __name__ == "__main__":
    mode = sys.argv[1]
    try:
        if mode == "prepare":
            prepare()
        elif mode == "cleanup":
            cleanup()
        elif mode == "wait":
            state = json.loads(STATE.read_text())
            deadline = time.monotonic() + 3600
            while time.monotonic() < deadline:
                try:
                    os.kill(state["control_pid"], 0)
                except ProcessLookupError:
                    break
                time.sleep(5)
            print("Native control window ended; acceptance requires office-side receipts.")
        else:
            raise ValueError("Invalid mode")
    except Exception as error:
        # Production UI errors/command parameters must not enter public CI logs.
        print("Native orchestration failed: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
