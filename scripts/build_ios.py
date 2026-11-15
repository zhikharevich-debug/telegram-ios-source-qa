"""Build public upstream source only; this job never logs in or reads accounts."""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import shutil
import subprocess
import time

CHANNELS = {
    "preview": ("24638bc69bd083981b178dd1e7f921eebbf7fc46", "27.1", "iOS 27.1"),
    "stable": ("f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838", "26.6", "iOS 26.5"),
}
UPSTREAM, XCODE_VERSION, IOS_RUNTIME = CHANNELS[os.environ.get("QA_BUILD_CHANNEL", "preview")]
ROOT = Path.cwd()
TEMP = Path(os.environ["RUNNER_TEMP"])
SOURCE = TEMP / "Telegram-iOS"
OUTPUT = ROOT / "artifacts"
OUTPUT.mkdir(exist_ok=True)
REPORT = {"status": "running", "upstream": UPSTREAM, "login": "not_run"}
DEVICE = None
PRESERVE = False
REDACT = []
# Leave time inside the 330-minute job for diagnostics and Simulator cleanup.
DEADLINE = time.monotonic() + (190 if os.environ.get("QA_PRESERVE_DEVICE") == "1" else 310) * 60


def save():
    (OUTPUT / "build.json").write_text(json.dumps(REPORT, indent=2) + "\n", encoding="utf-8")


def stage(label, args, timeout=120, cwd=SOURCE):
    REPORT["stage"] = label
    REPORT.pop("elapsed_stage_seconds", None)
    save()
    print(f"Stage: {label}", flush=True)
    remaining = int(DEADLINE - time.monotonic())
    if remaining <= 0:
        raise RuntimeError("Build time budget exhausted; preserving diagnostic time")
    timeout = min(timeout, remaining)
    log_path = TEMP / "native-build-private.log"
    failure = None
    with log_path.open("w", encoding="utf-8") as log:
        with subprocess.Popen(args, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True) as process:
            try:
                started = time.monotonic()
                until = started + timeout
                while True:
                    try:
                        returncode = process.wait(timeout=max(0, min(60, until - time.monotonic())))
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= until:
                            raise
                        REPORT["elapsed_stage_seconds"] = round(time.monotonic() - started)
                        REPORT["free_disk_gib"] = round(shutil.disk_usage(TEMP).free / 2**30, 2)
                        save()
                        print(f"Progress: {label}; elapsed={REPORT['elapsed_stage_seconds']}s; free_disk={REPORT['free_disk_gib']}GiB", flush=True)
                if returncode:
                    failure = f"exited {returncode}"
            except subprocess.TimeoutExpired:
                # Terminate Make.py and its compiler descendants together.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=30)
                failure = f"timed out after {timeout} seconds"
            except BaseException:
                # Disk-full/progress IO errors must not make Popen.__exit__ wait
                # for an unbounded compiler after the normal deadline is lost.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=30)
                raise
    if failure:
        # No credentials are supplied to this job. Still suppress bundled sample API values.
        with log_path.open("rb") as private_log:
            private_log.seek(0, os.SEEK_END)
            private_log.seek(max(0, private_log.tell() - 32000))
            tail = private_log.read().decode("utf-8", errors="replace")[-8000:]
        for value in REDACT:
            tail = tail.replace(value, "[redacted]")
        tail = re.sub(r"(?i)(api_hash|token|password|secret)([\s=:]+)\S+", r"\1\2[redacted]", tail)
        (OUTPUT / "build-failure.txt").write_text(tail, encoding="utf-8")
        raise RuntimeError(f"{label} {failure}; sanitized diagnostic saved")


def capture(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


try:
    REPORT.update(architecture=capture("uname", "-m"), xcode=capture("xcodebuild", "-version"))
    assert REPORT["architecture"] == "arm64" and REPORT["xcode"].startswith("Xcode " + XCODE_VERSION + "\n")
    stage("initialize", ["git", "init", str(SOURCE)], cwd=TEMP)
    stage("origin", ["git", "remote", "add", "origin", "https://github.com/TelegramMessenger/Telegram-iOS.git"])
    stage("fetch", ["git", "fetch", "--depth=1", "--filter=blob:none", "origin", UPSTREAM], timeout=1200)
    stage("checkout", ["git", "checkout", "--detach", "FETCH_HEAD"], timeout=1200)
    stage("submodules", ["git", "submodule", "update", "--init", "--recursive", "--depth=1", "--jobs=3"], timeout=2400)
    assert capture("git", "-C", str(SOURCE), "rev-parse", "HEAD") == UPSTREAM
    config = json.loads((SOURCE / "build-system/appstore-configuration.json").read_text())
    REDACT.extend(str(value) for key, value in config.items() if "hash" in key.lower())
    config.update(bundle_id="org.sodstr.qa.Telegram", is_internal_build="true", is_appstore_build="false", appstore_id="0", app_specific_url_scheme="sodstr-telegram-qa", enable_siri=False, enable_icloud=False)
    config_path = TEMP / "qa-configuration.json"
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    # HOME is an ephemeral GitHub runner. No developer configuration is modified.
    with (Path.home() / ".bazelrc").open("a") as rc:
        rc.write("\nbuild --//Telegram:disableProvisioningProfiles\nbuild --//Telegram:disableExtensions\nbuild --jobs=2\n")
    REPORT["disk_before_build_gib"] = round(shutil.disk_usage(TEMP).free / 2**30, 2)
    started = time.monotonic()
    stage("compile", ["python3", "build-system/Make/Make.py", "build", "--configurationPath=" + str(config_path), "--xcodeManagedCodesigning", "--buildNumber=100001", "--configuration=debug_sim_arm64"], timeout=16200)
    REPORT["build_seconds"] = round(time.monotonic() - started)
    # Release the resident Java build daemon before Simulator and XCTest need RAM.
    bazel = list((SOURCE / "build-input").glob("bazel-*-darwin-arm64"))
    if len(bazel) != 1:
        raise RuntimeError("Expected one pinned Bazel binary")
    stage("stop-bazel", [str(bazel[0]), "shutdown"], timeout=120)
    stage("source-integrity", ["git", "diff", "--exit-code", "--", ".", ":(exclude)MODULE.bazel.lock"])
    ipa = SOURCE / "bazel-bin/Telegram/Telegram.ipa"
    with ipa.open("rb") as ipa_file:
        REPORT["ipa_sha256"] = hashlib.file_digest(ipa_file, "sha256").hexdigest()
    app_root = TEMP / "simulator-app"
    # ditto preserves framework symlinks and executable modes from the IPA.
    stage("extract", ["ditto", "-x", "-k", str(ipa), str(app_root)])
    app = app_root / "Payload/Telegram.app"
    info = plistlib.loads((app / "Info.plist").read_bytes())
    executable = app / info["CFBundleExecutable"]
    executable.chmod(executable.stat().st_mode | 0o111)
    platform = capture("xcrun", "vtool", "-show-build", str(executable))
    assert "IOSSIMULATOR" in platform, "Device IPA is not a Simulator app"
    REPORT["bundle_id"] = info["CFBundleIdentifier"]
    runtime = next(r for r in json.loads(capture("xcrun", "simctl", "list", "runtimes", "--json"))["runtimes"] if r.get("isAvailable") and r["name"] == IOS_RUNTIME)
    devices = json.loads(capture("xcrun", "simctl", "list", "devices", "available", "--json"))["devices"]
    candidates = {d["deviceTypeIdentifier"] for d in devices.get(runtime["identifier"], []) if d.get("isAvailable")}
    candidates.update(d["identifier"] for d in runtime.get("supportedDeviceTypes", []))
    types = json.loads(capture("xcrun", "simctl", "list", "devicetypes", "--json"))["devicetypes"]
    phone = next(t for t in types if t["identifier"] in candidates and t["name"].startswith("iPhone"))
    REPORT.update(runtime=runtime["name"], device=phone["name"])
    DEVICE = capture("xcrun", "simctl", "create", "Telegram-Native-QA", phone["identifier"], runtime["identifier"])
    stage("boot", ["xcrun", "simctl", "boot", DEVICE])
    simulator = str(Path(os.environ["DEVELOPER_DIR"]) / "Applications/Simulator.app")
    stage("display", ["open", "-a", simulator, "--args", "-CurrentDeviceUDID", DEVICE])
    stage("bootstatus", ["xcrun", "simctl", "bootstatus", DEVICE, "-b"], timeout=480)
    stage("install", ["xcrun", "simctl", "install", DEVICE, str(app)], timeout=240)
    stage("launch", ["xcrun", "simctl", "launch", DEVICE, info["CFBundleIdentifier"]])
    time.sleep(10)
    stage("signed-out-screenshot", ["xcrun", "simctl", "io", DEVICE, "screenshot", str(OUTPUT / "signed-out-native.png")])
    REPORT.update(status="passed", native_client="launch_command_succeeded", acceptance="not_verified", login="not_run")
    if os.environ.get("QA_PRESERVE_DEVICE") == "1":
        state_path = TEMP / "native-build-state.json"
        state_path.write_text(json.dumps({"device": DEVICE, "bundle": info["CFBundleIdentifier"]}))
        state_path.chmod(0o600)
        PRESERVE = True
except Exception as error:
    REPORT.update(status="failed", failure_type=type(error).__name__, failure=str(error)[:300])
    raise
finally:
    save()
    cleanup_failed = False
    if DEVICE and not PRESERVE:
        for action in ("shutdown", "delete"):
            try:
                subprocess.run(["xcrun", "simctl", action, DEVICE], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (subprocess.SubprocessError, OSError) as error:
                REPORT[action + "_warning"] = type(error).__name__
                if action == "delete":
                    cleanup_failed = REPORT["status"] == "passed"
                    REPORT["status"] = "failed"
    save()
    print(json.dumps(REPORT))
    if cleanup_failed:
        raise RuntimeError("Simulator cleanup failed; primary build report was preserved")
