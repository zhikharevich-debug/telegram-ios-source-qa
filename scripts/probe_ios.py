"""Ephemeral hosted-macOS probe; never inspect accounts, keychains or application data."""

import json
import os
import pathlib
import shutil
import subprocess
import time


def command(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


def save_report():
    (output / "probe.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


output = pathlib.Path("artifacts")
output.mkdir(exist_ok=True)
device = None
report = {"status": "running", "native_telegram": "not_run"}
try:
    report.update(
        architecture=command("uname", "-m"),
        macos=command("sw_vers", "-productVersion"),
        xcode=command("xcodebuild", "-version").splitlines(),
        memory_gib=round(int(command("sysctl", "-n", "hw.memsize")) / 2**30, 2),
        free_disk_gib=round(shutil.disk_usage(".").free / 2**30, 2),
    )
    assert report["architecture"] == "arm64", "Expected standard ARM runner"
    assert report["xcode"][0] == "Xcode " + os.environ.get("QA_XCODE_VERSION", "27.1"), "Unexpected toolchain"
    runtimes = json.loads(command("xcrun", "simctl", "list", "runtimes", "--json"))["runtimes"]
    runtime = next(r for r in runtimes if r.get("isAvailable") and r["name"] == os.environ.get("QA_IOS_RUNTIME", "iOS 27.1"))
    devices = json.loads(command("xcrun", "simctl", "list", "devices", "available", "--json"))["devices"]
    available = devices.get(runtime["identifier"], [])
    supported = runtime.get("supportedDeviceTypes", [])
    report["available_devices"] = [d["name"] for d in available]
    report["supported_types"] = [d["name"] for d in supported]
    types = json.loads(command("xcrun", "simctl", "list", "devicetypes", "--json"))["devicetypes"]
    candidates = {d["deviceTypeIdentifier"] for d in available if d.get("isAvailable")}
    candidates.update(d["identifier"] for d in supported)
    phone = next(t for t in types if t["identifier"] in candidates and t["name"].startswith("iPhone"))
    report.update(runtime=runtime["name"], device=phone["name"])
    device = command("xcrun", "simctl", "create", "Native-QA-iPhone", phone["identifier"], runtime["identifier"])
    start = time.monotonic()
    subprocess.run(["xcrun", "simctl", "boot", device], check=True, timeout=60)
    simulator = str(pathlib.Path(os.environ["DEVELOPER_DIR"]) / "Applications/Simulator.app")
    subprocess.run(["open", "-a", simulator, "--args", "-CurrentDeviceUDID", device], check=True, timeout=60)
    subprocess.run(["xcrun", "simctl", "bootstatus", device, "-b"], check=True, timeout=480)
    report["boot_seconds"] = round(time.monotonic() - start, 1)
    subprocess.run(["xcrun", "simctl", "io", device, "screenshot", str(output / "clean-simulator.png")], check=True, timeout=120)
    report["status"] = "passed"
except Exception as error:
    report.update(status="failed", failure_type=type(error).__name__, failure=str(error)[:300])
    raise
finally:
    save_report()
    cleanup_failed = False
    if device:
        try:
            subprocess.run(["xcrun", "simctl", "shutdown", device], check=False, timeout=30)
        except subprocess.TimeoutExpired:
            report["shutdown_warning"] = "timeout"
        try:
            subprocess.run(["xcrun", "simctl", "delete", device], check=True, timeout=30)
            report["cleanup"] = "passed"
        except (subprocess.SubprocessError, OSError) as error:
            report["cleanup"] = type(error).__name__
            cleanup_failed = report["status"] == "passed"
            report["status"] = "failed"
    save_report()
    print(json.dumps(report))
    if cleanup_failed:
        raise RuntimeError("Simulator cleanup failed; primary probe report was preserved")
