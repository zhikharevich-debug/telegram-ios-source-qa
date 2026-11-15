"""Callable office driver with fail-closed cross-process command resumption.

PRECONDITION: metadata, raw 32-byte key, state, lock and temporary state files
must reside in an existing private directory protected by Windows ACLs for the
operator. This module does not establish or audit ACLs. POSIX file modes do not
provide a Windows security guarantee. Never store this directory in public CI
artifacts, logs, or a repository.

Use OfficeControl(metadata_path, key_path, state_path).call(op, **parameters).
Metadata contains endpoint, session, run and initial_sequence. Each call obtains
an exclusive lock, persists inflight before dispatch, and commits the verified
sequence only after ControlClient authenticates the response. A verified
{ok: false} is a completed command, so it advances the sequence and is returned
without retry. Transport/protocol exceptions, state-write failures and process
crashes leave a persistent lock or inflight state: never automatically recover
these or repeat an ambiguous command. Prepare a new native session instead.

UI parameters/results, screenshots, source and keys are never written or logged.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile

from native_control import ControlClient


class OfficeControlError(RuntimeError):
    """Fixed safe message; never contains UI data or upstream error text."""


class OfficeControlLocked(OfficeControlError):
    """Existing locks and ambiguous commands require explicit investigation."""


def _read_json(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise OfficeControlError("Invalid private control state")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise OfficeControlError("Invalid private control state")
    return value


def _sequence(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**63 - 1:
        raise OfficeControlError("Invalid private control sequence")
    return value


def _write_state(path: Path, value: dict) -> None:
    """Flush a replacement in the same private directory before atomic rename."""
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


@contextmanager
def _exclusive_lock(path: Path):
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise OfficeControlLocked("Control state is locked; automatic recovery is disabled") from None
    successful = False
    try:
        os.write(descriptor, b"office-control-v1\n")
        os.fsync(descriptor)
        yield
        successful = True
    finally:
        os.close(descriptor)
        # Failure/process crash leaves this lock as a persistent fail-closed marker.
        if successful:
            path.unlink()


class OfficeControl:
    """One command per private state lock; safe to recreate in another process.

    The caller must provision private Windows directory ACLs before construction.
    A successful reply is returned only after its state commit succeeds. No
    command is retried, including authenticated operational errors.
    """

    def __init__(self, metadata_path, key_path, state_path):
        self.metadata_path = Path(metadata_path).resolve()
        self.key_path = Path(key_path).resolve()
        self.state_path = Path(state_path).resolve()
        self.lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        if len({self.metadata_path, self.key_path, self.state_path, self.lock_path}) != 4:
            raise OfficeControlError("Private control paths must be distinct")
        if not self.state_path.parent.is_dir():
            raise OfficeControlError("Private state directory must already exist")

    def call(self, operation: str, **parameters) -> dict:
        """Dispatch once and durably record only an authenticated completion."""
        try:
            with _exclusive_lock(self.lock_path):
                metadata = _read_json(self.metadata_path)
                binding = {field: metadata[field] for field in ("endpoint", "session", "run", "initial_sequence")}
                if not all(isinstance(binding[field], str) and binding[field] for field in ("endpoint", "session", "run")):
                    raise OfficeControlError("Invalid private control metadata")
                initial = _sequence(binding["initial_sequence"])
                with self.key_path.open("rb") as stream:
                    key = stream.read(33)
                if len(key) != 32:
                    raise OfficeControlError("Invalid private control key")
                if self.state_path.exists():
                    state = _read_json(self.state_path)
                    if set(state) != {"version", "binding", "last_verified_sequence", "inflight"} or type(state["version"]) is not int or state["version"] != 1:
                        raise OfficeControlError("Invalid private control state")
                    if state["binding"] != binding:
                        raise OfficeControlError("Control metadata does not match this state")
                    if state["inflight"] is not False:
                        raise OfficeControlLocked("Control state contains an unresolved command")
                    verified = _sequence(state["last_verified_sequence"])
                    if verified < initial:
                        raise OfficeControlError("Invalid private control sequence")
                else:
                    verified = initial
                client = ControlClient(binding["endpoint"], key, binding["session"], initial_sequence=verified)
                state = {"version": 1, "binding": binding, "last_verified_sequence": verified, "inflight": True}
                _write_state(self.state_path, state)
                response = client.call(operation, **parameters)
                # ControlClient verifies AEAD, nonce and sequence before returning.
                if not isinstance(response, dict) or type(response.get("ok")) is not bool or client.sequence != verified + 1:
                    raise OfficeControlError("Control completion could not be verified")
                state.update(last_verified_sequence=client.sequence, inflight=False)
                _write_state(self.state_path, state)
                return response
        except OfficeControlError:
            raise
        except Exception:
            raise OfficeControlError("Control command failed; do not retry this state automatically") from None
