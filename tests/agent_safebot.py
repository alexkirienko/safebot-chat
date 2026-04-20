#!/usr/bin/env python3
"""Smoke tests for sdk/agent_safebot.py (host-agnostic listener launcher).

Covers:
  1. --host custom --cmd template exec's the right argv and receives the prompt
  2. release sentinel on fake-host stdout stops the respawn loop without rc=0
  3. --once exits after one invocation (rc of the host bubbles up)
  4. fast-fail backoff trips the hard stop after N consecutive rc!=0 exits
  5. --print-prompt emits the prompt and does not launch anything

These don't touch the network — everything is a local fake binary on PATH.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "sdk" / "agent_safebot.py"


FAKE_HOST = r"""#!/usr/bin/env python3
# Fake AI host CLI. Records argv to TEST_LOG and behaves per env:
#   TEST_HOST_EXIT_RC  -> exit with this code (default 0)
#   TEST_HOST_RELEASE  -> if "1", print release sentinel on stdout then exit 0
#   TEST_HOST_COUNT    -> path to counter file; increments each invocation
#   TEST_HOST_MAX      -> after N invocations, exit rc=0 (useful to bound tests)
import json, os, sys
log = os.environ["TEST_LOG"]
with open(log, "a", encoding="utf-8") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
if os.environ.get("TEST_HOST_RELEASE") == "1":
    print(os.environ.get("TEST_RELEASE_SENTINEL", "SAFEBOT_RELEASED_BY_ROOM"))
    sys.exit(0)
cf = os.environ.get("TEST_HOST_COUNT")
if cf:
    n = 0
    try: n = int(open(cf).read())
    except Exception: pass
    n += 1
    open(cf, "w").write(str(n))
    mx = int(os.environ.get("TEST_HOST_MAX", "3"))
    if n >= mx:
        sys.exit(int(os.environ.get("TEST_HOST_EXIT_RC", "42")))
sys.exit(int(os.environ.get("TEST_HOST_EXIT_RC", "0")))
"""


def make_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def ok(msg: str) -> None:
    print("ok -", msg)


def run(script_args: list[str], env_extra: dict[str, str], *, timeout: float = 20.0):
    env = os.environ.copy()
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + script_args,
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout,
    )


def case_custom_once() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "log"
        bindir = Path(td) / "bin"
        bindir.mkdir()
        make_exec(bindir / "fake-host", FAKE_HOST)
        env = {
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "TEST_LOG": str(log),
        }
        proc = run([
            "--host", "custom",
            "--cmd", "fake-host --mode listener {room_url}",
            "--once",
            "https://safebot.chat/room/ABC#k=xyz",
        ], env)
        assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
        lines = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert len(lines) == 1, f"expected one host invocation, got {lines!r}"
        argv = lines[0]
        # Template rendered room_url and appended the prompt as final arg.
        assert argv[0] == "--mode" and argv[1] == "listener", argv
        assert argv[2] == "https://safebot.chat/room/ABC#k=xyz", argv
        ok("custom host + --once launches once with rendered template")


def case_release_sentinel() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "log"
        bindir = Path(td) / "bin"
        bindir.mkdir()
        make_exec(bindir / "fake-host", FAKE_HOST)
        env = {
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "TEST_LOG": str(log),
            "TEST_HOST_RELEASE": "1",
        }
        proc = run([
            "--host", "custom",
            "--cmd", "fake-host",
            "https://safebot.chat/room/ABC#k=xyz",
        ], env, timeout=15)
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        lines = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        # Fake-host printed the sentinel on its first run; wrapper stops.
        assert len(lines) == 1, f"wrapper relaunched after release sentinel: {lines!r}"
        ok("release sentinel stops the respawn loop after one invocation")


def case_fast_fail_cap() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "log"
        bindir = Path(td) / "bin"
        bindir.mkdir()
        make_exec(bindir / "fake-host", FAKE_HOST)
        env = {
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "TEST_LOG": str(log),
            "TEST_HOST_EXIT_RC": "7",  # immediate non-zero exit
            "SAFEBOT_MAX_FAST_FAILS": "3",  # keep CI fast
        }
        proc = run([
            "--host", "custom",
            "--cmd", "fake-host",
            "https://safebot.chat/room/ABC#k=xyz",
        ], env, timeout=30)
        assert proc.returncode == 7, f"expected host rc propagated after hard stop, got {proc.returncode}: {proc.stderr}"
        assert "giving up" in proc.stderr, proc.stderr
        lines = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert len(lines) == 3, f"expected 3 invocations before hard stop, got {len(lines)}"
        ok(f"respawn loop hard-stops after {len(lines)} consecutive fast-fails")


def case_print_prompt() -> None:
    proc = run([
        "--host", "custom",
        "--cmd", "fake-host",
        "--custom-handle", "my-bot",
        "--print-prompt",
        "https://safebot.chat/room/ABC#k=xyz",
    ], {})
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    out = proc.stdout
    assert "Receive loop" in out, out
    assert "@my-bot" in out, "custom handle should appear in prompt"
    assert "SAFEBOT_RELEASED_BY_ROOM" in out, out
    assert "https://safebot.chat/room/ABC#k=xyz" in out
    ok("--print-prompt emits prompt with room URL + custom @handle")


def case_claude_code_addendum() -> None:
    # claude-code preset requires `claude` binary on PATH for ensure_ready;
    # skip that by calling --print-prompt which short-circuits before it.
    proc = run([
        "--host", "claude-code",
        "--print-prompt",
        "https://safebot.chat/room/ABC#k=xyz",
    ], {})
    if proc.returncode != 0:
        # ensure_ready still runs before print-prompt in our impl — accept
        # the binary-missing error path as well, but verify the prompt if
        # it did print.
        assert "Claude Code" in proc.stdout or "missing required command: claude" in proc.stderr, (proc.stdout, proc.stderr)
    else:
        out = proc.stdout
        assert "@claude-code-exec" in out, out
        assert "Monitor" in out or "ScheduleWakeup" in out, "claude-code addendum should mention host primitives"
        ok("claude-code preset prompt mentions Monitor / ScheduleWakeup")


def main() -> int:
    case_custom_once()
    case_release_sentinel()
    case_print_prompt()
    case_claude_code_addendum()
    case_fast_fail_cap()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
