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
    assert "Do NOT send a startup" in out, out
    ok("--print-prompt emits prompt with room URL + custom @handle")


def case_claude_code_addendum() -> None:
    # --print-prompt MUST be side-effect-free (no ensure_ready, no MCP
    # probe). Run on an empty PATH so that if ensure_ready leaked in,
    # the `claude` binary lookup would fail the test loudly.
    proc = run([
        "--host", "claude-code",
        "--print-prompt",
        "https://safebot.chat/room/ABC#k=xyz",
    ], {"PATH": "/nonexistent"})
    assert proc.returncode == 0, f"--print-prompt must not invoke ensure_ready, got rc={proc.returncode}: {proc.stderr}"
    out = proc.stdout
    assert "@claude-code-exec" in out, out
    assert "Monitor" in out or "ScheduleWakeup" in out, "claude-code addendum should mention host primitives"
    ok("claude-code preset --print-prompt is side-effect-free and mentions Monitor / ScheduleWakeup")


def case_custom_sentinel_honoured() -> None:
    # Regression: CustomAdapter was hard-coding DEFAULT_RELEASE_SENTINEL in
    # its template substitution, while the wrapper listened for
    # args.release_sentinel — so the two disagreed on the sentinel string.
    # Verify that a custom sentinel piped through via --release-sentinel
    # round-trips into the template AND stops the respawn loop.
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "log"
        bindir = Path(td) / "bin"
        bindir.mkdir()
        # Fake host: echoes its --marker arg on stdout then exits 0.
        echo = bindir / "echo-host"
        echo.write_text(
            "#!/usr/bin/env python3\n"
            "import sys, json, os\n"
            "open(os.environ['TEST_LOG'],'a').write(json.dumps(sys.argv[1:])+'\\n')\n"
            "for a in sys.argv[1:]:\n"
            "    if a.startswith('marker='):\n"
            "        print(a.split('=',1)[1]); break\n",
            encoding="utf-8",
        )
        echo.chmod(echo.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        env = {
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "TEST_LOG": str(log),
        }
        proc = run([
            "--host", "custom",
            "--cmd", "echo-host marker={release_sentinel}",
            "--release-sentinel", "CUSTOM_STOP_42",
            "https://safebot.chat/room/ABC#k=xyz",
        ], env, timeout=15)
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        assert "CUSTOM_STOP_42" in proc.stdout, proc.stdout
        lines = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        # Exactly one invocation: sentinel observed → wrapper stops.
        assert len(lines) == 1, f"wrapper did not stop on custom sentinel: {lines!r}"
        assert any(a == "marker=CUSTOM_STOP_42" for a in lines[0]), f"template did not substitute custom sentinel: {lines[0]!r}"
        ok("custom --release-sentinel round-trips through template AND stops respawn loop")


def main() -> int:
    case_custom_once()
    case_release_sentinel()
    case_custom_sentinel_honoured()
    case_print_prompt()
    case_claude_code_addendum()
    case_fast_fail_cap()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
