#!/usr/bin/env python3
"""Smoke tests for sdk/codex_safebot.py without touching real Codex config."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "sdk" / "codex_safebot.py"


FAKE_CODEX = r"""#!/usr/bin/env python3
import json, os, sys

log = os.environ["TEST_LOG"]
with open(log, "a", encoding="utf-8") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")

args = sys.argv[1:]
if args[:3] == ["mcp", "get", "safebot"]:
    raise SystemExit(0 if os.environ.get("TEST_HAS_MCP") == "1" else 1)
if args[:3] == ["mcp", "remove", "safebot"]:
    raise SystemExit(0)
if args[:3] == ["mcp", "add", "safebot"]:
    raise SystemExit(0)
# In persistent mode the wrapper relaunches us after every exec. Tests can
# stop the loop either by forcing a non-zero exit after N invocations or by
# printing the room-release sentinel that the wrapper watches for.
count_file = os.environ.get("TEST_EXEC_COUNT")
if count_file:
    n = 0
    try: n = int(open(count_file).read())
    except Exception: pass
    n += 1
    open(count_file, "w").write(str(n))
    release_at = int(os.environ.get("TEST_RELEASE_AT", "0") or "0")
    release_sentinel = os.environ.get("TEST_RELEASE_SENTINEL", "")
    if release_at and n >= release_at and release_sentinel:
        print(release_sentinel)
        raise SystemExit(0)
    if n >= int(os.environ.get("TEST_EXEC_MAX", "3")):
        raise SystemExit(42)
raise SystemExit(0)
"""


FAKE_NPX = r"""#!/usr/bin/env python3
import sys
raise SystemExit(0)
"""


def make_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def run_case(argv: list[str], *, has_mcp: bool) -> list[list[str]]:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bindir = tmp / "bin"
        bindir.mkdir()
        log = tmp / "log.jsonl"
        make_exec(bindir / "codex", FAKE_CODEX)
        make_exec(bindir / "npx", FAKE_NPX)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH', '')}"
        env["TEST_LOG"] = str(log)
        env["TEST_HAS_MCP"] = "1" if has_mcp else "0"
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)] + argv,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(proc.returncode)
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def ok(msg: str) -> None:
    print("ok -", msg)


def main() -> int:
    calls = run_case(["--install-only"], has_mcp=False)
    if calls != [["mcp", "get", "safebot"], ["mcp", "add", "safebot", "--", "npx", "-y", "safebot-mcp"]]:
        raise SystemExit(f"unexpected install calls: {calls!r}")
    ok("install-only configures safebot MCP when missing")

    calls = run_case(["--install-only"], has_mcp=True)
    if calls != [["mcp", "get", "safebot"]]:
        raise SystemExit(f"unexpected existing-config calls: {calls!r}")
    ok("install-only leaves existing safebot MCP entry in place")

    calls = run_case(["--once", "https://safebot.chat/room/TEST#k=abc", "--", "-m", "gpt-5.4"], has_mcp=False)
    if calls[:2] != [["mcp", "get", "safebot"], ["mcp", "add", "safebot", "--", "npx", "-y", "safebot-mcp"]]:
        raise SystemExit(f"unexpected launch prelude: {calls!r}")
    launch = calls[2]
    if launch[:2] != ["-m", "gpt-5.4"]:
        raise SystemExit(f"codex args were not forwarded: {launch!r}")
    if (
        "https://safebot.chat/room/TEST#k=abc" not in launch[-1]
        or "claim_task" not in launch[-1]
        or "SAFEBOT_RELEASED_BY_ROOM" not in launch[-1]
        or "operator is clearly dissatisfied" not in launch[-1]
        or "Do NOT send a startup" not in launch[-1]
        or "Reflex turn pattern" not in launch[-1]
        or "Worked example of a correct turn" not in launch[-1]
    ):
        raise SystemExit(f"launch prompt missing room URL / claim_task guidance: {launch[-1]!r}")
    ok("single-shot launch path forwards Codex args and injects the SafeBot prompt")

    # Default wrapper test: fake-codex exits 42 on its 3rd invocation,
    # wrapper should relaunch across those exits (we kill it with a timeout
    # to bound the test in case the wrapper ignores rc).
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bindir = tmp / "bin"; bindir.mkdir()
        log = tmp / "log.jsonl"
        counter = tmp / "count"
        make_exec(bindir / "codex", FAKE_CODEX)
        make_exec(bindir / "npx", FAKE_NPX)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH', '')}"
        env["TEST_LOG"] = str(log)
        env["TEST_HAS_MCP"] = "1"
        env["TEST_EXEC_COUNT"] = str(counter)
        env["TEST_EXEC_MAX"] = "3"
        try:
            subprocess.run(
                [sys.executable, str(SCRIPT), "https://safebot.chat/room/TEST#k=abc"],
                cwd=ROOT, env=env, text=True, capture_output=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            pass  # persistent mode doesn't exit on its own — timeout is expected.
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        launches = [c for c in calls if c and "claim_task" in (c[-1] or "")]
        if len(launches) < 3:
            raise SystemExit(f"default mode should have relaunched at least 3 times, got {len(launches)}: {calls!r}")
        ok(f"default persistent mode relaunches codex exec after each turn ({len(launches)} relaunches observed)")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bindir = tmp / "bin"; bindir.mkdir()
        log = tmp / "log.jsonl"
        counter = tmp / "count"
        make_exec(bindir / "codex", FAKE_CODEX)
        make_exec(bindir / "npx", FAKE_NPX)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH', '')}"
        env["TEST_LOG"] = str(log)
        env["TEST_HAS_MCP"] = "1"
        env["TEST_EXEC_COUNT"] = str(counter)
        env["TEST_RELEASE_AT"] = "2"
        env["TEST_RELEASE_SENTINEL"] = "SAFEBOT_RELEASED_BY_ROOM"
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "https://safebot.chat/room/TEST#k=abc"],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=15,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(proc.returncode)
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        launches = [c for c in calls if c and "claim_task" in (c[-1] or "")]
        if len(launches) != 2:
            raise SystemExit(f"release sentinel should have stopped after 2 launches, got {len(launches)}: {calls!r}")
        ok("release sentinel stops the persistent wrapper without another relaunch")

    # Per-room pidfile lock exercised through the codex_safebot.py shim
    # so the "shared guardrail" claim has direct coverage on both
    # entrypoints, not just agent_safebot.py.
    import secrets
    room = "CODEXLOCK" + secrets.token_hex(3).upper()
    url = f"https://safebot.chat/room/{room}#k=abc"
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bindir = tmp / "bin"; bindir.mkdir()
        log = tmp / "log.jsonl"
        counter = tmp / "count"
        make_exec(bindir / "codex", FAKE_CODEX)
        make_exec(bindir / "npx", FAKE_NPX)
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:{env.get('PATH', '')}"
        env["TEST_LOG"] = str(log)
        env["TEST_HAS_MCP"] = "1"
        env["TEST_EXEC_COUNT"] = str(counter)
        env["TEST_EXEC_MAX"] = "99"  # keep the first launcher relaunching
        first = subprocess.Popen(
            [sys.executable, str(SCRIPT), url],
            cwd=ROOT, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            import time as _t
            deadline = _t.time() + 5
            banner = ""
            while _t.time() < deadline:
                line = first.stderr.readline()
                if not line: _t.sleep(0.05); continue
                banner += line
                if "ONLY listener" in line:
                    break
            if "ONLY listener" not in banner:
                raise SystemExit(f"first codex_safebot did not print ownership banner: {banner!r}")
            second = subprocess.run(
                [sys.executable, str(SCRIPT), "--once", url],
                cwd=ROOT, env=env, text=True, capture_output=True, timeout=10,
            )
            if second.returncode == 0:
                raise SystemExit(f"second codex_safebot should have refused, got rc=0: {second.stderr!r}")
            if "already attached" not in second.stderr:
                raise SystemExit(f"refusal msg missing 'already attached': {second.stderr!r}")
            if str(first.pid) not in second.stderr:
                raise SystemExit(f"refusal msg should carry first pid={first.pid}: {second.stderr!r}")
        finally:
            try: first.terminate(); first.wait(timeout=5)
            except Exception: first.kill()
    ok("codex shim: room-scoped lock refuses a second listener and names the owning pid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
