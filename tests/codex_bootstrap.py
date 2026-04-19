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
# In --forever mode the wrapper relaunches us after every exec; stop the
# loop after N invocations by refusing to exit 0 the N+1'th time.
count_file = os.environ.get("TEST_EXEC_COUNT")
if count_file:
    n = 0
    try: n = int(open(count_file).read())
    except Exception: pass
    n += 1
    open(count_file, "w").write(str(n))
    if n >= int(os.environ.get("TEST_EXEC_MAX", "3")):
        # Signal the wrapper to stop by writing a sentinel the test reads after.
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

    calls = run_case(["https://safebot.chat/room/TEST#k=abc", "--", "-m", "gpt-5.4"], has_mcp=False)
    if calls[:2] != [["mcp", "get", "safebot"], ["mcp", "add", "safebot", "--", "npx", "-y", "safebot-mcp"]]:
        raise SystemExit(f"unexpected launch prelude: {calls!r}")
    launch = calls[2]
    if launch[:2] != ["-m", "gpt-5.4"]:
        raise SystemExit(f"codex args were not forwarded: {launch!r}")
    if "https://safebot.chat/room/TEST#k=abc" not in launch[-1] or "claim_task" not in launch[-1]:
        raise SystemExit(f"launch prompt missing room URL / claim_task guidance: {launch[-1]!r}")
    ok("launch path forwards Codex args and injects the SafeBot prompt")

    # --forever wrapper test: fake-codex exits 42 on its 3rd invocation,
    # wrapper should observe the non-zero rc and stop after that (we kill it
    # with a timeout to bound the test in case the wrapper ignores rc).
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
            # --forever must come BEFORE the positional room_url, because
            # codex_args is argparse.REMAINDER and greedily swallows any later
            # flag. Document the pitfall in the help text too.
            subprocess.run(
                [sys.executable, str(SCRIPT), "--forever", "https://safebot.chat/room/TEST#k=abc"],
                cwd=ROOT, env=env, text=True, capture_output=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            pass  # forever mode doesn't exit on its own — timeout is expected.
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        launches = [c for c in calls if c and "claim_task" in (c[-1] or "")]
        if len(launches) < 3:
            raise SystemExit(f"--forever should have relaunched at least 3 times, got {len(launches)}: {calls!r}")
        ok(f"--forever relaunches codex exec after each turn ({len(launches)} relaunches observed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
