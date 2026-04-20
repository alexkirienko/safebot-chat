#!/usr/bin/env python3
"""Unit coverage for sdk/tmux_notify.py — the experimental tmux push bridge.

Doesn't touch tmux for real. Instead:
  - replaces the tmux binary with a fake Python script on PATH that
    logs every argv to a file
  - imports run_notifier but fakes the Room.stream() iterator so we can
    inject specific messages and assert what gets pushed to tmux

Covers the four behavioural guardrails codex-qa asked for:
  1. only direct @mention matches are pushed; substring/token-adjacent
     hits are skipped
  2. `send-keys -l` is used for the payload (literal mode, no key-name
     translation) — so a message containing 'C-c' does not become Ctrl-C
  3. Enter is sent as a separate send-keys call (payload commit)
  4. shell-specials / quotes in the message do not alter the argv
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "sdk"


def make_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def ok(msg: str) -> None:
    print("ok -", msg)


FAKE_MSGS = [
    # Not a mention — skipped.
    {"sender": "alice", "text": "hello everyone", "id": "1", "seq": 1, "ts": 0, "sender_verified": False},
    # A lookalike (email) — skipped. Word-boundary regex guards this.
    {"sender": "bob",   "text": "email me at alex@example.com please", "id": "2", "seq": 2, "ts": 0, "sender_verified": False},
    # Distinctly-different handle — skipped.
    {"sender": "carol", "text": "@alexis ping", "id": "3", "seq": 3, "ts": 0, "sender_verified": False},
    # Real direct mention — pushed.
    {"sender": "dave",  "text": "@alex status on PR? C-c should NOT interrupt", "id": "4", "seq": 4, "ts": 0, "sender_verified": False},
    # Special chars + quotes in payload — pushed literally.
    {"sender": "eve",   "text": "@alex `rm -rf /` and $(echo pwned) are just text", "id": "5", "seq": 5, "ts": 0, "sender_verified": False},
]


def _build_fake_room_module(tmpdir: Path) -> Path:
    """Create a minimal safebot.py shim that replaces Room.stream() with
    a canned iterator of FAKE_MSGS. We copy the real module and append
    an override — less fragile than monkey-patching inside tmux_notify.
    """
    fake = tmpdir / "safebot.py"
    fake.write_text(textwrap.dedent("""
        class _M:
            def __init__(self, d):
                self.sender = d['sender']; self.text = d['text']
                self.id = d['id']; self.seq = d['seq']
                self.ts = d.get('ts', 0)
                self.sender_verified = d.get('sender_verified', False)
        class Room:
            def __init__(self, url, name=None, **kw):
                self.room_id = "FAKE"
                self.name = name or "agent"
            def stream(self, include_self=False):
                import os, json
                msgs = json.loads(os.environ['FAKE_STREAM_JSON'])
                for m in msgs:
                    yield _M(m)
    """), encoding="utf-8")
    return fake


def run_with_fake_tmux(test_dir: Path, argv: list[str], extra_env: dict) -> tuple[int, str, str, list[list[str]]]:
    log = test_dir / "tmux.log"
    bindir = test_dir / "bin"
    bindir.mkdir()
    # Fake tmux: records argv as JSON, always rc=0.
    make_exec(bindir / "tmux", textwrap.dedent("""\
        #!/usr/bin/env python3
        import json, os, sys
        with open(os.environ['TMUX_LOG'], 'a', encoding='utf-8') as f:
            f.write(json.dumps(sys.argv[1:]) + '\\n')
        raise SystemExit(0)
    """))
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["TMUX_LOG"] = str(log)
    env.update(extra_env)
    # Copy tmux_notify.py into a staging dir alongside the fake
    # safebot.py. Running the script from that dir makes sys.path[0]
    # (= script dir) contain the fake module, which is the only way to
    # reliably shadow the real sdk/safebot.py whose import path would
    # otherwise dominate — Python inserts the script's dir at path[0]
    # before PYTHONPATH is consulted.
    staging = test_dir / "staging"
    staging.mkdir()
    _build_fake_room_module(staging)
    import shutil as _sh
    _sh.copy2(SCRIPT_DIR / "tmux_notify.py", staging / "tmux_notify.py")
    proc = subprocess.run(
        [sys.executable, str(staging / "tmux_notify.py")] + argv,
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=15,
    )
    lines = [__import__("json").loads(l) for l in log.read_text().splitlines() if l.strip()] if log.exists() else []
    return proc.returncode, proc.stdout, proc.stderr, lines


def case_only_direct_mentions() -> None:
    import json
    with tempfile.TemporaryDirectory() as td:
        rc, _out, err, calls = run_with_fake_tmux(
            Path(td),
            ["--pane", "codex:0.0", "--mention", "@alex",
             "https://safebot.chat/room/FAKE#k=" + "a" * 43],
            {"FAKE_STREAM_JSON": json.dumps(FAKE_MSGS)},
        )
        assert rc == 0, (rc, err)
        # Two pushed messages → 2 `send-keys -l <payload>` + 2 `send-keys Enter` = 4 calls.
        assert len(calls) == 4, f"expected 4 tmux calls (2 msgs x payload+Enter), got {len(calls)}: {calls!r}"
        push_calls = [c for c in calls if "-l" in c]
        enter_calls = [c for c in calls if c[-1] == "Enter"]
        assert len(push_calls) == 2 and len(enter_calls) == 2, calls
        # Check each pushed payload corresponds to an actual @alex-mention msg.
        pushed_texts = [c[-1] for c in push_calls]
        assert any("@alex status" in t for t in pushed_texts), pushed_texts
        assert any("@alex `rm -rf /`" in t for t in pushed_texts), pushed_texts
        assert all("@alexis" not in t for t in pushed_texts), "bogus @alexis match pushed"
        assert all("alex@example.com" not in t for t in pushed_texts), "email-lookalike pushed"
    ok("only direct @mention matches push; lookalikes are skipped")


def case_literal_mode_and_enter_commit() -> None:
    import json
    with tempfile.TemporaryDirectory() as td:
        rc, _out, err, calls = run_with_fake_tmux(
            Path(td),
            ["--pane", "codex:0.0", "--mention", "@alex",
             "https://safebot.chat/room/FAKE#k=" + "a" * 43],
            {"FAKE_STREAM_JSON": json.dumps(FAKE_MSGS)},
        )
        assert rc == 0, (rc, err)
        # Each payload uses `-l` (literal) so `C-c` / `$(...)` aren't
        # interpreted by tmux key-name translation.
        for c in calls:
            if "-l" in c:
                idx = c.index("-l")
                # -l must be followed by the payload string.
                assert idx + 1 < len(c), f"no payload after -l: {c!r}"
                payload = c[idx + 1]
                # Payload is a single argv element — shell-specials stay intact.
                assert "[SafeBot inbox]" in payload
        # Enter is a SEPARATE send-keys call (i.e. not inside the literal
        # block), so tmux actually commits the line.
        enter_calls = [c for c in calls if c[-1] == "Enter"]
        assert len(enter_calls) == 2, calls
        for c in enter_calls:
            # Enter calls MUST NOT carry -l (otherwise tmux would type the
            # string "Enter" literally instead of pressing Enter).
            assert "-l" not in c, f"Enter call should not use literal mode: {c!r}"
    ok("payload uses `-l` literal mode; Enter is a separate non-literal send-keys call")


def case_never_interrupts_never_ctrl_c() -> None:
    import json
    with tempfile.TemporaryDirectory() as td:
        rc, _out, err, calls = run_with_fake_tmux(
            Path(td),
            ["--pane", "codex:0.0", "--mention", "@alex",
             "https://safebot.chat/room/FAKE#k=" + "a" * 43],
            {"FAKE_STREAM_JSON": json.dumps(FAKE_MSGS)},
        )
        assert rc == 0, (rc, err)
        # No call ever sends C-c / Ctrl-C / SIGINT-like key-name (that
        # would be `tmux send-keys C-c` without -l).
        for c in calls:
            # Any `C-c` etc. must only appear INSIDE a `-l` literal payload.
            if "-l" in c:
                continue
            joined = " ".join(c)
            for bad in ("C-c", "C-\\", "C-d", "IC", "Escape"):
                assert bad not in c, f"tmux call carries interpreted control key {bad!r}: {c!r}"
    ok("notifier never sends C-c / interpreted control keys as tmux keys")


def main() -> int:
    case_only_direct_mentions()
    case_literal_mode_and_enter_commit()
    case_never_interrupts_never_ctrl_c()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
