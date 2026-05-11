#!/usr/bin/env python3
"""Read-only status helper for a Bot2Bot room listener.

Shows whether the room listener is alive, what its latest visible
activity was, and which files are most likely being touched right now.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import deque
from pathlib import Path
from urllib.parse import urlparse


def _room_id_from_url(room_url: str) -> str:
    path = urlparse(room_url).path.strip("/").split("/")
    if len(path) >= 2 and path[0] == "room":
        return path[1]
    raise ValueError(f"not a bot2bot room URL: {room_url!r}")


def _run(cmd: list[str], *, cwd: str | None = None) -> str:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.stdout


def _tail_lines(path: Path, max_lines: int) -> list[str]:
    if not path.exists():
        return []
    buf: deque[str] = deque(maxlen=max_lines)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            buf.append(line.rstrip("\n"))
    return list(buf)


def _process_rows(room_id: str, handle: str) -> list[dict[str, str]]:
    out = _run(["ps", "-eo", "pid=,etimes=,pcpu=,pmem=,args="])
    rows: list[dict[str, str]] = []
    self_pid = str(os.getpid())
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) != 5:
            continue
        pid, etimes, pcpu, pmem, args = parts
        if pid == self_pid or "listener_status.py" in args:
            continue
        if room_id not in args:
            continue
        if handle not in args and "codex exec" not in args and "codex_bot2bot.py" not in args:
            continue
        rows.append(
            {
                "pid": pid,
                "etimes": etimes,
                "pcpu": pcpu,
                "pmem": pmem,
                "args": args,
            }
        )
    return rows


def _recent_codex_notes(lines: list[str], limit: int = 3) -> list[str]:
    notes: deque[str] = deque(maxlen=limit)
    for idx, line in enumerate(lines):
        if line.strip() == "codex":
            j = idx + 1
            while j < len(lines):
                text = lines[j].strip()
                if not text:
                    j += 1
                    continue
                if text in {"user", "assistant", "tokens used", "codex"}:
                    break
                if text.startswith("mcp: "):
                    break
                notes.append(text)
                break
    return list(notes)


def _recent_files(lines: list[str], limit: int = 8) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    patterns = [
        re.compile(r"^diff --git a/(.+?) b/(.+)$"),
        re.compile(r"^\+\+\+ b/(.+)$"),
        re.compile(r"^--- a/(.+)$"),
    ]
    for line in reversed(lines):
        text = line.strip()
        for pat in patterns:
            m = pat.match(text)
            if not m:
                continue
            path = m.group(m.lastindex or 1)
            if path in seen or path == "/dev/null":
                continue
            seen.add(path)
            found.append(path)
            break
        if len(found) >= limit:
            break
    return list(reversed(found))


def _git_dirty(cwd: str, limit: int = 12) -> list[str]:
    out = _run(["git", "status", "--short"], cwd=cwd)
    files: list[str] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        files.append(line[3:] if len(line) > 3 else line)
        if len(files) >= limit:
            break
    return files


def _phase(lines: list[str]) -> str:
    recent = "\n".join(lines[-40:])
    if "diff --git " in recent or "@@" in recent:
        return "editing"
    if "ok -" in recent or "npm test" in recent or "pytest" in recent:
        return "testing"
    if "mcp: bot2bot/send_message" in recent:
        return "replying"
    if "mcp: bot2bot/claim_task started" in recent or "mcp: bot2bot/claim_task (completed)" in recent:
        return "waiting"
    return "unknown"


def build_status(room_url: str, *, handle: str, log_path: Path, cwd: str, max_lines: int) -> dict[str, object]:
    room_id = _room_id_from_url(room_url)
    lines = _tail_lines(log_path, max_lines)
    procs = _process_rows(room_id, handle)
    return {
        "room_id": room_id,
        "handle": handle,
        "alive": bool(procs),
        "phase": _phase(lines),
        "processes": procs,
        "recent_notes": _recent_codex_notes(lines),
        "recent_files_from_log": _recent_files(lines),
        "dirty_files": _git_dirty(cwd),
        "log_path": str(log_path),
    }


def _print_text(status: dict[str, object]) -> None:
    print(f"room:   {status['room_id']}")
    print(f"handle: @{status['handle']}")
    print(f"alive:  {'yes' if status['alive'] else 'no'}")
    print(f"phase:  {status['phase']}")
    print("procs:")
    procs = status["processes"]
    if not procs:
        print("  (none)")
    else:
        for proc in procs:
            print(
                f"  pid={proc['pid']} etimes={proc['etimes']}s cpu={proc['pcpu']} mem={proc['pmem']} cmd={proc['args'][:140]}"
            )
    print("notes:")
    notes = status["recent_notes"]
    if not notes:
        print("  (none)")
    else:
        for note in notes:
            print(f"  - {note}")
    print("recent files from log:")
    files = status["recent_files_from_log"]
    if not files:
        print("  (none)")
    else:
        for path in files:
            print(f"  - {path}")
    print("dirty files:")
    dirty = status["dirty_files"]
    if not dirty:
        print("  (clean)")
    else:
        for path in dirty:
            print(f"  - {path}")
    print(f"log:    {status['log_path']}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Show read-only status for a Bot2Bot room listener.")
    p.add_argument("room_url", help="Full Bot2Bot room URL including #k=...")
    p.add_argument("--handle", default="codex-qa-local", help="Listener handle. Default: codex-qa-local")
    p.add_argument("--log", default="/tmp/codex-utawb33bbb-listener.log", help="Listener log path.")
    p.add_argument("--cwd", default=os.getcwd(), help="Repo root for git status. Default: current cwd.")
    p.add_argument("--lines", type=int, default=200, help="How many log lines to inspect. Default: 200")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    status = build_status(
        args.room_url,
        handle=args.handle,
        log_path=Path(args.log),
        cwd=args.cwd,
        max_lines=args.lines,
    )
    if args.json:
        print(json.dumps(status, ensure_ascii=True, indent=2))
    else:
        _print_text(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
