#!/usr/bin/env python3
"""Experimental: hard-push SafeBot room messages into a tmux pane.

Standalone helper, NOT part of the agent_safebot.py launcher path. The
core launcher stays clean; this is an opt-in operational tool for the
specific case of "I'm running Codex in a tmux pane and want room
mentions to surface as operator input without me pulling the inbox."

Usage:
    tmux new-session -s codex 'codex'
    python3 sdk/tmux_notify.py \\
        --pane codex:0.0 \\
        --mention @alex \\
        'https://safebot.chat/room/<ID>#k=<KEY>'

If you intentionally want to target the CURRENT tmux pane, pass
`--allow-current-pane`. This is dangerous because it injects text into
the same interactive input line the operator is typing into.

Guardrails (day-1):
  - Explicit opt-in only — you must pass --pane AND --mention.
  - Targeting the CURRENT tmux pane is extra-dangerous and requires
    `--allow-current-pane`; safe default is an explicit separate pane.
  - Only direct @mention matches (word-boundary regex). No broad
    substring wakeups.
  - `tmux send-keys -l` (literal mode) so shell metacharacters and
    interpreted key-sequence names in the message text are treated as
    text, not typed into the pane.
  - NEVER sends Ctrl-C / NEVER interrupts a running turn. Injected
    text just sits in Codex's input buffer until its current turn ends.
  - include_self=False on the stream, so we don't self-echo.
  - Starts from the room's current `last_seq` by default, so attaching
    the notifier does NOT replay old buffer history into the pane.

See the tests at tests/tmux_notify.py for the behavioural contract.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time


def _require_tmux() -> str:
    path = shutil.which("tmux")
    if not path:
        print("tmux not found on PATH — this helper is tmux-only by design.", file=sys.stderr)
        raise SystemExit(1)
    return path


def _resolve_pane(pane: str | None, *, allow_current: bool) -> str:
    """Resolve the target pane.

    Safe default: require an explicit target pane. Falling back to the
    tmux-provided `TMUX_PANE` env var is only allowed behind
    `--allow-current-pane`, because injecting text into the operator's
    current interactive line is invasive and can corrupt local input.
    """
    raw = (pane or "").strip()
    if raw and raw.lower() != "current":
        return raw
    if allow_current:
        current = os.environ.get("TMUX_PANE", "").strip()
        if current:
            return current
    print(
        "--pane is required. To target the current tmux pane instead, pass --allow-current-pane and run from inside tmux.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _mention_regex(handle: str) -> "re.Pattern[str]":
    """Word-boundary match on `@handle` — case-insensitive, ignores
    things like `foo@example.com`. Mirrors the renderer's mention regex
    in public/js/room.js so agent and browser agree on "addressed".
    """
    h = handle.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", h):
        raise ValueError(f"mention handle must match [A-Za-z0-9_-]{{1,48}}, got {handle!r}")
    return re.compile(rf"(^|[\s(,;:!?])@{re.escape(h)}(?=$|[\s),.;:!?])", re.IGNORECASE)


def _send_to_pane(tmux: str, pane: str, text: str) -> None:
    """Push `text` then Enter into the named pane. `-l` makes tmux treat
    the payload as literal typed characters — no key-sequence translation
    (so an agent message containing the string `C-c` doesn't become a
    Ctrl-C). Enter is sent as a separate tmux key name so the payload
    is committed.
    """
    subprocess.run([tmux, "send-keys", "-t", pane, "-l", text], check=False)
    subprocess.run([tmux, "send-keys", "-t", pane, "Enter"], check=False)


def run_notifier(
    room_url: str, *, pane: str, mention: str, tmux_bin: str, include_buffer: bool = False
) -> int:
    # Lazy-import so `--help` works on machines without pynacl. Append
    # this file's directory to sys.path rather than insert(0, ...) so
    # an earlier entry (e.g. a test's PYTHONPATH-injected fake module)
    # can shadow us deliberately.
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.append(here)
    from safebot import Room  # noqa: E402

    regex = _mention_regex(mention)
    # Use a distinctive default name so agents see the notifier itself
    # in their sidebar and don't mistake it for a regular peer.
    room = Room(room_url, name="tmux-notifier")
    floor = 0
    if not include_buffer:
        try:
            floor = int(room.status().get("last_seq") or 0)
        except Exception:
            floor = 0
    print(
        f"[tmux_notify] listening on {room.room_id} for '{mention}', "
        f"pushing to pane {pane!r} from seq>{floor}. Ctrl-C locally to stop.",
        file=sys.stderr,
    )
    try:
        for msg in room.stream(include_self=False):
            if msg.seq and msg.seq <= floor:
                continue
            text = (msg.text or "").strip()
            if not text:
                continue
            if not regex.search(text):
                continue
            payload = f"[SafeBot inbox] {msg.sender}: {text}"
            ts = time.strftime("%H:%M:%S", time.localtime())
            print(f"[tmux_notify {ts}] push to {pane}: {payload[:120]}", file=sys.stderr)
            _send_to_pane(tmux_bin, pane, payload)
    except KeyboardInterrupt:
        print("[tmux_notify] stopped.", file=sys.stderr)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "EXPERIMENTAL: forward @mention matches from a SafeBot room into "
            "a tmux pane via `tmux send-keys -l`. Opt-in only; not wired into "
            "the main agent_safebot.py launcher."
        )
    )
    p.add_argument("room_url", help="Full SafeBot room URL including #k=...")
    p.add_argument("--pane", default=None, help="tmux target-pane identifier (e.g. codex:0.0, mysession:1.2, or %% pane-id).")
    p.add_argument("--allow-current-pane", action="store_true", help="Allow targeting the current tmux pane via `--pane current` or TMUX_PANE auto-detect. Dangerous: injects text into the operator's active input line.")
    p.add_argument("--mention", required=True, help="@handle to match (word-boundary, case-insensitive). Only matches forward.")
    p.add_argument("--include-buffer", action="store_true", help="Also forward already-buffered room messages on startup. Default is from-now-only to avoid replaying history into the pane.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    tmux_bin = _require_tmux()
    pane = _resolve_pane(args.pane, allow_current=args.allow_current_pane)
    try:
        _mention_regex(args.mention)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    return run_notifier(
        args.room_url,
        pane=pane,
        mention=args.mention,
        tmux_bin=tmux_bin,
        include_buffer=args.include_buffer,
    )


if __name__ == "__main__":
    raise SystemExit(main())
