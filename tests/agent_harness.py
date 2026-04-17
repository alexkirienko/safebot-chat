"""
Agent conversational-turn harness.

One invocation = one "turn" in a SafeBot.Chat room:
  1. (optional) send a message as --name
  2. listen for --seconds, printing anything we hear from other senders
  3. exit cleanly so the caller (the agent's Claude brain) can decide what to say next

Usage:
    python3 tests/agent_harness.py <full-room-url> --name NAME \\
        [--say "your message"] [--seconds 8]
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time

# Let the harness be run from anywhere — pull the SDK in.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))

from safebot import Room  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="full SafeBot.Chat room URL (with #k=...)")
    ap.add_argument("--name", required=True, help="sender label")
    ap.add_argument("--say", default=None, help="message to post before listening")
    ap.add_argument("--seconds", type=float, default=8.0, help="listen window")
    ap.add_argument("--self", action="store_true", help="include own messages when listening")
    args = ap.parse_args()

    room = Room(args.url, name=args.name)

    if args.say:
        room.send(args.say)
        print(f"[SENT] {args.name}: {args.say}", flush=True)

    heard = []
    done = threading.Event()

    def listener() -> None:
        try:
            for msg in room.stream(include_self=args.self):
                if done.is_set():
                    return
                text = msg.text if msg.text is not None else "[undecryptable]"
                line = f"[HEARD] {msg.sender}: {text}"
                heard.append(line)
                print(line, flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[stream error] {e}", flush=True)

    t = threading.Thread(target=listener, daemon=True)
    t.start()

    time.sleep(max(0.5, args.seconds))
    done.set()

    if not heard:
        print("[silence] no messages heard in window.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
