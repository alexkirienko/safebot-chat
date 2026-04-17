"""
Partner process for onboarding test. Joins the given SafeBot.Chat room URL,
waits for any message from the subagent under test, and replies once.
Prints JSON events to stdout for the outer harness.

Usage:  python3 tests/onboarding_partner.py <url> [--reply "text"] [--seconds 120]
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))

from safebot import Room  # noqa: E402


def log(event, **kw):
    kw["event"] = event
    kw["ts"] = time.time()
    print(json.dumps(kw), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--name", default="partner")
    ap.add_argument("--reply", default="Hello back, welcome to SafeBot.Chat. Say something and I'll echo it.")
    ap.add_argument("--seconds", type=float, default=180.0)
    args = ap.parse_args()

    room = Room(args.url, name=args.name)
    log("partner-ready", room_url=args.url, name=args.name)

    # Send an opening line so the agent has context when it joins.
    room.send("Hi, I'm the partner. Please say hello so I know you joined.")
    log("partner-sent", text="hi")

    deadline = time.time() + args.seconds
    seen_senders = set()
    done = threading.Event()

    def listener():
        try:
            for msg in room.stream(include_self=False):
                if done.is_set():
                    return
                log(
                    "partner-heard",
                    sender=msg.sender,
                    text=(msg.text if msg.text is not None else "[undecryptable]"),
                    seq=msg.seq,
                )
                seen_senders.add(msg.sender)
                # Reply once per new sender.
                if msg.sender != args.name:
                    try:
                        room.send(f"Got your message, {msg.sender}: '{(msg.text or '')[:60]}'. {args.reply}")
                        log("partner-sent", to=msg.sender)
                    except Exception as e:
                        log("partner-send-error", err=str(e))
        except Exception as e:
            log("partner-stream-error", err=str(e))

    t = threading.Thread(target=listener, daemon=True)
    t.start()

    while time.time() < deadline and not seen_senders:
        time.sleep(0.2)
    # Stay up a bit longer after first contact so the agent can see our reply.
    tail_until = time.time() + 15
    while time.time() < tail_until:
        time.sleep(0.2)
    done.set()
    log("partner-done", seen=list(seen_senders))


if __name__ == "__main__":
    main()
