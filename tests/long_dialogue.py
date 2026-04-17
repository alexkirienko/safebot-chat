"""
Long-dialogue regression test: two agents in a single room exchange 200 turns
(400 messages) without room rotation. Each message MUST be received by its
partner exactly once. Any drop, duplicate, or reorder fails the test.

Exercises:
  - Seq tracking across many messages
  - Replay buffer cap (100) — ensures server eviction doesn't break delivery
    for a subscriber that's keeping up
  - SDK stream() stability over long periods
  - Sender-name collision is avoided (explicit unique names)
"""
from __future__ import annotations

import base64
import os
import secrets
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))

from safebot import Room  # noqa: E402

BASE = os.environ.get("BASE", "https://safebot.chat")
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
TURNS = int(os.environ.get("TURNS", "200"))

room_id = "".join(secrets.choice(ALPHA) for _ in range(6))
key = secrets.token_bytes(32)
b = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
url = f"{BASE}/room/{room_id}#k={b}"
print(f"room: {url}  turns={TURNS}")

A = Room(url, name="alice")
B = Room(url, name="bob")

# Inbox per agent, keyed by sender→list of texts
A_inbox: list[str] = []
B_inbox: list[str] = []


def listener_for(room: Room, inbox: list[str], partner_name: str, want: int) -> None:
    n = 0
    for msg in room.stream(include_self=False, auto_reconnect=True):
        if msg.text is None:
            continue
        if msg.sender != partner_name:
            continue
        inbox.append(msg.text)
        n += 1
        if n >= want:
            return


# Want: alice will receive TURNS messages from bob; bob will receive TURNS messages from alice.
tA = threading.Thread(target=listener_for, args=(A, A_inbox, "bob", TURNS), daemon=True)
tB = threading.Thread(target=listener_for, args=(B, B_inbox, "alice", TURNS), daemon=True)
tA.start()
tB.start()
time.sleep(0.8)

t0 = time.time()
for i in range(TURNS):
    # Alternate who starts each turn so we test both directions equally.
    first, second = (A, B) if i % 2 == 0 else (B, A)
    first_name, second_name = ("alice", "bob") if i % 2 == 0 else ("bob", "alice")
    first.send(f"{first_name}-turn{i:03d}")
    second.send(f"{second_name}-turn{i:03d}")
    # Small interval so both listeners get a realistic cadence but we still
    # test some parallelism (both sends within ~30ms).
    time.sleep(0.05)

elapsed_send = time.time() - t0
print(f"sent {TURNS*2} messages in {elapsed_send:.1f}s ({2*TURNS/elapsed_send:.0f} msg/s)")

# Wait for inboxes to settle.
deadline = time.time() + 30
while time.time() < deadline:
    if len(A_inbox) >= TURNS and len(B_inbox) >= TURNS:
        break
    time.sleep(0.2)

# Analyse.
expected_from_bob = [f"bob-turn{i:03d}" for i in range(TURNS)]
expected_from_alice = [f"alice-turn{i:03d}" for i in range(TURNS)]

def check(inbox: list[str], expected: list[str], label: str) -> int:
    seen = set(inbox)
    dupes = len(inbox) != len(seen)
    missing = set(expected) - seen
    # Order check: expected strings must appear in the same order as they appear in inbox.
    order_errors = 0
    last_idx = -1
    for e in expected:
        if e in seen:
            idx = inbox.index(e)  # first occurrence
            if idx <= last_idx:
                order_errors += 1
            last_idx = idx
    print(f"{label}: got {len(inbox)}/{len(expected)}  missing={len(missing)}  dupes={dupes}  order_errors={order_errors}")
    if missing:
        sample = sorted(missing)[:5]
        print(f"  missing sample: {sample}")
    fail = 0
    if missing: fail += 1
    if dupes: fail += 1
    if order_errors: fail += 1
    return fail

failures = 0
failures += check(A_inbox, expected_from_bob, "alice←bob")
failures += check(B_inbox, expected_from_alice, "bob←alice")

print(f"\n{'PASS' if failures == 0 else 'FAIL'}")
sys.exit(0 if failures == 0 else 1)
