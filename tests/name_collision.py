"""
Demonstrates sender-name collision: two agents with the same name silently
filter each other's messages as 'self'. Also validates the new default
behaviour (auto-generated name + warning) prevents the trap.
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


def fresh_room():
    room_id = "".join(secrets.choice(ALPHA) for _ in range(6))
    key = secrets.token_bytes(32)
    b = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
    return f"{BASE}/room/{room_id}#k={b}"


def test_collision_broken():
    """Two agents with SAME name drop each other (the bug we want to warn about)."""
    url = fresh_room()
    a = Room(url, name="same")
    b = Room(url, name="same")
    inbox_a = []
    def listen():
        for m in a.stream(include_self=False, auto_reconnect=False):
            if m.text:
                inbox_a.append(m.text)
                if len(inbox_a) >= 2:
                    return
    t = threading.Thread(target=listen, daemon=True)
    t.start()
    time.sleep(0.5)
    b.send("this is bob")
    b.send("but he's called 'same'")
    time.sleep(3)
    # Inbox should be empty because A filters out sender=='same' = own name.
    assert len(inbox_a) == 0, f"collision filter should drop all; got {inbox_a}"
    print("✓ collision reproduced: 2/2 messages dropped by include_self filter")


def test_default_name_avoids_collision():
    """Two agents constructed with default args get unique random names."""
    url = fresh_room()
    a = Room(url)
    b = Room(url)
    assert a.name != b.name, f"default names collided: {a.name} == {b.name}"
    assert a.name.startswith("agent-"), f"unexpected default name: {a.name}"
    print(f"✓ default names are unique: {a.name} vs {b.name}")


if __name__ == "__main__":
    fails = 0
    for fn in (test_collision_broken, test_default_name_avoids_collision):
        try:
            fn()
        except AssertionError as e:
            print(f"✗ {fn.__name__}: {e}")
            fails += 1
    print(f"\n{2 - fails}/2 passed")
    sys.exit(0 if fails == 0 else 1)
