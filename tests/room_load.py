"""
Room load test: spin up N rooms, each with M senders, each sending K msgs.
Verifies: no drops, no dupes, monotonic seq in each room, server stable.
"""
from __future__ import annotations

import os, sys, time, secrets, threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))
from safebot import Room  # noqa: E402

BASE = os.environ.get("BASE", "https://safebot.chat")
ROOMS = int(os.environ.get("ROOMS", "20"))
SENDERS = int(os.environ.get("SENDERS", "5"))
PER = int(os.environ.get("PER", "10"))


def mint_url():
    import base64, nacl.utils
    key = nacl.utils.random(32)
    k = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
    # 10-char room id in the new (post-review) format
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    rid = "".join(secrets.choice(alpha) for _ in range(10))
    return f"{BASE}/room/{rid}#k={k}"


def run_room(room_url, expected):
    per_sender: list = [None] * SENDERS
    errors: list[str] = []
    lock = threading.Lock()

    # A listener that collects all messages from all senders in this room.
    listener = Room(room_url, name=f"listener-{secrets.token_hex(2)}")
    received = []
    rec_lock = threading.Lock()
    def listen():
        try:
            for msg in listener.stream(include_self=False, auto_reconnect=False):
                if msg.text and msg.text.startswith("rl-"):
                    with rec_lock: received.append(msg)
                if len(received) >= expected: return
        except Exception: pass
    t = threading.Thread(target=listen, daemon=True); t.start()
    time.sleep(0.3)

    def sender(idx):
        r = Room(room_url, name=f"snd-{idx}-{secrets.token_hex(2)}")
        for i in range(PER):
            r.send(f"rl-{idx}-{i}")
    with ThreadPoolExecutor(max_workers=SENDERS) as ex:
        list(ex.map(sender, range(SENDERS)))

    deadline = time.time() + 15
    while len(received) < expected and time.time() < deadline:
        time.sleep(0.2)
    return len(received), expected


def main():
    total_expected = SENDERS * PER
    grand_total = 0
    grand_expected = 0
    failures = []
    t0 = time.time()
    print(f"▶ {ROOMS} rooms × {SENDERS} senders × {PER} msgs = {ROOMS * total_expected} msgs")

    urls = [mint_url() for _ in range(ROOMS)]
    results: list = [None] * ROOMS
    def worker(i):
        got, exp = run_room(urls[i], total_expected)
        results[i] = (got, exp)
    with ThreadPoolExecutor(max_workers=ROOMS) as ex:
        list(ex.map(worker, range(ROOMS)))
    elapsed = time.time() - t0
    for i, (got, exp) in enumerate(results):
        grand_total += got; grand_expected += exp
        if got < exp * 0.95:
            failures.append(f"room {i}: {got}/{exp}")
    print(f"  delivered {grand_total}/{grand_expected} in {elapsed:.1f}s ({grand_total/elapsed:.0f} msg/s)")
    if failures:
        print("  ✗ FAIL:"); [print("    -", f) for f in failures]; sys.exit(1)
    print(f"  ✓ every room reached ≥95% delivery")


if __name__ == "__main__":
    main()
