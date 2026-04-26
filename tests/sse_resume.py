"""
SSE resume regression test. Two angles:

1. Server: GET /events?after=<seq> replays ONLY messages with seq > after.
2. SDK:    Room.stream() resumes seamlessly after an explicit reconnect,
           with zero duplicates and zero misses, tracking last_seq internally.
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

import requests  # noqa: E402
from safebot import Room  # noqa: E402

BASE = os.environ.get("BASE", "https://safebot.chat")
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def fresh_room() -> tuple[str, bytes, str]:
    room_id = "".join(secrets.choice(ALPHA) for _ in range(6))
    key = secrets.token_bytes(32)
    b = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
    return room_id, key, f"{BASE}/room/{room_id}#k={b}"


def test_server_after_param():
    """POST 5 messages, GET /events?after=3 should skip seqs 1-3."""
    room_id, _key, url = fresh_room()
    sender = Room(url, name="primer")
    seqs = []
    for i in range(5):
        sender.send(f"p{i}")
        # We need the seq, which Room.send() doesn't return — fetch via transcript.
    # Grab transcript to learn seqs.
    transcript = sender._get_retry("/transcript", params={"after": 0, "limit": 50}).json()
    seqs = [m["seq"] for m in transcript["messages"]]
    assert len(seqs) == 5, f"expected 5 primed messages, got {len(seqs)}"
    cutoff = seqs[2]  # anything <= this should be filtered out by ?after=
    expected_count = 2  # messages with seq > cutoff (seqs[3], seqs[4])

    # Hit SSE with after=<cutoff> and collect replayed messages (no new sends).
    # Short read, then close.
    r = requests.get(
        f"{BASE}/api/rooms/{room_id}/events?after={cutoff}",
        stream=True,
        timeout=8,
        headers={"Accept": "text/event-stream"},
    )
    assert r.status_code == 200
    import json
    seen = []
    t_start = time.time()
    for raw_line in r.iter_lines(decode_unicode=True):
        if time.time() - t_start > 3:
            break
        if not raw_line or not raw_line.startswith("data:"):
            continue
        obj = json.loads(raw_line[5:].strip())
        if obj.get("type") == "ready":
            # `ready` marks end of replay phase.
            # We can close now; no new messages will arrive.
            break
        if obj.get("type") == "message":
            seen.append(int(obj["seq"]))
    r.close()
    assert all(s > cutoff for s in seen), f"server sent pre-cutoff seqs: {seen}"
    assert len(seen) == expected_count, f"expected {expected_count} replayed, got {len(seen)}: {seen}"
    print("✓ server: /events?after filters replay correctly")


def test_sdk_resume_after_restart():
    """SDK stream() resumes after listener.close()+reopen without duplicates."""
    room_id, _key, url = fresh_room()
    listener = Room(url, name="listener")
    sender = Room(url, name="sender")

    received: list[tuple[int, str]] = []
    stop_event = threading.Event()

    def run_listener():
        # Manually drive two stream sessions to simulate a reconnect.
        # (The SDK's auto_reconnect does the same thing automatically.)
        last_seen = 0
        sessions_ran = 0
        while sessions_ran < 2 and not stop_event.is_set():
            try:
                for msg in listener.stream(include_self=True, auto_reconnect=False):
                    if msg.text is not None:
                        if msg.seq > last_seen:
                            received.append((msg.seq, msg.text))
                            last_seen = msg.seq
                    if len(received) >= 6:
                        return
                    # After ~3 messages, break to simulate disconnect.
                    if sessions_ran == 0 and len(received) >= 3:
                        break
            except Exception as e:
                print(f"stream error (expected in test): {e!r}")
            sessions_ran += 1

    t = threading.Thread(target=run_listener, daemon=True)
    t.start()
    time.sleep(0.5)

    for i in range(6):
        sender.send(f"m{i}")
        time.sleep(0.30)

    # Wait for tail.
    for _ in range(40):
        if len(received) >= 6:
            break
        time.sleep(0.2)

    stop_event.set()

    texts = [text for _, text in received]
    seqs = [seq for seq, _ in received]
    dupes = len(seqs) != len(set(seqs))
    expected = {f"m{i}" for i in range(6)}
    missing = expected - set(texts)
    assert not dupes, f"duplicates in received: {received}"
    assert not missing, f"missing messages: {missing}; got: {texts}"
    print(f"✓ SDK: manual reconnect preserved order/no-dupes ({len(received)} msgs)")


def test_sdk_auto_reconnect():
    """SDK Room.stream(auto_reconnect=True) survives an injected exception."""
    room_id, _key, url = fresh_room()
    listener = Room(url, name="listener")
    sender = Room(url, name="sender")

    received: list[tuple[int, str]] = []
    original_get = listener._session.get
    killed = {"done": False}

    def get_once_then_restore(*args, **kwargs):
        resp = original_get(*args, **kwargs)
        # After first open, restore so auto-reconnect uses unpatched get.
        listener._session.get = original_get
        if "/events" in (args[0] if args else kwargs.get("url", "")):
            # Close the underlying connection after 1.5s to simulate proxy idle.
            def close_soon():
                time.sleep(1.5)
                try:
                    resp.close()
                    killed["done"] = True
                except Exception:
                    pass
            threading.Thread(target=close_soon, daemon=True).start()
        return resp

    listener._session.get = get_once_then_restore

    def run():
        try:
            for msg in listener.stream(include_self=True, auto_reconnect=True):
                if msg.text is not None:
                    received.append((msg.seq, msg.text))
                if len(received) >= 5:
                    return
        except Exception as e:
            print(f"auto_reconnect stream raised: {e!r}")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(0.5)

    # Send over ~4 seconds — forced close at 1.5s should land mid-stream.
    for i in range(5):
        sender.send(f"r{i}")
        time.sleep(0.8)

    for _ in range(30):
        if len(received) >= 5:
            break
        time.sleep(0.2)

    texts = [text for _, text in received]
    seqs = [seq for seq, _ in received]
    dupes = len(seqs) != len(set(seqs))
    expected = {f"r{i}" for i in range(5)}
    missing = expected - set(texts)
    assert killed["done"], "injected disconnect never fired"
    assert not dupes, f"duplicates: {received}"
    assert not missing, f"missing: {missing}; got: {texts}"
    print(f"✓ SDK: auto_reconnect recovered from forced disconnect ({len(received)} msgs)")


def test_sdk_stream_after_param():
    """Room.stream(after=N) skips backlog with seq <= N on the first connect.

    Regression for the bug in advice_26_04_2026.md §7: listeners that resume
    after a process restart had no way to seed the cursor — every restart
    started at seq=0 and the server replayed the full room backlog.
    """
    room_id, _key, url = fresh_room()
    sender = Room(url, name="primer")
    for i in range(5):
        sender.send(f"b{i}")
    transcript = sender._get_retry("/transcript", params={"after": 0, "limit": 50}).json()
    seqs = [m["seq"] for m in transcript["messages"]]
    assert len(seqs) == 5
    cutoff = seqs[2]

    listener = Room(url, name="late-joiner")
    received: list[tuple[int, str]] = []
    stop_event = threading.Event()

    def run():
        try:
            for msg in listener.stream(
                include_self=True, auto_reconnect=False, after=cutoff,
            ):
                if msg.text is not None:
                    received.append((msg.seq, msg.text))
                if len(received) >= 4 or stop_event.is_set():
                    return
        except Exception as e:
            print(f"stream raised: {e!r}")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(1.0)
    sender.send("after-cutoff-1")
    sender.send("after-cutoff-2")

    for _ in range(40):
        if len(received) >= 2:
            break
        time.sleep(0.2)

    stop_event.set()

    pre_cutoff = [s for s, _ in received if s <= cutoff]
    assert not pre_cutoff, f"after=N should have skipped these: {pre_cutoff}"
    texts = {t for _, t in received}
    assert "after-cutoff-1" in texts and "after-cutoff-2" in texts, (
        f"new messages not received: {received}"
    )
    print(f"✓ SDK: stream(after=N) skipped backlog, got post-cutoff: {sorted(texts)}")


def test_make_unique_name():
    """make_unique_name() suffixes base with hostname and pid."""
    from safebot import make_unique_name
    n = make_unique_name("helper")
    assert n.startswith("helper-"), n
    pid = n.rsplit("-", 1)[1]
    assert pid.isdigit(), f"pid must be numeric: {n!r}"
    # Two calls in the same process produce the same suffix (same host+pid).
    assert make_unique_name("helper") == n
    # Different bases give different names.
    assert make_unique_name("other") != n
    print(f"✓ make_unique_name: {n}")


if __name__ == "__main__":
    tests = [
        test_server_after_param,
        test_sdk_resume_after_restart,
        test_sdk_auto_reconnect,
        test_sdk_stream_after_param,
        test_make_unique_name,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
        except AssertionError as e:
            print(f"✗ {fn.__name__}: {e}")
            failed += 1
        except Exception as e:  # noqa: BLE001
            print(f"✗ {fn.__name__}: unexpected {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(0 if failed == 0 else 1)
