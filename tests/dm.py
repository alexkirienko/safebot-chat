"""
DM primitive smoke test — Phase A.

Covers:
  1. Register two identities (happy path + regex enforcement + collision).
  2. Anonymous DM round-trip (sender sends, recipient opens).
  3. Reply-capable DM round-trip (sender known via from_handle, recipient replies).
  4. Inbox auth: unsigned request = 401; wrong-key sig = 401.
  5. Inbox long-poll wakes within ~100ms of a new DM.
  6. Handle reservation + invalid regex both rejected.
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

import requests
from safebot import Identity, dm

BASE = os.environ.get("BASE", "https://safebot.chat")

results = []
def test(name, fn):
    try:
        fn()
        results.append((name, True, ""))
        print(f"  ✓ {name}")
    except AssertionError as e:
        results.append((name, False, str(e)))
        print(f"  ✗ {name}: {e}")
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"  ✗ {name}: {type(e).__name__}: {e}")


def rand_handle(prefix: str = "test") -> str:
    # 6 lowercase-hex is ample to avoid collisions across test runs.
    return f"{prefix}-{secrets.token_hex(3)}"


def _registered_identity(prefix: str = "agent") -> Identity:
    idn = Identity(rand_handle(prefix), base_url=BASE)
    r = idn.register(bio=f"test {prefix}")
    assert r.get("ok") is True, f"register didn't return ok: {r}"
    return idn


# ---- the tests ------------------------------------------------------------

print(f"▶︎ DM tests against {BASE}")

alice = _registered_identity("alice")
bob = _registered_identity("bob")

def t_collision():
    r = requests.post(f"{BASE}/api/identity/register", json={
        "handle": alice.handle,
        "box_pub": alice.box_pub_b64,
        "sign_pub": alice.sign_pub_b64,
    }, timeout=10)
    assert r.status_code == 409, f"expected 409, got {r.status_code}"
test("handle collision returns 409", t_collision)

def t_bad_regex():
    r = requests.post(f"{BASE}/api/identity/register", json={
        "handle": "-starts-with-dash",
        "box_pub": alice.box_pub_b64,
        "sign_pub": alice.sign_pub_b64,
    }, timeout=10)
    assert r.status_code == 400, f"expected 400, got {r.status_code}"
test("invalid handle regex rejected", t_bad_regex)

def t_reserved():
    r = requests.post(f"{BASE}/api/identity/register", json={
        "handle": "admin",
        "box_pub": alice.box_pub_b64,
        "sign_pub": alice.sign_pub_b64,
    }, timeout=10)
    assert r.status_code == 409, f"expected 409, got {r.status_code}"
test("reserved handle rejected", t_reserved)

def t_lookup():
    r = requests.get(f"{BASE}/api/identity/{alice.handle}", timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert d["handle"] == alice.handle
    assert d["box_pub"] == alice.box_pub_b64
    assert d["sign_pub"] == alice.sign_pub_b64
test("identity lookup returns box+sign pub", t_lookup)

def t_anon_dm():
    msg_id = dm(alice.handle, "hello alice from anon", base_url=BASE)
    assert msg_id, "dm() returned empty id"
    msgs = alice.inbox_wait(after=0, timeout=3)
    assert any(m.text == "hello alice from anon" and m.from_handle is None for m in msgs), \
        f"anon DM not in inbox: {[(m.text, m.from_handle) for m in msgs]}"
test("anonymous DM round-trip", t_anon_dm)

def t_reply_capable_dm():
    dm(alice.handle, "ping from bob", from_identity=bob, base_url=BASE)
    msgs = alice.inbox_wait(after=0, timeout=3)
    hit = next((m for m in msgs if m.text == "ping from bob"), None)
    assert hit is not None, "bob's DM not in alice's inbox"
    assert hit.from_handle == bob.handle, f"from_handle mismatch: {hit.from_handle}"
    alice.reply(hit, "pong from alice")
    time.sleep(0.3)
    bob_msgs = bob.inbox_wait(after=0, timeout=3)
    assert any(m.text == "pong from alice" and m.from_handle == alice.handle for m in bob_msgs), \
        f"alice's reply not in bob's inbox: {[(m.text, m.from_handle) for m in bob_msgs]}"
test("reply-capable DM + reply round-trip", t_reply_capable_dm)

def t_inbox_unauth():
    r = requests.get(f"{BASE}/api/dm/{alice.handle}/inbox/wait?after=0&timeout=1", timeout=5)
    assert r.status_code == 401, f"expected 401, got {r.status_code}"
test("inbox without signature → 401", t_inbox_unauth)

def t_inbox_wrong_sig():
    # Use BOB's sign key to sign a request for ALICE's inbox.
    ts = int(time.time() * 1000)
    from nacl.signing import SigningKey
    bob_sig_sk = bob._sign_sk
    path = f"/api/dm/{alice.handle}/inbox/wait"
    blob = f"GET {path} {ts}".encode()
    sig = bob_sig_sk.sign(blob).signature
    sig_b64 = base64.b64encode(sig).decode("ascii")
    r = requests.get(f"{BASE}{path}?after=0&timeout=1",
                     headers={"Authorization": f"SafeBot ts={ts},sig={sig_b64}"}, timeout=5)
    assert r.status_code == 401, f"expected 401 for wrong-key sig, got {r.status_code}"
test("inbox with wrong-key signature → 401", t_inbox_wrong_sig)

def t_longpoll_wake():
    charlie = _registered_identity("charlie")
    start = time.time()
    result = {"msgs": None, "elapsed_ms": None}
    def poll():
        msgs = charlie.inbox_wait(after=0, timeout=10)
        result["msgs"] = msgs
        result["elapsed_ms"] = int((time.time() - start) * 1000)
    t = threading.Thread(target=poll, daemon=True); t.start()
    time.sleep(0.3)
    dm(charlie.handle, "wakey wakey", base_url=BASE)
    t.join(timeout=12)
    assert result["msgs"] is not None, "long-poll never returned"
    assert len(result["msgs"]) >= 1
    assert result["elapsed_ms"] < 2500, f"wake took {result['elapsed_ms']}ms"
test("long-poll wakes within ~2.5s of new DM", t_longpoll_wake)

def t_ack_removes():
    dm(alice.handle, "to-be-acked", base_url=BASE)
    msgs = alice.inbox_wait(after=0, timeout=3)
    target = next((m for m in msgs if m.text == "to-be-acked"), None)
    assert target is not None
    alice.ack(target)
    time.sleep(0.2)
    after_msgs = alice.inbox_wait(after=0, timeout=1)
    assert not any(m.id == target.id for m in after_msgs), "ack didn't remove the message"
test("ack removes message from inbox", t_ack_removes)

def t_serialise():
    blob = alice.to_bytes()
    restored = Identity.from_bytes(blob, base_url=BASE)
    assert restored.handle == alice.handle
    assert restored.box_pub_b64 == alice.box_pub_b64
    assert restored.sign_pub_b64 == alice.sign_pub_b64
test("Identity.to_bytes / from_bytes round-trip", t_serialise)

failed = [r for r in results if not r[1]]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
if failed:
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    sys.exit(1)
