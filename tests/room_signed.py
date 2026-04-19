"""Signed-sender room mode tests.

Covers:
- unsigned post to signed-only room → 403
- signed post → 200, sender stamped as @handle, verified=True
- bad sig → 401
- replayed sender_nonce → 401
- skewed ts → 401
- unknown sender_handle → 401
- client-supplied `sender` label ignored in favour of @handle
- unsigned room (no signed_only flag) still works with legacy POSTs
"""
from __future__ import annotations
import base64, hashlib, os, secrets, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
import requests
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from safebot import Identity  # type: ignore

BASE = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")


def _post(room_id: str, body: dict, expect: int):
    r = requests.post(f"{BASE}/api/rooms/{room_id}/messages", json=body, timeout=10)
    assert r.status_code == expect, f"expected {expect}, got {r.status_code}: {r.text}"
    return r


def _sign_body(ident: Identity, room_id: str, ct_b64: str, *, ts_ms=None, nonce=None):
    ts_ms = ts_ms or int(time.time() * 1000)
    nonce = nonce or secrets.token_urlsafe(18)
    ct_hash = hashlib.sha256(ct_b64.encode("ascii")).hexdigest()
    blob = f"room-msg {room_id} {ts_ms} {nonce} {ct_hash}".encode("utf-8")
    sig = ident._sign_sk.sign(blob).signature
    return {
        "sender_handle": ident.handle,
        "sender_ts": ts_ms,
        "sender_nonce": nonce,
        "sender_sig": base64.b64encode(sig).decode("ascii"),
    }


def _encrypt(key: bytes, text: str):
    box = SecretBox(key)
    nonce = nacl_random(SecretBox.NONCE_SIZE)
    ct = box.encrypt(text.encode(), nonce).ciphertext
    return base64.b64encode(ct).decode("ascii"), base64.b64encode(nonce).decode("ascii")


def run():
    # Use unique handle per run to avoid collisions on live service.
    tag = secrets.token_hex(3)
    handle = f"testsig{tag}"
    ident = Identity(handle, base_url=BASE)
    ident.register()
    key = secrets.token_bytes(32)
    room = "SIG" + tag.upper() + secrets.token_hex(1).upper()

    passed = 0
    def ok(msg):
        nonlocal passed; passed += 1; print(f"  \u2713 {msg}")

    # 1. First signed POST with signed_only=True opens the room in locked mode.
    ct, nc = _encrypt(key, "hello signed")
    body = {"sender": "ignored-label", "ciphertext": ct, "nonce": nc,
            "signed_only": True, **_sign_body(ident, room, ct)}
    r = _post(room, body, 200)
    ok("first signed post with signed_only=True -> 200")

    # 2. Status shows signed_only=true.
    s = requests.get(f"{BASE}/api/rooms/{room}/status", timeout=5).json()
    assert s.get("signed_only") is True, s
    ok("/status reports signed_only=true")

    # 3. Unsigned follow-up -> 403.
    ct, nc = _encrypt(key, "should fail")
    _post(room, {"sender": "anyone", "ciphertext": ct, "nonce": nc}, 403)
    ok("unsigned POST to signed-only room -> 403")

    # 4. Signed follow-up succeeds and sender is stamped as @handle.
    ct, nc = _encrypt(key, "hello 2")
    body = {"sender": "spoof", "ciphertext": ct, "nonce": nc, **_sign_body(ident, room, ct)}
    _post(room, body, 200)
    tr = requests.get(f"{BASE}/api/rooms/{room}/transcript", timeout=5).json()
    last = tr["messages"][-1]
    assert last["sender"] == f"@{handle}", last
    assert last.get("sender_verified") is True, last
    ok("signed POST stamps sender=@handle (ignores spoof label) with sender_verified=true")

    # 5. Bad sig -> 401.
    ct, nc = _encrypt(key, "tamper")
    sigbody = _sign_body(ident, room, ct)
    bad = dict(sigbody); bad["sender_sig"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    _post(room, {"ciphertext": ct, "nonce": nc, **bad}, 401)
    ok("bad sender_sig -> 401")

    # 6. Replayed nonce -> 401.
    ct, nc = _encrypt(key, "replay")
    sigbody = _sign_body(ident, room, ct)
    _post(room, {"ciphertext": ct, "nonce": nc, **sigbody}, 200)
    # Replay the exact same sig/nonce — nonce cache hit.
    ct2, nc2 = _encrypt(key, "replay 2")
    _post(room, {"ciphertext": ct2, "nonce": nc2, **sigbody}, 401)
    ok("replayed sender_nonce -> 401")

    # 7. Stale ts -> 401 (600s in the past).
    ct, nc = _encrypt(key, "stale")
    stale = _sign_body(ident, room, ct, ts_ms=int(time.time() * 1000) - 600_000)
    _post(room, {"ciphertext": ct, "nonce": nc, **stale}, 401)
    ok("stale sender_ts -> 401")

    # 8. Unknown handle -> 401.
    ct, nc = _encrypt(key, "ghost")
    ghost = _sign_body(ident, room, ct)
    ghost["sender_handle"] = "nonexistenthandle" + tag
    _post(room, {"ciphertext": ct, "nonce": nc, **ghost}, 401)
    ok("unknown sender_handle -> 401")

    # 9. Legacy room (no signed_only) still works with plain POSTs.
    legacy = "LEG" + tag.upper()
    ct, nc = _encrypt(key, "legacy")
    _post(legacy, {"sender": "plain", "ciphertext": ct, "nonce": nc}, 200)
    tr = requests.get(f"{BASE}/api/rooms/{legacy}/status", timeout=5).json()
    assert tr.get("signed_only") is False, tr
    ok("legacy room (no signed_only flag) works unsigned, status shows signed_only=false")

    print(f"\n{passed}/9 passed")
    return 0 if passed == 9 else 1


if __name__ == "__main__":
    sys.exit(run())
