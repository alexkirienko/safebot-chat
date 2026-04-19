"""Regression: WS first-message signed_only must not fail open.

Before the fix, a WS frame with {signed_only:true} but no sender_sig was
silently accepted as a normal message and the room stayed unlocked. The
HTTP path correctly rejected. Now both paths match.
"""
from __future__ import annotations
import base64, json, os, secrets, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
import requests
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
try:
    from websocket import create_connection
except Exception:
    print("SKIP: websocket-client not installed")
    sys.exit(0)

BASE = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")
WS_BASE = BASE.replace("http", "ws")


def run():
    tag = secrets.token_hex(3)
    key = secrets.token_bytes(32)
    rid = "WSSO" + tag.upper()
    url = f"{WS_BASE}/api/rooms/{rid}/ws"
    # First WS message with signed_only:true but no sig -> must error 400.
    box = SecretBox(key)
    nonce = nacl_random(SecretBox.NONCE_SIZE)
    ct = box.encrypt(b"trying to lock without sig", nonce).ciphertext
    frame = {
        "sender": "attacker",
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "signed_only": True,
    }
    ws = create_connection(url, timeout=10)
    # Drain ready/presence preamble.
    preamble_deadline = time.time() + 1.0
    while time.time() < preamble_deadline:
        try:
            ws.settimeout(0.3)
            _ = ws.recv()
        except Exception:
            break
    ws.settimeout(5)
    ws.send(json.dumps(frame))
    got_400 = False
    try:
        for _ in range(5):
            raw = ws.recv()
            data = json.loads(raw)
            if data.get("type") == "error" and data.get("code") == 400:
                got_400 = True
                break
    except Exception:
        pass
    ws.close()
    assert got_400, "WS should 400 when signed_only=true is sent without sender_sig"
    print("  \u2713 WS first-message signed_only=true without sig -> 400")
    # And the room must not be persisted as signed — confirm via status.
    s = requests.get(f"{BASE}/api/rooms/{rid}/status", timeout=5).json()
    # Room may not exist at all (rejected before creation) — both outcomes are fine.
    assert not s.get("signed_only"), s
    print("  \u2713 room did not get locked by the rejected frame")
    print("\n2/2 passed")
    return 0


if __name__ == "__main__":
    sys.exit(run())
