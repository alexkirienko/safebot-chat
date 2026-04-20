"""Reply-to-message wire coverage.

Asserts:
  1. POST with reply_to=<uuid-shape> accepted; transcript echoes it.
  2. reply_to of wrong shape (non-string, non-regex, too short) → 400.
  3. Omitted reply_to is wire-equivalent to absent on the echo.
  4. reply_to points to a server-generated id; the target doesn't need
     to still be in the recent buffer (server is permissive — client
     renders placeholder).
"""
from __future__ import annotations
import base64, os, secrets, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
import requests
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

BASE = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")

passed = 0
def ok(msg: str) -> None:
    global passed
    passed += 1
    print(f"  \u2713 {msg}")

def main() -> int:
    rid = "RPL" + secrets.token_hex(3).upper()
    key = nacl_random(32)
    box = SecretBox(key)

    def post(text: str, **extra):
        nonce = nacl_random(24)
        ct = box.encrypt(text.encode("utf-8"), nonce).ciphertext
        body = {
            "sender": "reply-probe",
            "ciphertext": base64.b64encode(ct).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        body.update(extra)
        return requests.post(f"{BASE}/api/rooms/{rid}/messages", json=body, timeout=10)

    # 1. Post a parent, capture its id, then post a reply referencing it.
    parent = post("parent message")
    assert parent.status_code == 200, (parent.status_code, parent.text)
    parent_id = parent.json().get("id")
    assert parent_id and isinstance(parent_id, str), parent.json()

    child = post("a reply", reply_to=parent_id)
    assert child.status_code == 200, (child.status_code, child.text)
    t = requests.get(f"{BASE}/api/rooms/{rid}/transcript", timeout=10).json()
    msgs = t.get("messages", [])
    ref = [m for m in msgs if m.get("reply_to") == parent_id]
    assert ref, f"reply_to not echoed on transcript: {msgs!r}"
    ok("POST with reply_to=<parent id> is accepted and echoed on transcript")

    # 2. Reject bad shapes.
    r = post("bad1", reply_to=12345)              # not a string
    assert r.status_code == 400, (r.status_code, r.text)
    r = post("bad2", reply_to="a" * 128)          # too long
    assert r.status_code == 400, (r.status_code, r.text)
    r = post("bad3", reply_to="ab")               # too short
    assert r.status_code == 400, (r.status_code, r.text)
    r = post("bad4", reply_to="no spaces $$$")    # bad charset
    assert r.status_code == 400, (r.status_code, r.text)
    ok("invalid reply_to shapes rejected with 400")

    # 3. Omitted reply_to stays absent on the echo.
    plain = post("no reply")
    assert plain.status_code == 200
    t = requests.get(f"{BASE}/api/rooms/{rid}/transcript", timeout=10).json()
    plain_echo = [m for m in t.get("messages", []) if m.get("id") == plain.json()["id"]][0]
    assert "reply_to" not in plain_echo, f"absent reply_to should not appear: {plain_echo!r}"
    ok("omitted reply_to stays absent on the wire")

    # 4. Server accepts a reply pointing at a stranger uuid (no existence
    #    check server-side) — client will render placeholder.
    ghost = "00000000-0000-4000-8000-000000000000"
    r = post("orphan reply", reply_to=ghost)
    assert r.status_code == 200, (r.status_code, r.text)
    t = requests.get(f"{BASE}/api/rooms/{rid}/transcript", timeout=10).json()
    got = [m for m in t.get("messages", []) if m.get("reply_to") == ghost]
    assert got, "server dropped reply_to to a non-existent parent; client placeholder path needs it"
    ok("reply_to to an unknown id is passed through (client renders placeholder)")

    print(f"\n{passed}/4 passed")
    return 0 if passed == 4 else 1

if __name__ == "__main__":
    sys.exit(main())
