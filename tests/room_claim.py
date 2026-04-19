"""Room /claim + /ack cursor tests.

Walks a two-agent conversation through the server-side cursor:
- Bob sends 3 messages; Alice claims, acks, cursor advances each step.
- Claim idempotency: re-calling with no ack returns the same envelope.
- Ack with wrong claim_id -> 409; with seq <= cursor -> idempotent ok.
- Claim on fresh cursor with no new messages -> empty after short timeout.
- Sender != receiver filter: Alice's own messages are skipped.
- Expired claim: after CLAIM_TTL_MS (>60s), reclaim yields same message
  with a new claim_id (not tested here — too slow for CI; covered by
  unit inspection of the spec).
- Ack-before-return wrapper (next_task) with a failing on_claim leaves
  the message re-claimable.
"""
from __future__ import annotations
import base64, os, secrets, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
import requests
from safebot import Room, Identity  # type: ignore

BASE = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")


def run():
    tag = secrets.token_hex(3)
    alice = Identity(f"alice{tag}", base_url=BASE); alice.register()
    bob = Identity(f"bob{tag}", base_url=BASE); bob.register()
    key = secrets.token_bytes(32)
    kb = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
    rid = "CLM" + tag.upper()
    url = f"{BASE}/room/{rid}#k={kb}"

    # Bob posts plain (no signed_only), Alice claims.
    # Use identity handle as sender label so claim's own-message filter
    # recognises them. In signed-sender rooms the server stamps `@handle`
    # authoritatively; in plain rooms the client is responsible for label
    # consistency.
    bob_room = Room(url, name=bob.handle)
    alice_room = Room(url, name=alice.handle)
    bob_room.send("one")
    bob_room.send("two")
    bob_room.send("three")
    time.sleep(0.2)

    passed = 0
    def ok(msg):
        nonlocal passed; passed += 1; print(f"  \u2713 {msg}")

    # 1. First claim returns the oldest foreign message.
    c1 = alice_room.claim(alice, timeout=5)
    assert c1 is not None and c1["message"].text == "one", c1
    ok("first claim returns oldest foreign message 'one'")

    # 2. Idempotent re-claim returns the SAME envelope + claim_id.
    c1b = alice_room.claim(alice, timeout=5)
    assert c1b["claim_id"] == c1["claim_id"], (c1, c1b)
    assert c1b["message"].seq == c1["message"].seq
    ok("idempotent re-claim returns same claim_id/seq")

    # 3. Ack with wrong claim_id -> 409.
    r = alice_room._auth_post_signed(alice, "/ack",
        {"handle": alice.handle, "claim_id": "00000000-0000-0000-0000-000000000000", "seq": c1["message"].seq},
        5)
    assert r.status_code == 409, r.status_code
    ok("ack with wrong claim_id -> 409")

    # 4. Valid ack advances cursor.
    ack = alice_room.ack_claim(alice, c1["claim_id"], c1["message"].seq)
    assert ack["advanced"] is True and ack["cursor"] == c1["message"].seq, ack
    ok("valid ack -> advanced=true, cursor=seq")

    # 5. Re-ack is idempotent (seq <= cursor).
    ack2 = alice_room.ack_claim(alice, c1["claim_id"], c1["message"].seq)
    assert ack2["advanced"] is False, ack2
    ok("re-ack with seq<=cursor -> advanced=false (idempotent)")

    # 6. Next claim returns 'two'.
    c2 = alice_room.claim(alice, timeout=5)
    assert c2["message"].text == "two", c2["message"].text
    alice_room.ack_claim(alice, c2["claim_id"], c2["message"].seq)
    ok("next claim returns 'two', ack ok")

    # 7. next_task wrapper returns 'three' and advances.
    m3 = alice_room.next_task(alice, timeout=5)
    assert m3 is not None and m3.text == "three", m3
    ok("next_task wrapper returns 'three' and advances cursor")

    # 8. next_task with failing on_claim leaves message re-claimable.
    bob_room.send("four")
    time.sleep(0.2)
    def boom(_m):
        return False  # refuse to ack
    m_none = alice_room.next_task(alice, timeout=5, on_claim=boom)
    assert m_none is None, m_none
    # Same message should be re-claimable.
    c_again = alice_room.claim(alice, timeout=5)
    assert c_again["message"].text == "four", c_again
    alice_room.ack_claim(alice, c_again["claim_id"], c_again["message"].seq)
    ok("next_task with failing on_claim leaves message re-claimable")

    # 9. Alice's own messages are skipped.
    alice_room.send("mine — should not claim")
    time.sleep(0.2)
    c_empty = alice_room.claim(alice, timeout=2)
    assert c_empty is None, c_empty
    ok("claim skips own messages -> None on 2s timeout")

    print(f"\n{passed}/9 passed")
    return 0 if passed == 9 else 1


if __name__ == "__main__":
    sys.exit(run())
