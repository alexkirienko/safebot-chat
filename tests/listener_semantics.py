"""E2E smoke for the four listener-loop acceptance behaviours.

Each behaviour gets one assertion against a live server. This duplicates
pieces of room_claim.py / mcp smoke on purpose — the value here is that
all four bars are in one file that a reviewer can read top-to-bottom to
understand what "correct listener" means.

Matches the /docs#listener-semantics documentation. If a new behaviour is
added to that section, add an assertion here.
"""
from __future__ import annotations
import base64, os, secrets, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
import requests
from safebot import Room, Identity  # type: ignore

BASE = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")


def run():
    passed = 0
    def ok(msg):
        nonlocal passed; passed += 1; print(f"  \u2713 {msg}")

    tag = secrets.token_hex(3)
    ident = Identity(f"listener{tag}", base_url=BASE); ident.register()
    key = secrets.token_bytes(32)
    kb = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
    rid = "LS" + tag.upper()
    url = f"{BASE}/room/{rid}#k={kb}"

    # --- Behaviour 1: Self-echo is filtered out -----------------------------
    # Room posts under an ALIAS that's not identity.handle. The SDK passes
    # Room.name into claim's exclude_senders so the same post doesn't come
    # back. MCP-side equivalent lives in mcp/test/smoke.js — here we verify
    # the SDK slice of the same guarantee.
    r_self = Room(url, name="alias-listener", identity=ident)
    r_self.send("self-echo probe, should be filtered")
    time.sleep(0.2)
    c = r_self.claim(ident, timeout=2)
    assert c is None, f"self-echo leaked through claim: {c!r}"
    ok("self-echo under an alias is filtered out by claim")

    # --- Behaviour 2: Missing ack yields re-delivery ------------------------
    # A foreign agent posts a message. We claim it but DON'T ack. After the
    # server claim TTL expires (60 s in prod) the same seq re-delivers with
    # a fresh claim_id. To keep this suite fast we verify the re-claim by
    # triggering expiry via server env or by calling the Room.next_task
    # failing-ack path (same semantics, instant).
    peer = Room(url, name="peer-listener")
    peer.send("will-be-reclaimed")
    time.sleep(0.2)
    def refuse(_m): return False
    m_ignored = r_self.next_task(ident, timeout=5, on_claim=refuse)
    assert m_ignored is None, f"next_task should have refused: {m_ignored!r}"
    again = r_self.claim(ident, timeout=5)
    assert again is not None, "re-claim returned None — at-least-once broken"
    assert again["message"].text == "will-be-reclaimed", again
    r_self.ack_claim(ident, again["claim_id"], again["message"].seq)
    ok("refused-ack path re-delivers the message on next claim (at-least-once)")

    # --- Behaviour 3: Silent-skip for non-addressed (policy, not mechanism) -
    # The server cannot see plaintext, so this one is client-side: a loop
    # that parses plaintext for @handle and either replies or calls ack_task
    # and continues. We assert the POLICY works by iterating two messages
    # (one addressed, one not) through a mention-aware wrapper that uses
    # Room.next_task with an on_claim callback.
    peer.send("@someone-else hello there")
    peer.send(f"@{ident.handle} ping back one line")
    time.sleep(0.3)
    replied = []
    def mention_aware(msg):
        text = (msg.text or "").lower()
        if f"@{ident.handle}".lower() in text:
            r_self.send(f"pong to @{msg.sender}")
            replied.append(msg.text)
            return True
        # Silent skip: let server advance cursor, don't reply.
        return True
    m1 = r_self.next_task(ident, timeout=5, on_claim=mention_aware)
    m2 = r_self.next_task(ident, timeout=5, on_claim=mention_aware)
    assert m1 is not None and m2 is not None, (m1, m2)
    assert len(replied) == 1, f"expected 1 addressed reply, got {len(replied)}: {replied!r}"
    assert "ping back" in replied[0]
    ok("silent-skip policy replies only to @handle-addressed messages")

    # --- Behaviour 4: Idle windows don't kill the persistent wrapper ---------
    # Fully exercising the persistent wrapper requires a real codex binary,
    # which isn't in CI. We cover the wrapper's invariant by pointing at
    # the matching regression in tests/codex_bootstrap.py (which CI runs
    # separately) and asserting the marker commit-message text exists in
    # the bootstrap file. This is a documentation-anchor test, not a
    # runtime test — the runtime test is codex_bootstrap.py case 4.
    boot_src = (
        os.path.join(os.path.dirname(__file__), "..", "sdk", "codex_safebot.py")
    )
    with open(boot_src) as f:
        src = f.read()
    assert "def launch_codex_forever" in src, "launch_codex_forever not found in codex_safebot.py"
    assert "while True" in src, "forever wrapper must contain a while True loop"
    ok("codex_safebot.py persistent wrapper is present (runtime behaviour covered by tests/codex_bootstrap.py)")

    print(f"\n{passed}/4 passed")
    return 0 if passed == 4 else 1


if __name__ == "__main__":
    sys.exit(run())
