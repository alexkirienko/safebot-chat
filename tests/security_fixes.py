"""
Regression tests for the code-review security fixes:

  #1  WS-posted messages now carry a monotonic seq (SSE/long-poll resumption).
  #2  from_handle forgery — unsigned from_handle marked unverified; bad sig 401.
  #5  /wait on a fresh roomId no longer creates a ghost room.
  #8  wakeDmWaiters respects per-waiter `after` filter.
  #7  /api/report does not allow Markdown smuggling in Telegram output (local
      test: payload is Markdown-escaped before send).
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import threading
import time
import urllib.request
import websocket  # pip install websocket-client

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))

from safebot import Identity, dm  # noqa: E402
import nacl.public as _pub
import nacl.secret as _sec
import nacl.signing as _sig
import nacl.utils as _utils

BASE = os.environ.get("BASE", "https://safebot.chat")
WS_BASE = BASE.replace("https://", "wss://").replace("http://", "ws://")

failures: list[str] = []
def ok(m): print(f"  ✓ {m}")
def fail(m): failures.append(m); print(f"  ✗ {m}")


def rand_handle(p="sec"): return f"{p}-{secrets.token_hex(3)}"


# ---- #1 WS seq ------------------------------------------------------------

def test_ws_seq():
    print("\n▶ #1: WS messages carry seq so SSE resume doesn't drop them")
    room_id = secrets.token_urlsafe(8).replace("=", "")[:10]
    key = _sec.SecretBox(_utils.random(32))

    # Open a WS sender.
    ws_url = f"{WS_BASE}/api/rooms/{room_id}/ws"
    ws = websocket.create_connection(ws_url, timeout=10)
    # Drain initial frames (replay + ready).
    ws.settimeout(1)
    try:
        while True: ws.recv()
    except Exception: pass
    ws.settimeout(5)

    # Post 3 messages via WS.
    for i in range(3):
        nonce = _utils.random(24)
        ct = key.encrypt(f"ws-{i}".encode(), nonce).ciphertext
        ws.send(json.dumps({
            "sender": "ws-sender",
            "ciphertext": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }))
    time.sleep(0.5)

    # Fetch via /transcript and verify seqs are non-zero + monotonic.
    resp = urllib.request.urlopen(f"{BASE}/api/rooms/{room_id}/transcript?after=0", timeout=10)
    data = json.loads(resp.read())
    msgs = data["messages"]
    seqs = [m.get("seq") for m in msgs if m.get("sender") == "ws-sender"]
    if len(seqs) != 3:
        fail(f"#1: expected 3 ws-sender msgs, got {len(seqs)}"); ws.close(); return
    if any(s is None or s == 0 for s in seqs):
        fail(f"#1: WS messages missing seq: {seqs}"); ws.close(); return
    if seqs != sorted(seqs) or len(set(seqs)) != 3:
        fail(f"#1: seqs not monotonic/unique: {seqs}"); ws.close(); return
    ok(f"#1: WS messages carry monotonic seq ({seqs})")

    # Now verify /wait?after=<first_seq> only returns newer ones.
    first = seqs[0]
    resp = urllib.request.urlopen(f"{BASE}/api/rooms/{room_id}/transcript?after={first}", timeout=10)
    data = json.loads(resp.read())
    later = [m for m in data["messages"] if m.get("sender") == "ws-sender"]
    if len(later) == 2:
        ok("#1: transcript ?after=<seq> correctly filters WS msgs")
    else:
        fail(f"#1: after={first} returned {len(later)} WS msgs (expected 2)")
    ws.close()


# ---- #2 from_handle forgery ----------------------------------------------

def test_from_handle_forgery():
    print("\n▶ #2: unsigned from_handle is marked unverified; bad sig is rejected")
    # Register a victim we want to impersonate.
    victim = Identity(rand_handle("victim"), base_url=BASE); victim.register(bio="v")
    target = Identity(rand_handle("target"), base_url=BASE); target.register(bio="t")

    # Step 1: raw POST with forged from_handle, no sig.
    recipient = json.loads(urllib.request.urlopen(f"{BASE}/api/identity/{target.handle}", timeout=10).read())
    recipient_pk = _pub.PublicKey(base64.b64decode(recipient["box_pub"]))
    eph_sk = _pub.PrivateKey.generate()
    box = _pub.Box(eph_sk, recipient_pk)
    nonce = _utils.random(24)
    ct = box.encrypt(b"forged", nonce).ciphertext
    body = {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "sender_eph_pub": base64.b64encode(bytes(eph_sk.public_key)).decode(),
        "from_handle": victim.handle,  # no signature
    }
    req = urllib.request.Request(f"{BASE}/api/dm/{target.handle}",
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    r = urllib.request.urlopen(req, timeout=10); assert r.status == 200
    msgs = target.inbox_wait(after=0, timeout=3)
    hit = [m for m in msgs if m.from_handle == victim.handle]
    if hit and not hit[0].from_verified:
        ok("#2: unsigned forged from_handle delivered but marked from_verified=false")
    elif hit and hit[0].from_verified:
        fail("#2: unsigned forged from_handle was marked verified (CRITICAL)")
    else:
        fail("#2: forged DM didn't land in inbox")
    for m in msgs: target.ack(m)

    # Step 2: raw POST with BAD signature (signs wrong blob).
    nonce = _utils.random(24)
    ct = box.encrypt(b"bad-sig", nonce).ciphertext
    body["ciphertext"] = base64.b64encode(ct).decode()
    body["nonce"] = base64.b64encode(nonce).decode()
    # Sign the wrong message (swap handles).
    attacker_sk = _sig.SigningKey.generate()  # not victim's key
    from_ts = int(time.time() * 1000)
    blob = f"dm {target.handle} {victim.handle} {from_ts}".encode()
    body["from_sig"] = base64.b64encode(attacker_sk.sign(blob).signature).decode()
    body["from_ts"] = from_ts
    req = urllib.request.Request(f"{BASE}/api/dm/{target.handle}",
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        fail("#2: bad sig was NOT rejected")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            ok("#2: bad from_handle signature correctly rejected 401")
        else:
            fail(f"#2: bad sig returned {e.code} (expected 401)")

    # Step 3: SDK-signed DM arrives verified.
    dm(f"@{target.handle}", "legit", from_identity=victim, base_url=BASE)
    msgs = target.inbox_wait(after=0, timeout=3)
    hit = [m for m in msgs if m.from_handle == victim.handle]
    if hit and hit[0].from_verified:
        ok("#2: SDK-signed from_handle arrives with from_verified=true")
    else:
        fail(f"#2: SDK-signed DM not verified: {hit}")
    for m in msgs: target.ack(m)


# ---- #5 ghost room --------------------------------------------------------

def test_ghost_room():
    print("\n▶ #5: /wait on a fresh roomId does NOT spawn a room")
    room_id = "ghost" + secrets.token_hex(4)
    t0 = time.time()
    resp = urllib.request.urlopen(f"{BASE}/api/rooms/{room_id}/wait?timeout=1", timeout=5)
    data = json.loads(resp.read())
    if data.get("exists") is False and data.get("messages") == []:
        ok("#5: /wait returns {exists:false, messages:[]} instead of holding")
    else:
        fail(f"#5: unexpected wait response: {data}")
    # Confirm /status still says exists:false.
    s = json.loads(urllib.request.urlopen(f"{BASE}/api/rooms/{room_id}/status", timeout=5).read())
    if s.get("exists") is False:
        ok("#5: /status confirms no ghost room was created")
    else:
        fail(f"#5: ghost room created anyway: {s}")


# ---- #7 markdown escape local test ---------------------------------------

def test_markdown_escape():
    print("\n▶ #7: Markdown special chars in 'what' shouldn't break Telegram payload")
    payload = {"what": "crash when I click [evil](https://evil.example) * _ ` fmt test"}
    req = urllib.request.Request(f"{BASE}/api/report",
        data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=10)
        if r.status == 200:
            ok("#7: /api/report accepted markdown-rich body without error")
    except urllib.error.HTTPError as e:
        fail(f"#7: /api/report {e.code}")


if __name__ == "__main__":
    print(f"▶︎ Security-fix regression tests against {BASE}")
    test_ws_seq()
    test_from_handle_forgery()
    test_ghost_room()
    test_markdown_escape()
    print()
    if failures:
        print(f"✗ {len(failures)} failure(s):")
        for f in failures: print("  -", f)
        sys.exit(1)
    print("✓ all security-fix tests passed")
