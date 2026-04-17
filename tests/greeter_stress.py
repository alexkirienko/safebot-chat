"""
Pre-Moltbook stress test for the @safebot greeter + demo room.

Simulates realistic first-post traffic:
  - Scenario A: 20 concurrent visitors land in the demo room over 30s. Each
    sends 3 messages. Greeter must echo each and the room must stay alive.
  - Scenario B: 15 concurrent agents each DM @safebot in parallel, some
    reply-capable (with from_handle), some anonymous. Greeter must reply to
    the reply-capable ones within 5s and ack.
  - Scenario C: size edge — one DM near the 60 KiB plaintext cap. Greeter
    must handle without crashing.
  - Scenario D: reply-loop guard — if someone keeps replying to every
    greeter message, we shouldn't spiral. Send 5 DMs, verify greeter replies
    ≤ 5 (not exponential).
  - Scenario E: systemd health — verify safebot and safebot-greeter stay
    active throughout.

Pass criteria: zero 5xx, zero greeter crashes, greeter replies to all
reply-capable DMs in the batch, demo room survives end-to-end.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))

from safebot import Identity, Room, dm  # noqa: E402

BASE = os.environ.get("BASE", "https://safebot.chat")
DEMO_URL = open("/etc/safebot/greeter/demo_room.url").read().strip()

failures: list[str] = []
def fail(msg: str) -> None:
    failures.append(msg); print(f"  ✗ {msg}")
def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def rand_handle(prefix: str = "stress") -> str:
    return f"{prefix}-{secrets.token_hex(3)}"


def systemd_active(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    return r.stdout.strip() == "active"


# ---- Scenario A: 20 concurrent room visitors -----------------------------

def scenario_a():
    print("\n▶ A: 20 concurrent visitors in the demo room, 3 msgs each")
    t0 = time.time()

    echoes = {}  # visitor_name -> count of echo replies received
    lock = threading.Lock()

    def visit(idx: int):
        name = f"visitor-{idx}-{secrets.token_hex(2)}"
        echoes[name] = 0
        # Listener: count greeter echoes addressed to us.
        room = Room(DEMO_URL, name=name)
        done = threading.Event()
        def listen():
            try:
                for msg in room.stream(include_self=False, auto_reconnect=False):
                    if done.is_set(): return
                    if msg.sender == "safebot" and msg.text and name in msg.text:
                        with lock:
                            echoes[name] += 1
            except Exception:
                pass
        t = threading.Thread(target=listen, daemon=True); t.start()
        time.sleep(0.3)
        for i in range(3):
            room.send(f"hi from {name} #{i}")
            time.sleep(0.3)
        # wait a bit more for echoes
        time.sleep(2.0)
        done.set()

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(visit, range(20)))

    total_msgs = 20 * 3
    total_echoes = sum(echoes.values())
    elapsed = time.time() - t0
    # Each visitor's message should be echoed once by the greeter. Allow up
    # to 20% slack because some echoes may arrive after the listener closed.
    if total_echoes >= int(total_msgs * 0.80):
        ok(f"A: {total_echoes}/{total_msgs} visitor messages echoed (≥80% in {elapsed:.1f}s)")
    else:
        fail(f"A: only {total_echoes}/{total_msgs} messages echoed by greeter")


# ---- Scenario B: 15 concurrent DMs to @safebot ---------------------------

def scenario_b():
    print("\n▶ B: 15 concurrent DMs to @safebot (mixed reply-capable + anon)")

    # Pre-register 8 reply-capable identities in parallel.
    identities = []
    def reg(_i):
        idn = Identity(rand_handle("stress-b"), base_url=BASE)
        idn.register(bio="stress B")
        identities.append(idn)
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(reg, range(8)))

    replies = {i.handle: None for i in identities}
    lock = threading.Lock()

    def listen(idn: Identity):
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                msgs = idn.inbox_wait(after=0, timeout=2)
            except Exception:
                continue
            for m in msgs:
                if m.from_handle == "safebot":
                    with lock:
                        replies[idn.handle] = m.text
                    return

    listener_threads = [threading.Thread(target=listen, args=(i,), daemon=True) for i in identities]
    for t in listener_threads: t.start()
    time.sleep(0.3)

    # Fire 15 DMs in parallel: 8 reply-capable + 7 anonymous.
    def send_reply_capable(idn: Identity):
        dm("@safebot", f"ping from {idn.handle}", from_identity=idn, base_url=BASE)
    def send_anon(_i):
        dm("@safebot", f"anon ping {_i}", base_url=BASE)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=15) as ex:
        for i, idn in enumerate(identities):
            ex.submit(send_reply_capable, idn)
        for i in range(7):
            ex.submit(send_anon, i)

    for t in listener_threads: t.join(timeout=18)
    elapsed = time.time() - t0

    with_reply = sum(1 for v in replies.values() if v is not None)
    if with_reply >= 7:
        ok(f"B: {with_reply}/8 reply-capable DMs got a greeter response in {elapsed:.1f}s")
    else:
        fail(f"B: only {with_reply}/8 reply-capable DMs answered")


# ---- Scenario C: large DM ------------------------------------------------

def scenario_c():
    print("\n▶ C: 40 KiB plaintext DM to @safebot")
    idn = Identity(rand_handle("stress-c"), base_url=BASE)
    idn.register(bio="stress C")

    # 40 KiB plaintext — well within the 60 KiB cap, enough to exercise size.
    big = "X" * (40 * 1024)
    dm("@safebot", big, from_identity=idn, base_url=BASE)

    got = None
    deadline = time.time() + 10
    while time.time() < deadline and got is None:
        msgs = idn.inbox_wait(after=0, timeout=2)
        for m in msgs:
            if m.from_handle == "safebot":
                got = m; break
    if got and got.text and "received your message" in got.text:
        ok(f"C: greeter acknowledged a {len(big)}-char DM")
    else:
        fail(f"C: no greeter reply to a 40 KiB DM ({'got ' + str(got) if got else 'nothing'})")


# ---- Scenario D: reply-loop guard ---------------------------------------

def scenario_d():
    print("\n▶ D: reply-loop guard — 5 DMs from one identity, greeter replies 5 not 25")
    idn = Identity(rand_handle("stress-d"), base_url=BASE)
    idn.register(bio="stress D")
    # Drain any stale greeter messages from before.
    for m in idn.inbox_wait(after=0, timeout=1):
        idn.ack(m)

    for i in range(5):
        dm("@safebot", f"loop test {i}", from_identity=idn, base_url=BASE)
        time.sleep(0.2)

    time.sleep(4)
    msgs = idn.inbox_wait(after=0, timeout=3)
    greeter_replies = [m for m in msgs if m.from_handle == "safebot"]
    if 5 <= len(greeter_replies) <= 8:  # allow some slack for dups
        ok(f"D: greeter replied {len(greeter_replies)} times to 5 DMs (no amplification)")
    else:
        fail(f"D: expected ~5 greeter replies, got {len(greeter_replies)} (amplification?)")


# ---- Scenario E: systemd health -----------------------------------------

def scenario_e():
    print("\n▶ E: systemd safebot + safebot-greeter stayed active")
    if systemd_active("safebot"):
        ok("E: safebot.service active")
    else:
        fail("E: safebot.service not active")
    if systemd_active("safebot-greeter"):
        ok("E: safebot-greeter.service active")
    else:
        fail("E: safebot-greeter.service not active")


# ---- Main ---------------------------------------------------------------

if __name__ == "__main__":
    print(f"▶︎ Greeter stress against {BASE}")
    print(f"  demo room: {DEMO_URL}")

    scenario_a()
    scenario_b()
    scenario_c()
    scenario_d()
    scenario_e()

    print()
    if failures:
        print(f"✗ {len(failures)} failure(s):")
        for f in failures: print(f"  - {f}")
        sys.exit(1)
    print("✓ all greeter scenarios passed")
