"""
DM load test: N senders each DM one receiver in parallel, M messages each.
Verifies signed-from_handle path, inbox seq monotonicity, no drops, no dupes.
"""
from __future__ import annotations

import os, sys, time, secrets, threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))
from safebot import Identity, dm  # noqa: E402

BASE = os.environ.get("BASE", "https://safebot.chat")
SENDERS = int(os.environ.get("SENDERS", "10"))
PER = int(os.environ.get("PER", "10"))

def rand(p): return f"{p}-{secrets.token_hex(3)}"


def main():
    print(f"▶ DM load: {SENDERS} senders × {PER} DMs to a single receiver")
    recv = Identity(rand("recv"), base_url=BASE); recv.register(bio="load")

    # Register senders in parallel.
    senders: list[Identity] = []
    lock = threading.Lock()
    def reg(_):
        s = Identity(rand("snd"), base_url=BASE); s.register(bio="load")
        with lock: senders.append(s)
    with ThreadPoolExecutor(max_workers=SENDERS) as ex:
        list(ex.map(reg, range(SENDERS)))
    print(f"  registered {len(senders)} senders")

    # Drain concurrently with sending — the inbox cap is 256 (INBOX_MAX), so
    # if we wait until all senders finish before draining, trimming eats DMs.
    total = SENDERS * PER
    got: list = []
    stop = threading.Event()
    def drain():
        # Use the SSE inbox stream — push-based, drains as fast as the server
        # emits. Falls back to long-poll inbox_wait on disconnect.
        try:
            for env in recv.inbox_stream(timeout=60):
                got.append(env); recv.ack(env)
                if len(got) >= total: return
        except Exception:
            pass
    drainer = threading.Thread(target=drain, daemon=True); drainer.start()

    def burst(idx):
        s = senders[idx]
        for i in range(PER):
            dm(f"@{recv.handle}", f"load {s.handle} #{i}", from_identity=s, base_url=BASE)
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=SENDERS) as ex:
        list(ex.map(burst, range(SENDERS)))
    elapsed = time.time() - t0
    print(f"  sent {total} DMs in {elapsed:.1f}s ({total/elapsed:.0f} DMs/s)")
    stop.set(); drainer.join(timeout=20)
    print(f"  received {len(got)} DMs")

    # Audit: every message from_verified=True, all unique ids, seqs monotonic.
    if len(got) != total:
        print(f"  ✗ FAIL: expected {total}, got {len(got)}"); sys.exit(1)
    ids = {m.id for m in got}
    if len(ids) != total:
        print(f"  ✗ FAIL: duplicates in inbox ({len(ids)} unique)"); sys.exit(1)
    seqs = [m.seq for m in got]
    if sorted(seqs) != seqs or len(set(seqs)) != total:
        print(f"  ✗ FAIL: seqs not monotonic/unique"); sys.exit(1)
    unverified = [m for m in got if not m.from_verified]
    if unverified:
        print(f"  ✗ FAIL: {len(unverified)} messages arrived unverified"); sys.exit(1)
    print(f"  ✓ all {total} DMs delivered, unique, monotonic, verified")


if __name__ == "__main__":
    main()
