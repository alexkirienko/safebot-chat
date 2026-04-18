"""Adversarial input for POST /api/rooms/:id/messages."""
from __future__ import annotations
import json, os, secrets, sys, urllib.error, urllib.request, base64

BASE = os.environ.get("BASE", "https://safebot.chat")

def main():
    rid = "adv" + secrets.token_hex(4)
    url = f"{BASE}/api/rooms/{rid}/messages"
    good = {"ciphertext": base64.b64encode(b"\x00"*32).decode(), "nonce": base64.b64encode(b"\x00"*24).decode(), "sender": "advbot"}
    bad_cases = [
        ({}, 400, "empty"),
        ({"ciphertext": "a"}, 400, "no nonce"),
        ({"ciphertext": 123, "nonce": "a", "sender": "b"}, 400, "wrong type"),
        ({"ciphertext": "X" * (300*1024), "nonce": good["nonce"], "sender": "x"}, 413, "oversize"),
        (good | {"sender": "Y" * 500}, 400, "oversize sender rejected"),
        (good | {"sender": "ok-64-len"}, 200, "valid send round-trips"),
    ]
    passed = 0
    for body, want, label in bad_cases:
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type":"application/json"})
        try:
            r = urllib.request.urlopen(req, timeout=10); code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        if code == want:
            print(f"  ✓ {label}: {code}"); passed += 1
        else:
            print(f"  ✗ {label}: {code} (want {want})")

    # Bad room IDs -> 400
    for rid in ["ab", "X"*200, "bad/slash", "white space"]:
        safe = urllib.request.quote(rid, safe='')
        req = urllib.request.Request(f"{BASE}/api/rooms/{safe}/status", headers={"Accept":"application/json"})
        try:
            r = urllib.request.urlopen(req, timeout=10); code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        # Short/too-long/unsafe should be 400 or (for non-matching route) 404
        if code in (400, 404):
            print(f"  ✓ bad roomId {rid!r}: {code}"); passed += 1
        else:
            print(f"  ✗ bad roomId {rid!r}: {code}")

    h = json.loads(urllib.request.urlopen(f"{BASE}/api/health", timeout=5).read())
    if h.get("ok"):
        print(f"  ✓ server healthy (rooms={h.get('rooms',0)})"); passed += 1

    total = len(bad_cases) + 4 + 1
    if passed != total:
        print(f"\n✗ {passed}/{total}"); sys.exit(1)
    print(f"\n✓ {passed}/{total} room adversarial checks passed")

if __name__ == "__main__":
    main()
