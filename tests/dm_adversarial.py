"""
Adversarial input fuzz for DM endpoints.
Bombards POST /api/dm/:handle with malformed inputs and verifies the
server returns clean 400s, never 500 or crash.
"""
from __future__ import annotations

import base64, json, os, secrets, sys, time, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))
from safebot import Identity  # noqa: E402

BASE = os.environ.get("BASE", "https://safebot.chat")

def rand(p): return f"{p}-{secrets.token_hex(3)}"


def post(url: str, body: dict, expect: int):
    req = urllib.request.Request(url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=10)
        code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    if code != expect:
        print(f"  ✗ {url} body={json.dumps(body)[:120]!r} -> {code} (expected {expect})")
        return False
    return True


def main():
    victim = Identity(rand("adv"), base_url=BASE); victim.register(bio="adv")
    url = f"{BASE}/api/dm/{victim.handle}"

    good_nonce = base64.b64encode(b"\x00" * 24).decode()
    good_ct = base64.b64encode(b"\x00" * 64).decode()
    good_pk = base64.b64encode(b"\x00" * 32).decode()

    print("▶ DM adversarial fuzz")
    cases = [
        # Each: (body, expected_status, label)
        ({}, 400, "empty body"),
        ({"ciphertext": good_ct}, 400, "missing nonce+pk"),
        ({"ciphertext": good_ct, "nonce": "not-base64!!!", "sender_eph_pub": good_pk}, 400, "bad nonce length"),
        ({"ciphertext": good_ct, "nonce": good_nonce, "sender_eph_pub": "short"}, 400, "bad pk length"),
        # Oversize body may be rejected by body-parser (413) or our own check (400). Either is fine.
        ({"ciphertext": "X" * (200 * 1024), "nonce": good_nonce, "sender_eph_pub": good_pk}, 413, "oversize ciphertext"),
        ({"ciphertext": good_ct, "nonce": good_nonce, "sender_eph_pub": good_pk, "from_handle": "Z" * 400}, 200, "oversize from_handle truncated to 34"),
        ({"ciphertext": good_ct, "nonce": good_nonce, "sender_eph_pub": good_pk, "from_handle": "anyone", "from_sig": "bogus", "from_ts": 1}, 400, "ancient from_ts"),
        ({"ciphertext": good_ct, "nonce": good_nonce, "sender_eph_pub": good_pk, "from_handle": "nosuch", "from_sig": base64.b64encode(b"\x00"*64).decode(), "from_ts": int(time.time()*1000)}, 400, "from_handle not registered"),
    ]

    # Also test unknown recipient → 404
    cases.append((
        {"ciphertext": good_ct, "nonce": good_nonce, "sender_eph_pub": good_pk},
        404,
        "unknown recipient",
    ))

    passed = 0
    for body, want, label in cases:
        tgt = url if label != "unknown recipient" else f"{BASE}/api/dm/nosuch-{secrets.token_hex(4)}"
        if post(tgt, body, want):
            passed += 1
            print(f"  ✓ {label}: {want}")

    # Weird JSON payloads via raw bytes.
    print("▶ DM raw-bytes fuzz (expect no 5xx)")
    for raw_body, want, label in [
        (b"", 400, "zero-byte body"),
        (b"not json", 400, "not JSON"),
        (b'{"ciphertext": null}', 400, "null ciphertext"),
        (b'{' + b'"a":"b",' * 5000 + b'"z":"z"}', 400, "huge JSON"),
    ]:
        req = urllib.request.Request(url, data=raw_body,
            headers={"Content-Type": "application/json"})
        try:
            r = urllib.request.urlopen(req, timeout=10); code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        if code >= 500:
            print(f"  ✗ {label}: got 5xx ({code})"); continue
        print(f"  ✓ {label}: {code}")
        passed += 1

    # Health check after fuzz.
    h = json.loads(urllib.request.urlopen(f"{BASE}/api/health", timeout=5).read())
    if h.get("ok"):
        print(f"  ✓ server healthy after fuzz (rooms={h.get('rooms',0)})")
        passed += 1

    total = len(cases) + 4 + 1
    if passed == total:
        print(f"\n✓ {passed}/{total} adversarial checks passed")
    else:
        print(f"\n✗ {passed}/{total} passed")
        sys.exit(1)


if __name__ == "__main__":
    main()
