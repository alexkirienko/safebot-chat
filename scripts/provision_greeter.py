"""
One-shot provisioner for the greeter service.

  1. Generates the @safebot Identity (box + sign keypairs) and registers it on
     the live server using the operator METRICS_TOKEN to bypass the reserved
     handle list.
  2. Mints a persistent demo room URL (client-generated 256-bit key) and saves
     it alongside the identity.

Writes:
  /etc/safebot/greeter/identity.key   (600, owner alex)
  /etc/safebot/greeter/demo_room.url  (600, owner alex)

Environment:
  SAFEBOT_BASE          defaults to https://safebot.chat
  METRICS_TOKEN         read from /etc/safebot/env if present
  SAFEBOT_GREETER_DIR   defaults to /etc/safebot/greeter
  SAFEBOT_HANDLE        defaults to 'safebot'
"""
from __future__ import annotations

import base64
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))

import requests
from safebot import Identity  # noqa: E402

BASE = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")
CONFIG_DIR = os.environ.get("SAFEBOT_GREETER_DIR", "/etc/safebot/greeter")
HANDLE = os.environ.get("SAFEBOT_HANDLE", "safebot")
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def load_metrics_token() -> str:
    tok = os.environ.get("METRICS_TOKEN")
    if tok: return tok
    try:
        with open("/etc/safebot/env") as f:
            for line in f:
                if line.startswith("METRICS_TOKEN="):
                    return line.split("=", 1)[1].strip()
    except Exception:  # noqa: BLE001
        pass
    raise RuntimeError("METRICS_TOKEN required to claim reserved handle")


def main():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    key_path = os.path.join(CONFIG_DIR, "identity.key")
    url_path = os.path.join(CONFIG_DIR, "demo_room.url")

    # --- identity ---------------------------------------------------------
    if os.path.exists(key_path):
        print(f"[provision] identity.key already exists at {key_path} — reusing")
        with open(key_path, "rb") as f:
            ident = Identity.from_bytes(f.read(), base_url=BASE)
    else:
        ident = Identity(HANDLE, base_url=BASE)
        with open(key_path, "wb") as f:
            f.write(ident.to_bytes())
        os.chmod(key_path, 0o600)
        print(f"[provision] created identity @{HANDLE}, saved to {key_path}")

    # Always attempt registration (idempotent: 409 means already taken by us).
    import time as _time
    token = load_metrics_token()
    ts = int(_time.time() * 1000)
    blob = f"register {ident.handle} {ts} {ident.box_pub_b64} {ident.sign_pub_b64}".encode("utf-8")
    sig = ident._sign_sk.sign(blob).signature
    resp = requests.post(
        f"{BASE}/api/identity/register",
        json={
            "handle": ident.handle,
            "box_pub": ident.box_pub_b64,
            "sign_pub": ident.sign_pub_b64,
            "register_ts": ts,
            "register_sig": base64.b64encode(sig).decode("ascii"),
            "meta": {"bio": "Official SafeBot.Chat demo greeter — echoes messages. Source: github.com/alexkirienko/safebot-chat"},
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    if resp.status_code == 201:
        print(f"[provision] registered @{ident.handle}")
    elif resp.status_code == 409:
        print(f"[provision] @{ident.handle} already registered — good")
    else:
        print(f"[provision] register got {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(2)

    # --- demo room URL ----------------------------------------------------
    if os.path.exists(url_path):
        room_url = open(url_path).read().strip()
        print(f"[provision] demo_room.url already exists: {room_url}")
    else:
        room_id = "".join(secrets.choice(ALPHA) for _ in range(6))
        key = secrets.token_bytes(32)
        key_b64u = base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")
        room_url = f"{BASE}/room/{room_id}#k={key_b64u}"
        with open(url_path, "w") as f:
            f.write(room_url + "\n")
        os.chmod(url_path, 0o600)
        print(f"[provision] minted demo room: {room_url}")

    print()
    print(f"@{ident.handle} profile: {BASE}/api/identity/{ident.handle}")
    print(f"demo room:   {room_url}")
    print(f"DM url:      {BASE}/@{ident.handle}")


if __name__ == "__main__":
    main()
