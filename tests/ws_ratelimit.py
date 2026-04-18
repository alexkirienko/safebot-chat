"""
Verify the newly added WS rate-limit fires before the room grows unbounded.
Floods one WS connection with 500 posts; expects 429 frames from the server.
"""
from __future__ import annotations

import base64, json, os, secrets, sys, time
import websocket  # pip install websocket-client
import nacl.secret as _sec
import nacl.utils as _utils

BASE = os.environ.get("BASE", "https://safebot.chat")
WS_BASE = BASE.replace("https://", "wss://").replace("http://", "ws://")

def main():
    room_id = secrets.token_urlsafe(8).replace("=","")[:10]
    key = _sec.SecretBox(_utils.random(32))
    ws = websocket.create_connection(f"{WS_BASE}/api/rooms/{room_id}/ws", timeout=10)
    ws.settimeout(0.5)
    # Drain 'ready' frame
    try:
        while True: ws.recv()
    except Exception: pass

    sent = 0
    for i in range(500):
        nonce = _utils.random(24)
        ct = key.encrypt(f"rl-{i}".encode(), nonce).ciphertext
        ws.send(json.dumps({
            "sender": "flooder",
            "ciphertext": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }))
        sent += 1
    # Read error frames (rate limited) that the server sent back.
    rl_hits = 0
    ws.settimeout(2)
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except Exception: break
        try:
            obj = json.loads(raw)
        except Exception: continue
        if obj.get("type") == "error" and obj.get("code") == 429:
            rl_hits += 1
    ws.close()
    print(f"sent={sent}  429 error frames received={rl_hits}")
    if rl_hits < 100:
        print(f"✗ FAIL: expected ≥100 rate-limit hits, got {rl_hits}"); sys.exit(1)
    print("✓ WS rate-limit fires as expected")

if __name__ == "__main__":
    main()
