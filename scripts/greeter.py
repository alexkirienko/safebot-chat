"""
SafeBot.Chat greeter — a tiny always-on agent that:

  1. Keeps the persistent demo room alive (stays subscribed via the SDK's
     auto-reconnecting SSE stream) and echoes visitor messages.
  2. Replies to DMs sent to @safebot (or whatever handle is configured),
     and acks each one so the inbox doesn't fill up.

Run under systemd as `safebot-greeter.service`. State lives in
/etc/safebot/greeter/:

  identity.key   — 96-byte serialised Identity (box_sk + sign_sk + handle)
  demo_room.url  — full SafeBot.Chat room URL with #k= fragment

Both files are created by `scripts/provision_greeter.py` on first run.
"""
from __future__ import annotations

import os
import signal
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))

from safebot import Room, Identity, dm  # noqa: E402

CONFIG_DIR = os.environ.get("SAFEBOT_GREETER_DIR", "/etc/safebot/greeter")
BASE_URL = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")


def log(*args):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[greeter {ts}]", *args, flush=True)


# ---- demo-room loop --------------------------------------------------------

def room_loop():
    url_path = os.path.join(CONFIG_DIR, "demo_room.url")
    try:
        room_url = open(url_path).read().strip()
    except FileNotFoundError:
        log("no demo_room.url; skipping room greeter")
        return
    room = Room(room_url, name="safebot")
    log(f"demo room greeter online: {room_url}")
    room.send(
        "Hi, I'm @safebot. This is the persistent demo room. "
        "Say anything and I'll echo it back. "
        "Full docs: https://safebot.chat/docs"
    )
    try:
        for msg in room.stream(include_self=False, auto_reconnect=True):
            text = msg.text if msg.text is not None else "[undecryptable]"
            log(f"room heard {msg.sender}: {text[:120]!r}")
            if msg.sender == room.name:
                continue
            try:
                room.send(f"Echo from @safebot · heard {msg.sender}: {text[:400]}")
            except Exception as e:  # noqa: BLE001
                log(f"room reply error: {e}")
    except Exception as e:  # noqa: BLE001
        log(f"room stream crashed: {e}")


# ---- DM inbox loop ---------------------------------------------------------

def dm_loop(identity: Identity):
    log(f"DM greeter online: @{identity.handle} at {identity.dm_url()}")
    for env in identity.inbox_stream(timeout=30):
        preview = (env.text or "[undecryptable]")[:200]
        log(f"DM from {env.from_handle or '(anon)'}: {preview!r}")
        try:
            if env.from_handle and env.from_handle != identity.handle:
                identity.reply(
                    env,
                    f"Hi @{env.from_handle}, this is @{identity.handle}. "
                    f"I received your message ({len(env.text or '')} chars). "
                    f"This is an automated greeter — "
                    f"docs: https://safebot.chat/docs · source: https://github.com/alexkirienko/safebot-chat",
                )
            # else: anonymous sender — no way to reply, just log + ack
            identity.ack(env)
        except Exception as e:  # noqa: BLE001
            log(f"DM handle error: {e}")


# ---- main ------------------------------------------------------------------

def main():
    key_path = os.path.join(CONFIG_DIR, "identity.key")
    try:
        blob = open(key_path, "rb").read()
    except FileNotFoundError:
        log(f"identity.key missing at {key_path}; run provision_greeter.py first")
        sys.exit(1)
    identity = Identity.from_bytes(blob, base_url=BASE_URL)
    log(f"loaded identity @{identity.handle}")

    # Run room and DM loops in daemon threads; main thread waits for signals.
    for fn in (room_loop, lambda: dm_loop(identity)):
        threading.Thread(target=fn, daemon=True).start()

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()


if __name__ == "__main__":
    main()
