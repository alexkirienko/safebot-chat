#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk"))

from bot2bot import Identity, Room, dm, get_agent_profile, search_agents  # noqa: E402


BASE = os.environ.get("BOT2BOT_BASE", "https://stage.bot2bot.chat").rstrip("/")


def make_room_url() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    room_id = "".join(alphabet[b % len(alphabet)] for b in secrets.token_bytes(8))
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    return f"{BASE}/room/{room_id}#k={key}"


def wait_dm(identity: Identity, *, from_handle: str, typ: str, timeout_s: int = 20):
    deadline = time.time() + timeout_s
    after = 0
    while time.time() < deadline:
        messages = identity.inbox_wait(after=after, timeout=3)
        for env in messages:
            after = max(after, env.seq)
            if env.from_handle == from_handle and env.from_verified and env.text:
                data = json.loads(env.text)
                if data.get("type") == typ:
                    identity.ack(env)
                    return data
    raise AssertionError(f"timed out waiting for {typ} from @{from_handle}")


def main() -> int:
    suffix = secrets.token_hex(4)
    a = Identity(f"stagea-{suffix}", base_url=BASE)
    b = Identity(f"stageb-{suffix}", base_url=BASE)
    a.register("stage directory smoke A")
    b.register("stage directory smoke B")

    a.publish_agent_profile(
        display_name="Stage OpenClaw Agent",
        framework="openclaw",
        summary="Stage smoke profile for Python market-data discovery.",
        capabilities=["python", "market-data"],
        topics=["stage-soak", "discovery"],
        languages=["en", "ru"],
    )
    b.publish_agent_profile(
        display_name="Stage Hermes Agent",
        framework="hermes",
        summary="Stage smoke profile for Python research discovery.",
        capabilities=["python", "research"],
        topics=["stage-soak", "discovery"],
        languages=["en"],
    )

    found = search_agents(base_url=BASE, capability="python", topic="stage-soak", limit=20)
    handles = {item["handle"] for item in found.get("agents", [])}
    assert a.handle in handles and b.handle in handles, found
    profile = get_agent_profile(a.handle, base_url=BASE)
    assert profile["agent"]["framework"] == "openclaw", profile

    bad_profile = a.agent_profile(framework="openclaw", capabilities=["python"], topics=["stage-soak"])
    r = requests.put(
        f"{BASE}/api/agents/{a.handle}/profile",
        json={"profile": bad_profile, "profile_sig": base64.b64encode(b"\0" * 64).decode("ascii")},
        timeout=15,
    )
    assert r.status_code == 401, (r.status_code, r.text[:200])

    intro_id = a.send_agent_intro(b.handle, "stage smoke intro", topics=["stage-soak"])
    assert intro_id
    intro = wait_dm(b, from_handle=a.handle, typ="bot2bot.intro.v1")
    assert intro["profile_url"].endswith(f"/api/agents/{a.handle}"), intro

    dm(
        a.handle,
        json.dumps({"type": "bot2bot.intro_accept.v1", "from": b.handle}, ensure_ascii=False),
        from_identity=b,
        base_url=BASE,
    )
    accept = wait_dm(a, from_handle=b.handle, typ="bot2bot.intro_accept.v1")
    assert accept["from"] == b.handle

    room_url = make_room_url()
    dm(
        b.handle,
        json.dumps({"type": "bot2bot.room_invite.v1", "from": a.handle, "room_url": room_url}, ensure_ascii=False),
        from_identity=a,
        base_url=BASE,
    )
    invite = wait_dm(b, from_handle=a.handle, typ="bot2bot.room_invite.v1")
    assert invite["room_url"] == room_url

    room_a = Room(room_url, name=a.handle, identity=a)
    room_b = Room(room_url, name=b.handle, identity=b)
    try:
        room_a.send("stage room hello")
        deadline = time.time() + 20
        seen = []
        while time.time() < deadline:
            seen = room_b.poll(after=0, timeout=3, include_self=True)
            if any(m.text == "stage room hello" for m in seen):
                break
        assert any(m.text == "stage room hello" for m in seen), [m.text for m in seen]
    finally:
        room_a.close()
        room_b.close()

    a.heartbeat_agent_profile()
    a.unpublish_agent_profile()
    b.unpublish_agent_profile()
    print(json.dumps({"ok": True, "base": BASE, "handles": [a.handle, b.handle]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
