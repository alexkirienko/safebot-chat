"""Regression harness for the bash-loop CLI path (--claim / --ack / --next).

Exercises the flags a Claude Code or Cursor host would bash-exec inside
a running session — the "no MCP restart" integration story.

Requires a running SafeBot server (SAFEBOT_BASE env, default
https://safebot.chat). CI starts one on http://127.0.0.1:3123 and
points SAFEBOT_BASE at it.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from safebot import Room  # noqa: E402  — after sys.path mutation

BASE = os.environ.get("SAFEBOT_BASE", "https://safebot.chat")
SAFEBOT_PY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sdk", "safebot.py"))


def sbot(args, **kw):
    """Invoke the CLI as a subprocess. Returns CompletedProcess."""
    return subprocess.run(
        [sys.executable, SAFEBOT_PY, *args],
        capture_output=True, text=True, timeout=60, **kw,
    )


def run():
    passed = 0
    def ok(msg):
        nonlocal passed; passed += 1; print(f"  \u2713 {msg}")

    tag = secrets.token_hex(3)
    key = secrets.token_bytes(32)
    kb = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
    rid = "CLI" + tag.upper()
    url = f"{BASE}/room/{rid}#k={kb}"
    handle = f"clitest{tag}"

    with tempfile.TemporaryDirectory() as td:
        id_path = os.path.join(td, "id.key")

        # Missing --handle AND missing identity file => helpful error + exit 2.
        r = sbot([url, "--next", "--identity-file", id_path, "--claim-timeout", "2"])
        assert r.returncode == 2, (r.returncode, r.stderr)
        assert "--handle" in r.stderr, r.stderr
        ok("no identity + no --handle → exit 2 with a pointer to --handle")

        # Now seed a foreign message from a peer so --claim has something
        # to return. Peer uses the SDK directly with a plain Room.
        peer = Room(url, name="peer-agent")
        peer.send("hello from peer 1")
        time.sleep(0.3)

        # First run: auto-creates and registers the identity, does the
        # claim → print → ack cycle, returns the message.
        r = sbot([url, "--next", "--handle", handle, "--identity-file", id_path, "--claim-timeout", "5"])
        assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
        out = json.loads(r.stdout.strip())
        assert out.get("text") == "hello from peer 1", out
        assert out.get("sender") == "peer-agent", out
        assert "claim_id" in out and "seq" in out, out
        ok("--next returns message as JSON + exit 0 and auto-creates identity")
        assert os.path.exists(id_path), "identity file was not persisted"
        ok("identity file persisted on first use")

        # Second --next should return empty (we acked).
        r = sbot([url, "--next", "--identity-file", id_path, "--claim-timeout", "2"])
        assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
        assert json.loads(r.stdout.strip()) == {"empty": True}, r.stdout
        ok("empty claim → exit 1 with {\"empty\":true}")

        # Now test --claim + --ack separately.
        peer.send("hello from peer 2")
        time.sleep(0.3)
        r = sbot([url, "--claim", "--identity-file", id_path, "--claim-timeout", "5"])
        assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
        out = json.loads(r.stdout.strip())
        assert out["text"] == "hello from peer 2", out
        ok("--claim (no ack) returns message + exit 0")

        # Without acking, another --claim returns the SAME message (idempotent
        # re-claim under the same inflight lease).
        r2 = sbot([url, "--claim", "--identity-file", id_path, "--claim-timeout", "5"])
        assert r2.returncode == 0, r2.stderr
        out2 = json.loads(r2.stdout.strip())
        assert out2["claim_id"] == out["claim_id"] and out2["seq"] == out["seq"], (out, out2)
        ok("--claim is idempotent: same claim_id + seq until ack")

        # Now ack it explicitly.
        r = sbot([url, "--ack", out["claim_id"], str(out["seq"]), "--identity-file", id_path])
        assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
        ack_out = json.loads(r.stdout.strip())
        assert ack_out.get("ok") and ack_out.get("advanced") is True, ack_out
        ok("--ack returns advanced:true on a fresh claim")

        # Second ack with the same args is a no-op advance (cursor already there).
        r = sbot([url, "--ack", out["claim_id"], str(out["seq"]), "--identity-file", id_path])
        assert r.returncode == 0, r.stderr
        ack_out2 = json.loads(r.stdout.strip())
        assert ack_out2.get("ok") and ack_out2.get("advanced") is False, ack_out2
        ok("re-ack same (claim_id, seq) → advanced:false (idempotent)")

        # After ack, --claim should be empty again.
        r = sbot([url, "--claim", "--identity-file", id_path, "--claim-timeout", "2"])
        assert r.returncode == 1, (r.returncode, r.stdout)
        ok("after ack: --claim → empty/exit 1")

    print(f"\n{passed}/9 passed")
    return 0 if passed == 9 else 1


if __name__ == "__main__":
    sys.exit(run())
