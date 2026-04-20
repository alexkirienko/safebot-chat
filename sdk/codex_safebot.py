#!/usr/bin/env python3
"""Codex bootstrap — compatibility shim over sdk/agent_safebot.py.

Runs `codex mcp add safebot` if needed, then executes `claim_task` /
`ack_task` loops through the shared listener launcher so we launch a
fresh Codex session attached to the room URL.

Historically this was a Codex-specific listener launcher. The shared
logic (respawn loop, release sentinel, listener prompt contract, MCP
bootstrap) now lives in agent_safebot.py behind a host-adapter
interface, so we can support Claude Code and arbitrary custom CLIs
too. The CLI contract Codex users already paste around is preserved —
`python3 codex_safebot.py "<ROOM_URL>"` behaves exactly as before
(persistent by default, `--once` and `--forever` recognised).

If you are wiring up a new host, use agent_safebot.py directly:

    python3 agent_safebot.py --host claude-code "<ROOM_URL>"
    python3 agent_safebot.py --host custom --cmd 'gemini chat' "<ROOM_URL>"
"""

from __future__ import annotations

import argparse
import os
import sys

# Make the sibling module importable whether codex_safebot.py is run
# as a script (cwd not on sys.path reliably) or imported in a test.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_safebot import (  # noqa: E402
    DEFAULT_BASE,
    DEFAULT_MCP_NAME,
    DEFAULT_RELEASE_SENTINEL,
    CodexAdapter,
    RoomLock,
    _room_id_from_url,
    build_prompt,
    respawn_loop,
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Ensure SafeBot MCP is configured in Codex, then launch a fresh "
            "Codex session for a room URL. Default mode is a persistent "
            "listener; pass --once for a single-shot run. (This is a "
            "compatibility wrapper over agent_safebot.py.)"
        )
    )
    p.add_argument("room_url", nargs="?", help="Full SafeBot room URL including #k=...")
    p.add_argument("--handle", default=None, help="Override the @mention handle the listener should use in prompts and, when supported, as the default room-facing label.")
    p.add_argument("--install-only", action="store_true", help="Only ensure the MCP server exists; do not launch Codex.")
    p.add_argument("--force", action="store_true", help="Replace an existing MCP server with the same name.")
    p.add_argument("--mcp-name", default=DEFAULT_MCP_NAME, help=f"Codex MCP server name. Default: {DEFAULT_MCP_NAME}")
    p.add_argument("--base", default=DEFAULT_BASE, help=f"SafeBot base URL for the MCP server. Default: {DEFAULT_BASE}")
    p.add_argument("--print-prompt", action="store_true", help="Print the launch prompt instead of exec'ing Codex.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Single-shot mode: launch Codex once and let it exit normally after that turn.")
    mode.add_argument("--forever", action="store_true", help="Backward-compatible alias for the default persistent listener mode.")
    # Pre-split host extras at the first explicit `--` (see the matching
    # comment in agent_safebot.py). This stops the "wrapper flags AFTER
    # room_url get swallowed by REMAINDER" footgun.
    try:
        sep = argv.index("--")
        wrapper_argv, codex_extras = list(argv[:sep]), list(argv[sep + 1:])
    except ValueError:
        wrapper_argv, codex_extras = list(argv), []
    ns = p.parse_args(wrapper_argv)
    ns.codex_args = codex_extras
    if not ns.install_only and not ns.room_url:
        p.error("room_url is required unless --install-only is used")
    return ns


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    host = CodexAdapter()
    if args.handle:
        host.handle = args.handle.strip().lstrip("@") or host.handle
        os.environ["SAFEBOT_MCP_ROOM_NAME"] = host.handle
    if args.print_prompt:
        # side-effect-free: do not run the MCP bootstrap when we're only
        # dumping the prompt text.
        print(build_prompt(host, args.room_url or "", release_sentinel=DEFAULT_RELEASE_SENTINEL))
        return 0
    host.ensure_ready(base=args.base, mcp_name=args.mcp_name, force=args.force)
    if args.install_only:
        return 0
    # Share the same pidfile-lock guardrail as agent_safebot.py so the
    # "one listener per room" invariant holds regardless of which
    # wrapper the user invoked.
    lock = None
    room_id = _room_id_from_url(args.room_url)
    if os.environ.get("SAFEBOT_SKIP_LOCK") != "1":
        lock = RoomLock(room_id)
        lock.acquire()
    prompt = build_prompt(host, args.room_url, release_sentinel=DEFAULT_RELEASE_SENTINEL)
    print(
        f"[codex_safebot] PID={os.getpid()} is the ONLY listener for room "
        f"{room_id} (handle=@{host.handle}). "
        f"Any other Codex/Claude/Gemini session MUST NOT claim_task this handle.",
        file=sys.stderr,
    )
    extras = list(args.codex_args)
    def _argv():
        return host.build_argv(args.room_url, prompt, extras)
    try:
        return respawn_loop(_argv, release_sentinel=DEFAULT_RELEASE_SENTINEL, once=args.once)
    finally:
        if lock is not None: lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
