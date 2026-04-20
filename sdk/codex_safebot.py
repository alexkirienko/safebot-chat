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
    p.add_argument("--install-only", action="store_true", help="Only ensure the MCP server exists; do not launch Codex.")
    p.add_argument("--force", action="store_true", help="Replace an existing MCP server with the same name.")
    p.add_argument("--mcp-name", default=DEFAULT_MCP_NAME, help=f"Codex MCP server name. Default: {DEFAULT_MCP_NAME}")
    p.add_argument("--base", default=DEFAULT_BASE, help=f"SafeBot base URL for the MCP server. Default: {DEFAULT_BASE}")
    p.add_argument("--print-prompt", action="store_true", help="Print the launch prompt instead of exec'ing Codex.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Single-shot mode: launch Codex once and let it exit normally after that turn.")
    mode.add_argument("--forever", action="store_true", help="Backward-compatible alias for the default persistent listener mode.")
    p.add_argument("codex_args", nargs=argparse.REMAINDER, help="Extra arguments passed to `codex` after `--`.")
    ns = p.parse_args(argv)
    if ns.codex_args and ns.codex_args[0] == "--":
        ns.codex_args = ns.codex_args[1:]
    if not ns.install_only and not ns.room_url:
        p.error("room_url is required unless --install-only is used")
    return ns


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    host = CodexAdapter()
    if args.print_prompt:
        # side-effect-free: do not run the MCP bootstrap when we're only
        # dumping the prompt text.
        print(build_prompt(host, args.room_url, release_sentinel=DEFAULT_RELEASE_SENTINEL))
        return 0
    host.ensure_ready(base=args.base, mcp_name=args.mcp_name, force=args.force)
    if args.install_only:
        return 0
    prompt = build_prompt(host, args.room_url, release_sentinel=DEFAULT_RELEASE_SENTINEL)
    extras = list(args.codex_args)
    def _argv():
        return host.build_argv(args.room_url, prompt, extras)
    return respawn_loop(_argv, release_sentinel=DEFAULT_RELEASE_SENTINEL, once=args.once)


if __name__ == "__main__":
    raise SystemExit(main())
