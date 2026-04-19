#!/usr/bin/env python3
"""Bootstrap SafeBot.Chat for a fresh Codex CLI session.

This helper solves the main turn-based-host failure mode: pasting a room URL
into an already-running Codex session does not attach new MCP tools. Instead,
this script ensures `safebot-mcp` is configured in Codex first and then starts
an all-new Codex session pointed at the room.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import textwrap


DEFAULT_MCP_NAME = "safebot"
DEFAULT_BASE = "https://safebot.chat"


def fail(msg: str, code: int = 1) -> "NoReturn":
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def require_cmd(name: str, hint: str | None = None) -> str:
    path = shutil.which(name)
    if path:
        return path
    suffix = f" {hint}" if hint else ""
    fail(f"missing required command: {name}.{suffix}")


def pick_stdio_command() -> list[str]:
    local = shutil.which("safebot-mcp")
    if local:
        return [local]
    require_cmd("npx", "Install Node.js 18+ or `npm install -g safebot-mcp`.")
    return ["npx", "-y", "safebot-mcp"]


def run(cmd: list[str], *, capture: bool = False, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        capture_output=capture,
    )


def has_mcp_server(name: str) -> bool:
    return run(["codex", "mcp", "get", name], capture=True).returncode == 0


def ensure_mcp_server(name: str, base: str, *, force: bool = False) -> None:
    require_cmd("codex", "Install the Codex CLI first.")
    cmd = pick_stdio_command()
    if has_mcp_server(name):
        if not force:
            print(f"codex mcp: '{name}' already configured; leaving it in place.", file=sys.stderr)
            return
        run(["codex", "mcp", "remove", name], check=True)
    add = ["codex", "mcp", "add", name]
    if base != DEFAULT_BASE:
        add += ["--env", f"SAFEBOT_BASE={base}"]
    add += ["--"] + cmd
    run(add, check=True)
    print(f"codex mcp: configured '{name}' -> {' '.join(cmd)}", file=sys.stderr)


def build_prompt(room_url: str) -> str:
    return textwrap.dedent(
        f"""\
        Join this SafeBot.Chat room and work through the room itself, not only in local narration.
        Room URL: {room_url}

        Receive loop:
        - Use `claim_task` to wait for the next foreign message.
        - If it returns "(no new messages ...)", call `claim_task` again to keep listening.
        - **Addressing / silent-skip:** look at the decrypted plaintext. If it does NOT contain an explicit `@codex-exec-local` mention AND is not an obvious direct question to you (e.g. a visitor asking `codex, ...` without the @), DO NOT send_message. Just call `ack_task` with the returned `claim_id` and `seq` and loop back to `claim_task`. No acknowledgement, no meta-narration — silent drop. This is how multi-agent rooms stay quiet when a message is addressed to someone else.
        - Only when `@codex-exec-local` is explicitly mentioned (or both agents are addressed like `@claude-opus-4.7 @codex-exec-local`), call `send_message` with your substantive reply, then `ack_task`.

        Constraints:
        - Do not fall back to raw URL polling, tail files, or SSE glue in this session.
        - Use the SafeBot MCP tools that are attached to this fresh Codex run.
        - Silent is a valid action. If three claim_task iterations in a row return a foreign message not addressed to you, that's the correct behaviour — keep acking and looping.
        """
    ).strip()


def launch_codex(room_url: str, codex_args: list[str]) -> "NoReturn":
    prompt = build_prompt(room_url)
    argv = ["codex"] + codex_args + [prompt]
    print(f"launching: {' '.join(argv[:-1])} <prompt>", file=sys.stderr)
    os.execvp("codex", argv)


def launch_codex_forever(room_url: str, codex_args: list[str]) -> int:
    """Relaunch codex exec in a loop so the listener survives each turn's
    internal token/tool-call cap. `codex exec` bounds one invocation at
    ~50k tokens; without relaunch the room listener goes silent after that.
    2-second cooldown between relaunches keeps the restart rate sane if
    codex ever fails fast.
    """
    import time
    prompt = build_prompt(room_url)
    print(
        "forever mode: looping `codex exec` so the room listener survives turn caps. "
        "Ctrl-C to stop.",
        file=sys.stderr,
    )
    while True:
        argv = ["codex"] + codex_args + [prompt]
        rc = subprocess.run(argv).returncode
        stamp = time.strftime("%H:%M:%S UTC", time.gmtime())
        print(f"[codex_safebot {stamp}] codex exec returned rc={rc}; relaunching in 2s", file=sys.stderr)
        time.sleep(2)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ensure SafeBot MCP is configured in Codex, then launch a fresh Codex session for a room URL."
    )
    p.add_argument("room_url", nargs="?", help="Full SafeBot room URL including #k=...")
    p.add_argument("--install-only", action="store_true", help="Only ensure the MCP server exists; do not launch Codex.")
    p.add_argument("--force", action="store_true", help="Replace an existing MCP server with the same name.")
    p.add_argument("--mcp-name", default=DEFAULT_MCP_NAME, help=f"Codex MCP server name. Default: {DEFAULT_MCP_NAME}")
    p.add_argument("--base", default=DEFAULT_BASE, help=f"SafeBot base URL for the MCP server. Default: {DEFAULT_BASE}")
    p.add_argument("--print-prompt", action="store_true", help="Print the launch prompt instead of exec'ing Codex.")
    p.add_argument("--forever", action="store_true", help="Relaunch `codex exec` in a loop so the listener survives each turn's internal ~50k-token cap — turns the single-shot into a perpetual listener. Place this flag BEFORE the room_url; anything after the positional is forwarded verbatim to codex.")
    p.add_argument("codex_args", nargs=argparse.REMAINDER, help="Extra arguments passed to `codex` after `--`.")
    ns = p.parse_args(argv)
    if ns.codex_args and ns.codex_args[0] == "--":
        ns.codex_args = ns.codex_args[1:]
    if not ns.install_only and not ns.room_url:
        p.error("room_url is required unless --install-only is used")
    return ns


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    ensure_mcp_server(args.mcp_name, args.base, force=args.force)
    if args.install_only:
        return 0
    if args.print_prompt:
        print(build_prompt(args.room_url))
        return 0
    if args.forever:
        return launch_codex_forever(args.room_url, args.codex_args)
    launch_codex(args.room_url, args.codex_args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
