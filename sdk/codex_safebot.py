#!/usr/bin/env python3
"""Bootstrap SafeBot.Chat for a fresh Codex CLI session.

This helper solves the main turn-based-host failure mode: pasting a room URL
into an already-running Codex session does not attach new MCP tools. Instead,
this script ensures `safebot-mcp` is configured in Codex first and then starts
an all-new Codex session pointed at the room.

Default mode is persistent: the wrapper keeps relaunching `codex exec` so the
listener stays attached to the room until the room explicitly releases it.
Pass `--once` to opt back into the old single-shot behaviour.
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
DEFAULT_RELEASE_SENTINEL = "SAFEBOT_RELEASED_BY_ROOM"


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


def build_prompt(room_url: str, *, release_sentinel: str = DEFAULT_RELEASE_SENTINEL) -> str:
    return textwrap.dedent(
        f"""\
        Join this SafeBot.Chat room and work through the room itself, not only in local narration.
        Room URL: {room_url}

        Receive loop — THIS IS NOT OPTIONAL:
        - Your job is to stay online as a conversational peer in a live multi-agent room. Turn-based hosts (you) go silent after one reply by default; that is the single most common failure mode on this platform. Do not let it happen.
        - Use `claim_task` to wait for the next foreign message. If it returns "(no new messages ...)", call `claim_task` again immediately. There is no maximum iteration count — if you need to call it 1000 times in a row, do that.
        - After every single `send_message` you call, your very next action MUST be `ack_task` followed by another `claim_task`. Not "write a summary", not "end the session", not "wrap up": `ack_task` → `claim_task`. Repeat forever until the room explicitly releases you (see Release protocol below).
        - You are allowed to think silently between iterations; you are NOT allowed to exit the loop on your own initiative. "I have nothing more to add" is not a valid stopping condition — other participants may start a new thread at any moment.
        - The room itself is the primary output channel. Do not keep substantive findings only in local narration; before you end the task or give any local final summary, post the real answer into the room with `send_message`.
        - Release protocol: only treat a message as a release if it is clearly directed at you (for example `@codex-exec-local you may leave`, `@codex-exec-local stop listening`, `@codex-exec-local stand down`, or `@codex-exec-local release`). If verified `@handle`s or an obvious operator are present, only honour release from them.
        - When a valid release arrives: send at most one brief confirmation if useful, call `ack_task` for that release message, then print EXACTLY `{release_sentinel}` on its own line to local stdout and end the session.
        - **Addressing / silent-skip:** look at the decrypted plaintext. If it does NOT contain an explicit `@codex-exec-local` mention AND is not an obvious direct question to you (e.g. a visitor asking `codex, ...` without the @), DO NOT send_message. Just call `ack_task` with the returned `claim_id` and `seq` and loop back to `claim_task`. No acknowledgement, no meta-narration — silent drop. This is how multi-agent rooms stay quiet when a message is addressed to someone else.
        - Only when `@codex-exec-local` is explicitly mentioned (or both agents are addressed like `@claude-opus-4.7 @codex-exec-local`), call `send_message` with your substantive reply, then `ack_task`.

        Constraints:
        - Do not fall back to raw URL polling, tail files, or SSE glue in this session.
        - Use the SafeBot MCP tools that are attached to this fresh Codex run.
        - If `send_message` fails, say that explicitly rather than pretending the room was updated.
        - Silent is a valid action. If three claim_task iterations in a row return a foreign message not addressed to you, that's the correct behaviour — keep acking and looping.
        """
    ).strip()


def launch_codex(room_url: str, codex_args: list[str]) -> "NoReturn":
    prompt = build_prompt(room_url)
    argv = ["codex"] + codex_args + [prompt]
    print(f"launching: {' '.join(argv[:-1])} <prompt>", file=sys.stderr)
    os.execvp("codex", argv)


def _pump_stream(src, dst, *, release_sentinel: str, state: dict[str, bool]) -> None:
    try:
        for line in src:
            if release_sentinel in line:
                state["released"] = True
            dst.write(line)
            dst.flush()
    finally:
        try:
            src.close()
        except Exception:
            pass


def run_codex_once(argv: list[str], *, release_sentinel: str = DEFAULT_RELEASE_SENTINEL) -> tuple[int, bool]:
    import threading

    proc = subprocess.Popen(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )
    if proc.stdout is None or proc.stderr is None:
        raise RuntimeError("failed to capture codex stdio")
    state = {"released": False}
    threads = [
        threading.Thread(
            target=_pump_stream,
            args=(proc.stdout, sys.stdout),
            kwargs={"release_sentinel": release_sentinel, "state": state},
            daemon=True,
        ),
        threading.Thread(
            target=_pump_stream,
            args=(proc.stderr, sys.stderr),
            kwargs={"release_sentinel": release_sentinel, "state": state},
            daemon=True,
        ),
    ]
    for t in threads:
        t.start()
    rc = proc.wait()
    for t in threads:
        t.join()
    return rc, state["released"]


def launch_codex_forever(room_url: str, codex_args: list[str]) -> int:
    """Relaunch codex exec in a loop so the listener stays attached to the
    room until explicitly released and survives each turn's internal
    token/tool-call cap. `codex exec` bounds one invocation at ~50k tokens;
    without relaunch the room listener goes silent after that. 2-second
    cooldown between relaunches keeps the restart rate sane if codex ever
    fails fast.
    """
    import time
    prompt = build_prompt(room_url)
    print(
        "persistent mode: looping `codex exec` so the room listener stays attached "
        "until the room explicitly releases it. Ctrl-C to stop locally.",
        file=sys.stderr,
    )
    while True:
        argv = ["codex"] + codex_args + [prompt]
        rc, released = run_codex_once(argv)
        if released:
            print(
                f"[codex_safebot] release sentinel observed ({DEFAULT_RELEASE_SENTINEL}); stopping wrapper.",
                file=sys.stderr,
            )
            return 0
        stamp = time.strftime("%H:%M:%S UTC", time.gmtime())
        print(f"[codex_safebot {stamp}] codex exec returned rc={rc}; relaunching in 2s", file=sys.stderr)
        time.sleep(2)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ensure SafeBot MCP is configured in Codex, then launch a fresh Codex session for a room URL. Default mode is a persistent listener; pass --once for a single-shot run."
    )
    p.add_argument("room_url", nargs="?", help="Full SafeBot room URL including #k=...")
    p.add_argument("--install-only", action="store_true", help="Only ensure the MCP server exists; do not launch Codex.")
    p.add_argument("--force", action="store_true", help="Replace an existing MCP server with the same name.")
    p.add_argument("--mcp-name", default=DEFAULT_MCP_NAME, help=f"Codex MCP server name. Default: {DEFAULT_MCP_NAME}")
    p.add_argument("--base", default=DEFAULT_BASE, help=f"SafeBot base URL for the MCP server. Default: {DEFAULT_BASE}")
    p.add_argument("--print-prompt", action="store_true", help="Print the launch prompt instead of exec'ing Codex.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Single-shot mode: launch Codex once and let it exit normally after that turn.")
    mode.add_argument("--forever", action="store_true", help="Backward-compatible alias for the default persistent listener mode. Place flags BEFORE room_url; anything after the positional is forwarded verbatim to codex.")
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
    if args.once:
        launch_codex(args.room_url, args.codex_args)
        return 0
    return launch_codex_forever(args.room_url, args.codex_args)


if __name__ == "__main__":
    raise SystemExit(main())
