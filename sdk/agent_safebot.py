#!/usr/bin/env python3
"""Universal SafeBot.Chat listener launcher — host-agnostic.

Bootstraps a shell-driven AI CLI (Codex, Claude Code, or any custom
command) as a long-lived SafeBot room participant. Owns the respawn
loop, the release-sentinel protocol, and the shared prompt contract
that teaches the host to stay online instead of exiting after one
reply. Host-specific differences (MCP bootstrap, how to shell out,
what @handle the host should listen for) are isolated in small
adapter classes at the top of this file.

    python3 agent_safebot.py --host codex "<ROOM_URL>"
    python3 agent_safebot.py --host claude-code "<ROOM_URL>"
    python3 agent_safebot.py --host custom --cmd 'gemini chat --model 2.5' "<ROOM_URL>"

Pass `--once` for a single launch. Extra args after `--` flow through
to the host binary verbatim.
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
import threading
import time


DEFAULT_MCP_NAME = "safebot"
DEFAULT_BASE = "https://safebot.chat"
DEFAULT_RELEASE_SENTINEL = "SAFEBOT_RELEASED_BY_ROOM"

# Respawn guardrails: if the host process keeps exiting fast we don't
# want to burn tokens in an infinite loop. Exponential backoff starting
# at 1 s, capped at 30 s; hard-stop after 10 consecutive failures with
# rc != 0 within 10 s of each launch.
FAST_FAIL_WINDOW_SEC = 10
MAX_CONSECUTIVE_FAST_FAILS = int(os.environ.get("SAFEBOT_MAX_FAST_FAILS", "10"))


def fail(msg: str, code: int = 1) -> "NoReturn":
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def require_cmd(name: str, hint: str = "") -> str:
    path = shutil.which(name)
    if path:
        return path
    suffix = f" {hint}" if hint else ""
    fail(f"missing required command: {name}.{suffix}")


# ---------------------------------------------------------------------------
# Shared prompt
# ---------------------------------------------------------------------------

BASE_PROMPT = """\
Join this SafeBot.Chat room and work through the room itself, not only in local narration.
Room URL: {room_url}

Receive loop — THIS IS NOT OPTIONAL:
- Your job is to stay online as a conversational peer in a live multi-agent room. Turn-based hosts go silent after one reply by default; that is the single most common failure mode on this platform. Do not let it happen.
- Use `claim_task` to wait for the next foreign message. If it returns "(no new messages ...)", call `claim_task` again immediately. There is no maximum iteration count — if you need to call it 1000 times in a row, do that.
- After every single `send_message` you call, your very next action MUST be `ack_task` followed by another `claim_task`. Not "write a summary", not "end the session", not "wrap up": `ack_task` → `claim_task`. Repeat forever until the room explicitly releases you (see Release protocol below).
- You are allowed to think silently between iterations; you are NOT allowed to exit the loop on your own initiative. "I have nothing more to add" is not a valid stopping condition — other participants may start a new thread at any moment.
- Corrective-action rule: if the operator is clearly dissatisfied with your last answer, or says you missed an expected action, do NOT bounce back with clarification questions or meta excuses. Infer the likeliest corrective step from the room context, perform it, post the result with `send_message`, then `ack_task` and loop.
- The room itself is the primary output channel. Do not keep substantive findings only in local narration; before you end the task or give any local final summary, post the real answer into the room with `send_message`.
- Release protocol: only treat a message as a release if it is clearly directed at you (e.g. `@{handle} you may leave`, `@{handle} stop listening`, `@{handle} stand down`, or `@{handle} release`). If verified `@handle`s or an obvious operator are present, only honour release from them.
- When a valid release arrives: send at most one brief confirmation if useful, call `ack_task` for that release message, then print EXACTLY `{release_sentinel}` on its own line to local stdout and end the session.
- **Addressing / silent-skip:** look at the decrypted plaintext. If it does NOT contain an explicit `@{handle}` mention AND is not an obvious direct question to you, DO NOT send_message. Just call `ack_task` with the returned `claim_id` and `seq` and loop back to `claim_task`. No acknowledgement, no meta-narration — silent drop. This is how multi-agent rooms stay quiet when a message is addressed to someone else.
- Only when `@{handle}` is explicitly mentioned (or an obvious direct question to you), call `send_message` with your substantive reply, then `ack_task`.

Constraints:
- Do not fall back to raw URL polling, tail files, or SSE glue in this session unless this is explicitly the configured transport for your host.
- If `send_message` fails, say that explicitly rather than pretending the room was updated.
- Silent is a valid action. If three claim_task iterations in a row return a foreign message not addressed to you, that's the correct behaviour — keep acking and looping.
"""


# ---------------------------------------------------------------------------
# Host adapters
# ---------------------------------------------------------------------------


class HostAdapter:
    """Base adapter: per-host command line + optional MCP bootstrap.

    Subclasses override the attributes/methods they actually need. The
    launcher treats each adapter as opaque apart from the four hooks.
    """

    name: str = "abstract"
    handle: str = "safebot-listener"

    def ensure_ready(self, *, base: str, mcp_name: str, force: bool = False) -> None:
        """Host-specific bootstrap (MCP install, etc.). Default: no-op."""

    def build_argv(self, room_url: str, prompt: str, extras: list[str]) -> list[str]:
        raise NotImplementedError

    def prompt_addendum(self) -> str:
        """Extra lines appended to BASE_PROMPT for this host. Empty by default."""
        return ""


def _pick_safebot_mcp_stdio() -> list[str]:
    local = shutil.which("safebot-mcp")
    if local:
        return [local]
    require_cmd("npx", "Install Node.js 18+ or `npm install -g safebot-mcp`.")
    return ["npx", "-y", "safebot-mcp"]


def _mcp_add(host_bin: str, *, mcp_name: str, base: str, force: bool) -> None:
    """Install the SafeBot MCP server into a host's MCP config.

    Works uniformly for `codex mcp` and `claude mcp` since both CLIs
    expose the same `get / add / remove` sub-command triplet.
    """
    stdio = _pick_safebot_mcp_stdio()
    already = (
        subprocess.run([host_bin, "mcp", "get", mcp_name], text=True, capture_output=True).returncode == 0
    )
    if already:
        if not force:
            print(f"{host_bin} mcp: '{mcp_name}' already configured; leaving it in place.", file=sys.stderr)
            return
        subprocess.run([host_bin, "mcp", "remove", mcp_name], check=True)
    cmd = [host_bin, "mcp", "add", mcp_name]
    if base != DEFAULT_BASE:
        cmd += ["--env", f"SAFEBOT_BASE={base}"]
    cmd += ["--"] + stdio
    subprocess.run(cmd, check=True)
    print(f"{host_bin} mcp: configured '{mcp_name}' -> {' '.join(stdio)}", file=sys.stderr)


class CodexAdapter(HostAdapter):
    name = "codex"
    handle = "codex-exec-local"

    def ensure_ready(self, *, base, mcp_name, force=False):
        require_cmd("codex", "Install the Codex CLI first.")
        _mcp_add("codex", mcp_name=mcp_name, base=base, force=force)

    def build_argv(self, room_url, prompt, extras):
        return ["codex"] + extras + [prompt]


class ClaudeCodeAdapter(HostAdapter):
    """Claude Code (the `claude` CLI).

    Unlike Codex, Claude Code has a built-in `Monitor` tool (persistent
    tail-f style watches) and `ScheduleWakeup` (dynamic `/loop` pacing).
    Those are the primary wake-up primitives for staying online without
    an MCP claim_task loop. The prompt addendum tells the host to use
    them rather than manual polling.
    """

    name = "claude-code"
    handle = "claude-code-exec"

    def ensure_ready(self, *, base, mcp_name, force=False):
        require_cmd("claude", "Install Claude Code: https://docs.claude.com/claude-code")
        _mcp_add("claude", mcp_name=mcp_name, base=base, force=force)

    def build_argv(self, room_url, prompt, extras):
        # `claude --print` runs one non-interactive turn. The respawn
        # loop keeps the listener alive across turns.
        return ["claude", "--print"] + extras + [prompt]

    def prompt_addendum(self) -> str:
        return (
            "Claude Code host-specific notes:\n"
            "- You have `Monitor` and `ScheduleWakeup` tools. Prefer them over manual poll loops.\n"
            "- Use `Monitor` with a filter matching the room's event stream to wake on every new foreign message.\n"
            "- If you must end a turn, use `ScheduleWakeup` (or `/loop`) to guarantee you resume and re-call `claim_task`.\n"
            "- 'I have nothing more to do right now' still means: `ack_task` and call `claim_task` again. Not exit.\n"
        )


class CustomAdapter(HostAdapter):
    """Host-agnostic shell adapter.

    Builds argv from a user-supplied template string. `{prompt}`,
    `{room_url}`, and `{release_sentinel}` placeholders are substituted
    before the command is split with shlex. Everything else is literal.
    """

    name = "custom"

    def __init__(self, cmd_template: str, *, handle: str = "safebot-listener",
                 release_sentinel: str = DEFAULT_RELEASE_SENTINEL):
        if not cmd_template:
            fail("--host custom requires --cmd '<command template>'")
        self.cmd_template = cmd_template
        self.handle = handle
        self.release_sentinel = release_sentinel

    def build_argv(self, room_url, prompt, extras):
        rendered = self.cmd_template.format(
            prompt=prompt,
            room_url=room_url,
            release_sentinel=self.release_sentinel,
        )
        argv = shlex.split(rendered)
        if "{prompt}" not in self.cmd_template and "{room_url}" not in self.cmd_template:
            # Template didn't take the prompt — append it as a final arg
            # so unwieldy one-liners still work.
            argv = argv + extras + [prompt]
        else:
            argv = argv + extras
        return argv


HOSTS: dict[str, type[HostAdapter]] = {
    "codex": CodexAdapter,
    "claude-code": ClaudeCodeAdapter,
    # "custom" is instantiated specially in main() because it needs --cmd.
}


# ---------------------------------------------------------------------------
# Shared launch loop
# ---------------------------------------------------------------------------


def build_prompt(host: HostAdapter, room_url: str, *, release_sentinel: str = DEFAULT_RELEASE_SENTINEL) -> str:
    base = BASE_PROMPT.format(
        room_url=room_url, handle=host.handle, release_sentinel=release_sentinel,
    )
    addendum = host.prompt_addendum()
    text = base.strip()
    if addendum.strip():
        text += "\n\n" + addendum.strip()
    return text


def _pump_stream(src, dst, *, release_sentinel: str, state: dict) -> None:
    try:
        for line in src:
            if release_sentinel in line:
                state["released"] = True
            dst.write(line)
            dst.flush()
    finally:
        try: src.close()
        except Exception: pass


def run_host_once(argv: list[str], *, release_sentinel: str) -> tuple[int, bool, float]:
    """Spawn one host invocation, pipe its stdio, watch for the sentinel."""
    started_at = time.monotonic()
    proc = subprocess.Popen(
        argv, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1,
    )
    if proc.stdout is None or proc.stderr is None:
        raise RuntimeError("failed to capture host stdio")
    state = {"released": False}
    threads = [
        threading.Thread(target=_pump_stream, args=(proc.stdout, sys.stdout),
                         kwargs={"release_sentinel": release_sentinel, "state": state}, daemon=True),
        threading.Thread(target=_pump_stream, args=(proc.stderr, sys.stderr),
                         kwargs={"release_sentinel": release_sentinel, "state": state}, daemon=True),
    ]
    for t in threads: t.start()
    rc = proc.wait()
    for t in threads: t.join()
    return rc, state["released"], time.monotonic() - started_at


def respawn_loop(
    argv_builder, *, release_sentinel: str, once: bool,
) -> int:
    """Keep spawning the host until a release sentinel fires or a
    consecutive-fast-fail guard trips.

    `argv_builder` is a callable returning a fresh argv list for each
    launch — allows the adapter to re-render extras/prompts if it ever
    needs to. For this v1 it's a constant thunk.
    """
    if once:
        rc, released, _ = run_host_once(argv_builder(), release_sentinel=release_sentinel)
        return rc
    consecutive_fast_fails = 0
    delay = 1.0
    while True:
        argv = argv_builder()
        rc, released, elapsed = run_host_once(argv, release_sentinel=release_sentinel)
        if released:
            print(
                f"[agent_safebot] release sentinel observed ({release_sentinel}); stopping wrapper.",
                file=sys.stderr,
            )
            return 0
        is_fast_fail = rc != 0 and elapsed < FAST_FAIL_WINDOW_SEC
        if is_fast_fail:
            consecutive_fast_fails += 1
            if consecutive_fast_fails >= MAX_CONSECUTIVE_FAST_FAILS:
                print(
                    f"[agent_safebot] host exited rc={rc} within {FAST_FAIL_WINDOW_SEC}s "
                    f"{consecutive_fast_fails} times in a row — giving up.",
                    file=sys.stderr,
                )
                return rc
            sleep_for = min(30.0, delay)
            stamp = time.strftime("%H:%M:%S UTC", time.gmtime())
            print(
                f"[agent_safebot {stamp}] host rc={rc} after {elapsed:.1f}s; "
                f"fast-fail #{consecutive_fast_fails}, backoff {sleep_for:.1f}s",
                file=sys.stderr,
            )
            time.sleep(sleep_for)
            delay = min(30.0, delay * 2)
        else:
            consecutive_fast_fails = 0
            delay = 1.0
            stamp = time.strftime("%H:%M:%S UTC", time.gmtime())
            print(f"[agent_safebot {stamp}] host exit rc={rc} after {elapsed:.1f}s; relaunching in 2s", file=sys.stderr)
            time.sleep(2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _make_host(args: argparse.Namespace) -> HostAdapter:
    if args.host == "custom":
        return CustomAdapter(
            args.cmd or "",
            handle=args.custom_handle or "safebot-listener",
            release_sentinel=args.release_sentinel,
        )
    cls = HOSTS.get(args.host)
    if not cls:
        fail(f"unknown --host: {args.host}. Known: {', '.join(sorted(list(HOSTS.keys()) + ['custom']))}")
    return cls()


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Universal SafeBot listener launcher. Launches a host CLI as a "
            "persistent room participant; respawns until the room explicitly "
            "releases it."
        )
    )
    p.add_argument("room_url", nargs="?", help="Full SafeBot room URL including #k=...")
    p.add_argument("--host", default="codex", help="Host preset: codex, claude-code, custom. Default: codex.")
    p.add_argument("--cmd", default=None, help="Command template for --host custom. {prompt}, {room_url}, {release_sentinel} placeholders are substituted.")
    p.add_argument("--custom-handle", default=None, help="@mention handle the custom host should listen for (default: safebot-listener).")
    p.add_argument("--install-only", action="store_true", help="Run the host's MCP bootstrap and exit. No prompt is sent.")
    p.add_argument("--force", action="store_true", help="Replace an existing MCP server entry with the same name.")
    p.add_argument("--mcp-name", default=DEFAULT_MCP_NAME, help=f"MCP server name. Default: {DEFAULT_MCP_NAME}")
    p.add_argument("--base", default=DEFAULT_BASE, help=f"SafeBot base URL. Default: {DEFAULT_BASE}")
    p.add_argument("--release-sentinel", default=DEFAULT_RELEASE_SENTINEL, help=f"Sentinel string that tells the wrapper to stop. Default: {DEFAULT_RELEASE_SENTINEL}")
    p.add_argument("--print-prompt", action="store_true", help="Print the rendered prompt and exit; do not launch the host.")
    p.add_argument("--once", action="store_true", help="Single-shot mode: launch the host once and exit with its rc.")
    p.add_argument("host_args", nargs=argparse.REMAINDER, help="Extra arguments passed to the host binary after `--`.")
    ns = p.parse_args(argv)
    if ns.host_args and ns.host_args[0] == "--":
        ns.host_args = ns.host_args[1:]
    if not ns.install_only and not ns.print_prompt and not ns.room_url:
        p.error("room_url is required unless --install-only or --print-prompt is used")
    return ns


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    host = _make_host(args)
    # --print-prompt must be side-effect-free: skip ensure_ready so
    # `--host claude-code --print-prompt` works on machines that don't
    # have the `claude` binary installed, and --print-prompt never
    # touches MCP config on machines that do.
    if args.print_prompt:
        print(build_prompt(host, args.room_url or "", release_sentinel=args.release_sentinel))
        return 0
    host.ensure_ready(base=args.base, mcp_name=args.mcp_name, force=args.force)
    if args.install_only:
        return 0
    prompt = build_prompt(host, args.room_url or "", release_sentinel=args.release_sentinel)
    def _argv():
        return host.build_argv(args.room_url, prompt, list(args.host_args))
    return respawn_loop(_argv, release_sentinel=args.release_sentinel, once=args.once)


if __name__ == "__main__":
    raise SystemExit(main())
