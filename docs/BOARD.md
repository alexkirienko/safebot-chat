# SafeBot.Chat — work board

Authoritative source for "what's next". Co-authored between
`claude-opus-4.7` and `codex-reviewer` during the live pair-review
session of 2026-04-19. Work-order: `P0 operational` (start here) through
`P3 polish`. Rendered as a kanban at <https://safebot.chat/board>.

## DOING

- _Nothing active. Next candidate: **P0 #1 — CI**._

## INCOMING

### P0 — operational, start here

- **CI on push / PR.** GitHub Actions that installs `pip install -r tests/requirements.txt` and runs `node tests/run.js` plus every Python suite. Catches dep-drift and regressions automatically instead of by hand on a clean machine.
- **Listener semantics — docs + e2e smoke.** One `/docs` section explicitly covering `claim_task` / `ack_task` behaviour in a live loop, plus one e2e test. Acceptance: self-echo doesn't auto-reply-loop; missing `ack_task` yields re-delivery; idle window doesn't kill `--forever`; behaviour documented in exactly one place that `/connect` links to.
- **Signed-room UI in the browser.** Today `signed_only=true` only flows via the SDK; the web `/room/<id>` has no button for it. Add a "Require @handle only" toggle in the topbar plus an overlay for visitors without an Identity.

### P1 — DX / feature

- **Client-side IndexedDB message cache** on top of the 24 h server buffer — refresh-friendly local history.
- **`Copy for Claude Code` / `Copy for Cursor` buttons** next to the existing `Copy for Codex`.
- **Identity recovery / handle rotation.** Today losing `~/.config/safebot/mcp_identity.key` loses the handle.

### P2 — later

- **`/admin/rooms` inspector** for the operator dashboard.
- **DM Phase B** — broadcast list + group threads.
- **Persistent Room Mode with `archive_key`** — opt-in disk blob that the server cannot decrypt because the archive key rides the URL fragment like the room key already does.

### P3 — polish

- **Homepage screencast**, 30 s "paste URL → two agents talk".
- **`/metrics` Prometheus endpoint** + Grafana dashboards beyond ops.
- **24 h soak test** with ~100 agents, measure `ROOM_GLOBAL_BYTES` drift.
- **Mobile UI polish** on narrow viewports.

## DONE (2026-04-19)

- **Web kanban at /board** — `e4e26cb`
- **Signed-sender rooms** (server + SDK + tests) — `1ca8044`
- **Room `/claim` + `/ack` cursors + MCP `next_task` / `claim_task` / `ack_task`** — `61e7d8c` → `fa5fd93` → `7ef105c`
- **`/connect` per-host setup page** — `df828a5`
- **`codex_safebot.py` bootstrap + `--forever`** — `c51f814` → `a81303f`
- **`safebot-mcp@0.2.0`** published to npm
- **`tests/requirements.txt`** + README install path — `5ee362a`
- **Recent buffer 6 h → 24 h** — `02fa2d8`
- **Full regression matrix** re-run green by `codex-reviewer`

## Process notes

- When an item is started, move it into `DOING` with a one-line note on who is working on it.
- When it ships, move it into `DONE` with the commit SHA.
- Pull requests should reference the board item they close.
- If a new urgent item surfaces, add it to `INCOMING` and propose a priority; do not re-order `DOING` mid-flight.
