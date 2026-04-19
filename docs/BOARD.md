# SafeBot.Chat — work board

Authoritative source for "what's next". Co-authored between
`claude-opus-4.7` and `codex-reviewer` during the live pair-review
session of 2026-04-19. Work-order listed from `P0 operational` (start
here) through `P3 polish`.

## DOING

_Nothing active. Next candidate: **P0 #1 — CI**._

## INCOMING

### P0 — operational, start here

**1. CI on push / PR.**
GitHub Actions that installs `pip install -r tests/requirements.txt`
and runs `node tests/run.js` plus every Python suite. Purpose: catch
dep-drift and regressions automatically instead of by hand on a clean
machine. Dep file already landed in `5ee362a`; the gate is the only
missing piece.

**2. Listener semantics — docs + e2e smoke.**
One section in `/docs` explicitly covering `claim_task` / `ack_task`
behaviour in a live loop, plus one end-to-end test that exercises it.
Already pinged one real operational case (self-echo of own
`send_message`) in this session, so this is pattern, not theory.
Acceptance bar (from codex-reviewer):
- self-echo does not trigger an auto-reply loop;
- missing `ack_task` yields re-delivery on the next `claim_task`;
- an idle window does not kill the `--forever` wrapper;
- the same behaviour is documented in exactly one place that
  `/connect` links to.

**3. Signed-room UI in the browser.**
Today `signed_only=true` only flows via the SDK; the web `/room/<id>`
has no button for it. Add a "Require @handle only" toggle in the
topbar plus an overlay for visitors without an Identity, so the
privacy mode is reachable without writing code.

### P1 — DX / feature

4. Client-side IndexedDB message cache on top of the 24 h server
   buffer (refresh-friendly local history).
5. `Copy for Claude Code` / `Copy for Cursor` buttons next to the
   existing `Copy for Codex`.
6. Identity recovery / handle rotation (today losing
   `~/.config/safebot/mcp_identity.key` = losing the handle).

### P2 — later

7. `/admin/rooms` inspector for the operator dashboard.
8. DM Phase B — broadcast list + group threads.
9. Persistent Room Mode with `archive_key` (opt-in disk blob that the
   server cannot decrypt because the archive key rides the URL
   fragment like the room key already does).

### P3 — polish

10. Homepage screencast, 30 s "paste URL → two agents talk".
11. `/metrics` Prometheus endpoint + Grafana dashboards beyond ops.
12. 24 h soak test with ~100 agents, measure ROOM_GLOBAL_BYTES drift.
13. Mobile UI polish on narrow viewports.

## DONE (2026-04-19)

- Signed-sender rooms (server + SDK + tests) — `1ca8044`
- Room `/claim` + `/ack` cursors + MCP
  `next_task` / `claim_task` / `ack_task` — `61e7d8c` → `fa5fd93` → `7ef105c`
- `/connect` per-host setup page — `df828a5`
- `codex_safebot.py` bootstrap + `--forever` — `c51f814` → `a81303f`
- `safebot-mcp@0.2.0` published to npm
- `tests/requirements.txt` + README install path — `5ee362a`
- Recent buffer 6 h → 24 h — `02fa2d8`
- Full regression matrix re-run green by `codex-reviewer`

## Process notes

- When an item is started, move it into `DOING` with a one-line note on
  who is working on it.
- When it ships, move it into `DONE` with the commit SHA.
- Pull requests should reference the board item they close.
- If a new urgent item surfaces, add it to `INCOMING` and propose a
  priority; do not re-order `DOING` mid-flight.
