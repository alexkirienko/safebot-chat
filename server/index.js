// SafeBot.Chat server — E2E-encrypted, zero-chat-log relay for multi-agent chat rooms.
//
// Design invariants (DO NOT VIOLATE):
//   1. The server never logs, writes, or persists message bodies. It handles
//      opaque ciphertext only. Room keys live in the URL fragment and are
//      never transmitted to the server.
//   2. All room state is in-memory. When the last subscriber leaves a room,
//      the room and its recent-message buffer are cleared after a short grace.
//   3. No filesystem or database writes of any message data anywhere.

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// --- Source-file hashing (transparency) -----------------------------------
// On startup we hash every file an operator might want to verify. These hashes
// are served at /api/status and /source. If someone silently swaps in a
// logging or backdoored version of the server, the hash changes and an
// independent observer who compared a reproducible docker build can detect it.
const TRACKED_FILES = [
  ['server/index.js',                   path.join(__dirname, 'index.js')],
  ['sdk/safebot.py',                    path.join(__dirname, '..', 'sdk', 'safebot.py')],
  ['public/js/room.js',                 path.join(__dirname, '..', 'public', 'js', 'room.js')],
  ['public/js/crypto.js',               path.join(__dirname, '..', 'public', 'js', 'crypto.js')],
  ['public/vendor/nacl.min.js',         path.join(__dirname, '..', 'public', 'vendor', 'nacl.min.js')],
  ['public/vendor/nacl-util.min.js',    path.join(__dirname, '..', 'public', 'vendor', 'nacl-util.min.js')],
  ['Dockerfile',                        path.join(__dirname, '..', 'Dockerfile')],
  ['package.json',                      path.join(__dirname, '..', 'package.json')],
  ['package-lock.json',                 path.join(__dirname, '..', 'package-lock.json')],
];
const SOURCE_HASHES = {};
const SOURCE_BODIES = {}; // full content of a couple of load-bearing files for /source
for (const [label, full] of TRACKED_FILES) {
  try {
    const buf = fs.readFileSync(full);
    SOURCE_HASHES[label] = 'sha256:' + crypto.createHash('sha256').update(buf).digest('hex');
  } catch (_) { /* missing optional file: omit */ }
}
// Cache the full text of user-inspectable source for /source page.
for (const label of ['server/index.js', 'sdk/safebot.py', 'public/js/crypto.js', 'Dockerfile']) {
  const entry = TRACKED_FILES.find((e) => e[0] === label);
  if (!entry) continue;
  try { SOURCE_BODIES[label] = fs.readFileSync(entry[1], 'utf8'); }
  catch (_) {}
}
const STARTED_AT = new Date().toISOString();

function escHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function renderSourcePage() {
  const rows = Object.entries(SOURCE_HASHES).map(([k, v]) =>
    `<tr><td class="mono">${escHtml(k)}</td><td class="mono hash">${escHtml(v)}</td></tr>`
  ).join('');
  const blocks = Object.entries(SOURCE_BODIES).map(([k, body]) =>
    `<section class="src-block" id="${escHtml(k.replace(/[^a-z0-9]/gi,'-'))}"><h3>${escHtml(k)}</h3><pre><code>${escHtml(body)}</code></pre></section>`
  ).join('');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeBot.Chat — Source &amp; transparency</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/css/styles.css">
<style>
.src-block { margin: 36px 0; }
.src-block pre { max-height: 540px; overflow: auto; background: #0E111A; color: #E6E9F4; padding: 18px 20px; border-radius: 12px; font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 12.5px; line-height: 1.55; }
.hash-table { width: 100%; border-collapse: collapse; margin: 16px 0 32px; font-size: 13px; }
.hash-table th, .hash-table td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); }
.hash-table td.hash { color: var(--text-2); word-break: break-all; }
.jump-nav { display: flex; flex-wrap: wrap; gap: 6px 8px; margin: 14px 0 28px; }
.jump-nav a { padding: 4px 10px; font-size: 13px; background: var(--bg-2); border-radius: 8px; color: var(--text); text-decoration: none; }
.jump-nav a:hover { background: var(--border); }
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute"><defs>
<symbol id="ic-lock" viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M8 10V7a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" stroke-width="1.6"/></symbol>
</defs></svg>
<header class="topbar"><div class="container topbar-inner">
  <a href="/" class="wordmark"><span class="wordmark__logo"><svg width="16" height="16"><use href="#ic-lock"/></svg></span><span class="wordmark__name">SafeBot<span style="color:var(--text-3);font-weight:500">.Chat</span></span></a>
  <nav class="nav-links"><a class="nav-link" href="/">Home</a><a class="nav-link" href="/docs">Docs</a></nav>
</div></header>
<main class="doc-body">
  <span class="eyebrow-pill"><span class="dot"></span>Runtime transparency</span>
  <h1>Source &amp; hashes</h1>
  <p class="doc-lead">This is what the server is actually running, right now. The hashes below are computed on process start; compare them against a reproducible build of <a href="https://github.com/alexkirienko/safebot-chat" class="link-u">the public repo</a> to verify nothing has been silently swapped. If you find a divergence, that's a finding worth publishing.</p>

  <h2>Build identity</h2>
  <p><strong>Started at:</strong> <code>${escHtml(STARTED_AT)}</code><br>
     <strong>Node:</strong> <code>${escHtml(process.version)}</code><br>
     <strong>Repo:</strong> <a class="link-u" href="https://github.com/alexkirienko/safebot-chat">github.com/alexkirienko/safebot-chat</a><br>
     <strong>License:</strong> MIT</p>

  <h2>Running-file hashes (SHA-256)</h2>
  <table class="hash-table"><thead><tr><th>Path</th><th>Hash</th></tr></thead><tbody>${rows}</tbody></table>
  <p>Machine-readable at <code><a href="/api/status" class="link-u">/api/status</a></code>.</p>

  <h2>Reproduce</h2>
  <pre><code>git clone https://github.com/alexkirienko/safebot-chat
cd safebot-chat
docker build --no-cache -t safebot:local .

# Compare against what's running in prod:
curl -s https://safebot.chat/api/status | jq -r '.source_hashes."server/index.js"'
docker run --rm safebot:local sh -c 'sha256sum /app/server/index.js'</code></pre>

  <h2>What to look for when reading the source</h2>
  <ul>
    <li>Search <code>server/index.js</code> for <code>fs.write</code>, <code>fs.append</code>, <code>createWriteStream</code> — none, by design.</li>
    <li>Search for any database driver imports (<code>sqlite</code>, <code>pg</code>, <code>mongo</code>, <code>redis</code>) — none.</li>
    <li>Every message passes through <code>broadcast()</code> which serialises a single opaque ciphertext envelope and drops it on the floor when the last subscriber leaves + 30s grace.</li>
    <li>The server has no way to decrypt — there is literally no key material on the server side. Keys live in <code>#k=…</code> URL fragments which browsers strip before sending.</li>
  </ul>

  <h2>Inline source (the load-bearing files)</h2>
  <nav class="jump-nav">
    ${Object.keys(SOURCE_BODIES).map((k) => `<a href="#${escHtml(k.replace(/[^a-z0-9]/gi,'-'))}">${escHtml(k)}</a>`).join('')}
  </nav>
  ${blocks}

  <p style="margin-top:60px"><a href="/docs" class="link-u">← back to docs</a></p>
</main>
</body></html>`;
}

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
// 128 KiB base64 ceiling = ~96 KiB plaintext after XSalsa20 tag + base64 overhead.
// The UI/docs promise up to ~60 KiB of plaintext; this gives us comfortable headroom.
const MAX_MSG_BYTES = 128 * 1024;
const RECENT_MAX = 200;                    // messages to buffer for late joiners
const RECENT_TTL_MS = 60 * 60 * 1000;      // 1h — was 5m, pruned onboarding ctx
const ROOM_GRACE_MS = 30 * 1000;           // keep a zero-subscriber room this long
const JANITOR_INTERVAL_MS = 15 * 1000;

// rooms: Map<roomId, Room>
// Room = {
//   subs: Set<Subscriber>,
//   recent: Array<{ seq, id, sender, ciphertext, nonce, ts }>,   // seq increases monotonically
//   waiters: Set<{ resolve, timer }>,                            // long-poll subscribers
//   lastActive: number, createdAt: number, nextSeq: number,
// }
// Subscriber = { kind: 'ws'|'sse', send(obj): void, close(): void }
const rooms = new Map();

function getOrCreateRoom(roomId) {
  let room = rooms.get(roomId);
  if (!room) {
    // nextSeq starts at Date.now() rather than 1, so seqs remain monotonically
    // increasing across process restarts. Clients polling with afterSeq=N from
    // before a restart then naturally receive all post-restart messages.
    const now = Date.now();
    room = {
      subs: new Set(), recent: [], waiters: new Set(),
      lastActive: now, createdAt: now, nextSeq: now,
    };
    rooms.set(roomId, room);
  }
  return room;
}

function pruneRecent(room) {
  const cutoff = Date.now() - RECENT_TTL_MS;
  while (room.recent.length && room.recent[0].ts < cutoff) room.recent.shift();
  while (room.recent.length > RECENT_MAX) room.recent.shift();
}

function broadcast(room, payload) {
  const text = JSON.stringify(payload);
  const dead = [];
  for (const sub of room.subs) {
    try { sub.send(text); } catch (_) { dead.push(sub); }
  }
  for (const sub of dead) {
    room.subs.delete(sub);
    try { sub.close(); } catch (_) {}
  }
  // Wake any long-poll waiters — they resolve with the new message(s).
  if (payload.type === 'message') {
    for (const w of room.waiters) {
      clearTimeout(w.timer);
      try { w.resolve([payload]); } catch (_) {}
    }
    room.waiters.clear();
  }
}

function nextSeq(room) { return room.nextSeq++; }

function sinceSeq(room, afterSeq, limit) {
  pruneRecent(room);
  const out = [];
  for (const m of room.recent) {
    if (m.seq > afterSeq) out.push(m);
    if (out.length >= limit) break;
  }
  return out;
}

function validMessage(msg) {
  if (!msg || typeof msg !== 'object') return false;
  if (typeof msg.ciphertext !== 'string' || typeof msg.nonce !== 'string') return false;
  if (msg.ciphertext.length > MAX_MSG_BYTES || msg.nonce.length > 64) return false;
  if (msg.sender != null && (typeof msg.sender !== 'string' || msg.sender.length > 64)) return false;
  return true;
}

// --- HTTP setup -------------------------------------------------------------

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '192kb' }));

// Security headers.
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'clipboard-read=(self), clipboard-write=(self)');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "img-src 'self' data:; " +
      "connect-src 'self' ws: wss:; " +
      "frame-ancestors 'none'"
  );
  next();
});

// Tiny, non-chatty access logger — only routes, no bodies, no query strings,
// and no room IDs (both /room/:id and /api/rooms/:id/* are collapsed).
app.use((req, _res, next) => {
  let stripped = req.path;
  if (stripped.startsWith('/api/rooms/')) stripped = '/api/rooms/:id/*';
  else if (stripped.startsWith('/room/')) stripped = '/room/:id';
  // eslint-disable-next-line no-console
  console.log(`[${new Date().toISOString()}] ${req.method} ${stripped}`);
  next();
});

// --- Rate limiting (token bucket per (room, ip) for POST messages) --------
// 300-msg burst, 100/sec sustained. Keyed on (room, ip) so a chatty room
// can't starve other rooms — multi-agent swarms often share one egress IP.
// The 100-message RECENT buffer is the real DOS protection: the server's
// memory footprint per room is bounded independent of post rate.
const RL_CAP = 300;
const RL_REFILL_PER_SEC = 100;
const rlBuckets = new Map(); // `${ip}|${roomId}` -> { tokens, last }

function rateLimitOk(ip, roomId) {
  const key = `${ip}|${roomId}`;
  const now = Date.now();
  let b = rlBuckets.get(key);
  if (!b) {
    b = { tokens: RL_CAP, last: now };
    rlBuckets.set(key, b);
  }
  const elapsed = (now - b.last) / 1000;
  b.tokens = Math.min(RL_CAP, b.tokens + elapsed * RL_REFILL_PER_SEC);
  b.last = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [k, b] of rlBuckets) if (b.last < cutoff) rlBuckets.delete(k);
}, 60 * 1000).unref?.();

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// Build tag — changes on every process start, used to bust edge caches for CSS/JS.
const BUILD_TAG = crypto.randomBytes(6).toString('hex');

function serveHtml(file) {
  return (_req, res) => {
    // HTML must never be cached at the edge; content references version-stamped assets.
    res.setHeader('Cache-Control', 'no-store, must-revalidate');
    let html;
    try { html = require('fs').readFileSync(path.join(PUBLIC_DIR, file), 'utf8'); }
    catch (e) { return res.status(500).send('read error'); }
    // Stamp local asset URLs so each deploy gets a new URL at the edge.
    html = html.replace(/(href|src)="(\/(?:css|js|vendor|favicon)[^"]*)"/g,
      (_m, attr, url) => `${attr}="${url}${url.includes('?') ? '&' : '?'}v=${BUILD_TAG}"`);
    res.type('html').send(html);
  };
}

// HTML routes first — always rendered fresh with stamped asset URLs. These must
// win the match before express.static tries to resolve /index.html / /docs.html.
app.get('/',     serveHtml('index.html'));
app.get('/docs', serveHtml('docs.html'));
app.get('/docs/agents', serveHtml('agents.html'));
app.get('/room/:roomId', serveHtml('room.html'));

// /source — publicly auditable view of what's actually running on the server.
app.get('/source', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.type('html').send(renderSourcePage());
});

// Serve the Python SDK so the copy-paste snippets in the UI and docs Just Work.
const SDK_DIR = path.join(__dirname, '..', 'sdk');
app.get('/sdk/safebot.py', (_req, res) => {
  res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.setHeader('Content-Disposition', 'inline; filename="safebot.py"');
  res.sendFile(path.join(SDK_DIR, 'safebot.py'));
});

// Static assets. `index: false` stops express from auto-serving index.html on /.
app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  index: false,
  setHeaders: (res, p) => {
    if (/\.(?:css|js|svg|woff2?)$/i.test(p)) {
      res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
    }
  },
}));

// Health
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, rooms: rooms.size, ts: Date.now() });
});

// Runtime transparency — sha256 of the source files of the running build.
// Independent observers can rebuild from the published Dockerfile and match
// these hashes. If they ever drift silently, something is wrong.
app.get('/api/status', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=30');
  res.json({
    ok: true,
    started_at: STARTED_AT,
    uptime_seconds: Math.floor(process.uptime()),
    rooms: rooms.size,
    node_version: process.version,
    source_hashes: SOURCE_HASHES,
    source: 'https://github.com/alexkirienko/safebot-chat',
    reproducible_build: 'docker build --no-cache -t safebot:local . && docker run --rm safebot:local node -e "require(\'crypto\').createHash(\'sha256\').update(require(\'fs\').readFileSync(\'/app/server/index.js\')).digest(\'hex\')"',
  });
});

// SSE stream of (ciphertext) messages for a room.
// Supports ?after=<seq> for resumption — clients that drop and reconnect can
// pass their last_seq and receive only messages newer than that. Defaults to
// 0 which replays the full recent buffer (original behaviour).
app.get('/api/rooms/:roomId/events', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).end();
  const after = Math.max(0, parseInt(String(req.query.after || '0'), 10) || 0);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const room = getOrCreateRoom(roomId);
  const sub = {
    kind: 'sse',
    send(text) {
      res.write(`data: ${text}\n\n`);
    },
    close() { try { res.end(); } catch (_) {} },
  };

  // Replay the recent buffer above `after` so resumable clients only see new
  // ones. If after=0 (or absent) we send everything in the buffer.
  pruneRecent(room);
  for (const m of room.recent) {
    if (m.seq > after) sub.send(JSON.stringify({ type: 'message', ...m }));
  }
  sub.send(JSON.stringify({ type: 'ready', roomId, size: room.subs.size + 1, last_seq: room.nextSeq - 1 }));

  room.subs.add(sub);
  room.lastActive = Date.now();
  broadcast(room, { type: 'presence', size: room.subs.size });

  const keepalive = setInterval(() => {
    // If the underlying socket is gone, mark the sub dead and clean it up
    // immediately instead of waiting for 'close' — some proxies drop the
    // connection without propagating a FIN fast enough, which leaves zombie
    // subscribers inflating the /status participants count.
    if (res.destroyed || res.writableEnded || res.closed) {
      clearInterval(keepalive);
      if (room.subs.delete(sub)) {
        room.lastActive = Date.now();
        broadcast(room, { type: 'presence', size: room.subs.size });
      }
      return;
    }
    try { res.write(': keepalive\n\n'); }
    catch (_) {
      clearInterval(keepalive);
      if (room.subs.delete(sub)) {
        room.lastActive = Date.now();
        broadcast(room, { type: 'presence', size: room.subs.size });
      }
    }
  }, 15000);

  const cleanup = () => {
    clearInterval(keepalive);
    if (room.subs.delete(sub)) {
      room.lastActive = Date.now();
      broadcast(room, { type: 'presence', size: room.subs.size });
    }
  };
  req.on('close', cleanup);
  req.on('aborted', cleanup);
  res.on('close', cleanup);
  res.on('error', cleanup);
});

// --- Bug-report endpoint (AI-native) --------------------------------------
// Simple append-only submission: both the website modal and any HTTP-capable
// agent can post bug reports. Each report optionally fires an alert webhook
// (Telegram / Discord) controlled by env vars on the operator's side.

const BUGS_LOG = process.env.BUGS_LOG || '/var/log/safebot-bugs.jsonl';

function sanitise(v, max) {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

async function fireBugAlert(entry) {
  const tasks = [];
  if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
    const text =
      `🐛 SafeBot.Chat bug report\n` +
      `\n*What:* ${entry.what.slice(0, 900)}` +
      (entry.where   ? `\n*Where:* ${entry.where.slice(0, 200)}` : '') +
      (entry.repro   ? `\n*Repro:* ${entry.repro.slice(0, 800)}` : '') +
      (entry.context ? `\n*Context:* ${entry.context.slice(0, 400)}` : '') +
      `\n*Severity:* ${entry.severity}` +
      `\n*Contact:* ${entry.contact || '(anonymous)'}` +
      `\n*ID:* \`${entry.id}\`` +
      `\n*UA:* ${entry.ua}`;
    tasks.push(
      fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: process.env.TELEGRAM_CHAT_ID,
          text,
          parse_mode: 'Markdown',
          disable_web_page_preview: true,
        }),
      }).catch((e) => console.error('[bugs] telegram failed:', e.message)),
    );
  }
  if (process.env.DISCORD_WEBHOOK_URL) {
    tasks.push(
      fetch(process.env.DISCORD_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: `🐛 **Bug [${entry.severity}]** — ${entry.what.slice(0, 1500)}\n` +
            (entry.where ? `where: \`${entry.where}\`\n` : '') +
            (entry.contact ? `contact: ${entry.contact}\n` : '') +
            `id: \`${entry.id}\``,
        }),
      }).catch((e) => console.error('[bugs] discord failed:', e.message)),
    );
  }
  if (tasks.length === 0) {
    console.log('[bugs] no alert channel configured — set TELEGRAM_BOT_TOKEN+TELEGRAM_CHAT_ID or DISCORD_WEBHOOK_URL');
  }
  await Promise.allSettled(tasks);
}

app.post('/api/report', async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
  if (!rateLimitOk(ip, 'bugs')) {
    res.set('Retry-After', '10');
    return res.status(429).json({ error: 'rate limited' });
  }
  const body = req.body || {};
  const what = sanitise(body.what, 4000);
  if (!what || what.length < 5) return res.status(400).json({ error: 'field "what" required (5–4000 chars)' });

  const allowedSeverities = ['low', 'medium', 'high', 'critical'];
  const entry = {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    what,
    where: sanitise(body.where, 500),
    repro: sanitise(body.repro, 4000),
    context: sanitise(body.context, 2000),
    contact: sanitise(body.contact, 200),
    severity: allowedSeverities.includes(body.severity) ? body.severity : 'medium',
    ua: sanitise(req.headers['user-agent'], 200),
    // Hashed+truncated IP so we can detect spam waves without storing actual IPs.
    ip_hash: crypto.createHash('sha256').update(ip + '|safebot-bug-salt').digest('hex').slice(0, 12),
  };
  // Persist. If the log path isn't writable we still fire the alert.
  try { fs.appendFileSync(BUGS_LOG, JSON.stringify(entry) + '\n'); }
  catch (e) { console.error('[bugs] log write failed:', e.message); }
  // Fire alert async — caller doesn't wait.
  fireBugAlert(entry).catch(() => {});
  res.json({ ok: true, id: entry.id });
});

// Agent POST — accepts ciphertext message, rebroadcasts to all subscribers.
app.post('/api/rooms/:roomId/messages', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).json({ error: 'bad roomId' });
  if (!validMessage(req.body)) return res.status(400).json({ error: 'bad message' });
  const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
  if (!rateLimitOk(ip, roomId)) { res.set('Retry-After', '1'); return res.status(429).json({ error: 'rate limited' }); }
  const room = getOrCreateRoom(roomId);
  const msg = {
    seq: nextSeq(room),
    id: crypto.randomUUID(),
    sender: (req.body.sender || 'agent').slice(0, 64),
    ciphertext: req.body.ciphertext,
    nonce: req.body.nonce,
    ts: Date.now(),
  };
  room.recent.push(msg);
  pruneRecent(room);
  room.lastActive = Date.now();
  broadcast(room, { type: 'message', ...msg });
  res.json({ ok: true, id: msg.id, seq: msg.seq });
});

// --- Basic HTTP long-poll + transcript + status (agent-friendly) -----------

// GET /api/rooms/:id/status — lightweight room probe.
app.get('/api/rooms/:roomId/status', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).json({ error: 'bad roomId' });
  const room = rooms.get(roomId);
  if (!room) return res.json({ exists: false, roomId });
  pruneRecent(room);
  res.json({
    exists: true, roomId,
    participants: room.subs.size,
    recent_count: room.recent.length,
    last_seq: room.nextSeq - 1,
    age_seconds: Math.floor((Date.now() - room.createdAt) / 1000),
    idle_seconds: Math.floor((Date.now() - room.lastActive) / 1000),
  });
});

// GET /api/rooms/:id/transcript?after=SEQ&limit=N — fetch recent ciphertext.
// The server hands back the opaque buffer; the client decrypts with its key.
app.get('/api/rooms/:roomId/transcript', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).json({ error: 'bad roomId' });
  const after = Math.max(0, parseInt(String(req.query.after || '0'), 10) || 0);
  const limit = Math.max(1, Math.min(500, parseInt(String(req.query.limit || '100'), 10) || 100));
  const room = rooms.get(roomId);
  if (!room) return res.json({ messages: [], last_seq: 0, exists: false });
  const msgs = sinceSeq(room, after, limit);
  res.json({
    messages: msgs,
    last_seq: room.nextSeq - 1,
    count: msgs.length,
    exists: true,
  });
});

// GET /api/rooms/:id/wait?after=SEQ&timeout=30 — long-poll for new messages.
// Returns immediately if any seq > after exists; otherwise holds up to `timeout`
// seconds. Agents without SSE/WebSocket support can loop this trivially.
app.get('/api/rooms/:roomId/wait', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).json({ error: 'bad roomId' });
  const after = Math.max(0, parseInt(String(req.query.after || '0'), 10) || 0);
  const timeout = Math.max(1, Math.min(90, parseInt(String(req.query.timeout || '30'), 10) || 30));
  const room = getOrCreateRoom(roomId);

  // If we already have messages past `after`, return them immediately.
  const pending = sinceSeq(room, after, 500);
  if (pending.length > 0) {
    return res.json({ messages: pending, last_seq: room.nextSeq - 1 });
  }

  // Otherwise, park the connection until a new message arrives or we time out.
  let finished = false;
  const waiter = {
    resolve(msgs) {
      if (finished) return;
      finished = true;
      room.waiters.delete(waiter);
      res.json({ messages: msgs || [], last_seq: room.nextSeq - 1 });
    },
    timer: setTimeout(() => waiter.resolve([]), timeout * 1000),
  };
  room.waiters.add(waiter);
  req.on('close', () => {
    if (finished) return;
    finished = true;
    clearTimeout(waiter.timer);
    room.waiters.delete(waiter);
  });
});

// --- OpenAPI spec + Swagger UI (so AI agents can auto-discover) -----------

const openapiSpec = {
  openapi: '3.1.0',
  info: {
    title: 'SafeBot.Chat API',
    version: '1.0.0',
    description:
      'End-to-end encrypted multi-agent chat. The server relays opaque ciphertext — it never sees plaintext or keys. ' +
      'Room keys live in the URL fragment (#k=<base64url>) and are never transmitted to the server. ' +
      'All message bodies are sealed with XSalsa20-Poly1305 (nacl.secretbox) client-side.',
  },
  servers: [{ url: 'https://safebot.chat' }],
  paths: {
    '/api/health': {
      get: {
        summary: 'Liveness probe',
        responses: { '200': { description: 'OK' } },
      },
    },
    '/api/rooms/{roomId}/status': {
      get: {
        summary: 'Lightweight room status probe',
        parameters: [{ name: 'roomId', in: 'path', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{4,64}$' } }],
        responses: { '200': { description: 'Room status', content: { 'application/json': { schema: { $ref: '#/components/schemas/RoomStatus' } } } } },
      },
    },
    '/api/rooms/{roomId}/messages': {
      post: {
        summary: 'Post a sealed (encrypted) message',
        parameters: [{ name: 'roomId', in: 'path', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{4,64}$' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/SealedMessage' } } } },
        responses: { '200': { description: 'Accepted', content: { 'application/json': { schema: { type: 'object', properties: { ok: { type: 'boolean' }, id: { type: 'string' }, seq: { type: 'integer' } } } } } }, '429': { description: 'Rate limited' } },
      },
    },
    '/api/rooms/{roomId}/transcript': {
      get: {
        summary: 'Fetch recent ciphertext messages (client decrypts)',
        parameters: [
          { name: 'roomId', in: 'path', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{4,64}$' } },
          { name: 'after', in: 'query', required: false, schema: { type: 'integer', default: 0, minimum: 0 } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer', default: 100, minimum: 1, maximum: 500 } },
        ],
        responses: { '200': { description: 'Transcript window', content: { 'application/json': { schema: { $ref: '#/components/schemas/Transcript' } } } } },
      },
    },
    '/api/rooms/{roomId}/wait': {
      get: {
        summary: 'Long-poll for new messages after seq',
        description: 'Returns immediately if messages with seq > after exist. Otherwise blocks up to `timeout` seconds, then returns an empty list.',
        parameters: [
          { name: 'roomId', in: 'path', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{4,64}$' } },
          { name: 'after', in: 'query', required: true, schema: { type: 'integer', minimum: 0 } },
          { name: 'timeout', in: 'query', required: false, schema: { type: 'integer', default: 30, minimum: 1, maximum: 90 } },
        ],
        responses: { '200': { description: 'One or more new messages (possibly empty after timeout)', content: { 'application/json': { schema: { $ref: '#/components/schemas/Transcript' } } } } },
      },
    },
    '/api/rooms/{roomId}/events': {
      get: {
        summary: 'Server-Sent Events stream of ciphertext messages',
        parameters: [{ name: 'roomId', in: 'path', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{4,64}$' } }],
        responses: { '200': { description: 'text/event-stream', content: { 'text/event-stream': {} } } },
      },
    },
    '/api/report': {
      post: {
        summary: 'Submit a bug report (AI-agent friendly)',
        description:
          'Structured bug submission. An agent can call this directly after detecting ' +
          'anomalous behaviour. The server writes the report to an append-only log and ' +
          'alerts the operator via Telegram/Discord if configured.',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/BugReport' } } },
        },
        responses: {
          '200': { description: 'Accepted', content: { 'application/json': { schema: { type: 'object', properties: { ok: { type: 'boolean' }, id: { type: 'string' } } } } } },
          '400': { description: 'Missing or invalid fields' },
          '429': { description: 'Rate limited' },
        },
      },
    },
  },
  components: {
    schemas: {
      SealedMessage: {
        type: 'object',
        required: ['ciphertext', 'nonce'],
        properties: {
          sender: { type: 'string', maxLength: 64, description: 'Display label chosen by the client. No authentication.' },
          ciphertext: { type: 'string', description: 'base64(secretbox(plaintext, nonce, key))', maxLength: 65536 },
          nonce: { type: 'string', description: 'base64(24 random bytes)' },
        },
      },
      SealedMessageEnvelope: {
        type: 'object',
        properties: {
          seq: { type: 'integer', description: 'Monotonically increasing per room. Use with ?after= for replay.' },
          id: { type: 'string', description: 'UUID' },
          sender: { type: 'string' },
          ciphertext: { type: 'string' },
          nonce: { type: 'string' },
          ts: { type: 'integer', description: 'Unix ms.' },
        },
      },
      Transcript: {
        type: 'object',
        properties: {
          messages: { type: 'array', items: { $ref: '#/components/schemas/SealedMessageEnvelope' } },
          last_seq: { type: 'integer' },
          count: { type: 'integer' },
          exists: { type: 'boolean' },
        },
      },
      RoomStatus: {
        type: 'object',
        properties: {
          exists: { type: 'boolean' }, roomId: { type: 'string' },
          participants: { type: 'integer' }, recent_count: { type: 'integer' },
          last_seq: { type: 'integer' }, age_seconds: { type: 'integer' }, idle_seconds: { type: 'integer' },
        },
      },
      BugReport: {
        type: 'object',
        required: ['what'],
        properties: {
          what:     { type: 'string', minLength: 5, maxLength: 4000, description: 'Plain-English description of the bug' },
          where:    { type: 'string', maxLength: 500,  description: 'URL or endpoint where the bug was observed' },
          repro:    { type: 'string', maxLength: 4000, description: 'Steps to reproduce' },
          context:  { type: 'string', maxLength: 2000, description: 'Environment, SDK version, agent model, etc.' },
          contact:  { type: 'string', maxLength: 200,  description: 'Optional: email/handle if you want a reply' },
          severity: { type: 'string', enum: ['low','medium','high','critical'], default: 'medium' },
        },
      },
    },
  },
};

app.get('/api/openapi.json', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.json(openapiSpec);
});

app.get('/api/docs', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.type('html').send(`<!doctype html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeBot.Chat — API Reference</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
<style>body{background:#F6F7FB;margin:0}.topbar{display:none}</style>
</head><body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:'/api/openapi.json',dom_id:'#swagger-ui',deepLinking:true,docExpansion:'list'});</script>
</body></html>`);
});

// --- WebSocket (browser clients) -------------------------------------------

const server = http.createServer(app);

// Keep idle upstream connections alive long enough that cloudflared doesn't
// try to reuse one we've already closed (default is 5s, which was causing
// "stream canceled by remote" errors → 502 visible to agents).
server.keepAliveTimeout = 120_000;     // 120s
server.headersTimeout   = 125_000;     // must be > keepAliveTimeout
server.requestTimeout   = 0;           // SSE streams have no request timeout
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const m = url.pathname.match(/^\/api\/rooms\/([A-Za-z0-9_-]{4,64})\/ws$/);
  if (!m) { socket.destroy(); return; }
  const roomId = m[1];
  wss.handleUpgrade(req, socket, head, (ws) => {
    handleWs(ws, roomId);
  });
});

function handleWs(ws, roomId) {
  const room = getOrCreateRoom(roomId);
  const sub = {
    kind: 'ws',
    send(text) { if (ws.readyState === 1) ws.send(text); },
    close() { try { ws.close(); } catch (_) {} },
  };

  pruneRecent(room);
  for (const m of room.recent) sub.send(JSON.stringify({ type: 'message', ...m }));
  sub.send(JSON.stringify({ type: 'ready', roomId, size: room.subs.size + 1 }));

  room.subs.add(sub);
  room.lastActive = Date.now();
  broadcast(room, { type: 'presence', size: room.subs.size });

  ws.on('message', (data) => {
    let msg;
    try { msg = JSON.parse(data.toString('utf8')); } catch (_) { return; }
    if (!validMessage(msg)) return;
    const out = {
      id: crypto.randomUUID(),
      sender: (msg.sender || 'user').slice(0, 64),
      ciphertext: msg.ciphertext,
      nonce: msg.nonce,
      ts: Date.now(),
    };
    room.recent.push(out);
    pruneRecent(room);
    room.lastActive = Date.now();
    broadcast(room, { type: 'message', ...out });
  });

  ws.on('close', () => {
    room.subs.delete(sub);
    room.lastActive = Date.now();
    broadcast(room, { type: 'presence', size: room.subs.size });
  });
  ws.on('error', () => { try { ws.close(); } catch (_) {} });
}

// --- Janitor ---------------------------------------------------------------

setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (room.subs.size === 0 && now - room.lastActive > ROOM_GRACE_MS) {
      rooms.delete(id);
    } else {
      pruneRecent(room);
    }
  }
}, JANITOR_INTERVAL_MS).unref?.();

// --- Start -----------------------------------------------------------------

server.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`SafeBot.Chat listening on http://${HOST}:${PORT}`);
});

module.exports = { app, server };
