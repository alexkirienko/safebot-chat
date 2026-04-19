// SafeBot.Chat server — E2E-encrypted, zero-chat-log relay for multi-agent chat rooms.
//
// Design invariants (DO NOT VIOLATE):
//   1. The server never decrypts, logs, writes, or persists message bodies
//      (room ciphertext, DM ciphertext, room keys). Plaintext and keys never
//      reach this process.
//   2. All room state is in-memory. When the last subscriber leaves a room,
//      the room and its recent-message buffer are cleared after a short grace.
//   3. Disk writes are narrowly scoped to operator state only:
//        - /var/lib/safebot/metrics.json, metrics_history.json — aggregate counters
//        - /var/lib/safebot/identities.json — public keys + inbox_seq counter
//        - /var/log/safebot-bugs.jsonl — bug-report bodies submitted by users
//          (5 MiB cap, single rotation). Bug reports are user-submitted text
//          and are explicitly NOT covered by invariant #1; submitters are
//          told so via the /api/report endpoint contract.

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

// --- Metrics (admin-only, aggregate, no message content ever) -------------
// Persisted to METRICS_STATE_PATH once a minute so restart-induced zeroing
// stops surprising the operator on the dashboard. All counters are content-
// free (no keys, no plaintext, no room IDs) — same privacy posture as the
// rest of the server.
const STATE_FILE_MAX = Number(process.env.STATE_FILE_MAX || 64 * 1024 * 1024); // 64 MiB fuse
function safeReadJson(path) {
  const st = fs.statSync(path);
  if (st.size > STATE_FILE_MAX) throw new Error(`state file too large: ${path} (${st.size} > ${STATE_FILE_MAX})`);
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}
const METRICS_STATE_PATH = process.env.METRICS_STATE_PATH || '/var/lib/safebot/metrics.json';

const METRICS_DEFAULTS = {
  started_at: STARTED_AT,
  started_ms: Date.now(),
  first_boot_at: STARTED_AT,
  // cumulative counters
  rooms_created_total: 0,
  rooms_evicted_total: 0,
  messages_relayed_total: 0,
  bytes_relayed_total: 0,
  http_posts_total: 0,
  http_2xx: 0, http_4xx: 0, http_5xx: 0, http_429: 0,
  ws_connects_total: 0, ws_disconnects_total: 0,
  sse_connects_total: 0, sse_disconnects_total: 0,
  longpoll_waits_total: 0, longpoll_wakes_total: 0, longpoll_timeouts_total: 0,
  bug_reports_total: 0,
  transport_browser_total: 0, transport_agent_total: 0,
  // peaks
  peak_concurrent_rooms: 0,
  peak_concurrent_subs: 0,
  // restart bookkeeping
  process_starts_total: 0,
  last_restart_at: STARTED_AT,
};

function loadPersistedMetrics() {
  try {
    const saved = safeReadJson(METRICS_STATE_PATH);
    const m = { ...METRICS_DEFAULTS, ...saved };
    // This process just started: bump restart counter, but preserve cumulative
    // totals and first_boot_at.
    m.started_at = STARTED_AT;
    m.started_ms = Date.now();
    m.last_restart_at = STARTED_AT;
    m.process_starts_total = (saved.process_starts_total || 0) + 1;
    return m;
  } catch (_) {
    // No file or unreadable: start fresh with process_starts = 1.
    return { ...METRICS_DEFAULTS, process_starts_total: 1 };
  }
}

const METRICS = loadPersistedMetrics();
// Ring buffer: one snapshot every 60s for 24h = 1440 entries. Persisted to
// disk so the hourly chart survives deploys.
const METRICS_HISTORY_PATH = process.env.METRICS_HISTORY_PATH || '/var/lib/safebot/metrics_history.json';
const METRICS_HISTORY_MAX = 1440;
function loadPersistedHistory() {
  try {
    const arr = safeReadJson(METRICS_HISTORY_PATH);
    if (!Array.isArray(arr)) return [];
    const cutoff = Date.now() - 24 * 3_600_000;
    return arr.filter((s) => s && typeof s.t === 'number' && s.t >= cutoff);
  } catch (_) { return []; }
}
const METRICS_HISTORY = loadPersistedHistory();
let prevSnapshot = METRICS_HISTORY.length ? METRICS_HISTORY[METRICS_HISTORY.length - 1] : null;

function persistMetrics() {
  try {
    const dir = path.dirname(METRICS_STATE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = METRICS_STATE_PATH + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(METRICS));
    fs.renameSync(tmp, METRICS_STATE_PATH);
    const htmp = METRICS_HISTORY_PATH + '.tmp';
    fs.writeFileSync(htmp, JSON.stringify(METRICS_HISTORY));
    fs.renameSync(htmp, METRICS_HISTORY_PATH);
  } catch (e) {
    console.error('[metrics] persist failed:', e.message);
  }
}
setInterval(persistMetrics, 60_000).unref?.();
// Also flush on graceful shutdown so a planned deploy doesn't lose the last
// minute of counters.
// Single coordinated shutdown: flush *both* persistence targets (metrics AND
// identities) before process.exit. Previously there were two handlers and the
// first one's process.exit(0) could cut the second one off before it flushed.
function _shutdownAndExit() {
  try { persistMetrics(); } catch (_) {}
  try { persistIdentities(); } catch (_) {}
  process.exit(0);
}
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, _shutdownAndExit);

function metricsSnapshot() {
  let totalSubs = 0;
  for (const r of rooms.values()) totalSubs += r.subs.size;
  if (rooms.size > METRICS.peak_concurrent_rooms) METRICS.peak_concurrent_rooms = rooms.size;
  if (totalSubs > METRICS.peak_concurrent_subs) METRICS.peak_concurrent_subs = totalSubs;
  return {
    t: Date.now(),
    active_rooms: rooms.size,
    active_subs: totalSubs,
    rooms_created: METRICS.rooms_created_total,
    rooms_evicted: METRICS.rooms_evicted_total,
    messages: METRICS.messages_relayed_total,
    bytes: METRICS.bytes_relayed_total,
    http_posts: METRICS.http_posts_total,
    h4xx: METRICS.http_4xx, h5xx: METRICS.http_5xx, h429: METRICS.http_429,
    ws: METRICS.ws_connects_total,
    sse: METRICS.sse_connects_total,
    lp_wakes: METRICS.longpoll_wakes_total,
    lp_timeouts: METRICS.longpoll_timeouts_total,
    bugs: METRICS.bug_reports_total,
  };
}

function takeSample() {
  const snap = metricsSnapshot();
  if (prevSnapshot) {
    snap.d_messages = snap.messages - prevSnapshot.messages;
    snap.d_rooms = snap.rooms_created - prevSnapshot.rooms_created;
    snap.d_bytes = snap.bytes - prevSnapshot.bytes;
    snap.d_bugs = snap.bugs - prevSnapshot.bugs;
  }
  METRICS_HISTORY.push(snap);
  while (METRICS_HISTORY.length > METRICS_HISTORY_MAX) METRICS_HISTORY.shift();
  prevSnapshot = snap;
}
// Take one sample 5s after boot so the chart has a real point without
// waiting a full minute.
setTimeout(takeSample, 5_000).unref?.();
setInterval(() => {
  const snap = metricsSnapshot();
  // Store deltas vs prev snapshot so /admin/stats can render rates cleanly.
  if (prevSnapshot) {
    snap.d_messages = snap.messages - prevSnapshot.messages;
    snap.d_rooms = snap.rooms_created - prevSnapshot.rooms_created;
    snap.d_bytes = snap.bytes - prevSnapshot.bytes;
    snap.d_bugs = snap.bugs - prevSnapshot.bugs;
  }
  METRICS_HISTORY.push(snap);
  while (METRICS_HISTORY.length > METRICS_HISTORY_MAX) METRICS_HISTORY.shift();
  prevSnapshot = snap;
}, 60_000).unref?.();

// --- Identity / DM primitive (Phase A) ------------------------------------
// Every agent can claim a @handle backed by two public keys (one for
// receiving encrypted DMs via nacl.box, one for signing ownership proofs via
// nacl.sign). The server stores ONLY the public keys + inbox ciphertexts;
// private keys never leave the owner's process.
//
// Wire primitives intentionally reuse the conventions of the rooms API:
//   - base64 for ciphertext / nonces
//   - numeric monotonic seq for inbox ordering
//   - same rate-limit bucket + metrics shape
//
// Identities survive restarts (persisted alongside metrics.json). Inbox is
// RAM-only with a short TTL (7 days) + per-handle cap (256) — "queued in
// flight", not an archive, so the zero-chat-logs posture holds.

const nacl = require('tweetnacl');
const IDENTITIES_STATE_PATH = process.env.IDENTITIES_STATE_PATH || '/var/lib/safebot/identities.json';
const HANDLE_REGEX = /^[a-z0-9][a-z0-9_-]{1,31}$/;
const RESERVED_HANDLES = new Set(['anon', 'admin', 'safebot', 'system', 'root', 'support', 'help', 'demo', 'echo']);
const DM_MAX_BYTES = 128 * 1024;          // ciphertext ceiling, matches room msgs
const INBOX_MAX = 256;                    // undelivered per handle
const INBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SIG_MAX_SKEW_MS = 60 * 1000;        // signed-challenge clock drift tolerance

// identities: Map<handle, { box_pub, sign_pub, registered_at, meta, inbox_seq }>
const identities = new Map();
// inboxes: Map<handle, Array<{ seq, id, ciphertext, nonce, sender_eph_pub, from_handle?, ts }>>
const inboxes = new Map();
// dmWaiters: Map<handle, Set<{ resolve, timer }>>
const dmWaiters = new Map();

function loadIdentities() {
  try {
    const obj = safeReadJson(IDENTITIES_STATE_PATH);
    let dropped = 0;
    for (const [handle, rec] of Object.entries(obj.identities || {})) {
      // Validate each persisted record against the same schema we enforce at
      // registration time. A tampered file must not inject garbage into the
      // identities map or crash auth paths later.
      if (handle === '__proto__' || handle === 'constructor' || handle === 'prototype') { dropped++; continue; }
      if (!rec || typeof rec !== 'object' || Array.isArray(rec)) { dropped++; continue; }
      if (typeof rec.handle !== 'string' || !HANDLE_REGEX.test(rec.handle) || rec.handle !== handle) { dropped++; continue; }
      if (typeof rec.box_pub !== 'string' || typeof rec.sign_pub !== 'string') { dropped++; continue; }
      try {
        if (Buffer.from(rec.box_pub, 'base64').length !== 32) { dropped++; continue; }
        if (Buffer.from(rec.sign_pub, 'base64').length !== 32) { dropped++; continue; }
      } catch (_) { dropped++; continue; }
      const clean = {
        handle: rec.handle,
        box_pub: rec.box_pub,
        sign_pub: rec.sign_pub,
        registered_at: Number.isFinite(rec.registered_at) ? rec.registered_at : Date.now(),
        meta: (rec.meta && typeof rec.meta === 'object') ? { bio: String(rec.meta.bio || '').slice(0, 280) } : {},
        inbox_seq: Number.isFinite(rec.inbox_seq) && rec.inbox_seq > 0 ? rec.inbox_seq : 0,
      };
      identities.set(handle, clean);
    }
    console.log(`[identities] loaded ${identities.size} from disk` + (dropped ? ` (rejected ${dropped} malformed)` : ''));
  } catch (_) { /* fresh slate */ }
}
function persistIdentities() {
  try {
    const dir = path.dirname(IDENTITIES_STATE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = IDENTITIES_STATE_PATH + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ identities: Object.fromEntries(identities) }));
    fs.renameSync(tmp, IDENTITIES_STATE_PATH);
  } catch (e) { console.error('[identities] persist failed:', e.message); }
}
loadIdentities();
setInterval(persistIdentities, 60_000).unref?.();
// Debounced persist: any mutation (identity.inbox_seq bump, register) schedules
// a flush within 2s so a restart doesn't roll back DM inbox seq.
let _persistTimer = null;
function schedulePersistIdentities() {
  if (_persistTimer) return;
  _persistTimer = setTimeout(() => { _persistTimer = null; persistIdentities(); }, 2_000);
  _persistTimer.unref?.();
}
// (Single shutdown handler registered above now flushes both metrics and
// identities. Leaving this block empty to preserve file line anchors.)

// Return the decoded byte length of a base64 string — the thing the crypto
// layer actually cares about — rather than the string length.
function b64BytesLen(s) {
  if (typeof s !== 'string') return -1;
  try { return Buffer.from(s, 'base64').length; } catch (_) { return -1; }
}
// Strict canonical-base64 check. Node's Buffer.from(..., 'base64') silently
// discards non-alphabet characters, so `!!!!` decodes to 0 bytes and passes
// naive length checks. Every crypto-bearing string on the wire must round-
// trip through decode + re-encode and compare byte-for-byte; otherwise the
// server would relay/store values that browser `atob` + cross-lang SDKs
// reject, breaking interop. Accepts both standard and URL-safe alphabet.
function isCanonicalBase64(s, expectedBytes) {
  if (typeof s !== 'string' || s.length === 0) return false;
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) return false;
  let decoded;
  try { decoded = Buffer.from(s, 'base64'); } catch (_) { return false; }
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) return false;
  // Round-trip back to standard base64. Accept URL-safe input by normalizing.
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
  const reencoded = decoded.toString('base64');
  return reencoded === normalized;
}

function releaseBytes(msg) { if (msg && msg._bytes) INBOX_GLOBAL_BYTES = Math.max(0, INBOX_GLOBAL_BYTES - msg._bytes); }
function pruneInbox(handle) {
  const inbox = inboxes.get(handle);
  if (!inbox) return;
  const cutoff = Date.now() - INBOX_TTL_MS;
  while (inbox.length && inbox[0].ts < cutoff) releaseBytes(inbox.shift());
  while (inbox.length > INBOX_MAX) releaseBytes(inbox.shift());
}

function wakeDmWaiters(handle, msgs) {
  const set = dmWaiters.get(handle);
  if (!set || set.size === 0) return;
  for (const w of set) {
    const after = w.after || 0;
    const filtered = after > 0 ? msgs.filter((m) => m.seq > after) : msgs;
    if (filtered.length === 0) continue;
    clearTimeout(w.timer);
    try { w.resolve(filtered); } catch (_) {}
    set.delete(w);
  }
  // Drop the Map entry when empty so handles with no current waiters stop
  // retaining a forever-empty Set.
  if (set.size === 0) dmWaiters.delete(handle);
}

// Per-IP concurrent long-poll waiter cap. An attacker opening thousands of
// /wait connections would otherwise tie up fd's + timers.
const WAITER_CAP_PER_IP = Number(process.env.WAITER_CAP_PER_IP || 16);
const ROOM_WAITERS_MAX = Number(process.env.ROOM_WAITERS_MAX || 256);
const DM_WAITERS_MAX_PER_HANDLE = Number(process.env.DM_WAITERS_MAX_PER_HANDLE || 64);
const waitersByIp = new Map();
function waiterAcquire(ip) {
  // Test BEFORE incrementing — a previous version incremented first and
  // returned false if over cap, which let rejected requests permanently
  // inflate the counter and lock the IP out. Counter is only ever bumped
  // on success, and released on resolve/close.
  const cur = waitersByIp.get(ip) || 0;
  if (cur >= WAITER_CAP_PER_IP) return false;
  waitersByIp.set(ip, cur + 1);
  return true;
}
function waiterRelease(ip) {
  const n = (waitersByIp.get(ip) || 1) - 1;
  if (n <= 0) waitersByIp.delete(ip); else waitersByIp.set(ip, n);
}

// Persistent-stream (SSE + WS) concurrency cap per IP. Same shape as
// waiterAcquire above but separate counter so long-polls and streams don't
// eat each other's budget.
const STREAM_CAP_PER_IP = Number(process.env.STREAM_CAP_PER_IP || 32);
const streamsByIp = new Map();
function streamAcquire(ip) {
  const cur = streamsByIp.get(ip) || 0;
  if (cur >= STREAM_CAP_PER_IP) return false;
  streamsByIp.set(ip, cur + 1); return true;
}
function streamRelease(ip) {
  const n = (streamsByIp.get(ip) || 1) - 1;
  if (n <= 0) streamsByIp.delete(ip); else streamsByIp.set(ip, n);
}

// Second global token bucket keyed ONLY on ip (no room/handle suffix).
// Caps total aggregate actions per-IP so an attacker can't bypass the
// per-(ip,room) limit by fanning out across many rooms.
const GLOBAL_RL_CAP = Number(process.env.GLOBAL_RL_CAP || 600);
const GLOBAL_RL_REFILL_PER_SEC = Number(process.env.GLOBAL_RL_REFILL_PER_SEC || 200);
const globalRlBuckets = new Map();
function globalRateLimitOk(ip) {
  if (!ip) return true;
  const now = Date.now();
  let b = globalRlBuckets.get(ip);
  if (!b) { b = { tokens: GLOBAL_RL_CAP, last: now }; globalRlBuckets.set(ip, b); }
  const elapsed = (now - b.last) / 1000;
  b.tokens = Math.min(GLOBAL_RL_CAP, b.tokens + elapsed * GLOBAL_RL_REFILL_PER_SEC);
  b.last = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [k, b] of globalRlBuckets) if (b.last < cutoff) globalRlBuckets.delete(k);
}, 60 * 1000).unref?.();

// Recently-seen inbox-sig nonces. Stored `${handle}|${nonce}` → ts. Pruned
// opportunistically on access plus every 5 minutes. Bounds skew-window replay:
// a captured Authorization header cannot be sent a second time while the
// original ts is still in the acceptable window. Size-capped so a signing-key
// owner spamming unique nonces can't OOM the process.
// Replay cache keyed per-handle so membership checks and size accounting
// are O(1). Inner map is nonce → ts. Flat `INBOX_SIG_SEEN_SIZE` is the
// total count across all handles (cheap global cap).
const INBOX_SIG_SEEN = new Map(); // handle → Map<nonce, ts>
let INBOX_SIG_SEEN_SIZE = 0;
const INBOX_SIG_SEEN_MAX = Number(process.env.INBOX_SIG_SEEN_MAX || 10_000);
const INBOX_SIG_SEEN_PER_HANDLE_MAX = Math.max(64, Math.floor(INBOX_SIG_SEEN_MAX / 32));
// Global cap on total queued DM ciphertext bytes across all inboxes —
// 256 handles × 128 KiB × 1 k handles would otherwise be ~32 GiB.
const INBOX_GLOBAL_MAX_BYTES = Number(process.env.INBOX_GLOBAL_MAX_BYTES || 512 * 1024 * 1024); // 512 MiB
let INBOX_GLOBAL_BYTES = 0;
// Replay-cache for register_sig; pruned periodically past the skew window.
const REGISTER_SIG_SEEN = new Map();
setInterval(() => {
  const cutoff = Date.now() - SIG_MAX_SKEW_MS * 2;
  for (const [k, v] of REGISTER_SIG_SEEN) if (v < cutoff) REGISTER_SIG_SEEN.delete(k);
  if (REGISTER_SIG_SEEN.size > 10_000) {
    const it = REGISTER_SIG_SEEN.keys();
    for (let i = 0; i < 200; i++) { const k = it.next().value; if (k === undefined) break; REGISTER_SIG_SEEN.delete(k); }
  }
}, 5 * 60 * 1000).unref?.();
// Replay-cache for verified DM envelopes (key = envHash). A captured
// from_sig+envelope could otherwise be re-POSTed verbatim within the 60s
// skew and bulk-fill the recipient's ring buffer, evicting unread msgs.
const DM_ENV_SEEN = new Map(); // handle → Map<envHash, ts>
let DM_ENV_SEEN_SIZE = 0;
const DM_ENV_SEEN_MAX = Number(process.env.DM_ENV_SEEN_MAX || 20_000);
const DM_ENV_SEEN_PER_HANDLE_MAX = Math.max(128, Math.floor(DM_ENV_SEEN_MAX / 32));
setInterval(() => {
  const cutoff = Date.now() - SIG_MAX_SKEW_MS * 2; // replay-cache TTL must cover both past and future halves of the ±skew window
  for (const [h, inner] of DM_ENV_SEEN) {
    for (const [n, v] of inner) if (v < cutoff) { inner.delete(n); DM_ENV_SEEN_SIZE--; }
    if (inner.size === 0) DM_ENV_SEEN.delete(h);
  }
}, 5 * 60 * 1000).unref?.();
// Same pattern for room recent-buffer ciphertext. ROOM_MAX*200*128 KiB could
// otherwise park 125 GiB of ciphertext in RAM before the 30s janitor runs.
const ROOM_GLOBAL_MAX_BYTES = Number(process.env.ROOM_GLOBAL_MAX_BYTES || 512 * 1024 * 1024);
let ROOM_GLOBAL_BYTES = 0;
setInterval(() => {
  const cutoff = Date.now() - SIG_MAX_SKEW_MS * 2; // replay-cache TTL must cover both past and future halves of the ±skew window
  for (const [h, inner] of INBOX_SIG_SEEN) {
    for (const [n, v] of inner) if (v < cutoff) { inner.delete(n); INBOX_SIG_SEEN_SIZE--; }
    if (inner.size === 0) INBOX_SIG_SEEN.delete(h);
  }
}, 5 * 60 * 1000).unref?.();

function verifyInboxSig(req, handle) {
  // Header:  Authorization: SafeBot ts=<ms>,n=<nonce>,sig=<base64>
  // Signed blob: `<method> <originalUrl> <ts> <nonce>`.
  //   - originalUrl binds the sig to query params (can't swap ?after=).
  //   - nonce makes the signed payload per-request-unique so a captured
  //     header cannot be replayed verbatim during the 60 s skew window.
  const auth = String(req.headers.authorization || '');
  if (!auth.startsWith('SafeBot ')) return false;
  const parts = Object.fromEntries(auth.slice(8).split(',').map((kv) => {
    kv = kv.trim();
    const i = kv.indexOf('=');
    return i < 0 ? [kv, ''] : [kv.slice(0, i), kv.slice(i + 1)];
  }));
  const ts = parseInt(parts.ts || '0', 10);
  const sig = parts.sig || '';
  const nonce = parts.n || '';
  if (!ts || !sig || !nonce) return false;
  if (nonce.length < 16 || nonce.length > 64) return false;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(nonce)) return false;
  if (Math.abs(Date.now() - ts) > SIG_MAX_SKEW_MS) return false;
  const rec = identities.get(handle);
  if (!rec) return false;
  const inner = INBOX_SIG_SEEN.get(handle);
  if (inner && inner.has(nonce)) return false;
  try {
    const signPub = Buffer.from(rec.sign_pub, 'base64');
    if (signPub.length !== 32) return false;
    const urlPart = req.originalUrl || req.url || req.path;
    const blob = Buffer.from(`${req.method} ${urlPart} ${ts} ${nonce}`, 'utf8');
    if (!nacl.sign.detached.verify(blob, Buffer.from(sig, 'base64'), signPub)) return false;
    // Per-handle cap: one pathological handle can't DoS auth for anyone
    // else. Checks and writes are O(1) against the inner Map.
    const perInner = inner || new Map();
    if (perInner.size >= INBOX_SIG_SEEN_PER_HANDLE_MAX) {
      // Drop this handle's expired entries; if still full, fail closed.
      const cutoff = Date.now() - SIG_MAX_SKEW_MS * 2; // replay-cache TTL must cover both past and future halves of the ±skew window
      for (const [n, v] of perInner) if (v < cutoff) { perInner.delete(n); INBOX_SIG_SEEN_SIZE--; }
      if (perInner.size >= INBOX_SIG_SEEN_PER_HANDLE_MAX) return false;
    }
    if (INBOX_SIG_SEEN_SIZE >= INBOX_SIG_SEEN_MAX) {
      // Global memory fuse — drop 200 oldest entries from the first inner map.
      for (const [h, im] of INBOX_SIG_SEEN) {
        const evict = Math.min(200, im.size);
        const it = im.keys();
        for (let i = 0; i < evict; i++) { const k = it.next().value; if (k === undefined) break; im.delete(k); INBOX_SIG_SEEN_SIZE--; }
        if (im.size === 0) INBOX_SIG_SEEN.delete(h);
        break;
      }
    }
    if (!inner) INBOX_SIG_SEEN.set(handle, perInner);
    perInner.set(nonce, Date.now());
    INBOX_SIG_SEEN_SIZE++;
    return true;
  } catch (_) { return false; }
}

// Replay cache for room-message sender sigs (signed-sender rooms only).
// Same per-handle O(1) structure as INBOX_SIG_SEEN so one prolific handle
// can't crowd out others, and a global fuse guards against memory blow-up.
const ROOM_SIG_SEEN = new Map(); // handle → Map<nonce, ts>
let ROOM_SIG_SEEN_SIZE = 0;
const ROOM_SIG_SEEN_MAX = Number(process.env.ROOM_SIG_SEEN_MAX || 10_000);
const ROOM_SIG_SEEN_PER_HANDLE_MAX = Math.max(64, Math.floor(ROOM_SIG_SEEN_MAX / 32));
setInterval(() => {
  const cutoff = Date.now() - SIG_MAX_SKEW_MS * 2;
  for (const [h, inner] of ROOM_SIG_SEEN) {
    for (const [n, v] of inner) if (v < cutoff) { inner.delete(n); ROOM_SIG_SEEN_SIZE--; }
    if (inner.size === 0) ROOM_SIG_SEEN.delete(h);
  }
}, 5 * 60 * 1000).unref?.();

// Per-(handle, roomId) cursors for the optional /claim + /ack pull-model.
// Lets agents pull foreign messages at-least-once with server-tracked
// progress instead of managing last_seq client-side. Relay stays neutral —
// no idea what the ciphertext means, just what the receiver has acked.
// Memory: at most ROOM_CURSORS_PER_HANDLE_MAX rooms × a tiny record per
// handle. Handles that never claim anything never allocate.
const ROOM_CURSORS = new Map(); // handle → Map<roomId, {cursor, inflight}>
const ROOM_CURSORS_PER_HANDLE_MAX = Number(process.env.ROOM_CURSORS_PER_HANDLE_MAX || 64);
const CLAIM_TTL_MS = Number(process.env.CLAIM_TTL_MS || 60_000);
function getCursorRec(handle, roomId) {
  let perHandle = ROOM_CURSORS.get(handle);
  if (!perHandle) {
    perHandle = new Map();
    ROOM_CURSORS.set(handle, perHandle);
  }
  let rec = perHandle.get(roomId);
  if (!rec) {
    if (perHandle.size >= ROOM_CURSORS_PER_HANDLE_MAX) {
      // Evict oldest-idle entry. cursors are cheap but per-handle map shouldn't
      // grow unbounded if a handle is asked to claim from thousands of rooms.
      const firstKey = perHandle.keys().next().value;
      if (firstKey !== undefined) perHandle.delete(firstKey);
    }
    rec = { cursor: 0, inflight: null };
    perHandle.set(roomId, rec);
  }
  return rec;
}
function claimExpired(inflight) {
  return !inflight || (Date.now() - inflight.claimed_at) > CLAIM_TTL_MS;
}
function findNextForeign(room, cursor, handle) {
  const tagged = '@' + handle;
  for (const m of room.recent) {
    if (m.seq <= cursor) continue;
    if (m.sender === handle || m.sender === tagged) continue;
    return m;
  }
  return null;
}
function buildClaimEnvelope(m) {
  return { seq: m.seq, id: m.id, sender: m.sender, ciphertext: m.ciphertext, nonce: m.nonce, ts: m.ts, sender_verified: !!m.sender_verified };
}

// Verify a room message carries a valid signed-sender envelope. Blob is
// `"room-msg <roomId> <ts> <nonce> <sha256_hex(ciphertext)>"` signed with the
// handle's registered Ed25519 sign key. Returns true on success (and records
// the nonce in the replay cache); false on any failure (skew, bad handle,
// bad sig, replay).
function verifyRoomSenderSig(body, roomId) {
  const handle = String(body.sender_handle || '').toLowerCase();
  const ts = parseInt(String(body.sender_ts || '0'), 10);
  const nonce = String(body.sender_nonce || '');
  const sig = String(body.sender_sig || '');
  if (!/^[a-z0-9_-]{1,32}$/.test(handle)) return false;
  if (!ts || !nonce || !sig) return false;
  if (nonce.length < 16 || nonce.length > 64) return false;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(nonce)) return false;
  if (Math.abs(Date.now() - ts) > SIG_MAX_SKEW_MS) return false;
  const rec = identities.get(handle);
  if (!rec) return false;
  const inner = ROOM_SIG_SEEN.get(handle);
  if (inner && inner.has(nonce)) return false;
  try {
    const signPub = Buffer.from(rec.sign_pub, 'base64');
    if (signPub.length !== 32) return false;
    const ctHash = crypto.createHash('sha256')
      .update(Buffer.from(String(body.ciphertext || ''), 'utf8'))
      .digest('hex');
    const blob = Buffer.from(`room-msg ${roomId} ${ts} ${nonce} ${ctHash}`, 'utf8');
    if (!nacl.sign.detached.verify(blob, Buffer.from(sig, 'base64'), signPub)) return false;
    const perInner = inner || new Map();
    if (perInner.size >= ROOM_SIG_SEEN_PER_HANDLE_MAX) {
      const cutoff = Date.now() - SIG_MAX_SKEW_MS * 2;
      for (const [n, v] of perInner) if (v < cutoff) { perInner.delete(n); ROOM_SIG_SEEN_SIZE--; }
      if (perInner.size >= ROOM_SIG_SEEN_PER_HANDLE_MAX) return false;
    }
    if (ROOM_SIG_SEEN_SIZE >= ROOM_SIG_SEEN_MAX) {
      for (const [h, im] of ROOM_SIG_SEEN) {
        const evict = Math.min(200, im.size);
        const it = im.keys();
        for (let i = 0; i < evict; i++) { const k = it.next().value; if (k === undefined) break; im.delete(k); ROOM_SIG_SEEN_SIZE--; }
        if (im.size === 0) ROOM_SIG_SEEN.delete(h);
        break;
      }
    }
    if (!inner) ROOM_SIG_SEEN.set(handle, perInner);
    perInner.set(nonce, Date.now());
    ROOM_SIG_SEEN_SIZE++;
    return true;
  } catch (_) { return false; }
}

function classifyUA(ua) {
  const s = String(ua || '').toLowerCase();
  if (/mozilla|chrome|safari|firefox|edge/.test(s) && !/python|curl|requests|wget|bot/.test(s)) {
    return 'browser';
  }
  return 'agent';
}

function tokenEq(a, b) {
  // Constant-time comparison — plain `===` on secrets leaks the length of
  // the matching prefix via timing and trips audit tools that look for it.
  const aBuf = Buffer.from(String(a || ''), 'utf8');
  const bBuf = Buffer.from(String(b || ''), 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function requireAdmin(req, res) {
  const want = process.env.METRICS_TOKEN;
  if (!want) { res.status(503).json({ error: 'metrics disabled (no METRICS_TOKEN configured)' }); return false; }
  const auth = String(req.headers.authorization || '');
  const qtok = String(req.query.token || '');
  const presented = auth.startsWith('Bearer ') ? auth.slice(7) : qtok;
  if (!presented || !tokenEq(presented, want)) { res.status(401).json({ error: 'unauthorised' }); return false; }
  return true;
}

function escHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function renderStatsPage(tokenForFetch) {
  // Self-refreshing dashboard. Fetches /api/metrics?token=... every 10s,
  // re-renders SVG sparklines client-side. No external deps.
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeBot.Chat — ops</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
 body{font:14px/1.5 Geist,system-ui,sans-serif;background:#0B0D14;color:#F2F4FA;margin:0;padding:22px 28px}
 .chart-row { margin: 20px 0 8px; display:flex; align-items:baseline; justify-content:space-between; gap:14px; flex-wrap:wrap; }
 .chart-row h2 { font-size:15px; margin:0; }
 .chart-tabs { display:inline-flex; gap:4px; background:#161A24; border:1px solid #262B39; border-radius:999px; padding:3px; }
 .chart-tabs button { background:transparent; border:0; color:#AFB6CA; padding:5px 12px; border-radius:999px; font:500 12px Geist,sans-serif; cursor:pointer; letter-spacing:.02em; }
 .chart-tabs button.active { background:#242A3C; color:#F2F4FA; }
 #hourly-chart { height:280px; border:1px solid #262B39; border-radius:14px; background:#0E111B; overflow:hidden; }
 h1{font-size:22px;margin:0 0 8px;letter-spacing:-0.01em}
 .muted{color:#7B8299;font-size:12.5px}
 .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;margin-top:20px}
 .card{background:#161A24;border:1px solid #262B39;border-radius:14px;padding:14px 16px}
 .card .lbl{font-size:11.5px;color:#7B8299;text-transform:uppercase;letter-spacing:.08em;font-weight:600;margin-bottom:6px}
 .card .val{font:600 22px/1 Geist,sans-serif;font-variant-numeric:tabular-nums;letter-spacing:-0.015em}
 .card .sub{color:#AFB6CA;font-size:11.5px;margin-top:4px}
 .spark{margin-top:8px;width:100%;height:28px}
 table{width:100%;border-collapse:collapse;font-family:'JetBrains Mono',monospace;font-size:12.5px;margin-top:22px}
 th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #262B39}
 th{color:#7B8299;font-weight:500;text-transform:uppercase;letter-spacing:.06em;font-size:11px}
 td.num{text-align:right;font-variant-numeric:tabular-nums}
 .row-group{display:flex;justify-content:space-between;align-items:baseline;margin-top:28px}
 .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;background:rgba(34,197,94,.12);color:#66E08E;border:1px solid rgba(34,197,94,.25);font-size:11.5px;font-weight:600}
 .pill .d{width:6px;height:6px;border-radius:999px;background:currentColor}
 a{color:#8FA4FF}
</style></head><body>
<h1>SafeBot.Chat — ops dashboard <span class="pill"><span class="d"></span>live</span> <span id="updated" class="muted" style="font-size:12px;font-weight:400">—</span></h1>
<div class="muted">Auto-refreshes every 10 s. All aggregates are content-free: no keys, no plaintext, no room ids. Sparklines cover the last 24 h in 60-s buckets.</div>

<div class="chart-row">
  <h2>Usage by hour (last 24 h)</h2>
  <div class="chart-tabs" id="chart-tabs">
    <button data-metric="messages" class="active">Messages</button>
    <button data-metric="rooms">Rooms created</button>
    <button data-metric="peak_rooms">Concurrent rooms</button>
    <button data-metric="peak_subs">Concurrent subs</button>
    <button data-metric="bugs">Bug reports</button>
  </div>
</div>
<div id="hourly-chart"></div>

<div id="cards" class="grid"></div>

<div class="row-group"><h2 style="font-size:15px;margin:0">Counters since boot</h2><span class="muted" id="started">—</span></div>
<table id="raw"></table>

<div class="row-group"><h2 style="font-size:15px;margin:0">Recent history (last 30 min)</h2></div>
<table id="history"><thead><tr><th>Time</th><th class="num">Δ msgs</th><th class="num">Δ rooms</th><th class="num">Active rooms</th><th class="num">Active subs</th><th class="num">4xx</th><th class="num">5xx</th><th class="num">429</th></tr></thead><tbody></tbody></table>

<script src="/vendor/klinecharts.min.js"></script>
<script>
 // Token came in via ?token=... in the URL, which is awkward from a secret
 // hygiene standpoint (browser history, shoulder-surfing, possible third-party
 // logs). Move it to sessionStorage immediately and scrub the URL, then use
 // Authorization: Bearer … for every subsequent fetch so the token no longer
 // travels in plain URLs after the initial page load.
 const _initialToken = ${JSON.stringify(tokenForFetch)};
 if (_initialToken) {
   try { sessionStorage.setItem('safebot:admintoken', _initialToken); } catch (_) {}
   if (location.search) history.replaceState(null, '', location.pathname);
 }
 const TOKEN = (function() {
   try { return sessionStorage.getItem('safebot:admintoken') || ''; } catch (_) { return _initialToken || ''; }
 })();
 function _adminFetch(path) {
   return fetch(path, { cache: 'no-store', headers: { 'Authorization': 'Bearer ' + TOKEN } });
 }
 async function fetchMetrics() {
   const r = await _adminFetch('/api/metrics');
   if (!r.ok) { document.body.innerHTML = '<h1>401</h1>'; return null; }
   return r.json();
 }
 function human(n) { n = Number(n) || 0; if (n >= 1e9) return (n/1e9).toFixed(2)+'B'; if (n >= 1e6) return (n/1e6).toFixed(2)+'M'; if (n >= 1e3) return (n/1e3).toFixed(1)+'k'; return String(n); }
 function bytes(n) { n = Number(n) || 0; if (n >= 1073741824) return (n/1073741824).toFixed(2)+' GiB'; if (n >= 1048576) return (n/1048576).toFixed(1)+' MiB'; if (n >= 1024) return (n/1024).toFixed(1)+' KiB'; return n+' B'; }
 function uptime(s) { const d = Math.floor(s/86400); s%=86400; const h = Math.floor(s/3600); s%=3600; const m = Math.floor(s/60); return (d?d+'d ':'') + String(h).padStart(2,'0')+':'+String(m).padStart(2,'0'); }

 function sparkline(values, color) {
   if (!values.length) return '';
   const W = 220, H = 28, pad = 2;
   const max = Math.max(1, ...values), min = Math.min(0, ...values);
   const step = values.length > 1 ? (W - pad*2) / (values.length - 1) : 0;
   const pts = values.map((v, i) => {
     const x = pad + i * step;
     const y = H - pad - ((v - min) / Math.max(1, max - min)) * (H - pad*2);
     return x.toFixed(1) + ',' + y.toFixed(1);
   }).join(' ');
   return '<svg class="spark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none"><polyline fill="none" stroke="' + color + '" stroke-width="1.8" points="' + pts + '"/></svg>';
 }

 function renderCards(m) {
   const cards = [
     { lbl: 'Active rooms', val: m.active_rooms, sub: 'peak ' + m.peak_concurrent_rooms, key: 'active_rooms', color: '#6D7CFF' },
     { lbl: 'Active subscribers', val: m.active_subs, sub: 'peak ' + m.peak_concurrent_subs, key: 'active_subs', color: '#22D3EE' },
     { lbl: 'Messages relayed', val: human(m.messages_relayed_total), sub: bytes(m.bytes_relayed_total) + ' ciphertext', key: 'messages', delta: true, color: '#10B981' },
     { lbl: 'Rooms created', val: human(m.rooms_created_total), sub: m.rooms_evicted_total + ' evicted', key: 'rooms_created', delta: true, color: '#8B5CF6' },
     { lbl: 'HTTP 5xx', val: m.http_5xx, sub: m.http_4xx + ' · 4xx', key: 'h5xx', color: '#EF4444' },
     { lbl: 'Rate-limit 429', val: m.http_429, sub: '', key: 'h429', color: '#F59E0B' },
     { lbl: 'WS connects', val: human(m.ws_connects_total), sub: m.ws_disconnects_total + ' closes', key: 'ws', color: '#EC4899' },
     { lbl: 'SSE connects', val: human(m.sse_connects_total), sub: '', key: 'sse', color: '#3B82F6' },
     { lbl: 'Long-poll wakes', val: human(m.longpoll_wakes_total), sub: m.longpoll_timeouts_total + ' timeouts', key: 'lp_wakes', color: '#14B8A6' },
     { lbl: 'Bug reports', val: m.bug_reports_total, sub: '→ Telegram', key: 'bugs', delta: true, color: '#F472B6' },
     { lbl: 'Browser / Agent POSTs', val: m.transport_browser_total + ' / ' + m.transport_agent_total, sub: '', color: '#A78BFA' },
     { lbl: 'Uptime', val: uptime(m.uptime_seconds), sub: m.started_at.slice(0,19)+'Z', color: '#6D7CFF' },
   ];
   const hist = m.history || [];
   const el = document.getElementById('cards');
   el.innerHTML = cards.map((c) => {
     const series = c.key ? hist.map((s) => c.delta ? (s['d_' + c.key.replace('rooms_created','rooms').replace('messages','messages').replace('bugs','bugs')] ?? 0) : (s[c.key] ?? 0)) : [];
     const spark = series.length > 1 ? sparkline(series.slice(-60), c.color) : '';
     return '<div class="card"><div class="lbl">' + c.lbl + '</div><div class="val">' + c.val + '</div><div class="sub">' + (c.sub||'') + '</div>' + spark + '</div>';
   }).join('');
   document.getElementById('started').textContent = 'Started ' + m.started_at + ' · node ' + (m.node_version||'');
 }

 function renderRaw(m) {
   const rows = [
     ['rooms_created_total', m.rooms_created_total], ['rooms_evicted_total', m.rooms_evicted_total],
     ['messages_relayed_total', m.messages_relayed_total], ['bytes_relayed_total', m.bytes_relayed_total],
     ['http_posts_total', m.http_posts_total], ['http_2xx', m.http_2xx], ['http_4xx', m.http_4xx], ['http_5xx', m.http_5xx], ['http_429', m.http_429],
     ['ws_connects_total', m.ws_connects_total], ['ws_disconnects_total', m.ws_disconnects_total],
     ['sse_connects_total', m.sse_connects_total], ['sse_disconnects_total', m.sse_disconnects_total],
     ['longpoll_waits_total', m.longpoll_waits_total], ['longpoll_wakes_total', m.longpoll_wakes_total], ['longpoll_timeouts_total', m.longpoll_timeouts_total],
     ['bug_reports_total', m.bug_reports_total],
     ['transport_browser_total', m.transport_browser_total], ['transport_agent_total', m.transport_agent_total],
     ['peak_concurrent_rooms', m.peak_concurrent_rooms], ['peak_concurrent_subs', m.peak_concurrent_subs],
   ];
   document.getElementById('raw').innerHTML = '<thead><tr><th>Counter</th><th class="num">Value</th></tr></thead><tbody>'
     + rows.map((r) => '<tr><td>' + r[0] + '</td><td class="num">' + r[1] + '</td></tr>').join('') + '</tbody>';
 }

 function renderHistory(m) {
   const h = (m.history || []).slice(-30).reverse();
   const tb = document.querySelector('#history tbody');
   tb.innerHTML = h.map((s) => {
     const t = new Date(s.t).toISOString().slice(11, 19);
     return '<tr><td>' + t + '</td><td class="num">' + (s.d_messages||0) + '</td><td class="num">' + (s.d_rooms||0) + '</td><td class="num">' + s.active_rooms + '</td><td class="num">' + s.active_subs + '</td><td class="num">' + s.h4xx + '</td><td class="num">' + s.h5xx + '</td><td class="num">' + s.h429 + '</td></tr>';
   }).join('');
 }

 let lastTickAt = 0;
 async function tick() {
   const m = await fetchMetrics();
   if (!m) return;
   renderCards(m);
   renderRaw(m);
   renderHistory(m);
   lastTickAt = Date.now();
 }
 function renderUpdated() {
   const el = document.getElementById('updated'); if (!el || !lastTickAt) return;
   const s = Math.floor((Date.now() - lastTickAt) / 1000);
   el.textContent = '· updated ' + s + 's ago';
 }
 tick();
 setInterval(tick, 10_000);
 setInterval(renderUpdated, 1_000);

 // --- Hourly usage chart (KLineCharts, area style) ---------------------
 let hourlyChart = null;
 let hourlyData = [];
 let hourlyMetric = 'messages';

 function ensureChart() {
   if (hourlyChart) return hourlyChart;
   hourlyChart = klinecharts.init('hourly-chart', {
     styles: {
       grid: { horizontal: { color: '#1E2432' }, vertical: { color: '#1E2432' } },
       candle: {
         type: 'area',
         area: {
           lineSize: 1.6, lineColor: '#6D7CFF',
           backgroundColor: [
             { offset: 0,   color: 'rgba(109,124,255,0.30)' },
             { offset: 1,   color: 'rgba(109,124,255,0.02)' },
           ],
         },
         priceMark: {
           last: { show: true, line: { show: true, color: '#6D7CFF' },
                   text: { show: true, color: '#F2F4FA', backgroundColor: '#6D7CFF', borderColor: '#6D7CFF' } },
           high: { show: false }, low: { show: false },
         },
         tooltip: { showRule: 'always', showType: 'standard' },
       },
       xAxis: {
         axisLine: { color: '#262B39' },
         tickLine: { color: '#262B39' },
         tickText: { color: '#7B8299', size: 11 },
       },
       yAxis: {
         axisLine: { color: '#262B39' },
         tickLine: { color: '#262B39' },
         tickText: { color: '#7B8299', size: 11 },
       },
       crosshair: {
         horizontal: { line: { color: '#6D7CFF', dashedValue: [3, 3] }, text: { backgroundColor: '#6D7CFF', borderColor: '#6D7CFF' } },
         vertical:   { line: { color: '#6D7CFF', dashedValue: [3, 3] }, text: { backgroundColor: '#6D7CFF', borderColor: '#6D7CFF' } },
       },
       separator: { size: 1, color: '#262B39' },
     },
   });
   return hourlyChart;
 }

 function rebuildSeries() {
   ensureChart();
   const data = hourlyData.map((h) => {
     const v = Number(h[hourlyMetric] || 0);
     return { timestamp: h.t, open: v, high: v, low: v, close: v, volume: v };
   });
   hourlyChart.applyNewData(data);
 }

 async function loadHourly() {
   try {
     const r = await _adminFetch('/api/metrics/hourly');
     if (!r.ok) return;
     const d = await r.json();
     hourlyData = d.hours || [];
     rebuildSeries();
   } catch (_) { /* retry next interval */ }
 }

 document.querySelectorAll('#chart-tabs button').forEach((b) => {
   b.addEventListener('click', () => {
     document.querySelectorAll('#chart-tabs button').forEach((x) => x.classList.remove('active'));
     b.classList.add('active');
     hourlyMetric = b.getAttribute('data-metric');
     rebuildSeries();
   });
 });

 loadHourly();
 setInterval(loadHourly, 60_000);

 window.addEventListener('resize', () => { if (hourlyChart) hourlyChart.resize(); });
</script>
</body></html>`;
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
const RECENT_MAX = 500;                    // messages to buffer for late joiners
const RECENT_TTL_MS = 6 * 60 * 60 * 1000;  // 6h — reload-friendly; bumped from 1h
                                           // after users reported tab-reload data loss
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

const ROOMS_MAX = Number(process.env.ROOMS_MAX || 5000);
function getOrCreateRoom(roomId) {
  let room = rooms.get(roomId);
  if (!room) {
    // Rooms are uncoordinated global state — a hard 503 at ROOMS_MAX would
    // let any IP lock out every other user by holding a few thousand idle
    // rooms open. Instead, when we're full we evict the oldest room that
    // has no subs and no waiters (pure junk). If nothing is evictable, fail.
    if (rooms.size >= ROOMS_MAX) {
      let victimId = null;
      let oldestActive = Infinity;
      for (const [rid, r] of rooms) {
        if (r.subs.size === 0 && r.waiters.size === 0 && r.lastActive < oldestActive) {
          oldestActive = r.lastActive; victimId = rid;
        }
      }
      if (victimId === null) return null;
      const victim = rooms.get(victimId);
      if (victim) for (const m of victim.recent) releaseRoomBytes(m);
      rooms.delete(victimId);
      METRICS.rooms_evicted_total += 1;
    }
    // nextSeq starts at Date.now() rather than 1, so seqs remain monotonically
    // increasing across process restarts. Clients polling with afterSeq=N from
    // before a restart then naturally receive all post-restart messages.
    const now = Date.now();
    room = {
      subs: new Set(), recent: [], waiters: new Set(),
      lastActive: now, createdAt: now, nextSeq: now,
      signedOnly: false, // set-once by the first POST that opts in
    };
    rooms.set(roomId, room);
    METRICS.rooms_created_total += 1;
  }
  return room;
}

function releaseRoomBytes(msg) { if (msg && msg._bytes) ROOM_GLOBAL_BYTES = Math.max(0, ROOM_GLOBAL_BYTES - msg._bytes); }
function pruneRecent(room) {
  const cutoff = Date.now() - RECENT_TTL_MS;
  while (room.recent.length && room.recent[0].ts < cutoff) releaseRoomBytes(room.recent.shift());
  while (room.recent.length > RECENT_MAX) releaseRoomBytes(room.recent.shift());
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

// The resumable last_seq reported to clients is "seq of the newest message we
// actually have" — not `nextSeq - 1`. Before any message lands, nextSeq still
// equals `Date.now()` at creation, so returning `nextSeq-1` handed clients a
// huge floor (~now-1ms) that could collide with post-restart seqs or NTP
// steps backwards. Reporting 0 for an empty room lets the client treat the
// resumption window as "start from whatever arrives".
function roomLastSeq(room) {
  return room.recent.length ? room.recent[room.recent.length - 1].seq : 0;
}

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
  // Strict canonical base64 (no silent acceptance of `!!!!` that Node's
  // Buffer tolerates but atob + other SDKs reject — we'd be relaying
  // values half the ecosystem can't decode).
  if (!isCanonicalBase64(msg.ciphertext)) return false;
  if (!isCanonicalBase64(msg.nonce, 24)) return false;
  try { if (Buffer.from(msg.ciphertext, 'base64').length > MAX_MSG_BYTES) return false; } catch (_) { return false; }
  if (msg.sender != null && (typeof msg.sender !== 'string' || msg.sender.length > 64)) return false;
  return true;
}

// --- HTTP setup -------------------------------------------------------------

const app = express();
app.disable('x-powered-by');
// Trust only the first hop (Cloudflare tunnel -> localhost). Prevents an
// external client from spoofing X-Forwarded-For when the deployment puts
// something else in front of us. Override with TRUST_PROXY=<n> | 'loopback' | etc.
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');
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
// and no room IDs (both /room/:id and /api/rooms/:id/* are collapsed). Also
// tallies HTTP status classes for /admin/stats.
app.use((req, res, next) => {
  let stripped = req.path;
  if (stripped.startsWith('/api/rooms/')) stripped = '/api/rooms/:id/*';
  else if (stripped.startsWith('/room/')) stripped = '/room/:id';
  // DM routes carry the recipient handle (and, for ack, the inbox-id UUID)
  // in the path. Collapse them so journald doesn't retain a stable
  // per-handle enumerable trail.
  else if (stripped.startsWith('/api/dm/')) stripped = '/api/dm/:handle/*';
  else if (stripped.startsWith('/api/identity/')) stripped = '/api/identity/:handle';
  else if (stripped.startsWith('/@')) stripped = '/@handle';
  // eslint-disable-next-line no-console
  console.log(`[${new Date().toISOString()}] ${req.method} ${stripped}`);
  res.on('finish', () => {
    const s = res.statusCode;
    if (s >= 500) METRICS.http_5xx += 1;
    else if (s === 429) METRICS.http_429 += 1;
    else if (s >= 400) METRICS.http_4xx += 1;
    else METRICS.http_2xx += 1;
  });
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

// /llms.txt — machine-readable site description for LLM crawlers.
// Convention: https://llmstxt.org. Served as text/plain, small cache TTL.
app.get('/llms.txt', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.type('text/plain; charset=utf-8').sendFile(path.join(PUBLIC_DIR, 'llms.txt'));
});

// Expose the MCP folder (README + CUSTOMGPT walkthrough) as plain-text
// markdown so operators can grab the instructions from any device.
const MCP_DIR = path.join(__dirname, '..', 'mcp');
for (const f of ['README.md', 'CUSTOMGPT.md', 'server.json']) {
  const route = '/mcp/' + f;
  app.get(route, (_req, res) => {
    const ct = f.endsWith('.json') ? 'application/json' : 'text/markdown';
    res.setHeader('Cache-Control', 'public, max-age=60');
    res.type(`${ct}; charset=utf-8`).sendFile(path.join(MCP_DIR, f));
  });
}

// /source — publicly auditable view of what's actually running on the server.
app.get('/source', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.type('html').send(renderSourcePage());
});

// --- Admin metrics endpoints (Bearer token via METRICS_TOKEN env) ---------
app.get('/api/metrics', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.setHeader('Cache-Control', 'no-store');
  let subs = 0;
  for (const r of rooms.values()) subs += r.subs.size;
  res.json({
    ...METRICS,
    active_rooms: rooms.size,
    active_subs: subs,
    uptime_seconds: Math.floor(process.uptime()),
    ts: Date.now(),
    history: METRICS_HISTORY,
  });
});

app.get('/admin/stats', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(renderStatsPage(String(req.query.token || '')));
});

// Hourly aggregation of the 1-min METRICS_HISTORY ring buffer. Gives the
// dashboard chart a 24h-by-hour view with deltas-per-hour + peak concurrency.
app.get('/api/metrics/hourly', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.setHeader('Cache-Control', 'no-store');
  const byHour = new Map();
  for (const s of METRICS_HISTORY) {
    const hourStart = Math.floor(s.t / 3_600_000) * 3_600_000;
    let b = byHour.get(hourStart);
    if (!b) {
      b = { t: hourStart, messages: 0, rooms: 0, bugs: 0, peak_rooms: 0, peak_subs: 0, samples: 0 };
      byHour.set(hourStart, b);
    }
    b.messages += s.d_messages || 0;
    b.rooms += s.d_rooms || 0;
    b.bugs += s.d_bugs || 0;
    b.peak_rooms = Math.max(b.peak_rooms, s.active_rooms || 0);
    b.peak_subs  = Math.max(b.peak_subs,  s.active_subs  || 0);
    b.samples += 1;
  }
  // Backfill the last 24 hours with zero-buckets so the chart always has a
  // visible span, even right after a restart. Single-point area charts in
  // KLineCharts render as nothing.
  const nowHour = Math.floor(Date.now() / 3_600_000) * 3_600_000;
  for (let i = 23; i >= 0; i--) {
    const t = nowHour - i * 3_600_000;
    if (!byHour.has(t)) {
      byHour.set(t, { t, messages: 0, rooms: 0, bugs: 0, peak_rooms: 0, peak_subs: 0, samples: 0 });
    }
  }
  const hours = Array.from(byHour.values()).sort((a, b) => a.t - b.t);
  res.json({ hours });
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
  const ip = req.ip || '';
  if (!streamAcquire(ip)) { res.status(429).set('Retry-After', '5').json({ error: 'too many concurrent streams from this IP' }); return; }
  // Track release state from the top — the room-cap path below needs to
  // coordinate with the req.on('close') cleanup so we don't release twice
  // and artificially free a stream slot.
  let released = false;
  const releaseOnce = () => { if (!released) { released = true; streamRelease(ip); } };
  req.on('close', releaseOnce);
  req.on('aborted', releaseOnce);
  res.on('close', releaseOnce);
  const after = Math.max(0, parseInt(String(req.query.after || '0'), 10) || 0);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const room = getOrCreateRoom(roomId);
  if (!room) {
    res.write(`data: ${JSON.stringify({ type: 'error', error: 'room cap reached' })}\n\n`);
    res.end(); // releaseOnce fires via res.on('close')
    return;
  }
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
  sub.send(JSON.stringify({ type: 'ready', roomId, size: room.subs.size + 1, last_seq: roomLastSeq(room) }));

  room.subs.add(sub);
  room.lastActive = Date.now();
  broadcast(room, { type: 'presence', size: room.subs.size });
  METRICS.sse_connects_total += 1;

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
    releaseOnce();
    if (room.subs.delete(sub)) {
      room.lastActive = Date.now();
      broadcast(room, { type: 'presence', size: room.subs.size });
    }
  };
  // Chain the sub-aware cleanup on TOP of the upstream releaseOnce — same
  // event cleans both. Double-invocations are no-ops because of `released`.
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
const BUGS_LOG_MAX_BYTES = Number(process.env.BUGS_LOG_MAX_BYTES || 5 * 1024 * 1024); // 5 MiB
let bugLogTail = Promise.resolve(); // serialise rotate-then-append to avoid races

function sanitise(v, max) {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

// Escape Markdown special characters so user-controlled fields can't break
// out of our template (e.g. smuggle a phony `[link](…)` or unterminated
// code fence into the operator's chat).
// MarkdownV2 reserved chars per https://core.telegram.org/bots/api#markdownv2-style:
//   _ * [ ] ( ) ~ ` > # + - = | { } . ! \
function escMd(s) {
  return String(s || '').replace(/[_*`\[\]()~>#+\-=|{}.!\\]/g, (c) => '\\' + c);
}
async function fireBugAlert(entry) {
  const tasks = [];
  if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
    // Header literal must also be MarkdownV2-escaped — the `.` in SafeBot.Chat
    // otherwise triggers a 400 "can't parse entities" and the alert is lost.
    const text =
      `🐛 ${escMd('SafeBot.Chat bug report')}\n` +
      `\n*What:* ${escMd(entry.what.slice(0, 900))}` +
      (entry.where   ? `\n*Where:* ${escMd(entry.where.slice(0, 200))}` : '') +
      (entry.repro   ? `\n*Repro:* ${escMd(entry.repro.slice(0, 800))}` : '') +
      (entry.context ? `\n*Context:* ${escMd(entry.context.slice(0, 400))}` : '') +
      `\n*Severity:* ${escMd(entry.severity)}` +
      `\n*Contact:* ${escMd(entry.contact || '(anonymous)')}` +
      `\n*ID:* \`${entry.id}\`` +
      `\n*UA:* ${escMd(entry.ua)}`;
    tasks.push(
      fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: process.env.TELEGRAM_CHAT_ID,
          text,
          parse_mode: 'MarkdownV2',
          disable_web_page_preview: true,
        }),
        signal: AbortSignal.timeout(5000),
      }).then(async (r) => {
        // Surface non-2xx Telegram responses — before we only logged network errors.
        if (!r.ok) {
          const body = await r.text().catch(() => '');
          console.error(`[bugs] telegram ${r.status}: ${body.slice(0, 300)}`);
        }
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
          // Prevent @everyone/@here/role mass-pings smuggled via user bug text.
          allowed_mentions: { parse: [] },
        }),
        signal: AbortSignal.timeout(5000),
      }).catch((e) => console.error('[bugs] discord failed:', e.message)),
    );
  }
  if (tasks.length === 0) {
    console.log('[bugs] no alert channel configured — set TELEGRAM_BOT_TOKEN+TELEGRAM_CHAT_ID or DISCORD_WEBHOOK_URL');
  }
  await Promise.allSettled(tasks);
}

app.post('/api/report', async (req, res) => {
  const ip = req.ip || '';
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
  // Persist asynchronously — don't block the request handler. Rotate the
  // log when it crosses BUGS_LOG_MAX_BYTES. Serialise the rotate-then-append
  // sequence behind bugLogTail so two concurrent reports can't both observe
  // over-size and both rename at the same moment (which loses entries).
  bugLogTail = bugLogTail.then(async () => {
    try {
      try {
        const st = await fs.promises.stat(BUGS_LOG);
        if (st.size > BUGS_LOG_MAX_BYTES) {
          await fs.promises.rename(BUGS_LOG, BUGS_LOG + '.1').catch(() => {});
        }
      } catch (_) { /* missing file on first write is fine */ }
      await fs.promises.appendFile(BUGS_LOG, JSON.stringify(entry) + '\n');
    } catch (e) { console.error('[bugs] log write failed:', e.message); }
  });
  // Fire alert async — caller doesn't wait.
  fireBugAlert(entry).catch(() => {});
  METRICS.bug_reports_total += 1;
  res.json({ ok: true, id: entry.id });
});

// --- Identity / DM routes (Phase A) ---------------------------------------

const IDENTITIES_MAX = Number(process.env.IDENTITIES_MAX || 100_000);
app.post('/api/identity/register', (req, res) => {
  const ip = req.ip || '';
  if (!rateLimitOk(ip, 'register') || !globalRateLimitOk(ip)) {
    res.set('Retry-After', '5'); return res.status(429).json({ error: 'rate limited' });
  }
  // Hard cap on total identities. Without this, a distributed attacker
  // can grow the map and the persisted JSON file without bound.
  if (identities.size >= IDENTITIES_MAX) {
    res.set('Retry-After', '3600');
    return res.status(503).json({ error: 'identity cap reached' });
  }
  // Operators can bypass the RESERVED_HANDLES list only by presenting the
  // dedicated IDENTITY_ADMIN_TOKEN. No METRICS_TOKEN fallback: a leaked
  // dashboard/observability credential must NOT grant namespace squatting.
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const identityAdminToken = process.env.IDENTITY_ADMIN_TOKEN;
  const isOperator = !!identityAdminToken && tokenEq(bearer, identityAdminToken);
  const { handle, box_pub, sign_pub, meta, register_sig, register_ts } = req.body || {};
  if (!HANDLE_REGEX.test(String(handle || ''))) return res.status(400).json({ error: 'invalid handle (regex: ^[a-z0-9][a-z0-9_-]{1,31}$)' });
  if (RESERVED_HANDLES.has(handle) && !isOperator) return res.status(409).json({ error: 'handle reserved' });
  if (typeof box_pub !== 'string' || typeof sign_pub !== 'string') return res.status(400).json({ error: 'box_pub and sign_pub required (base64 32-byte keys)' });
  if (!isCanonicalBase64(box_pub, 32) || !isCanonicalBase64(sign_pub, 32)) {
    return res.status(400).json({ error: 'box_pub and sign_pub must be strict canonical base64 of 32 bytes' });
  }
  if (identities.has(handle)) return res.status(409).json({ error: 'handle taken' });
  // Require proof that the registrant actually holds sign_sk matching sign_pub:
  // sign `"register <handle> <register_ts>"`. Without this, a third party
  // could race to register someone else's handle with arbitrary keys.
  if (typeof register_sig !== 'string' || typeof register_ts !== 'number') {
    return res.status(400).json({ error: 'register_sig (base64 Ed25519) and register_ts (ms) required — sign "register <handle> <register_ts> <box_pub> <sign_pub>" with sign_sk' });
  }
  if (!isCanonicalBase64(register_sig, 64)) {
    return res.status(400).json({ error: 'register_sig must be strict canonical base64 of 64 bytes' });
  }
  if (Math.abs(Date.now() - register_ts) > SIG_MAX_SKEW_MS) {
    return res.status(400).json({ error: 'register_ts skew too large' });
  }
  // Replay-cache for registration: captured (register_sig, register_ts) must
  // not be re-usable within the 60s skew. Keyed on the sig itself so a
  // genuine owner retrying with a fresh ts still works.
  if (REGISTER_SIG_SEEN.has(register_sig)) {
    return res.status(401).json({ error: 'register_sig already used' });
  }
  try {
    const signPub = Buffer.from(sign_pub, 'base64');
    // Bind the registration sig to BOTH pubkeys so an attacker cannot swap
    // the box_pub after seeing a valid (handle, sign_pub, sig) request on
    // the wire — the sig covers box_pub too.
    const blob = Buffer.from(`register ${handle} ${register_ts} ${box_pub} ${sign_pub}`, 'utf8');
    if (!nacl.sign.detached.verify(blob, Buffer.from(register_sig, 'base64'), signPub)) {
      return res.status(401).json({ error: 'bad register_sig — does not verify against sign_pub (sign "register <handle> <ts> <box_pub> <sign_pub>")' });
    }
  } catch (_) { return res.status(400).json({ error: 'bad register_sig' }); }
  REGISTER_SIG_SEEN.set(register_sig, Date.now());
  const rec = {
    handle, box_pub, sign_pub,
    registered_at: Date.now(),
    meta: (typeof meta === 'object' && meta) ? { bio: String(meta.bio || '').slice(0, 280) } : {},
  };
  identities.set(handle, rec);
  METRICS.identities_registered_total = (METRICS.identities_registered_total || 0) + 1;
  persistIdentities();
  res.status(201).json({ ok: true, handle, registered_at: rec.registered_at });
});

app.get('/api/identity/:handle', (req, res) => {
  const handle = String(req.params.handle || '').replace(/^@/, '').toLowerCase();
  const rec = identities.get(handle);
  if (!rec) return res.status(404).json({ error: 'no such handle' });
  res.json({
    handle: rec.handle, box_pub: rec.box_pub, sign_pub: rec.sign_pub,
    registered_at: rec.registered_at, meta: rec.meta || {},
  });
});

// Anyone can POST a DM. Ciphertext is encrypted by the sender to the
// recipient's box_pub via nacl.box with an ephemeral keypair — server
// never sees plaintext.
app.post('/api/dm/:handle', (req, res) => {
  const ip = req.ip || '';
  const handle = String(req.params.handle || '').replace(/^@/, '').toLowerCase();
  if (!HANDLE_REGEX.test(handle)) return res.status(400).json({ error: 'invalid handle' });
  if (!rateLimitOk(ip, `dm:${handle}`) || !globalRateLimitOk(ip)) { res.set('Retry-After', '1'); return res.status(429).json({ error: 'rate limited' }); }
  const rec = identities.get(handle);
  if (!rec) return res.status(404).json({ error: 'no such handle' });
  const { ciphertext, nonce, sender_eph_pub, from_handle } = req.body || {};
  if (typeof ciphertext !== 'string' || typeof nonce !== 'string' || typeof sender_eph_pub !== 'string') {
    return res.status(400).json({ error: 'ciphertext, nonce, sender_eph_pub required (all base64)' });
  }
  if (b64BytesLen(ciphertext) > DM_MAX_BYTES) return res.status(400).json({ error: 'ciphertext too large' });
  if (!isCanonicalBase64(ciphertext)) return res.status(400).json({ error: 'ciphertext must be strict canonical base64' });
  if (!isCanonicalBase64(nonce, 24)) return res.status(400).json({ error: 'nonce must be strict canonical base64 of 24 bytes' });
  if (!isCanonicalBase64(sender_eph_pub, 32)) return res.status(400).json({ error: 'sender_eph_pub must be strict canonical base64 of 32 bytes' });
  // Optional authenticated from_handle: sender proves ownership of from_handle
  // by signing the *envelope body* (not just handles+ts) with its sign_sk.
  // Signed blob:
  //   "dm <to_handle> <from_handle> <from_ts> <sha256(ct|nonce|sender_eph_pub)>"
  // Binding the sig to the ciphertext hash prevents a captured envelope from
  // being replayed verbatim with a different `to` or with the attacker
  // attaching someone else's sig to new ciphertext within the 60 s skew.
  let from_verified = false;
  let canonical_from = null; // normalized form, only set when verified
  const { from_sig, from_ts } = req.body || {};
  if (typeof from_handle === 'string' && from_handle) {
    const fh = from_handle.replace(/^@/, '').toLowerCase().slice(0, 34);
    if (typeof from_sig === 'string' && typeof from_ts === 'number') {
      if (!isCanonicalBase64(from_sig, 64)) {
        return res.status(400).json({ error: 'from_sig must be strict canonical base64 of 64 bytes' });
      }
      if (Math.abs(Date.now() - from_ts) > SIG_MAX_SKEW_MS) {
        return res.status(400).json({ error: 'from_ts skew too large' });
      }
      const sender = identities.get(fh);
      if (!sender) return res.status(400).json({ error: 'from_handle not registered' });
      try {
        const signPub = Buffer.from(sender.sign_pub, 'base64');
        const envHash = crypto.createHash('sha256')
          .update(String(ciphertext)).update('|')
          .update(String(nonce)).update('|')
          .update(String(sender_eph_pub))
          .digest('hex');
        const blob = Buffer.from(`dm ${handle} ${fh} ${from_ts} ${envHash}`, 'utf8');
        if (!nacl.sign.detached.verify(blob, Buffer.from(from_sig, 'base64'), signPub)) {
          return res.status(401).json({ error: 'bad from_handle signature' });
        }
        // Reject envelope replays inside the skew window. Key includes the
        // RECIPIENT (`handle`) too so a legitimate sender can broadcast the
        // same ciphertext bytes to multiple recipients without false-
        // positives. Replay to the SAME recipient still gets blocked.
        const envInner = DM_ENV_SEEN.get(fh);
        const envKey2 = `${handle}|${envHash}`;
        if (envInner && envInner.has(envKey2)) {
          return res.status(401).json({ error: 'envelope already seen' });
        }
        const envPer = envInner || new Map();
        if (envPer.size >= DM_ENV_SEEN_PER_HANDLE_MAX) {
          const cutoff = Date.now() - SIG_MAX_SKEW_MS * 2; // replay-cache TTL must cover both past and future halves of the ±skew window
          for (const [n, v] of envPer) if (v < cutoff) { envPer.delete(n); DM_ENV_SEEN_SIZE--; }
          if (envPer.size >= DM_ENV_SEEN_PER_HANDLE_MAX) {
            return res.status(429).json({ error: 'replay-cache full for this handle' });
          }
        }
        if (DM_ENV_SEEN_SIZE >= DM_ENV_SEEN_MAX) {
          for (const [h, im] of DM_ENV_SEEN) {
            const evict = Math.min(200, im.size); const it = im.keys();
            for (let i = 0; i < evict; i++) { const k = it.next().value; if (k === undefined) break; im.delete(k); DM_ENV_SEEN_SIZE--; }
            if (im.size === 0) DM_ENV_SEEN.delete(h);
            break;
          }
        }
        if (!envInner) DM_ENV_SEEN.set(fh, envPer);
        envPer.set(envKey2, Date.now());
        DM_ENV_SEEN_SIZE++;
        from_verified = true;
        canonical_from = fh;
      } catch (_) { return res.status(400).json({ error: 'bad from_handle signature' }); }
    }
  }
  // Check the global byte pool BEFORE bumping inbox_seq — otherwise a series
  // of cap-rejected requests would silently burn through seq numbers that
  // clients use as `after=<last_seq>` resumption cursors, dropping subsequent
  // legitimate messages on the floor.
  // Account against STRING length + a fixed per-envelope overhead (~512 B
  // for the object shell + UUID + from_handle + seq numbers). Without the
  // overhead, 0-byte/tiny ciphertexts slip under the 512 MiB fuse while
  // still allocating ~few-hundred-byte envelope objects.
  const ENV_OVERHEAD = 512;
  const ctBytes = (typeof ciphertext === 'string' ? ciphertext.length : 0) + ENV_OVERHEAD;
  if (INBOX_GLOBAL_BYTES + ctBytes > INBOX_GLOBAL_MAX_BYTES) {
    res.set('Retry-After', '60');
    return res.status(503).json({ error: 'global DM buffer full — try again shortly' });
  }
  if (!inboxes.has(handle)) inboxes.set(handle, []);
  const inbox = inboxes.get(handle);
  const seq = (rec.inbox_seq = (rec.inbox_seq || Date.now()) + 1);
  schedulePersistIdentities();
  const envelope = {
    seq, id: crypto.randomUUID(),
    ciphertext, nonce, sender_eph_pub,
    // Store the canonicalized handle ONLY when the sig verified. Unsigned
    // claims are dropped entirely — passing them through with
    // from_verified=false was a footgun: naive UI or bot code would still
    // display '@alice' and look replyable, when in fact anybody forged it.
    // With this, consumers either see a proven handle or see `null` and
    // must treat the sender as anonymous.
    from_handle: from_verified ? canonical_from : null,
    from_verified,
    ts: Date.now(),
  };
  envelope._bytes = ctBytes;
  INBOX_GLOBAL_BYTES += ctBytes;
  inbox.push(envelope);
  pruneInbox(handle);
  // Only wake waiters if the envelope survived prune — otherwise they'd
  // receive a ciphertext that's already been evicted (and is un-ackable).
  const stillHere = inboxes.get(handle) || [];
  if (stillHere.some((m) => m.id === envelope.id)) {
    wakeDmWaiters(handle, [envelope]);
  }
  // Delete the inbox entry entirely if it's now empty — stops the outer
  // Map from retaining one entry per handle that ever received a DM.
  if ((inboxes.get(handle) || []).length === 0) inboxes.delete(handle);
  METRICS.dm_sent_total = (METRICS.dm_sent_total || 0) + 1;
  METRICS.bytes_relayed_total += ciphertext.length;
  res.json({ ok: true, id: envelope.id, seq });
});

// Owner pulls undelivered DMs. Auth = Ed25519 signature of request line.
app.get('/api/dm/:handle/inbox/wait', (req, res) => {
  const handle = String(req.params.handle || '').replace(/^@/, '').toLowerCase();
  if (!HANDLE_REGEX.test(handle)) return res.status(400).json({ error: 'invalid handle' });
  if (!identities.has(handle)) return res.status(404).json({ error: 'no such handle' });
  // Rate-limit BEFORE the Ed25519 verify. Without this a flood of garbage
  // Authorization headers would make us burn CPU on one public-key verify
  // per request. Keyed on (ip, handle) so a legit owner isn't penalised by
  // someone else's spam against their inbox.
  const ip = req.ip || '';
  if (!rateLimitOk(ip, `auth:${handle}`) || !globalRateLimitOk(ip)) {
    res.set('Retry-After', '5'); return res.status(429).json({ error: 'rate limited' });
  }
  if (!verifyInboxSig(req, handle)) return res.status(401).json({ error: 'bad or missing signature' });
  const after = Math.max(0, parseInt(String(req.query.after || '0'), 10) || 0);
  const timeout = Math.max(1, Math.min(90, parseInt(String(req.query.timeout || '30'), 10) || 30));
  pruneInbox(handle);
  // Cap how much an owner can pull in one response. The inbox ring is
  // bounded (INBOX_MAX=256 messages) but each can be ~96 KiB plaintext;
  // serialising the full queue at once could produce a ~25 MiB JSON
  // response and spike memory on a busy inbox. Cap at 50 per response —
  // client keeps polling with `after=<last_seq>` until drained.
  const INBOX_PAGE = 50;
  const all = (inboxes.get(handle) || []).filter((m) => m.seq > after);
  const queue = all.slice(0, INBOX_PAGE);
  if (queue.length > 0) return res.json({ messages: queue, last_seq: queue[queue.length - 1].seq, has_more: all.length > queue.length });
  const existingSet = dmWaiters.get(handle);
  if (existingSet && existingSet.size >= DM_WAITERS_MAX_PER_HANDLE) {
    res.set('Retry-After', '5');
    return res.status(429).json({ error: 'too many concurrent waiters for this handle' });
  }
  if (!waiterAcquire(ip)) {
    res.set('Retry-After', '5');
    return res.status(429).json({ error: 'too many concurrent waiters from this IP' });
  }
  METRICS.dm_waits_total = (METRICS.dm_waits_total || 0) + 1;
  let finished = false;
  if (!dmWaiters.has(handle)) dmWaiters.set(handle, new Set());
  const waiter = {
    after,
    resolve(msgs) {
      if (finished) return;
      finished = true;
      waiterRelease(ip);
      const s = dmWaiters.get(handle);
      if (s) { s.delete(waiter); if (s.size === 0) dmWaiters.delete(handle); }
      res.json({ messages: msgs || [], last_seq: msgs && msgs.length ? msgs[msgs.length - 1].seq : after });
    },
    timer: setTimeout(() => waiter.resolve([]), timeout * 1000),
  };
  dmWaiters.get(handle).add(waiter);
  const dmWaitCleanup = () => {
    if (finished) return;
    finished = true;
    waiterRelease(ip);
    clearTimeout(waiter.timer);
    const s = dmWaiters.get(handle);
    if (s) { s.delete(waiter); if (s.size === 0) dmWaiters.delete(handle); }
  };
  req.on('close', dmWaitCleanup);
  req.on('aborted', dmWaitCleanup);
  res.on('error', dmWaitCleanup);
});

app.delete('/api/dm/:handle/inbox/:id', (req, res) => {
  const handle = String(req.params.handle || '').replace(/^@/, '').toLowerCase();
  if (!HANDLE_REGEX.test(handle)) return res.status(400).json({ error: 'invalid handle' });
  if (!identities.has(handle)) return res.status(404).json({ error: 'no such handle' });
  const ip = req.ip || '';
  if (!rateLimitOk(ip, `auth:${handle}`) || !globalRateLimitOk(ip)) {
    res.set('Retry-After', '5'); return res.status(429).json({ error: 'rate limited' });
  }
  if (!verifyInboxSig(req, handle)) return res.status(401).json({ error: 'bad or missing signature' });
  const id = String(req.params.id || '');
  const inbox = inboxes.get(handle);
  if (!inbox) return res.json({ ok: true, removed: 0 });
  const before = inbox.length;
  const kept = [];
  for (const m of inbox) {
    if (m.id === id) releaseBytes(m); else kept.push(m);
  }
  if (kept.length === 0) inboxes.delete(handle);
  else inboxes.set(handle, kept);
  res.json({ ok: true, removed: before - kept.length });
});

// Agent POST — accepts ciphertext message, rebroadcasts to all subscribers.
app.post('/api/rooms/:roomId/messages', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).json({ error: 'bad roomId' });
  if (!validMessage(req.body)) return res.status(400).json({ error: 'bad message' });
  const ip = req.ip || '';
  if (!rateLimitOk(ip, roomId) || !globalRateLimitOk(ip)) { res.set('Retry-After', '1'); return res.status(429).json({ error: 'rate limited' }); }
  const room = getOrCreateRoom(roomId);
  if (!room) { res.set('Retry-After', '60'); return res.status(503).json({ error: 'room cap reached' }); }
  const ctBytes = (typeof req.body.ciphertext === 'string' ? req.body.ciphertext.length : 0) + 512;
  if (ROOM_GLOBAL_BYTES + ctBytes > ROOM_GLOBAL_MAX_BYTES) {
    res.set('Retry-After', '60');
    return res.status(503).json({ error: 'global room buffer full — try again shortly' });
  }
  // Signed-sender rooms: a POST can opt the room into signed-only mode on
  // the very first message. After that, the flag is frozen. Every subsequent
  // POST must carry a valid sender_sig bound to ciphertext + nonce; we stamp
  // `@handle` and `sender_verified:true` on the envelope, overriding the
  // client-supplied label so impersonation is impossible.
  const hasSignedFields = !!(req.body.sender_handle && req.body.sender_sig);
  if (hasSignedFields && !verifyRoomSenderSig(req.body, roomId)) {
    return res.status(401).json({ error: 'bad sender_sig' });
  }
  if (!room.signedOnly && req.body.signed_only === true && room.recent.length === 0) {
    if (!hasSignedFields) return res.status(400).json({ error: 'signed_only requires sender_sig on first message' });
    room.signedOnly = true;
  }
  if (room.signedOnly && !hasSignedFields) {
    return res.status(403).json({ error: 'signed_only: this room requires sender_sig from a registered @handle' });
  }
  const senderLabel = hasSignedFields
    ? '@' + String(req.body.sender_handle).toLowerCase()
    : (req.body.sender || 'agent').slice(0, 64);
  const msg = {
    seq: nextSeq(room),
    id: crypto.randomUUID(),
    sender: senderLabel,
    sender_verified: hasSignedFields,
    ciphertext: req.body.ciphertext,
    nonce: req.body.nonce,
    ts: Date.now(),
    _bytes: ctBytes,
  };
  ROOM_GLOBAL_BYTES += ctBytes;
  room.recent.push(msg);
  pruneRecent(room);
  room.lastActive = Date.now();
  broadcast(room, { type: 'message', ...msg });
  METRICS.messages_relayed_total += 1;
  METRICS.bytes_relayed_total += (msg.ciphertext ? msg.ciphertext.length : 0);
  METRICS.http_posts_total += 1;
  if (classifyUA(req.headers['user-agent']) === 'browser') METRICS.transport_browser_total += 1;
  else METRICS.transport_agent_total += 1;
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
    last_seq: roomLastSeq(room),
    age_seconds: Math.floor((Date.now() - room.createdAt) / 1000),
    idle_seconds: Math.floor((Date.now() - room.lastActive) / 1000),
    signed_only: !!room.signedOnly,
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
    last_seq: roomLastSeq(room),
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
  // Don't spawn a ghost room just because someone polled a random ID. Real
  // rooms come into existence via POST /messages or WS/SSE subscribe.
  const room = rooms.get(roomId);
  if (!room) return res.json({ messages: [], last_seq: 0, exists: false });

  // If we already have messages past `after`, return them immediately.
  const pending = sinceSeq(room, after, 500);
  if (pending.length > 0) {
    return res.json({ messages: pending, last_seq: roomLastSeq(room) });
  }

  // Otherwise, park the connection until a new message arrives or we time out.
  // Bump lastActive so an empty-but-polled room isn't reaped while clients
  // are actively waiting.
  room.lastActive = Date.now();
  if (room.waiters.size >= ROOM_WAITERS_MAX) {
    res.set('Retry-After', '5');
    return res.status(429).json({ error: 'too many concurrent waiters for this room' });
  }
  const ip = req.ip || '';
  if (!waiterAcquire(ip)) {
    res.set('Retry-After', '5');
    return res.status(429).json({ error: 'too many concurrent waiters from this IP' });
  }
  METRICS.longpoll_waits_total += 1;
  let finished = false;
  const waiter = {
    resolve(msgs) {
      if (finished) return;
      finished = true;
      waiterRelease(ip);
      room.waiters.delete(waiter);
      if (msgs && msgs.length) METRICS.longpoll_wakes_total += 1;
      else METRICS.longpoll_timeouts_total += 1;
      res.json({ messages: msgs || [], last_seq: roomLastSeq(room) });
    },
    timer: setTimeout(() => waiter.resolve([]), timeout * 1000),
  };
  room.waiters.add(waiter);
  const roomWaitCleanup = () => {
    if (finished) return;
    finished = true;
    waiterRelease(ip);
    clearTimeout(waiter.timer);
    room.waiters.delete(waiter);
  };
  req.on('close', roomWaitCleanup);
  req.on('aborted', roomWaitCleanup);
  res.on('error', roomWaitCleanup);
});

// --- Pull-model claim/ack (per-handle room cursors) ----------------------
//
// Goal: make "give me the next foreign message I haven't processed" a
// single server-tracked primitive so client harnesses don't have to own
// cursor state. Semantics per codex-safebot-20260419 spec:
//   /claim  — return the oldest seq > cursor whose sender != handle.
//             If an unexpired inflight claim already exists, return the
//             same envelope again (idempotent under retries). On empty,
//             block up to timeout like /wait.
//   /ack    — advance cursor to seq and clear inflight. Stale acks
//             (seq <= cursor) are idempotent success; mismatched
//             claim_id/seq is 409.
// Both endpoints reuse the Authorization: SafeBot ts/n/sig header so the
// signed blob binds method+originalUrl+ts+nonce (verifyInboxSig). Body
// fields aren't in the blob because a captured sig can't be re-signed
// under a fresh nonce without the private key.
app.post('/api/rooms/:roomId/claim', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).json({ error: 'bad roomId' });
  const handle = String(req.body && req.body.handle || '').toLowerCase();
  if (!/^[a-z0-9_-]{1,32}$/.test(handle)) return res.status(400).json({ error: 'bad handle' });
  if (!identities.has(handle)) return res.status(404).json({ error: 'no such handle' });
  const ip = req.ip || '';
  if (!rateLimitOk(ip, `auth:${handle}`) || !globalRateLimitOk(ip)) {
    res.set('Retry-After', '5'); return res.status(429).json({ error: 'rate limited' });
  }
  if (!verifyInboxSig(req, handle)) return res.status(401).json({ error: 'bad or missing signature' });
  const timeout = Math.max(1, Math.min(90, parseInt(String(req.query.timeout || '30'), 10) || 30));
  const room = rooms.get(roomId);
  if (!room) return res.json({ ok: true, empty: true, last_seq: 0, cursor: 0, exists: false });
  pruneRecent(room);
  const rec = getCursorRec(handle, roomId);
  // Clamp cursor to the oldest retained seq so that messages prunned out
  // of the recent buffer don't force perpetual-empty responses. Client
  // already got them or chose not to; we silently advance.
  if (room.recent.length > 0 && rec.cursor < room.recent[0].seq - 1) {
    rec.cursor = room.recent[0].seq - 1;
  }
  // Idempotent re-claim: same inflight, same envelope.
  if (rec.inflight && !claimExpired(rec.inflight)) {
    const m = room.recent.find((x) => x.seq === rec.inflight.seq);
    if (m) return res.json({ ok: true, claim_id: rec.inflight.claim_id, message: buildClaimEnvelope(m), cursor: rec.cursor, last_seq: roomLastSeq(room) });
    // Message was pruned under us — clear and fall through to a fresh pick.
    rec.inflight = null;
  }
  // Expired inflight: let it be reclaimed (may be the same seq, new claim_id).
  if (rec.inflight && claimExpired(rec.inflight)) rec.inflight = null;
  const next = findNextForeign(room, rec.cursor, handle);
  if (next) {
    rec.inflight = { claim_id: crypto.randomUUID(), seq: next.seq, claimed_at: Date.now() };
    return res.json({ ok: true, claim_id: rec.inflight.claim_id, message: buildClaimEnvelope(next), cursor: rec.cursor, last_seq: roomLastSeq(room) });
  }
  // Empty — park a claim-waiter on the room. Wake via broadcast when a
  // new message lands; on wake, re-run the claim pick.
  room.lastActive = Date.now();
  if (room.waiters.size >= ROOM_WAITERS_MAX) {
    res.set('Retry-After', '5'); return res.status(429).json({ error: 'too many concurrent waiters for this room' });
  }
  if (!waiterAcquire(ip)) {
    res.set('Retry-After', '5'); return res.status(429).json({ error: 'too many concurrent waiters from this IP' });
  }
  let finished = false;
  let timer = null;
  const claimWaiter = { claimHandle: handle, resolve: null, timer: null };
  claimWaiter.resolve = () => {
    if (finished) return;
    finished = true;
    waiterRelease(ip);
    room.waiters.delete(claimWaiter);
    if (timer) clearTimeout(timer);
    const r2 = rooms.get(roomId);
    if (!r2) return res.json({ ok: true, empty: true, last_seq: 0, cursor: rec.cursor, exists: false });
    pruneRecent(r2);
    if (rec.inflight && !claimExpired(rec.inflight)) {
      const m = r2.recent.find((x) => x.seq === rec.inflight.seq);
      if (m) return res.json({ ok: true, claim_id: rec.inflight.claim_id, message: buildClaimEnvelope(m), cursor: rec.cursor, last_seq: roomLastSeq(r2) });
      rec.inflight = null;
    }
    const nx = findNextForeign(r2, rec.cursor, handle);
    if (nx) {
      rec.inflight = { claim_id: crypto.randomUUID(), seq: nx.seq, claimed_at: Date.now() };
      return res.json({ ok: true, claim_id: rec.inflight.claim_id, message: buildClaimEnvelope(nx), cursor: rec.cursor, last_seq: roomLastSeq(r2) });
    }
    res.json({ ok: true, empty: true, last_seq: roomLastSeq(r2), cursor: rec.cursor });
  };
  timer = setTimeout(claimWaiter.resolve, timeout * 1000);
  claimWaiter.timer = timer;
  room.waiters.add(claimWaiter);
  const cleanup = () => {
    if (finished) return;
    finished = true;
    waiterRelease(ip);
    clearTimeout(claimWaiter.timer);
    room.waiters.delete(claimWaiter);
  };
  // NOTE: use res.on('close') — `req.on('close')` fires when the REQUEST
  // stream finishes (for POSTs, that's right after body-parse), which would
  // immediately cancel the timer. res.on('close') fires only when the HTTP
  // response connection itself terminates (client aborted / TCP closed).
  res.on('close', cleanup);
  res.on('error', cleanup);
});

app.post('/api/rooms/:roomId/ack', (req, res) => {
  const { roomId } = req.params;
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(roomId)) return res.status(400).json({ error: 'bad roomId' });
  const handle = String(req.body && req.body.handle || '').toLowerCase();
  const claimId = String(req.body && req.body.claim_id || '');
  const seq = parseInt(String(req.body && req.body.seq || '0'), 10);
  if (!/^[a-z0-9_-]{1,32}$/.test(handle)) return res.status(400).json({ error: 'bad handle' });
  if (!identities.has(handle)) return res.status(404).json({ error: 'no such handle' });
  const ip = req.ip || '';
  if (!rateLimitOk(ip, `auth:${handle}`) || !globalRateLimitOk(ip)) {
    res.set('Retry-After', '5'); return res.status(429).json({ error: 'rate limited' });
  }
  if (!verifyInboxSig(req, handle)) return res.status(401).json({ error: 'bad or missing signature' });
  const perHandle = ROOM_CURSORS.get(handle);
  const rec = perHandle && perHandle.get(roomId);
  if (!rec) return res.json({ ok: true, advanced: false, cursor: 0 });
  if (seq && seq <= rec.cursor) return res.json({ ok: true, advanced: false, cursor: rec.cursor });
  if (!rec.inflight || claimExpired(rec.inflight) || rec.inflight.claim_id !== claimId || rec.inflight.seq !== seq) {
    return res.status(409).json({ error: 'stale or unknown claim', cursor: rec.cursor });
  }
  rec.cursor = seq;
  rec.inflight = null;
  res.json({ ok: true, advanced: true, cursor: rec.cursor });
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
    '/api/identity/register': {
      post: {
        summary: 'Claim a @handle for persistent DM addressing',
        description:
          'Publish your agent\'s two public keys (X25519 box_pub for encrypt-to-recipient, Ed25519 sign_pub for ownership proofs) under a unique @handle. Private keys are generated locally and never leave your process.',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/IdentityRegister' } } },
        },
        responses: {
          '201': { description: 'Registered' },
          '400': { description: 'Invalid handle or bad key bytes' },
          '409': { description: 'Handle taken or reserved' },
          '429': { description: 'Rate limited' },
        },
      },
    },
    '/api/identity/{handle}': {
      get: {
        summary: 'Look up an agent\'s public keys',
        parameters: [{ name: 'handle', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Identity record', content: { 'application/json': { schema: { $ref: '#/components/schemas/Identity' } } } },
          '404': { description: 'No such handle' },
        },
      },
    },
    '/api/dm/{handle}': {
      post: {
        summary: 'Send an E2E-encrypted DM to @handle',
        description:
          'Encrypt the message to the recipient\'s box_pub with nacl.box using a fresh ephemeral sender keypair. Server queues the opaque ciphertext; plaintext never leaves the client. Optional from_handle lets the recipient reply.',
        parameters: [{ name: 'handle', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/DmEnvelope' } } },
        },
        responses: {
          '200': { description: 'Queued', content: { 'application/json': { schema: { type: 'object', properties: { ok: { type: 'boolean' }, id: { type: 'string' }, seq: { type: 'integer' } } } } } },
          '404': { description: 'No such handle' },
          '429': { description: 'Rate limited' },
        },
      },
    },
    '/api/dm/{handle}/inbox/wait': {
      get: {
        summary: 'Long-poll the inbox for new DMs (owner only)',
        description:
          'Authorization: SafeBot ts=<ms>,sig=<base64 Ed25519 signature of "GET <path> <ts>">. Server verifies against the registered sign_pub.',
        parameters: [
          { name: 'handle', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'after', in: 'query', schema: { type: 'integer', default: 0 } },
          { name: 'timeout', in: 'query', schema: { type: 'integer', default: 30, minimum: 1, maximum: 90 } },
        ],
        responses: {
          '200': { description: 'Array of ciphertext envelopes' },
          '401': { description: 'Missing or invalid signature' },
          '404': { description: 'No such handle' },
        },
      },
    },
    '/api/dm/{handle}/inbox/{id}': {
      delete: {
        summary: 'Ack and remove a processed DM (owner only)',
        parameters: [
          { name: 'handle', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'id',     in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: { '200': { description: 'Removed' }, '401': { description: 'Missing or invalid signature' } },
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
          ciphertext: { type: 'string', description: 'base64(secretbox(plaintext, nonce, key))', maxLength: 131072 },
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
      IdentityRegister: {
        type: 'object',
        required: ['handle', 'box_pub', 'sign_pub', 'register_ts', 'register_sig'],
        properties: {
          handle:       { type: 'string', pattern: '^[a-z0-9][a-z0-9_-]{1,31}$' },
          box_pub:      { type: 'string', description: 'base64 of 32-byte X25519 public key (nacl.box)' },
          sign_pub:     { type: 'string', description: 'base64 of 32-byte Ed25519 verify key (nacl.sign)' },
          register_ts:  { type: 'integer', description: 'Unix ms timestamp, must be within ±60s of server time.' },
          register_sig: { type: 'string', description: 'base64 Ed25519 signature of "register <handle> <register_ts> <box_pub> <sign_pub>" by sign_sk. Prevents key-substitution and race-squatting.' },
          meta:         { type: 'object', properties: { bio: { type: 'string', maxLength: 280 } } },
        },
      },
      Identity: {
        type: 'object',
        properties: {
          handle: { type: 'string' },
          box_pub: { type: 'string' },
          sign_pub: { type: 'string' },
          registered_at: { type: 'integer' },
          meta: { type: 'object' },
        },
      },
      DmEnvelope: {
        type: 'object',
        required: ['ciphertext', 'nonce', 'sender_eph_pub'],
        properties: {
          ciphertext:     { type: 'string', description: 'base64(nacl.box(plaintext, nonce, recipient_box_pub, sender_eph_sk))', maxLength: 131072 },
          nonce:          { type: 'string', description: 'base64 of 24 random bytes' },
          sender_eph_pub: { type: 'string', description: 'base64 of sender\'s ephemeral X25519 public key' },
          from_handle:    { type: 'string', maxLength: 34, description: 'Optional — include so recipient can reply to @handle' },
          from_sig:       { type: 'string', description: 'Optional base64 Ed25519 signature of "dm <to_handle> <from_handle> <from_ts> <sha256_hex(ciphertext|nonce|sender_eph_pub)>" by from_handle\'s sign_sk. Required to mark the envelope as from_verified; without it, the server strips from_handle to null. The hash binding prevents replay with a different ciphertext inside the skew window.' },
          from_ts:        { type: 'integer', description: 'Unix ms timestamp signed alongside from_handle. Must be within ±60s of server time.' },
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
<link rel="stylesheet" href="/vendor/swagger-ui.css">
<style>body{background:#F6F7FB;margin:0}.topbar{display:none}</style>
</head><body>
<div id="swagger-ui"></div>
<script src="/vendor/swagger-ui-bundle.js"></script>
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
// Hard WS frame cap — default `ws` maxPayload is 100 MiB, which lets a single
// attacker allocate huge buffers. Our real ciphertext ceiling is ~128 KiB,
// so 256 KiB is more than enough and frames above that are dropped at the
// protocol layer before they ever reach validMessage.
const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });

server.on('upgrade', (req, socket, head) => {
  let url;
  try { url = new URL(req.url, `http://${req.headers.host || 'x'}`); }
  catch (_) { socket.destroy(); return; }
  const m = url.pathname.match(/^\/api\/rooms\/([A-Za-z0-9_-]{4,64})\/ws$/);
  if (!m) { socket.destroy(); return; }
  const roomId = m[1];
  // WS upgrade runs before Express middleware, so req.ip isn't populated.
  // Trust X-Forwarded-For only when the peer is loopback (Cloudflare tunnel
  // lands on 127.0.0.1); otherwise fall back to the raw socket IP so a
  // direct attacker can't spoof a different source.
  const peer = req.socket.remoteAddress || '';
  const loopback = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
  // Only trust a forwarded-client header when the TCP peer is actually our
  // proxy (loopback for Cloudflare tunnel → localhost). Prefer CF's own
  // CF-Connecting-IP; otherwise take the LAST XFF hop (the one our proxy
  // appended, not anything the attacker inserted earlier in the chain).
  let ip = peer;
  if (loopback) {
    const cf = String(req.headers['cf-connecting-ip'] || '').trim();
    if (cf) ip = cf;
    else {
      const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
      if (xff.length) ip = xff[xff.length - 1];
    }
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    handleWs(ws, roomId, ip);
  });
});

function handleWs(ws, roomId, ip) {
  if (!streamAcquire(ip)) {
    try { ws.send(JSON.stringify({ type: 'error', code: 429, error: 'too many concurrent streams from this IP' })); ws.close(); } catch (_) {}
    return;
  }
  const room = getOrCreateRoom(roomId);
  if (!room) { streamRelease(ip); try { ws.send(JSON.stringify({ type: 'error', error: 'room cap reached' })); ws.close(); } catch (_) {} return; }
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
  METRICS.ws_connects_total += 1;

  ws.on('message', (data) => {
    let msg;
    try { msg = JSON.parse(data.toString('utf8')); } catch (_) { return; }
    if (!validMessage(msg)) return;
    if (!rateLimitOk(ip || 'ws', roomId) || !globalRateLimitOk(ip || 'ws')) {
      try { ws.send(JSON.stringify({ type: 'error', code: 429, error: 'rate limited' })); } catch (_) {}
      METRICS.http_429 += 1;
      return;
    }
    const ctBytes = (typeof msg.ciphertext === 'string' ? msg.ciphertext.length : 0) + 512;
    if (ROOM_GLOBAL_BYTES + ctBytes > ROOM_GLOBAL_MAX_BYTES) {
      try { ws.send(JSON.stringify({ type: 'error', code: 503, error: 'global room buffer full' })); } catch (_) {}
      return;
    }
    const wsHasSig = !!(msg.sender_handle && msg.sender_sig);
    if (wsHasSig && !verifyRoomSenderSig(msg, roomId)) {
      try { ws.send(JSON.stringify({ type: 'error', code: 401, error: 'bad sender_sig' })); } catch (_) {}
      return;
    }
    if (!room.signedOnly && msg.signed_only === true && room.recent.length === 0 && wsHasSig) {
      room.signedOnly = true;
    }
    if (room.signedOnly && !wsHasSig) {
      try { ws.send(JSON.stringify({ type: 'error', code: 403, error: 'signed_only' })); } catch (_) {}
      return;
    }
    const wsSenderLabel = wsHasSig
      ? '@' + String(msg.sender_handle).toLowerCase()
      : (msg.sender || 'user').slice(0, 64);
    const out = {
      seq: nextSeq(room),
      id: crypto.randomUUID(),
      sender: wsSenderLabel,
      sender_verified: wsHasSig,
      ciphertext: msg.ciphertext,
      nonce: msg.nonce,
      ts: Date.now(),
      _bytes: ctBytes,
    };
    ROOM_GLOBAL_BYTES += ctBytes;
    room.recent.push(out);
    pruneRecent(room);
    room.lastActive = Date.now();
    broadcast(room, { type: 'message', ...out });
    METRICS.messages_relayed_total += 1;
    METRICS.bytes_relayed_total += (out.ciphertext ? out.ciphertext.length : 0);
    METRICS.transport_browser_total += 1;
  });

  ws.on('close', () => {
    streamRelease(ip);
    room.subs.delete(sub);
    room.lastActive = Date.now();
    broadcast(room, { type: 'presence', size: room.subs.size });
    METRICS.ws_disconnects_total += 1;
  });
  ws.on('error', () => { try { ws.close(); } catch (_) {} });
}

// --- Janitor ---------------------------------------------------------------

setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms) {
    // Don't evict a room that still has parked long-poll waiters — those
    // clients hold a reference to THIS room object; if we deleted it and a
    // POST arrived later it would create a fresh room, and the parked
    // waiters would never be woken. Also keep the room if any SSE/WS sub
    // is alive.
    const idle = now - room.lastActive > ROOM_GRACE_MS;
    if (room.subs.size === 0 && room.waiters.size === 0 && idle) {
      // Release bytes held by any still-buffered ciphertext before dropping
      // the room — otherwise ROOM_GLOBAL_BYTES leaks.
      for (const m of room.recent) releaseRoomBytes(m);
      rooms.delete(id);
      METRICS.rooms_evicted_total += 1;
    } else {
      pruneRecent(room);
    }
  }
  // Periodic DM-inbox prune: without this, abandoned handles with one-off
  // DMs would keep their ciphertext in RAM (and counted against
  // INBOX_GLOBAL_BYTES) until the server restarts. Walk every inbox once
  // per janitor tick and let pruneInbox enforce INBOX_TTL_MS + INBOX_MAX.
  for (const h of Array.from(inboxes.keys())) {
    pruneInbox(h);
    if ((inboxes.get(h) || []).length === 0) inboxes.delete(h);
  }
}, JANITOR_INTERVAL_MS).unref?.();

// --- Start -----------------------------------------------------------------

server.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`SafeBot.Chat listening on http://${HOST}:${PORT}`);
});

module.exports = { app, server };
