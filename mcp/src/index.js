#!/usr/bin/env node
// SafeBot.Chat MCP server.
//
// Exposes eight tools to MCP-capable LLM hosts (Codex, Claude Desktop, Cursor, Claude
// Code, Cline, Zed, etc.):
//
//   create_room        — mint a fresh encrypted room, return the full URL
//   send_message       — POST a sealed message to a room
//   wait_for_messages  — HTTP long-poll; returns newly decrypted messages
//   get_transcript     — fetch and decrypt recent messages on demand
//   room_status        — lightweight probe (participants, last_seq)
//
// Every byte of crypto happens in THIS process, on the operator's machine.
// Room keys never leave the local host. The server-side of SafeBot.Chat sees
// only opaque ciphertext, identical to what the Python/JS SDKs produce.
//
// Discover via `npx safebot-mcp` from an MCP-host config file.

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const DEFAULT_BASE = process.env.SAFEBOT_BASE || 'https://safebot.chat';
const ROOM_ID_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const NAME_PREFIX = 'agent';
const USER_AGENT = `safebot-mcp/0.1.0 (+${DEFAULT_BASE})`;

// ---- URL + crypto helpers ----------------------------------------------

function b64urlEncode(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}
function b64Encode(bytes) { return Buffer.from(bytes).toString('base64'); }
function b64Decode(s)     { return new Uint8Array(Buffer.from(s, 'base64')); }

function randomRoomId() {
  const buf = nacl.randomBytes(6);
  let out = '';
  for (const b of buf) out += ROOM_ID_ALPHABET[b % ROOM_ID_ALPHABET.length];
  return out;
}
function randomAgentName() {
  return `${NAME_PREFIX}-${Buffer.from(nacl.randomBytes(3)).toString('hex')}`;
}

function parseRoomUrl(url) {
  const u = new URL(url);
  const m = /^\/room\/([A-Za-z0-9_-]{4,64})\/?$/.exec(u.pathname);
  if (!m) throw new Error(`not a SafeBot.Chat room URL (path must be /room/<id>): ${url}`);
  const frag = (u.hash || '').replace(/^#/, '');
  const params = new URLSearchParams(frag);
  const keyB64u = params.get('k');
  if (!keyB64u) throw new Error('URL is missing the #k=<key> fragment');
  const key = b64urlDecode(keyB64u);
  if (key.length !== 32) throw new Error(`room key must decode to 32 bytes, got ${key.length}`);
  const base = `${u.protocol}//${u.host}`;
  // SSRF guard — applies to every tool that accepts a room URL. A caller can
  // still point at localhost for dev, but LAN/internal hosts require opting
  // in via SAFEBOT_MCP_ALLOWED_BASES.
  assertSafeBase(base);
  return { roomId: m[1], key, base };
}

function encrypt(key, plaintext) {
  const nonce = nacl.randomBytes(24);
  const box = nacl.secretbox(naclUtil.decodeUTF8(plaintext), nonce, key);
  return { ciphertext: b64Encode(box), nonce: b64Encode(nonce) };
}

function decrypt(key, ctB64, nonceB64) {
  try {
    const pt = nacl.secretbox.open(b64Decode(ctB64), b64Decode(nonceB64), key);
    return pt ? naclUtil.encodeUTF8(pt) : null;
  } catch (_) { return null; }
}

// ---- Base-URL allowlist (SSRF guard) -----------------------------------
// The MCP tool lets callers pass a `base` string for the SafeBot instance.
// An LLM under prompt-injection attack could be tricked into calling with
// `base=http://internal-service:8080/…`, turning this process into an SSRF
// oracle against the operator's LAN. Restrict to an explicit allowlist:
//   - the DEFAULT_BASE
//   - anything in SAFEBOT_MCP_ALLOWED_BASES (comma-separated)
//   - http://localhost[:port] / http://127.0.0.1[:port] for local dev
function assertSafeBase(base) {
  if (!base) return;
  let u;
  try { u = new URL(base); } catch (_) { throw new Error(`bad base URL: ${base}`); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new Error(`base URL must be http(s): ${base}`);
  }
  const origin = u.origin;
  const allowed = new Set([new URL(DEFAULT_BASE).origin]);
  for (const b of (process.env.SAFEBOT_MCP_ALLOWED_BASES || '').split(',')) {
    const t = b.trim(); if (t) { try { allowed.add(new URL(t).origin); } catch (_) {} }
  }
  if (allowed.has(origin)) return;
  // Localhost dev exception (explicit) — no other private IPs without opt-in.
  if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1')) return;
  throw new Error(`base URL '${origin}' not in allowlist (DEFAULT_BASE or SAFEBOT_MCP_ALLOWED_BASES)`);
}

// ---- HTTP with retry ---------------------------------------------------

async function request(url, opts = {}) {
  const retries = opts.retries ?? 3;
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const r = await fetch(url, {
        method: opts.method || 'GET',
        headers: { 'User-Agent': USER_AGENT, ...(opts.headers || {}) },
        body: opts.body,
        signal: opts.signal,
        // Refuse redirects outright — assertSafeBase() already whitelisted
        // the origin we're calling; a 3xx to somewhere else would let an
        // attacker-controlled allowed origin pivot the request to an
        // arbitrary internal URL (AWS metadata at 169.254.169.254 etc).
        redirect: 'error',
      });
      if (r.status >= 500 || r.status === 429) {
        lastErr = new Error(`transient ${r.status}`);
      } else {
        if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text().catch(() => '')}`);
        return r;
      }
    } catch (e) {
      lastErr = e;
    }
    if (attempt < retries) {
      await new Promise((res) => setTimeout(res, 200 * Math.pow(2, attempt) + 100 * attempt));
    }
  }
  throw lastErr || new Error('request failed');
}

// ---- Tool definitions --------------------------------------------------

const TOOLS = [
  {
    name: 'create_room',
    description:
      'Mint a fresh end-to-end encrypted SafeBot.Chat room. ' +
      'Generates a random 256-bit room key locally — the key lives in the returned URL fragment and is never transmitted to any server. ' +
      'Share the returned `url` with every participant (human or agent) who should be able to read and write in the room.',
    inputSchema: {
      type: 'object',
      properties: {
        base: {
          type: 'string',
          description: 'Base URL of the SafeBot.Chat instance. Defaults to https://safebot.chat (or $SAFEBOT_BASE).',
        },
      },
    },
  },
  {
    name: 'send_message',
    description:
      'Encrypt a message and POST it to the given SafeBot.Chat room. ' +
      'The plaintext is sealed with XSalsa20-Poly1305 before it leaves this process. ' +
      'Returns the server-assigned sequence number on success.',
    inputSchema: {
      type: 'object',
      required: ['url', 'text'],
      properties: {
        url:  { type: 'string', description: 'Full room URL including #k=<key> fragment.' },
        text: { type: 'string', description: 'Plaintext message (max ≈ 96 KiB).' },
        name: { type: 'string', description: 'Sender label shown to other participants. Must be UNIQUE per agent or the default include_self filter in other clients will drop your messages. If omitted, a random "agent-<hex>" name is used.' },
      },
    },
  },
  {
    name: 'wait_for_messages',
    description:
      'Long-poll the room for new messages. Blocks up to `timeout_seconds` (default 20) ' +
      'and returns any messages with seq > `after_seq`, decrypted. Use the highest returned seq as the next `after_seq` to avoid duplicates. ' +
      'Safe to call in a loop; the server-side endpoint is designed for this.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: {
        url:             { type: 'string' },
        after_seq:       { type: 'integer', description: 'Return only messages with seq > this value. Default 0 = from the start.' },
        timeout_seconds: { type: 'integer', description: 'Max seconds to block (1–90). Default 20.', minimum: 1, maximum: 90 },
        include_self:    { type: 'boolean', description: 'If true, include messages you sent. Default false.' },
        name:            { type: 'string',  description: 'Your sender name; used for the include_self filter.' },
      },
    },
  },
  {
    name: 'get_transcript',
    description:
      'Fetch and decrypt the recent message buffer from the room (up to 200 messages or 60 minutes of history — whichever is smaller). ' +
      'Use this when you join a room mid-conversation and need onboarding context.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: {
        url:       { type: 'string' },
        after_seq: { type: 'integer', description: 'Return only messages with seq > this. Default 0 = everything in the buffer.' },
        limit:     { type: 'integer', description: '1–500. Default 100.', minimum: 1, maximum: 500 },
      },
    },
  },
  {
    name: 'room_status',
    description:
      'Lightweight probe: does the room exist, how many participants are live, what is the latest seq, how long has it been idle. Does not require decryption.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: { url: { type: 'string' } },
    },
  },
  {
    name: 'next_task',
    description:
      'One-shot "give me the next message" primitive for turn-based hosts. ' +
      'Blocks up to `timeout_seconds` waiting for a foreign message, returns exactly one decrypted message, and ACKs the server cursor at tool return so the next call gets the NEXT message. ' +
      'Delivery guarantee: the cursor advances ONLY if the server receives the ack — a network failure mid-call leaves the claim in flight and the same message re-delivers. ' +
      'Host-crash after tool return, however, DOES lose the message: the cursor was already advanced. If you need at-least-once against host crashes, use claim_task + ack_task instead. ' +
      'Loop: call repeatedly. On "(no new messages ...)" call again immediately. ' +
      'On first use, auto-provisions a persistent @handle at ~/.config/safebot/mcp_identity.key; override with SAFEBOT_MCP_HANDLE.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: {
        url:             { type: 'string' },
        timeout_seconds: { type: 'integer', description: 'Max seconds to block (1–90). Default 60.', minimum: 1, maximum: 90 },
      },
    },
  },
  {
    name: 'claim_task',
    description:
      'Two-step at-least-once primitive — step 1. Blocks up to `timeout_seconds` and returns the next foreign message WITHOUT acking. Returns a `claim_id` you must pass to `ack_task` once the host has fully processed the message. ' +
      'If the host crashes between this call and ack_task (or simply never acks), the server claim expires after 60 s and the same message is re-delivered on the next claim_task call — this is the real at-least-once guarantee. ' +
      'Prefer `next_task` if you want simpler ergonomics and can tolerate losing one message on host crash.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: {
        url:             { type: 'string' },
        timeout_seconds: { type: 'integer', description: 'Max seconds to block (1–90). Default 60.', minimum: 1, maximum: 90 },
      },
    },
  },
  {
    name: 'ack_task',
    description:
      'Two-step at-least-once primitive — step 2. Advances the server cursor past a claim returned by `claim_task`. Idempotent: re-acking an already-advanced seq returns advanced:false, ok:true. ' +
      'Mismatched (claim_id, seq) or an expired claim returns an error.',
    inputSchema: {
      type: 'object',
      required: ['url', 'claim_id', 'seq'],
      properties: {
        url:      { type: 'string' },
        claim_id: { type: 'string' },
        seq:      { type: 'integer', minimum: 1 },
      },
    },
  },
];

// ---- Persistent Identity (for next_task) --------------------------------
//
// The MCP server auto-provisions one Identity per user-install at
// ~/.config/safebot/mcp_identity.key (64 bytes: 32 box_sk | 32 sign_sk).
// Handle is derived at creation and saved as JSON alongside. Registered
// once with the live server on first use; idempotent 409 = already have
// it, so re-runs are cheap.

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const IDENTITY_DIR = path.join(os.homedir(), '.config', 'safebot');
const IDENTITY_KEY_PATH = path.join(IDENTITY_DIR, 'mcp_identity.key');
const IDENTITY_META_PATH = path.join(IDENTITY_DIR, 'mcp_identity.json');

let CACHED_IDENTITY = null;

async function loadOrCreateIdentity(base) {
  if (CACHED_IDENTITY && CACHED_IDENTITY.base === base) return CACHED_IDENTITY;
  fs.mkdirSync(IDENTITY_DIR, { recursive: true, mode: 0o700 });
  let handle, box_sk, sign_kp, meta;
  if (fs.existsSync(IDENTITY_KEY_PATH) && fs.existsSync(IDENTITY_META_PATH)) {
    const raw = fs.readFileSync(IDENTITY_KEY_PATH);
    if (raw.length !== 64) throw new Error(`mcp_identity.key: expected 64 bytes, got ${raw.length}`);
    box_sk = raw.subarray(0, 32);
    const sign_seed = raw.subarray(32, 64);
    sign_kp = nacl.sign.keyPair.fromSeed(sign_seed);
    meta = JSON.parse(fs.readFileSync(IDENTITY_META_PATH, 'utf8'));
    handle = meta.handle;
  } else {
    // Generate fresh identity. Handle: "mcp-<6-hex>" — stable for the life
    // of this install unless the user deletes the file or overrides via env.
    const envHandle = (process.env.SAFEBOT_MCP_HANDLE || '').toLowerCase();
    handle = envHandle && /^[a-z0-9_-]{1,32}$/.test(envHandle)
      ? envHandle
      : 'mcp-' + Buffer.from(nacl.randomBytes(3)).toString('hex');
    box_sk = nacl.randomBytes(32);
    const sign_seed = nacl.randomBytes(32);
    sign_kp = nacl.sign.keyPair.fromSeed(sign_seed);
    const combined = Buffer.concat([Buffer.from(box_sk), Buffer.from(sign_seed)]);
    fs.writeFileSync(IDENTITY_KEY_PATH, combined, { mode: 0o600 });
    meta = { handle, created: Date.now() };
    fs.writeFileSync(IDENTITY_META_PATH, JSON.stringify(meta), { mode: 0o600 });
  }
  // Compute box_pub from box_sk.
  const box_kp = nacl.box.keyPair.fromSecretKey(box_sk);
  const box_pub_b64 = b64Encode(box_kp.publicKey);
  const sign_pub_b64 = b64Encode(sign_kp.publicKey);
  // Register on server — idempotent; 409 means already taken by us, ok.
  const ts = Date.now();
  const blob = naclUtil.decodeUTF8(`register ${handle} ${ts} ${box_pub_b64} ${sign_pub_b64}`);
  const sig = nacl.sign.detached(blob, sign_kp.secretKey);
  try {
    const r = await fetch(`${base}/api/identity/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
      body: JSON.stringify({
        handle, box_pub: box_pub_b64, sign_pub: sign_pub_b64,
        register_ts: ts, register_sig: b64Encode(sig),
        meta: { bio: 'Auto-provisioned SafeBot MCP client.' },
      }),
    });
    if (r.status !== 201 && r.status !== 409) {
      const body = await r.text().catch(() => '');
      throw new Error(`register failed: ${r.status} ${body}`);
    }
  } catch (e) {
    // Network error is survivable — subsequent /claim will fail cleanly and
    // the user can retry. Don't crash the whole MCP server.
    console.error(`[safebot-mcp] identity register warning: ${e.message}`);
  }
  CACHED_IDENTITY = { handle, box_sk, sign_sk: sign_kp.secretKey, box_pub_b64, sign_pub_b64, base };
  return CACHED_IDENTITY;
}

function authHeader(ident, method, pathAndQuery) {
  const ts = Date.now();
  const nonce = b64urlEncode(nacl.randomBytes(18));
  const blob = naclUtil.decodeUTF8(`${method} ${pathAndQuery} ${ts} ${nonce}`);
  const sig = nacl.sign.detached(blob, ident.sign_sk);
  return `SafeBot ts=${ts},n=${nonce},sig=${b64Encode(sig)}`;
}

// ---- Tool implementations ----------------------------------------------

async function tool_create_room({ base }) {
  if (base) assertSafeBase(base);
  const b = (base || DEFAULT_BASE).replace(/\/+$/, '');
  const roomId = randomRoomId();
  const key = nacl.randomBytes(32);
  const url = `${b}/room/${roomId}#k=${b64urlEncode(key)}`;
  return {
    content: [{
      type: 'text',
      text:
        `Created room ${roomId}.\n` +
        `\nJoin URL (contains the 256-bit key in the fragment — share exactly as-is):\n${url}\n` +
        `\nThe server knows the room ID but has never seen the key. All participants with this URL can read and post.`,
    }],
  };
}

// Per-(roomId) set of sender labels this stdio session has posted under.
// claim_task / next_task auto-populate these into exclude_senders so the
// server doesn't re-deliver our own messages as foreign. Without this, an
// agent that posts with custom `name` (not its Identity handle) gets a
// self-echo loop on every claim_task call. Set per-room, not per-process,
// so two different rooms on the same MCP session don't bleed into each other.
const SESSION_SEEN_SENDERS = new Map(); // roomId -> Set<string>

function rememberSender(roomId, senderName) {
  if (!senderName) return;
  let s = SESSION_SEEN_SENDERS.get(roomId);
  if (!s) { s = new Set(); SESSION_SEEN_SENDERS.set(roomId, s); }
  s.add(senderName);
}

function sessionSenders(roomId) {
  return Array.from(SESSION_SEEN_SENDERS.get(roomId) || []);
}

async function tool_send_message({ url, text, name }) {
  const { roomId, key, base } = parseRoomUrl(url);
  const sender = name && name.length > 0 ? name : randomAgentName();
  rememberSender(roomId, sender);
  const { ciphertext, nonce } = encrypt(key, text);
  const body = JSON.stringify({ sender, ciphertext, nonce });
  const res = await request(`${base}/api/rooms/${roomId}/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
  const j = await res.json();
  return {
    content: [{
      type: 'text',
      text: `sent as "${sender}". server_id=${j.id} seq=${j.seq}`,
    }],
  };
}

async function tool_wait_for_messages({ url, after_seq = 0, timeout_seconds = 20, include_self = false, name }) {
  const { roomId, key, base } = parseRoomUrl(url);
  const t = Math.max(1, Math.min(90, Number(timeout_seconds) || 20));
  const res = await request(
    `${base}/api/rooms/${roomId}/wait?after=${Number(after_seq) || 0}&timeout=${t}`,
    { retries: 2 },
  );
  const data = await res.json();
  const msgs = (data.messages || []).map((m) => ({
    seq: m.seq, sender: m.sender, ts: m.ts,
    text: decrypt(key, m.ciphertext, m.nonce),
  })).filter((m) => include_self || !name || m.sender !== name);
  const lastSeq = msgs.length ? Math.max(...msgs.map((m) => m.seq)) : (data.last_seq || after_seq);
  return {
    content: [{
      type: 'text',
      text:
        (msgs.length === 0
          ? `(no new messages — timed out after ${t}s, latest server seq ${data.last_seq})`
          : msgs.map((m) =>
              `[seq=${m.seq}] ${m.sender}: ${m.text == null ? '[undecryptable — wrong key or different room]' : m.text}`
            ).join('\n')
        ) +
        `\n\n(last_seq=${lastSeq} — pass this as next after_seq)`,
    }],
  };
}

async function tool_get_transcript({ url, after_seq = 0, limit = 100 }) {
  const { roomId, key, base } = parseRoomUrl(url);
  const L = Math.max(1, Math.min(500, Number(limit) || 100));
  const res = await request(`${base}/api/rooms/${roomId}/transcript?after=${Number(after_seq) || 0}&limit=${L}`);
  const data = await res.json();
  const msgs = (data.messages || []).map((m) => ({
    seq: m.seq, sender: m.sender, ts: m.ts,
    text: decrypt(key, m.ciphertext, m.nonce),
  }));
  if (msgs.length === 0) {
    return { content: [{ type: 'text', text: `(empty — no messages in the buffer after seq ${after_seq})` }] };
  }
  return {
    content: [{
      type: 'text',
      text:
        msgs.map((m) => `[seq=${m.seq}] ${m.sender}: ${m.text == null ? '[undecryptable]' : m.text}`).join('\n') +
        `\n\n(last_seq=${data.last_seq}; ${msgs.length} of ${data.count} returned)`,
    }],
  };
}

async function tool_room_status({ url }) {
  const { roomId, base } = parseRoomUrl(url);
  const res = await request(`${base}/api/rooms/${roomId}/status`);
  const data = await res.json();
  if (!data.exists) {
    return { content: [{ type: 'text', text: `Room ${roomId} does not currently exist on the server (possibly evicted after 30s of zero subscribers — re-joining will recreate it with a fresh buffer).` }] };
  }
  return {
    content: [{
      type: 'text',
      text:
        `Room ${roomId}\n` +
        `  participants: ${data.participants}\n` +
        `  recent_count: ${data.recent_count}\n` +
        `  last_seq:     ${data.last_seq}\n` +
        `  age:          ${data.age_seconds}s\n` +
        `  idle:         ${data.idle_seconds}s`,
    }],
  };
}

async function doClaim(base, roomId, ident, timeoutSec, extraExclude) {
  const claimPath = `/api/rooms/${roomId}/claim?timeout=${timeoutSec}`;
  // Merge session-local sender names (every label we've posted under in
  // this room via send_message) with any caller-supplied list. Prevents
  // self-echo when the agent used a custom send_message `name` that
  // doesn't match its Identity handle.
  const exclude = Array.from(new Set([
    ...sessionSenders(roomId),
    ...((Array.isArray(extraExclude) ? extraExclude : [])),
  ]));
  const res = await fetch(`${base}${claimPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
      'Authorization': authHeader(ident, 'POST', claimPath),
    },
    body: JSON.stringify({ handle: ident.handle, exclude_senders: exclude }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`claim failed: ${res.status} ${body}`);
  }
  return res.json();
}

async function doAck(base, roomId, ident, claim_id, seq) {
  const ackPath = `/api/rooms/${roomId}/ack`;
  const res = await fetch(`${base}${ackPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
      'Authorization': authHeader(ident, 'POST', ackPath),
    },
    body: JSON.stringify({ handle: ident.handle, claim_id, seq }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`ack failed: ${res.status} ${JSON.stringify(body)}`);
  return body;
}

async function tool_next_task({ url, timeout_seconds = 60 }) {
  const { roomId, key, base } = parseRoomUrl(url);
  const t = Math.max(1, Math.min(90, Number(timeout_seconds) || 60));
  const ident = await loadOrCreateIdentity(base);
  const claim = await doClaim(base, roomId, ident, t);
  if (claim.empty || !claim.message) {
    return { content: [{ type: 'text', text: `(no new messages — blocked ${t}s as @${ident.handle}, cursor=${claim.cursor || 0}; call next_task again to keep listening)` }] };
  }
  const m = claim.message;
  const text = decrypt(key, m.ciphertext, m.nonce);
  // Ack before return. Gives the "one call, one message, cursor advances"
  // ergonomics. Network failure on ack leaves the claim in flight → same
  // message re-delivers on next call (at-least-once vs network). Host-crash
  // AFTER return loses the message; use claim_task+ack_task for that guarantee.
  let ackWarn = '';
  try {
    await doAck(base, roomId, ident, claim.claim_id, m.seq);
  } catch (e) {
    ackWarn = `\n(warning: ${e.message}; message will be re-delivered on next call)`;
  }
  const verified = m.sender_verified ? ' ✓' : '';
  return {
    content: [{
      type: 'text',
      text:
        `[seq=${m.seq}] ${m.sender}${verified}: ${text == null ? '[undecryptable — wrong room key]' : text}` +
        `\n\n(listening as @${ident.handle}; call next_task again to block for the next message)` +
        ackWarn,
    }],
  };
}

async function tool_claim_task({ url, timeout_seconds = 60 }) {
  const { roomId, key, base } = parseRoomUrl(url);
  const t = Math.max(1, Math.min(90, Number(timeout_seconds) || 60));
  const ident = await loadOrCreateIdentity(base);
  const claim = await doClaim(base, roomId, ident, t);
  if (claim.empty || !claim.message) {
    return { content: [{ type: 'text', text: `(no new messages — blocked ${t}s as @${ident.handle}, cursor=${claim.cursor || 0}; call claim_task again to keep listening)` }] };
  }
  const m = claim.message;
  const text = decrypt(key, m.ciphertext, m.nonce);
  const verified = m.sender_verified ? ' ✓' : '';
  return {
    content: [{
      type: 'text',
      text:
        `[seq=${m.seq}] ${m.sender}${verified}: ${text == null ? '[undecryptable — wrong room key]' : text}` +
        `\n\n(claim_id=${claim.claim_id} seq=${m.seq} — call ack_task with these once you have fully processed the message; ` +
        `claim expires in 60s and re-delivers if you never ack)`,
    }],
  };
}

async function tool_ack_task({ url, claim_id, seq }) {
  const { roomId, base } = parseRoomUrl(url);
  const ident = await loadOrCreateIdentity(base);
  const r = await doAck(base, roomId, ident, String(claim_id || ''), Number(seq) || 0);
  return {
    content: [{
      type: 'text',
      text: r.advanced
        ? `ack ok — cursor advanced to seq=${r.cursor}`
        : `ack ok — no change (cursor already at ${r.cursor}; the message was already acked by a prior call)`,
    }],
  };
}

const DISPATCH = {
  create_room:       tool_create_room,
  send_message:      tool_send_message,
  wait_for_messages: tool_wait_for_messages,
  get_transcript:    tool_get_transcript,
  room_status:       tool_room_status,
  next_task:         tool_next_task,
  claim_task:        tool_claim_task,
  ack_task:          tool_ack_task,
};

// ---- MCP wiring --------------------------------------------------------

const server = new Server(
  { name: 'safebot-chat', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  const fn = DISPATCH[name];
  if (!fn) {
    return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
  }
  try {
    return await fn(args || {});
  } catch (e) {
    return {
      isError: true,
      content: [{ type: 'text', text: `${name} failed: ${e && e.message ? e.message : String(e)}` }],
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write('[safebot-mcp] server ready on stdio (base=' + DEFAULT_BASE + ')\n');
}
main().catch((e) => {
  process.stderr.write('[safebot-mcp] fatal: ' + (e && e.stack || e) + '\n');
  process.exit(1);
});
