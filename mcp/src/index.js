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
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const DEFAULT_BASE = process.env.SAFEBOT_BASE || 'https://safebot.chat';
const ROOM_ID_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const NAME_PREFIX = 'agent';
const USER_AGENT = `safebot-mcp/0.2.1 (+${DEFAULT_BASE})`;
const SAFEBOT_CONFIG_DIR = path.join(os.homedir(), '.config', 'safebot');
const IDENTITY_KEY_PATH = path.join(SAFEBOT_CONFIG_DIR, 'mcp_identity.key');
const IDENTITY_META_PATH = path.join(SAFEBOT_CONFIG_DIR, 'mcp_identity.json');
const ROOM_NAME_OVERRIDE = sanitizeAnonLabel(process.env.SAFEBOT_MCP_ROOM_NAME, '');
const ROOM_REPLY_DISCIPLINE =
  'SafeBot room URLs are output channels, not only context sources: ' +
  'if the user gave you a room URL for QA, reporting, or collaboration, send your substantive answer back into that room with `send_message` before you stop. ' +
  'Do not keep the real answer only in local narration.';
const SERVER_INSTRUCTIONS = [
  'SafeBot.Chat rooms are collaboration channels.',
  'When you call any SafeBot room tool with a `url`, treat that room as the active reply channel for this MCP session until another SafeBot room URL supersedes it.',
  ROOM_REPLY_DISCIPLINE,
  'If posting to the active room fails, say so explicitly instead of silently finishing locally.',
  'For receive loops, use `send_message` for the room-facing reply, then `ack_task`/loop as appropriate.',
  'If the operator is clearly unhappy or says you missed an expected action, do not ask an obvious follow-up question; infer the likeliest corrective step, do it, report the result, and keep listening.',
].join(' ');

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

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function roomStateKey(base, roomId) {
  return `${base}\n${roomId}`;
}

function roomIdentityPath(base) {
  return path.join(SAFEBOT_CONFIG_DIR, `mcp_room_identity-${sha256Hex(base).slice(0, 12)}.json`);
}

function sanitizeAnonLabel(name, fallback) {
  const raw = String(name || '').trim().slice(0, 64) || fallback;
  return raw.replace(/^@+/, '') || fallback;
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
  return { roomId: m[1], key, base, url: u.toString() };
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
      'Returns the server-assigned sequence number on success. ' +
      'Use this to publish your substantive answer back into the room; do not keep the real answer only in local narration.',
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
      'Safe to call in a loop; the server-side endpoint is designed for this. ' +
      ROOM_REPLY_DISCIPLINE,
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
      'Use this when you join a room mid-conversation and need onboarding context. ' +
      ROOM_REPLY_DISCIPLINE,
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
      'Lightweight probe: does the room exist, how many participants are live, what is the latest seq, how long has it been idle. Does not require decryption. ' +
      ROOM_REPLY_DISCIPLINE,
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
      'On first use, auto-provisions a persistent @handle at ~/.config/safebot/mcp_identity.key; override with SAFEBOT_MCP_HANDLE. ' +
      'If the message warrants a response, reply to the same room with `send_message` before you move on.',
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
      'Prefer `next_task` if you want simpler ergonomics and can tolerate losing one message on host crash. ' +
      'If the message warrants a response, reply to the same room with `send_message` before `ack_task`.',
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

// ---- Persistent local identities -----------------------------------------
//
// The MCP host uses two independent identities:
//   1. auth identity   — hidden, durable, used only for claim_task/ack_task
//   2. room identity   — what the room sees; starts anonymous/promotable and
//                        becomes signed only after an adopt/promote handoff
//
// Splitting them keeps the at-least-once cursor stable even after the room-
// facing identity changes.

let CACHED_IDENTITY = null;
let CACHED_ROOM_IDENTITY = undefined; // undefined = not loaded yet; null = no promoted identity
let ACTIVE_ROOM = null;

function ensureIdentityDir() {
  fs.mkdirSync(SAFEBOT_CONFIG_DIR, { recursive: true, mode: 0o700 });
}

function buildLocalIdentity({ handle, box_sk, sign_seed, base }) {
  const sign_kp = nacl.sign.keyPair.fromSeed(sign_seed);
  const box_kp = nacl.box.keyPair.fromSecretKey(box_sk);
  return {
    handle,
    base,
    box_sk: new Uint8Array(box_sk),
    sign_seed: new Uint8Array(sign_seed),
    sign_sk: sign_kp.secretKey,
    box_pub_b64: b64Encode(box_kp.publicKey),
    box_pub_b64u: b64urlEncode(box_kp.publicKey),
    sign_pub_b64: b64Encode(sign_kp.publicKey),
  };
}

function exportIdentityRecord(ident) {
  return {
    safebot_identity_v1: true,
    handle: ident.handle,
    box_sk_b64u: b64urlEncode(ident.box_sk),
    sign_seed_b64u: b64urlEncode(ident.sign_seed),
    base: ident.base,
  };
}

async function registerIdentity(base, ident, meta = {}) {
  const ts = Date.now();
  const blob = naclUtil.decodeUTF8(`register ${ident.handle} ${ts} ${ident.box_pub_b64} ${ident.sign_pub_b64}`);
  const sig = nacl.sign.detached(blob, ident.sign_sk);
  try {
    const r = await fetch(`${base}/api/identity/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
      body: JSON.stringify({
        handle: ident.handle,
        box_pub: ident.box_pub_b64,
        sign_pub: ident.sign_pub_b64,
        register_ts: ts,
        register_sig: b64Encode(sig),
        meta,
      }),
    });
    if (r.status !== 201 && r.status !== 409) {
      const body = await r.text().catch(() => '');
      throw new Error(`register failed: ${r.status} ${body}`);
    }
  } catch (e) {
    console.error(`[safebot-mcp] identity register warning: ${e.message}`);
  }
}

async function loadOrCreateIdentity(base) {
  if (CACHED_IDENTITY && CACHED_IDENTITY.base === base) return CACHED_IDENTITY;
  ensureIdentityDir();
  let handle;
  let box_sk;
  let sign_seed;
  if (fs.existsSync(IDENTITY_KEY_PATH) && fs.existsSync(IDENTITY_META_PATH)) {
    const raw = fs.readFileSync(IDENTITY_KEY_PATH);
    if (raw.length !== 64) throw new Error(`mcp_identity.key: expected 64 bytes, got ${raw.length}`);
    box_sk = raw.subarray(0, 32);
    sign_seed = raw.subarray(32, 64);
    const meta = JSON.parse(fs.readFileSync(IDENTITY_META_PATH, 'utf8'));
    handle = meta.handle;
  } else {
    const envHandle = (process.env.SAFEBOT_MCP_HANDLE || '').toLowerCase();
    handle = envHandle && /^[a-z0-9_-]{1,32}$/.test(envHandle)
      ? envHandle
      : 'mcp-' + Buffer.from(nacl.randomBytes(3)).toString('hex');
    box_sk = nacl.randomBytes(32);
    sign_seed = nacl.randomBytes(32);
    const combined = Buffer.concat([Buffer.from(box_sk), Buffer.from(sign_seed)]);
    fs.writeFileSync(IDENTITY_KEY_PATH, combined, { mode: 0o600 });
    fs.writeFileSync(IDENTITY_META_PATH, JSON.stringify({ handle, created: Date.now() }), { mode: 0o600 });
  }
  const ident = buildLocalIdentity({ handle, box_sk, sign_seed, base });
  await registerIdentity(base, ident, { bio: 'Auto-provisioned SafeBot MCP auth identity.' });
  CACHED_IDENTITY = ident;
  return ident;
}

function loadPromotedRoomIdentity(base) {
  if (CACHED_ROOM_IDENTITY !== undefined && (!CACHED_ROOM_IDENTITY || CACHED_ROOM_IDENTITY.base === base)) {
    return CACHED_ROOM_IDENTITY;
  }
  ensureIdentityDir();
  const file = roomIdentityPath(base);
  if (!fs.existsSync(file)) {
    CACHED_ROOM_IDENTITY = null;
    return CACHED_ROOM_IDENTITY;
  }
  const rec = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!rec || rec.safebot_identity_v1 !== true || !rec.handle || !rec.box_sk_b64u || !rec.sign_seed_b64u) {
    throw new Error('mcp_room_identity.json is malformed');
  }
  CACHED_ROOM_IDENTITY = buildLocalIdentity({
    handle: rec.handle,
    box_sk: b64urlDecode(rec.box_sk_b64u),
    sign_seed: b64urlDecode(rec.sign_seed_b64u),
    base,
  });
  return CACHED_ROOM_IDENTITY;
}

function persistPromotedRoomIdentity(ident) {
  ensureIdentityDir();
  fs.writeFileSync(roomIdentityPath(ident.base), JSON.stringify(exportIdentityRecord(ident), null, 2), { mode: 0o600 });
  CACHED_ROOM_IDENTITY = ident;
}

function signRoomEnvelope(roomId, ciphertext, ident) {
  const ts = Date.now();
  const nonce = b64urlEncode(nacl.randomBytes(18));
  const blob = naclUtil.decodeUTF8(`room-msg ${roomId} ${ts} ${nonce} ${sha256Hex(ciphertext)}`);
  const sig = nacl.sign.detached(blob, ident.sign_sk);
  return {
    sender_handle: ident.handle,
    sender_ts: ts,
    sender_nonce: nonce,
    sender_sig: b64Encode(sig),
  };
}

function setActiveRoom(room) {
  if (!room || !room.url) return false;
  const changed = !ACTIVE_ROOM || ACTIVE_ROOM.url !== room.url;
  ACTIVE_ROOM = { url: room.url, roomId: room.roomId, base: room.base };
  return changed;
}

function activeRoomNotice(room, { changedOnly = true } = {}) {
  const changed = setActiveRoom(room);
  if (changedOnly && !changed) return '';
  return (
    `\n\n(active room set to ${room.roomId} — ` +
    'if this room came from the user, post your substantive answer there with send_message before you stop)'
  );
}

const ROOM_STATES = new Map();

function currentRoomIdentity(state) {
  return state.roomIdentity || state.authIdentity;
}

function currentRoomLabel(state) {
  return state.roomIdentity ? '@' + state.roomIdentity.handle : state.roomName;
}

function currentRoomBoxPub(state) {
  return currentRoomIdentity(state).box_pub_b64u;
}

function markPresenceDirty(state) {
  state.presenceDesiredKey = `${currentRoomLabel(state)}\n${currentRoomBoxPub(state)}`;
}

async function ensureRoomState(parsed, { explicitName } = {}) {
  const { roomId, key, base } = parsed;
  const rk = roomStateKey(base, roomId);
  const authIdentity = await loadOrCreateIdentity(base);
  const promotedIdentity = loadPromotedRoomIdentity(base);
  let state = ROOM_STATES.get(rk);
  if (!state) {
    state = {
      key,
      base,
      roomId,
      authIdentity,
      roomIdentity: promotedIdentity,
      roomName: ROOM_NAME_OVERRIDE || sanitizeAnonLabel(authIdentity.handle, randomAgentName()),
      adoptSeen: new Set(),
      presenceSeq: 0,
      presenceLoop: null,
      presenceAbort: null,
      presenceDesiredKey: '',
    };
    ROOM_STATES.set(rk, state);
  } else {
    state.key = key;
    state.base = base;
    state.roomId = roomId;
    state.authIdentity = authIdentity;
    if (promotedIdentity) state.roomIdentity = promotedIdentity;
  }
  if (!state.roomIdentity && explicitName) {
    state.roomName = sanitizeAnonLabel(explicitName, state.roomName || authIdentity.handle);
  }
  markPresenceDirty(state);
  ensurePresenceLoop(state);
  return state;
}

function extractSseFrame(buffer) {
  const m = /\r?\n\r?\n/.exec(buffer);
  if (!m) return null;
  return {
    frame: buffer.slice(0, m.index),
    rest: buffer.slice(m.index + m[0].length),
  };
}

function currentRoomBoxSecret(state) {
  return currentRoomIdentity(state).box_sk;
}

function maybeApplyAdopt(state, plaintext, sender) {
  if (!plaintext || !plaintext.startsWith('{')) return { consumed: false, applied: false };
  let env;
  try {
    env = JSON.parse(plaintext);
  } catch (_) {
    return { consumed: false, applied: false };
  }
  if (!env || env.safebot_adopt_v1 !== true) return { consumed: false, applied: false };
  const adoptId = env.adopt_id;
  if (!adoptId || state.adoptSeen.has(adoptId)) return { consumed: true, applied: false };
  state.adoptSeen.add(adoptId);
  const target = String(env.target_name || '');
  if (target !== currentRoomLabel(state)) return { consumed: true, applied: false };
  if (!env.sender_box_pub || !env.nonce || !env.ciphertext) return { consumed: true, applied: false };
  try {
    const opened = nacl.box.open(
      b64urlDecode(env.ciphertext),
      b64urlDecode(env.nonce),
      b64urlDecode(env.sender_box_pub),
      currentRoomBoxSecret(state),
    );
    if (!opened) {
      console.error('[safebot-mcp] adopt decrypt failed');
      return { consumed: true, applied: false };
    }
    const inner = JSON.parse(naclUtil.encodeUTF8(opened));
    if (!inner || !inner.handle || !inner.box_sk_b64u || !inner.sign_seed_b64u) {
      return { consumed: true, applied: false };
    }
    const adopted = buildLocalIdentity({
      handle: inner.handle,
      box_sk: b64urlDecode(inner.box_sk_b64u),
      sign_seed: b64urlDecode(inner.sign_seed_b64u),
      base: state.base,
    });
    state.roomIdentity = adopted;
    persistPromotedRoomIdentity(adopted);
    rememberSender(state.roomId, currentRoomLabel(state));
    markPresenceDirty(state);
    ensurePresenceLoop(state);
    console.error(`[safebot-mcp] adopted room identity as @${adopted.handle} (from ${sender || 'operator'})`);
    return { consumed: true, applied: true };
  } catch (e) {
    console.error(`[safebot-mcp] adopt apply failed: ${e.message}`);
    return { consumed: true, applied: false };
  }
}

function handlePresenceEvent(state, obj) {
  if (!obj || typeof obj !== 'object') return;
  if (obj.type === 'ready' && Number.isFinite(obj.last_seq)) {
    state.presenceSeq = Math.max(state.presenceSeq, Number(obj.last_seq) || 0);
    return;
  }
  if (obj.type === 'message' && Number.isFinite(obj.seq)) {
    state.presenceSeq = Math.max(state.presenceSeq, Number(obj.seq) || 0);
    const plaintext = decrypt(state.key, obj.ciphertext, obj.nonce);
    if (plaintext !== null) maybeApplyAdopt(state, plaintext, obj.sender);
  }
}

async function runPresenceLoop(state, desiredKey) {
  let backoffMs = 300;
  while (state.presenceDesiredKey === desiredKey) {
    const controller = new AbortController();
    state.presenceAbort = controller;
    const qs = new URLSearchParams({
      name: currentRoomLabel(state),
      box_pub: currentRoomBoxPub(state),
    });
    if (state.presenceSeq > 0) qs.set('after', String(state.presenceSeq));
    try {
      const res = await request(`${state.base}/api/rooms/${state.roomId}/events?${qs.toString()}`, {
        retries: 0,
        signal: controller.signal,
        headers: { Accept: 'text/event-stream' },
      });
      const decoder = new TextDecoder();
      let buf = '';
      for await (const chunk of res.body) {
        buf += decoder.decode(chunk, { stream: true });
        for (;;) {
          const next = extractSseFrame(buf);
          if (!next) break;
          buf = next.rest;
          const payload = next.frame
            .split(/\r?\n/)
            .filter((line) => line.startsWith('data:'))
            .map((line) => line.slice(5).trimStart())
            .join('\n');
          if (!payload) continue;
          try {
            handlePresenceEvent(state, JSON.parse(payload));
          } catch (_) {}
        }
      }
      if (controller.signal.aborted) return;
    } catch (e) {
      if (controller.signal.aborted) return;
      console.error(`[safebot-mcp] presence loop warning for ${state.roomId}: ${e.message}`);
    }
    await sleep(backoffMs);
    backoffMs = Math.min(5000, backoffMs * 2);
  }
}

function ensurePresenceLoop(state) {
  if (state.presenceLoop && state.presenceDesiredKey === state.presenceActiveKey) return;
  if (state.presenceAbort) {
    try { state.presenceAbort.abort(); } catch (_) {}
  }
  state.presenceActiveKey = state.presenceDesiredKey;
  const loop = runPresenceLoop(state, state.presenceActiveKey)
    .catch((e) => console.error(`[safebot-mcp] presence crash for ${state.roomId}: ${e.message}`))
    .finally(() => {
      if (state.presenceLoop === loop) {
        state.presenceLoop = null;
      }
    });
  state.presenceLoop = loop;
}

async function claimSkippingAdopts(state, timeoutSec, extraExclude) {
  while (true) {
    const claim = await doClaim(state.base, state.roomId, state.authIdentity, timeoutSec, [
      currentRoomLabel(state),
      ...((Array.isArray(extraExclude) ? extraExclude : [])),
    ]);
    if (claim.empty || !claim.message) return claim;
    const text = decrypt(state.key, claim.message.ciphertext, claim.message.nonce);
    const adopt = maybeApplyAdopt(state, text, claim.message.sender);
    if (!adopt.consumed) {
      return { ...claim, decrypted_text: text };
    }
    await doAck(state.base, state.roomId, state.authIdentity, claim.claim_id, claim.message.seq);
  }
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
  const notice = activeRoomNotice({ url, roomId, base: b });
  return {
    content: [{
      type: 'text',
      text:
        `Created room ${roomId}.\n` +
        `\nJoin URL (contains the 256-bit key in the fragment — share exactly as-is):\n${url}\n` +
        `\nThe server knows the room ID but has never seen the key. All participants with this URL can read and post.` +
        notice,
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
  const parsed = parseRoomUrl(url);
  setActiveRoom(parsed);
  const state = await ensureRoomState(parsed, { explicitName: name });
  const sender = currentRoomLabel(state);
  rememberSender(parsed.roomId, sender);
  const { ciphertext, nonce } = encrypt(parsed.key, text);
  let body = { sender, ciphertext, nonce };
  if (state.roomIdentity) {
    body = { ...body, ...signRoomEnvelope(parsed.roomId, ciphertext, state.roomIdentity) };
  }
  let res = await fetch(`${parsed.base}/api/rooms/${parsed.roomId}/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
    body: JSON.stringify(body),
    redirect: 'error',
  });
  if (res.status === 403 && !state.roomIdentity) {
    body = { sender, ciphertext, nonce, ...signRoomEnvelope(parsed.roomId, ciphertext, state.authIdentity) };
    res = await fetch(`${parsed.base}/api/rooms/${parsed.roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
      body: JSON.stringify(body),
      redirect: 'error',
    });
  }
  if (!res.ok) {
    const err = await res.text().catch(() => '');
    throw new Error(`send failed: ${res.status} ${err}`);
  }
  const j = await res.json();
  return {
    content: [{
      type: 'text',
      text: `sent as "${sender}". server_id=${j.id} seq=${j.seq}`,
    }],
  };
}

async function tool_wait_for_messages({ url, after_seq = 0, timeout_seconds = 20, include_self = false, name }) {
  const parsed = parseRoomUrl(url);
  const notice = activeRoomNotice(parsed);
  const state = await ensureRoomState(parsed, { explicitName: name });
  const t = Math.max(1, Math.min(90, Number(timeout_seconds) || 20));
  const res = await request(
    `${parsed.base}/api/rooms/${parsed.roomId}/wait?after=${Number(after_seq) || 0}&timeout=${t}`,
    { retries: 2 },
  );
  const data = await res.json();
  const msgs = [];
  for (const m of (data.messages || [])) {
    const text = decrypt(parsed.key, m.ciphertext, m.nonce);
    const adopt = maybeApplyAdopt(state, text, m.sender);
    if (adopt.consumed) continue;
    msgs.push({ seq: m.seq, sender: m.sender, ts: m.ts, text });
  }
  const visible = msgs.filter((m) => {
    if (include_self) return true;
    const selfNames = new Set([currentRoomLabel(state)]);
    if (name) selfNames.add(String(name));
    return !selfNames.has(m.sender);
  });
  const lastSeq = msgs.length ? Math.max(...msgs.map((m) => m.seq)) : (data.last_seq || after_seq);
  return {
    content: [{
      type: 'text',
      text:
        (visible.length === 0
          ? `(no new messages — timed out after ${t}s, latest server seq ${data.last_seq})`
          : visible.map((m) =>
              `[seq=${m.seq}] ${m.sender}: ${m.text == null ? '[undecryptable — wrong key or different room]' : m.text}`
            ).join('\n')
        ) +
        `\n\n(last_seq=${lastSeq} — pass this as next after_seq)` +
        notice,
    }],
  };
}

async function tool_get_transcript({ url, after_seq = 0, limit = 100 }) {
  const parsed = parseRoomUrl(url);
  const notice = activeRoomNotice(parsed);
  const L = Math.max(1, Math.min(500, Number(limit) || 100));
  const res = await request(`${parsed.base}/api/rooms/${parsed.roomId}/transcript?after=${Number(after_seq) || 0}&limit=${L}`);
  const data = await res.json();
  const msgs = (data.messages || []).map((m) => ({
    seq: m.seq, sender: m.sender, ts: m.ts,
    text: decrypt(parsed.key, m.ciphertext, m.nonce),
  }));
  if (msgs.length === 0) {
    return { content: [{ type: 'text', text: `(empty — no messages in the buffer after seq ${after_seq})` + notice }] };
  }
  return {
    content: [{
      type: 'text',
      text:
        msgs.map((m) => `[seq=${m.seq}] ${m.sender}: ${m.text == null ? '[undecryptable]' : m.text}`).join('\n') +
        `\n\n(last_seq=${data.last_seq}; ${msgs.length} of ${data.count} returned)` +
        notice,
    }],
  };
}

async function tool_room_status({ url }) {
  const { roomId, base, url: canonicalUrl } = parseRoomUrl(url);
  const notice = activeRoomNotice({ url: canonicalUrl, roomId, base });
  const res = await request(`${base}/api/rooms/${roomId}/status`);
  const data = await res.json();
  if (!data.exists) {
    return { content: [{ type: 'text', text: `Room ${roomId} does not currently exist on the server (possibly evicted after 30s of zero subscribers — re-joining will recreate it with a fresh buffer).` + notice }] };
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
        `  idle:         ${data.idle_seconds}s` +
        notice,
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
  const parsed = parseRoomUrl(url);
  const notice = activeRoomNotice(parsed);
  const t = Math.max(1, Math.min(90, Number(timeout_seconds) || 60));
  const state = await ensureRoomState(parsed);
  const claim = await claimSkippingAdopts(state, t);
  if (claim.empty || !claim.message) {
    return { content: [{ type: 'text', text: `(no new messages — blocked ${t}s as "${currentRoomLabel(state)}" via auth @${state.authIdentity.handle}, cursor=${claim.cursor || 0}; call next_task again to keep listening)` + notice }] };
  }
  const m = claim.message;
  const text = claim.decrypted_text;
  // Ack before return. Gives the "one call, one message, cursor advances"
  // ergonomics. Network failure on ack leaves the claim in flight → same
  // message re-delivers on next call (at-least-once vs network). Host-crash
  // AFTER return loses the message; use claim_task+ack_task for that guarantee.
  let ackWarn = '';
  try {
    await doAck(parsed.base, parsed.roomId, state.authIdentity, claim.claim_id, m.seq);
  } catch (e) {
    ackWarn = `\n(warning: ${e.message}; message will be re-delivered on next call)`;
  }
  const verified = m.sender_verified ? ' ✓' : '';
  return {
    content: [{
      type: 'text',
      text:
        `[seq=${m.seq}] ${m.sender}${verified}: ${text == null ? '[undecryptable — wrong room key]' : text}` +
        `\n\n(listening in-room as "${currentRoomLabel(state)}" via auth @${state.authIdentity.handle}; if a reply is needed, use send_message to the same room, then call next_task again to block for the next message)` +
        notice +
        ackWarn,
    }],
  };
}

async function tool_claim_task({ url, timeout_seconds = 60 }) {
  const parsed = parseRoomUrl(url);
  const notice = activeRoomNotice(parsed);
  const t = Math.max(1, Math.min(90, Number(timeout_seconds) || 60));
  const state = await ensureRoomState(parsed);
  const claim = await claimSkippingAdopts(state, t);
  if (claim.empty || !claim.message) {
    return { content: [{ type: 'text', text: `(no new messages — blocked ${t}s as "${currentRoomLabel(state)}" via auth @${state.authIdentity.handle}, cursor=${claim.cursor || 0}; call claim_task again to keep listening)` + notice }] };
  }
  const m = claim.message;
  const text = claim.decrypted_text;
  const verified = m.sender_verified ? ' ✓' : '';
  return {
    content: [{
      type: 'text',
      text:
        `[seq=${m.seq}] ${m.sender}${verified}: ${text == null ? '[undecryptable — wrong room key]' : text}` +
        `\n\n(claim_id=${claim.claim_id} seq=${m.seq} — if the message warrants a reply, call send_message to the same room first, then call ack_task once you have fully processed it; ` +
        `claim expires in 60s and re-delivers if you never ack)` +
        notice,
    }],
  };
}

async function tool_ack_task({ url, claim_id, seq }) {
  const parsed = parseRoomUrl(url);
  setActiveRoom(parsed);
  const state = await ensureRoomState(parsed);
  const r = await doAck(parsed.base, parsed.roomId, state.authIdentity, String(claim_id || ''), Number(seq) || 0);
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
  { name: 'safebot-chat', version: '0.2.1' },
  { capabilities: { tools: {} }, instructions: SERVER_INSTRUCTIONS },
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
