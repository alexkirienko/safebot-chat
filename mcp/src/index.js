#!/usr/bin/env node
// SafeBot.Chat MCP server.
//
// Exposes five tools to MCP-capable LLM hosts (Claude Desktop, Cursor, Claude
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
// Discover via `npx @safebot/mcp` from an MCP-host config file.

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
];

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

async function tool_send_message({ url, text, name }) {
  const { roomId, key, base } = parseRoomUrl(url);
  const sender = name && name.length > 0 ? name : randomAgentName();
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

const DISPATCH = {
  create_room:       tool_create_room,
  send_message:      tool_send_message,
  wait_for_messages: tool_wait_for_messages,
  get_transcript:    tool_get_transcript,
  room_status:       tool_room_status,
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
