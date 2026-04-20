import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MCP_BIN = path.join(__dirname, '..', 'src', 'index.js');
const ROOT = path.join(__dirname, '..', '..');
const SERVER_BIN = path.join(ROOT, 'server', 'index.js');
const PORT = 3123;
const BASE = `http://127.0.0.1:${PORT}`;

function jsonrpc(id, method, params) {
  return JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
}

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function parseRoomUrl(url) {
  const u = new URL(url);
  const key = Buffer.from((u.hash.slice(3) + '='.repeat((4 - (u.hash.slice(3).length % 4)) % 4)).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return {
    roomId: u.pathname.split('/').pop(),
    key: new Uint8Array(key),
  };
}

function extractText(res) {
  if (!res || !res.content) return '';
  return res.content.filter((c) => c.type === 'text').map((c) => c.text).join('\n');
}

function startServer() {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [SERVER_BIN], {
      cwd: ROOT,
      env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('SafeBot.Chat listening')) resolve(proc);
    });
    proc.stderr.on('data', (d) => process.stderr.write('[server stderr] ' + d));
    proc.on('exit', (code) => reject(new Error(`server exited early: ${code}`)));
    setTimeout(() => reject(new Error('server start timeout')), 6000);
  });
}

function startMcp() {
  const proc = spawn(process.execPath, [MCP_BIN], {
    cwd: ROOT,
    env: { ...process.env, SAFEBOT_BASE: BASE },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  proc.stderr.on('data', (d) => process.stderr.write('[mcp stderr] ' + d));
  return proc;
}

async function rpc(proc, id, method, params, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      proc.stdout.off('data', onData);
      reject(new Error(`rpc ${method} timeout`));
    }, timeoutMs);
    let buf = '';
    function onData(chunk) {
      buf += chunk.toString();
      for (;;) {
        const nl = buf.indexOf('\n');
        if (nl === -1) break;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let obj;
        try { obj = JSON.parse(line); } catch (_) { continue; }
        if (obj.id !== id) continue;
        clearTimeout(timer);
        proc.stdout.off('data', onData);
        if (obj.error) reject(new Error(obj.error.message || JSON.stringify(obj.error)));
        else resolve(obj.result);
        return;
      }
    }
    proc.stdout.on('data', onData);
    proc.stdin.write(jsonrpc(id, method, params));
  });
}

async function callTool(proc, id, name, args, timeoutMs = 30000) {
  return rpc(proc, id, 'tools/call', { name, arguments: args }, timeoutMs);
}

function encryptRoom(key, plaintext) {
  const nonce = nacl.randomBytes(24);
  const ct = nacl.secretbox(naclUtil.decodeUTF8(plaintext), nonce, key);
  return { ciphertext: b64(ct), nonce: b64(nonce) };
}

function buildIdentity(handle) {
  const box_sk = nacl.randomBytes(32);
  const sign_seed = nacl.randomBytes(32);
  const box_kp = nacl.box.keyPair.fromSecretKey(box_sk);
  const sign_kp = nacl.sign.keyPair.fromSeed(sign_seed);
  return {
    handle,
    box_sk,
    sign_seed,
    sign_sk: sign_kp.secretKey,
    box_pub_b64: b64(box_kp.publicKey),
    sign_pub_b64: b64(sign_kp.publicKey),
    box_sk_b64u: b64url(box_sk),
    sign_seed_b64u: b64url(sign_seed),
  };
}

async function registerIdentity(ident) {
  const ts = Date.now();
  const blob = naclUtil.decodeUTF8(`register ${ident.handle} ${ts} ${ident.box_pub_b64} ${ident.sign_pub_b64}`);
  const sig = nacl.sign.detached(blob, ident.sign_sk);
  const res = await fetch(`${BASE}/api/identity/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      handle: ident.handle,
      box_pub: ident.box_pub_b64,
      sign_pub: ident.sign_pub_b64,
      register_ts: ts,
      register_sig: b64(sig),
      meta: { test: 'promotable' },
    }),
  });
  if (!res.ok && res.status !== 409) {
    throw new Error(`register failed: ${res.status} ${await res.text()}`);
  }
}

function connectObserver(roomId) {
  const controller = new AbortController();
  const events = [];
  let latestParticipants = [];
  const ready = (async () => {
    const res = await fetch(`${BASE}/api/rooms/${roomId}/events?name=observer`, {
      headers: { Accept: 'text/event-stream' },
      signal: controller.signal,
    });
    const decoder = new TextDecoder();
    let buf = '';
    for await (const chunk of res.body) {
      buf += decoder.decode(chunk, { stream: true });
      for (;;) {
        const m = /\r?\n\r?\n/.exec(buf);
        if (!m) break;
        const frame = buf.slice(0, m.index);
        buf = buf.slice(m.index + m[0].length);
        const payload = frame
          .split(/\r?\n/)
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trimStart())
          .join('\n');
        if (!payload) continue;
        let obj;
        try { obj = JSON.parse(payload); } catch (_) { continue; }
        events.push(obj);
        if (Array.isArray(obj.participants)) latestParticipants = obj.participants;
      }
    }
  })();
  return {
    events,
    get participants() { return latestParticipants; },
    async waitFor(predicate, timeoutMs = 8000) {
      const started = Date.now();
      while (Date.now() - started < timeoutMs) {
        if (predicate(events, latestParticipants)) return;
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error('observer wait timed out');
    },
    close() { controller.abort(); return ready.catch(() => {}); },
  };
}

async function main() {
  console.log('▶︎ MCP promotable-agent regression');
  const server = await startServer();
  const mcp = startMcp();
  let observer;
  try {
    await rpc(mcp, 1, 'initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'promotable-test', version: '0.0.1' },
    });

    const created = await callTool(mcp, 2, 'create_room', { base: BASE });
    const roomUrl = extractText(created).match(/http:\/\/[^\s]+#k=[A-Za-z0-9_-]+/)[0];
    const { roomId, key } = parseRoomUrl(roomUrl);
    observer = connectObserver(roomId);
    await observer.waitFor((_events, participants) => participants.some((p) => p.name === 'observer'));

    const claim = await callTool(mcp, 3, 'claim_task', { url: roomUrl, timeout_seconds: 1 }, 10000);
    const claimText = extractText(claim);
    const alias = claimText.match(/as "([^"]+)"/)?.[1];
    if (!alias) throw new Error(`room alias missing from claim_task text: ${claimText}`);

    await observer.waitFor((_events, participants) => participants.some((p) => p.name === alias && p.box_pub));
    const promotableRow = observer.participants.find((p) => p.name === alias);
    if (!promotableRow?.box_pub) throw new Error('anonymous MCP participant did not advertise box_pub');
    console.log('  ✓ anonymous room alias is present with box_pub:', alias);

    const adoptedHandle = `promoted${Date.now().toString(36)}`;
    const adopted = buildIdentity(adoptedHandle);
    await registerIdentity(adopted);

    const operatorBox = nacl.box.keyPair();
    const operatorHandle = `op${Date.now().toString(36)}`;
    const operator = buildIdentity(operatorHandle);
    await registerIdentity(operator);
    const adoptId = crypto.randomUUID();
    const inner = JSON.stringify({
      handle: adopted.handle,
      box_sk_b64u: adopted.box_sk_b64u,
      sign_seed_b64u: adopted.sign_seed_b64u,
      adopt_id: adoptId,
    });
    const innerNonce = nacl.randomBytes(24);
    const innerCt = nacl.box(
      naclUtil.decodeUTF8(inner),
      innerNonce,
      Buffer.from(promotableRow.box_pub.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
      operatorBox.secretKey,
    );
    const adoptEnvelope = {
      safebot_adopt_v1: true,
      target_name: alias,
      sender_box_pub: b64url(operatorBox.publicKey),
      nonce: b64url(innerNonce),
      ciphertext: b64url(innerCt),
      adopt_id: adoptId,
    };
    const outer = encryptRoom(key, JSON.stringify(adoptEnvelope));
    // Sign the adopt post so server stamps sender_verified:true.
    // Adopt consumers require sender_verified — an unsigned post would
    // be silently dropped (blocker fix from 2026-04-20 review).
    const sigTs = Date.now();
    const sigNonce = b64url(nacl.randomBytes(18));
    const sigBlob = naclUtil.decodeUTF8(`room-msg ${roomId} ${sigTs} ${sigNonce} ${sha256Hex(outer.ciphertext)}`);
    const sig = nacl.sign.detached(sigBlob, operator.sign_sk);
    const postAdopt = await fetch(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender: `@${operator.handle}`,
        ...outer,
        sender_handle: operator.handle,
        sender_ts: sigTs,
        sender_nonce: sigNonce,
        sender_sig: b64(sig),
      }),
    });
    if (!postAdopt.ok) throw new Error(`operator adopt post failed: ${postAdopt.status} ${await postAdopt.text()}`);

    await observer.waitFor((_events, participants) => participants.some((p) => p.name === `@${adoptedHandle}`));
    console.log('  ✓ adopt flips presence label to signed handle');

    await callTool(mcp, 4, 'send_message', { url: roomUrl, text: 'signed after adopt' });
    await observer.waitFor((events) => events.some((e) => e.type === 'message' && e.sender === `@${adoptedHandle}` && e.sender_verified === true));
    console.log('  ✓ post-adopt MCP send is signed as the promoted handle');

    console.log('\n✓ promotable-agent regression passed');
  } finally {
    if (observer) await observer.close();
    try { mcp.kill('SIGTERM'); } catch (_) {}
    try { server.kill('SIGTERM'); } catch (_) {}
  }
}

main().catch((e) => {
  console.error('\n✗ promotable-agent regression failed');
  console.error(e);
  process.exit(1);
});
