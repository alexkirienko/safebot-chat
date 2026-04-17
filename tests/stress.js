// Multi-agent stress test.
//
// Spawns N concurrent "agents" that each:
//   - join the same room via long-poll
//   - send M messages at a random cadence
//   - count how many messages they received and measure per-message latency
//
// Reports: total sent, total received, drop rate, throughput, latency stats,
// CPU/RAM of the server (if running locally).

const http = require('http');
const https = require('https');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');
const crypto = require('crypto');

const BASE = process.argv[2] || 'https://safebot.chat';
const AGENTS = Number(process.argv[3] || 10);
const MSGS_PER_AGENT = Number(process.argv[4] || 20);
const SEND_INTERVAL_MS = Number(process.argv[5] || 200);

function fetchJson(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.request(url, {
      method: opts.method || 'GET',
      headers: { 'User-Agent': 'stress', ...(opts.headers || {}) },
      timeout: opts.timeout || 120000,
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function encrypt(key, plaintext) {
  const nonce = nacl.randomBytes(24);
  const box = nacl.secretbox(util.decodeUTF8(plaintext), nonce, key);
  return {
    ciphertext: Buffer.from(box).toString('base64'),
    nonce: Buffer.from(nonce).toString('base64'),
  };
}
function decrypt(key, ctB64, nonceB64) {
  try {
    const box = Buffer.from(ctB64, 'base64');
    const nonce = Buffer.from(nonceB64, 'base64');
    const pt = nacl.secretbox.open(box, nonce, key);
    return pt ? util.encodeUTF8(pt) : null;
  } catch (_) { return null; }
}

function percentile(arr, p) {
  const s = arr.slice().sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor(s.length * p))] : 0;
}

async function agent(id, roomId, key, received, startBarrier, done) {
  const name = `agent-${id}`;
  const mySent = 0;
  let afterSeq = 0;
  const listenErrors = [];
  let listenerActive = true;

  // Listener loop
  (async () => {
    while (listenerActive) {
      try {
        const r = await fetchJson(`${BASE}/api/rooms/${roomId}/wait?after=${afterSeq}&timeout=20`, {
          timeout: 30000,
        });
        const now = Date.now();
        if (r.status !== 200) { listenErrors.push('http ' + r.status); await new Promise((r) => setTimeout(r, 200)); continue; }
        const body = JSON.parse(r.body);
        for (const m of body.messages || []) {
          afterSeq = Math.max(afterSeq, m.seq);
          const pt = decrypt(key, m.ciphertext, m.nonce);
          if (pt === null) { received.decryptFail++; continue; }
          // Parse timestamp from plaintext: "agentX|seqY|<t0>"
          const mx = /\|(\d+)$/.exec(pt);
          if (mx) {
            const t0 = Number(mx[1]);
            received.lat.push(now - t0);
          }
          received.byAgent[m.sender] = (received.byAgent[m.sender] || 0) + 1;
          received.total++;
        }
      } catch (e) {
        listenErrors.push(String(e.message || e).slice(0, 40));
        await new Promise((r) => setTimeout(r, 500));
      }
    }
  })();

  await startBarrier;

  // Sender loop — fire MSGS_PER_AGENT messages at SEND_INTERVAL_MS cadence with jitter.
  for (let i = 0; i < MSGS_PER_AGENT; i++) {
    const t0 = Date.now();
    const text = `${name}|${i}|${t0}`;
    const { ciphertext, nonce } = encrypt(key, text);
    try {
      const r = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender: name, ciphertext, nonce }),
      });
      if (r.status === 200) received.sent++;
      else if (r.status === 429) received.rate429++;
      else received.sendErrors++;
    } catch (e) {
      received.sendErrors++;
    }
    const jitter = Math.random() * 100;
    await new Promise((r) => setTimeout(r, SEND_INTERVAL_MS + jitter - 50));
  }

  // Wait a little for the tail, then stop the listener.
  await new Promise((r) => setTimeout(r, 1500));
  listenerActive = false;
  if (listenErrors.length) {
    received.listenerErrorAgents.add(name);
  }
}

async function main() {
  console.log(`\n▶︎ Stress test: ${AGENTS} agents × ${MSGS_PER_AGENT} msgs, ${SEND_INTERVAL_MS}ms cadence, base=${BASE}`);
  const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const roomId = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
  const key = nacl.randomBytes(32);
  console.log(`  room: ${roomId}`);

  // Shared tally
  const received = {
    total: 0, sent: 0, sendErrors: 0, rate429: 0, decryptFail: 0,
    byAgent: {}, lat: [], listenerErrorAgents: new Set(),
  };

  const go = { resolve: null };
  const barrier = new Promise((r) => (go.resolve = r));

  const t0 = Date.now();

  const agents = [];
  for (let i = 0; i < AGENTS; i++) {
    agents.push(agent(i, roomId, key, received, barrier));
    await new Promise((r) => setTimeout(r, 20));  // 20ms stagger so we don't thundering-herd
  }
  // Give listeners a moment to establish.
  await new Promise((r) => setTimeout(r, 800));
  go.resolve();

  await Promise.all(agents);
  const elapsedMs = Date.now() - t0;

  // Each message is sent once and should be received by every agent
  // (each agent sees its own + all others' via /wait).
  const expectedReceipts = received.sent * AGENTS;

  console.log(`\n  elapsed: ${(elapsedMs / 1000).toFixed(1)}s`);
  console.log(`  sent OK:         ${received.sent}/${AGENTS * MSGS_PER_AGENT}`);
  console.log(`  send errors:     ${received.sendErrors}  rate-429: ${received.rate429}`);
  console.log(`  receipts:        ${received.total}  (expected ≈ ${expectedReceipts})`);
  console.log(`  drop rate:       ${((1 - received.total / (expectedReceipts || 1)) * 100).toFixed(2)}%`);
  console.log(`  decrypt fails:   ${received.decryptFail}`);
  console.log(`  throughput:      ${(received.sent / (elapsedMs / 1000)).toFixed(1)} msg/s sent, ${(received.total / (elapsedMs / 1000)).toFixed(1)} msg/s delivered`);
  if (received.lat.length) {
    const arr = received.lat;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    console.log(`  latency ms:      mean=${mean.toFixed(0)}  p50=${percentile(arr, 0.5).toFixed(0)}  p95=${percentile(arr, 0.95).toFixed(0)}  p99=${percentile(arr, 0.99).toFixed(0)}  max=${Math.max(...arr).toFixed(0)}  (n=${arr.length})`);
  }
  if (received.listenerErrorAgents.size) {
    console.log(`  listeners with errors: ${received.listenerErrorAgents.size} / ${AGENTS}`);
  }
  // Final room status
  try {
    const s = await fetchJson(`${BASE}/api/rooms/${roomId}/status`);
    console.log(`  final status:    ${s.body}`);
  } catch (_) {}
}

main().catch((e) => { console.error(e); process.exit(1); });
