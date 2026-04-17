// Edge-case coverage that normal tests miss.

const http = require('http');
const https = require('https');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');
const crypto = require('crypto');

const BASE = process.argv[2] || 'https://safebot.chat';

function fetchJson(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.request(url, {
      method: opts.method || 'GET',
      headers: { 'User-Agent': 'edge', ...(opts.headers || {}) },
      timeout: opts.timeout || 60000,
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function enc(key, pt) {
  const nonce = nacl.randomBytes(24);
  const box = nacl.secretbox(util.decodeUTF8(pt), nonce, key);
  return {
    ciphertext: Buffer.from(box).toString('base64'),
    nonce: Buffer.from(nonce).toString('base64'),
  };
}
function dec(key, ct, n) {
  try {
    const box = Buffer.from(ct, 'base64');
    const nonce = Buffer.from(n, 'base64');
    const pt = nacl.secretbox.open(box, nonce, key);
    return pt ? util.encodeUTF8(pt) : null;
  } catch (_) { return null; }
}

const results = [];
async function test(name, fn) {
  try { await fn(); results.push({ name, ok: true }); console.log('  ✓', name); }
  catch (e) { results.push({ name, ok: false, e: e.message }); console.log('  ✗', name, '—', e.message); }
}

async function main() {
  console.log('\n▶︎ Edge-case tests against', BASE);

  const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const roomId = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
  const key = nacl.randomBytes(32);

  await test('56 KB message round-trip (near-max size)', async () => {
    const big = 'x'.repeat(56 * 1024);
    const { ciphertext, nonce } = enc(key, big);
    const r = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: 'big-sender', ciphertext, nonce }),
    });
    if (r.status !== 200) throw new Error('POST status ' + r.status);
    const j = JSON.parse(r.body);
    const t = await fetchJson(`${BASE}/api/rooms/${roomId}/transcript?after=0&limit=5`);
    const tj = JSON.parse(t.body);
    const last = tj.messages[tj.messages.length - 1];
    if (last.seq !== j.seq) throw new Error('seq mismatch');
    const back = dec(key, last.ciphertext, last.nonce);
    if (back !== big) throw new Error('plaintext mismatch (len ' + (back ? back.length : 0) + ')');
  });

  await test('oversize message (ciphertext >128 KB) rejected', async () => {
    // 120 KB plaintext → ~160 KB base64, above the 128 KB server ceiling.
    const huge = 'y'.repeat(120 * 1024);
    const { ciphertext, nonce } = enc(key, huge);
    const r = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: 'huge', ciphertext, nonce }),
    });
    if (r.status < 400) throw new Error('expected 4xx, got ' + r.status);
  });

  await test('malformed JSON → 400', async () => {
    const r = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{broken',
    });
    if (r.status !== 400) throw new Error('got ' + r.status);
  });

  await test('bad room id → 400', async () => {
    const r = await fetchJson(`${BASE}/api/rooms/.;DROP TABLE;/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: 'x', ciphertext: 'a', nonce: 'b' }),
    });
    if (r.status < 400) throw new Error('got ' + r.status);
  });

  await test('wrong-key ciphertext still relays (server is opaque)', async () => {
    const wrongKey = nacl.randomBytes(32);
    const { ciphertext, nonce } = enc(wrongKey, 'this will not decrypt for real members');
    const r = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: 'imposter', ciphertext, nonce }),
    });
    if (r.status !== 200) throw new Error('POST status ' + r.status);
    // Legit client with real key should get null on decrypt (= silently dropped by UI).
    const t = await fetchJson(`${BASE}/api/rooms/${roomId}/transcript?after=0&limit=50`);
    const tj = JSON.parse(t.body);
    const imposterMsg = tj.messages.find((m) => m.sender === 'imposter');
    if (!imposterMsg) throw new Error('imposter message not in transcript');
    const back = dec(key, imposterMsg.ciphertext, imposterMsg.nonce);
    if (back !== null) throw new Error('wrong-key should not decrypt');
  });

  await test('monotonic seq is strictly increasing', async () => {
    const { ciphertext: c1, nonce: n1 } = enc(key, 'seq-a');
    const { ciphertext: c2, nonce: n2 } = enc(key, 'seq-b');
    const r1 = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sender: 'seq', ciphertext: c1, nonce: n1 }) });
    const r2 = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sender: 'seq', ciphertext: c2, nonce: n2 }) });
    const j1 = JSON.parse(r1.body), j2 = JSON.parse(r2.body);
    if (j2.seq <= j1.seq) throw new Error(`seq not monotonic: ${j1.seq} -> ${j2.seq}`);
  });

  await test('replay buffer caps at 200', async () => {
    const miniRoom = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
    let firstSeq = null, lastSeq = null;
    for (let i = 0; i < 230; i++) {
      const { ciphertext, nonce } = enc(key, 'msg-' + i);
      const r = await fetchJson(`${BASE}/api/rooms/${miniRoom}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender: 'spammer', ciphertext, nonce }),
      });
      const j = JSON.parse(r.body);
      if (firstSeq == null) firstSeq = j.seq;
      lastSeq = j.seq;
    }
    const s = await fetchJson(`${BASE}/api/rooms/${miniRoom}/status`);
    const sj = JSON.parse(s.body);
    if (sj.recent_count > 200) throw new Error('buffer > 200: ' + sj.recent_count);
    if (sj.last_seq !== lastSeq) throw new Error('expected last_seq ' + lastSeq + ', got ' + sj.last_seq);
    if (lastSeq - firstSeq !== 229) throw new Error('seq delta should be 229, got ' + (lastSeq - firstSeq));
  });

  await test('/wait wakes within 100ms on new message', async () => {
    const waitRoom = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
    // Prime with one message so afterSeq is real
    const { ciphertext: c1, nonce: n1 } = enc(key, 'prime');
    const primeR = await fetchJson(`${BASE}/api/rooms/${waitRoom}/messages`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sender: 'x', ciphertext: c1, nonce: n1 }) });
    const primeSeq = JSON.parse(primeR.body).seq;
    const waitStart = Date.now();
    const waitP = fetchJson(`${BASE}/api/rooms/${waitRoom}/wait?after=${primeSeq}&timeout=10`);
    // Fire a POST after 500ms.
    setTimeout(async () => {
      const { ciphertext, nonce } = enc(key, 'wakey');
      await fetchJson(`${BASE}/api/rooms/${waitRoom}/messages`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sender: 'x', ciphertext, nonce }) });
    }, 500);
    const w = await waitP;
    const elapsed = Date.now() - waitStart;
    const wj = JSON.parse(w.body);
    if (wj.messages.length === 0) throw new Error('wait returned empty');
    if (elapsed < 450 || elapsed > 750) throw new Error('wake timing off: ' + elapsed + 'ms');
  });

  const fails = results.filter((r) => !r.ok);
  console.log(`\n${results.length - fails.length}/${results.length} edge tests passed`);
  if (fails.length) process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(1); });
