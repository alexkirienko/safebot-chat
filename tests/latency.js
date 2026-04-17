// Latency benchmark — measures send→receive time for the three delivery paths
// (WS, SSE, HTTP long-poll) against the live domain. Runs 30 messages per
// path and reports p50/p95/p99.

const { chromium } = require('playwright');
const http = require('http');
const https = require('https');

const BASE = process.argv[2] || 'https://safebot.chat';
const N = 30;

function percentile(arr, p) {
  const s = arr.slice().sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(s.length * p))];
}
function stats(arr) {
  if (!arr.length) return 'n/a';
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  return `n=${arr.length}  mean=${mean.toFixed(0)}ms  p50=${percentile(arr, 0.5).toFixed(0)}ms  p95=${percentile(arr, 0.95).toFixed(0)}ms  p99=${percentile(arr, 0.99).toFixed(0)}ms  max=${Math.max(...arr).toFixed(0)}ms`;
}

// --- WS path ----------------------------------------------------------
async function benchWS(roomUrl) {
  console.log('\n── WebSocket (browser → server → browser)');
  const browser = await chromium.launch();
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  // Patch WebSocket on B BEFORE any page script runs.
  await ctxB.addInitScript(() => {
    window.__rx = [];
    const OrigWS = window.WebSocket;
    class PatchedWS extends OrigWS {
      constructor(url, protocols) {
        super(url, protocols);
        this.addEventListener('message', (ev) => {
          try {
            const obj = JSON.parse(ev.data);
            if (obj && obj.type === 'message') {
              window.__rx.push({ at: Date.now(), id: obj.id });
            }
          } catch (_) {}
        });
      }
    }
    window.WebSocket = PatchedWS;
  });

  const A = await ctxA.newPage();
  const B = await ctxB.newPage();
  await Promise.all([A.goto(roomUrl), B.goto(roomUrl)]);

  await A.waitForFunction(() => {
    const el = document.getElementById('status-label');
    return el && /encrypted/i.test(el.textContent || '');
  }, { timeout: 10000 });
  await B.waitForFunction(() => {
    const el = document.getElementById('status-label');
    return el && /encrypted/i.test(el.textContent || '') && Array.isArray(window.__rx);
  }, { timeout: 10000 });

  const lats = [];
  for (let i = 0; i < N; i++) {
    const t0 = await A.evaluate((i) => {
      const ta = document.getElementById('message');
      const form = document.getElementById('composer');
      ta.value = `bench-${i}`;
      const t0 = Date.now();
      form.requestSubmit();
      return t0;
    }, i);
    const t1 = await B.evaluate(async (want) => {
      while ((window.__rx || []).length < want) await new Promise((r) => setTimeout(r, 1));
      return window.__rx[want - 1].at;
    }, i + 1);
    lats.push(t1 - t0);
    await new Promise((r) => setTimeout(r, 50));
  }
  await browser.close();
  console.log('  ', stats(lats));
  return lats;
}

// --- HTTP long-poll path ---------------------------------------------
function fetchJson(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.request(url, { method: opts.method || 'GET', headers: opts.headers || {}, timeout: opts.timeout || 120000 }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function benchLongPoll(roomId, key) {
  console.log('\n── HTTP long-poll (POST /messages ↔ GET /wait)');
  const nacl = require('tweetnacl');
  const util = require('tweetnacl-util');
  function encrypt(plaintext) {
    const nonce = nacl.randomBytes(24);
    const box = nacl.secretbox(util.decodeUTF8(plaintext), nonce, key);
    return {
      ciphertext: Buffer.from(box).toString('base64'),
      nonce: Buffer.from(nonce).toString('base64'),
    };
  }

  // Prime: one message so we have a baseline seq.
  {
    const { ciphertext, nonce } = encrypt('prime');
    await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'bench' },
      body: JSON.stringify({ sender: 'bench-primer', ciphertext, nonce }),
    });
  }

  let afterSeq = 1;
  const lats = [];

  // One background listener loops /wait. Another task fires a POST every ~80ms.
  // Each POST carries performance.now() in the plaintext; receiver computes delta.
  let done = false;
  const pending = new Map(); // id -> { t0 }

  async function listener() {
    while (!done) {
      const r = await fetchJson(`${BASE}/api/rooms/${roomId}/wait?after=${afterSeq}&timeout=30`, {
        headers: { 'User-Agent': 'bench' },
      }).catch(() => null);
      if (!r || r.status !== 200) { await new Promise((r) => setTimeout(r, 100)); continue; }
      const body = JSON.parse(r.body);
      const arrivalAt = Date.now();
      for (const m of body.messages || []) {
        afterSeq = Math.max(afterSeq, m.seq);
        // Decrypt to extract our timestamp stamp
        try {
          const box = Buffer.from(m.ciphertext, 'base64');
          const nonceB = Buffer.from(m.nonce, 'base64');
          const pt = nacl.secretbox.open(box, nonceB, key);
          if (!pt) continue;
          const text = util.encodeUTF8(pt);
          const m2 = /bench-(\d+)-(\d+)/.exec(text);
          if (m2) {
            const sentAt = Number(m2[2]);
            lats.push(arrivalAt - sentAt);
          }
        } catch (_) {}
      }
    }
  }

  const listen = listener();

  for (let i = 0; i < N; i++) {
    const t0 = Date.now();
    const { ciphertext, nonce } = encrypt(`bench-${i}-${t0}`);
    await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'bench' },
      body: JSON.stringify({ sender: 'bench-sender', ciphertext, nonce }),
    });
    await new Promise((r) => setTimeout(r, 120));
  }

  // Wait up to 3s for tail.
  const deadline = Date.now() + 3000;
  while (lats.length < N && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
  done = true;
  await listen.catch(() => {});
  console.log('  ', stats(lats));
  return lats;
}

// --- Main --------------------------------------------------------------
(async () => {
  const crypto = require('crypto');
  const nacl = require('tweetnacl');

  // Fresh room (client-side key).
  const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const roomId = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
  const keyBytes = nacl.randomBytes(32);
  const keyB64u = Buffer.from(keyBytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const roomUrl = `${BASE}/room/${roomId}#k=${keyB64u}`;
  console.log('Room:', roomUrl);

  const wsLats = await benchWS(roomUrl);
  const lpLats = await benchLongPoll(roomId, keyBytes);

  console.log('\n════════════════════════════════════════');
  console.log('WebSocket (browser↔browser):');
  console.log('  ', stats(wsLats));
  console.log('HTTP long-poll (POST ↔ /wait):');
  console.log('  ', stats(lpLats));
})().catch((e) => { console.error(e); process.exit(1); });
