// Soak test — continuously creates rooms and exercises SSE / WS / long-poll
// against the live domain for a configurable duration. Reports any 502/5xx,
// disconnected streams, decrypt failures, or latency regressions.
//
// Usage: node tests/soak.js <base-url> <minutes>

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');
const WebSocket = require('ws');

const BASE = process.argv[2] || 'https://safebot.chat';
const MINUTES = Number(process.argv[3] || 60);
const DEADLINE = Date.now() + MINUTES * 60 * 1000;

const metrics = {
  rooms_created: 0,
  ws_connect_attempts: 0,
  ws_connect_ok: 0,
  ws_connect_err: 0,
  ws_msg_sent: 0,
  ws_msg_recv: 0,
  sse_connect_attempts: 0,
  sse_connect_ok: 0,
  sse_connect_err: 0,
  sse_disconnects_unexpected: 0,
  sse_msg_recv: 0,
  longpoll_cycles: 0,
  longpoll_wakes: 0,
  longpoll_empty_timeouts: 0,
  longpoll_errors: 0,
  post_ok: 0, post_5xx: 0, post_4xx: 0, post_err: 0,
  decrypt_fail: 0,
  lat_ws: [], lat_sse: [], lat_longpoll: [],
};

function fetchJson(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.request(url, { method: opts.method || 'GET', headers: opts.headers || {}, timeout: opts.timeout || 120000 }, (res) => {
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

function newRoom() {
  const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const roomId = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
  const key = nacl.randomBytes(32);
  return { roomId, key };
}
function enc(key, pt) {
  const nonce = nacl.randomBytes(24);
  const box = nacl.secretbox(util.decodeUTF8(pt), nonce, key);
  return { ciphertext: Buffer.from(box).toString('base64'), nonce: Buffer.from(nonce).toString('base64') };
}
function dec(key, c, n) {
  try {
    const pt = nacl.secretbox.open(Buffer.from(c, 'base64'), Buffer.from(n, 'base64'), key);
    return pt ? util.encodeUTF8(pt) : null;
  } catch (_) { return null; }
}

async function sendMsg(roomId, key, sender, text) {
  const { ciphertext, nonce } = enc(key, text);
  try {
    const r = await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender, ciphertext, nonce }),
    });
    if (r.status === 200) metrics.post_ok++;
    else if (r.status >= 500) metrics.post_5xx++;
    else metrics.post_4xx++;
    return r;
  } catch (e) {
    metrics.post_err++;
    return null;
  }
}

// --- WS worker ---------------------------------------------------------
function wsWorker(roomId, key, senderName) {
  const url = `${BASE.replace(/^http/, 'ws')}/api/rooms/${roomId}/ws`;
  return new Promise((resolve) => {
    metrics.ws_connect_attempts++;
    const ws = new WebSocket(url);
    let settled = false;
    const deadline = setTimeout(() => { if (!settled) { settled = true; try { ws.terminate(); } catch (_) {} resolve(); } }, 60000);
    ws.on('open', () => {
      metrics.ws_connect_ok++;
      // Send one message
      const { ciphertext, nonce } = enc(key, `ws-ping-${Date.now()}`);
      ws.send(JSON.stringify({ sender: senderName, ciphertext, nonce }));
      metrics.ws_msg_sent++;
    });
    ws.on('message', (buf) => {
      try {
        const obj = JSON.parse(buf.toString());
        if (obj.type === 'message') {
          metrics.ws_msg_recv++;
          const pt = dec(key, obj.ciphertext, obj.nonce);
          if (pt === null) metrics.decrypt_fail++;
          else {
            const m = /ws-ping-(\d+)/.exec(pt);
            if (m) metrics.lat_ws.push(Date.now() - Number(m[1]));
          }
        }
      } catch (_) {}
    });
    ws.on('close', () => {
      if (!settled) { settled = true; clearTimeout(deadline); resolve(); }
    });
    ws.on('error', (e) => {
      metrics.ws_connect_err++;
      if (!settled) { settled = true; clearTimeout(deadline); try { ws.close(); } catch (_) {} resolve(); }
    });
    // Close ourselves after ~10s
    setTimeout(() => { try { ws.close(); } catch (_) {} }, 10000);
  });
}

// --- SSE worker --------------------------------------------------------
function sseWorker(roomId, key) {
  return new Promise((resolve) => {
    metrics.sse_connect_attempts++;
    const url = `${BASE}/api/rooms/${roomId}/events`;
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname,
      method: 'GET',
      headers: { 'Accept': 'text/event-stream' },
      timeout: 60000,
    }, (res) => {
      if (res.statusCode !== 200) {
        metrics.sse_connect_err++;
        console.log(`  ! SSE status ${res.statusCode} for ${roomId}`);
        res.destroy(); resolve(); return;
      }
      metrics.sse_connect_ok++;
      res.setEncoding('utf8');
      let buf = '';
      let closedCleanly = false;
      res.on('data', (c) => {
        buf += c;
        let idx;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const frame = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 2);
          if (frame.startsWith('data:')) {
            try {
              const obj = JSON.parse(frame.slice(5).trim());
              if (obj.type === 'message') {
                metrics.sse_msg_recv++;
                const pt = dec(key, obj.ciphertext, obj.nonce);
                if (pt === null) metrics.decrypt_fail++;
                else {
                  const m = /sse-ping-(\d+)/.exec(pt);
                  if (m) metrics.lat_sse.push(Date.now() - Number(m[1]));
                }
              }
            } catch (_) {}
          }
        }
      });
      res.on('end', () => { closedCleanly = true; resolve(); });
      res.on('error', () => { metrics.sse_disconnects_unexpected++; resolve(); });

      // After 8s, close cleanly.
      setTimeout(() => { closedCleanly = true; res.destroy(); resolve(); }, 10000);
    });
    req.on('error', () => { metrics.sse_connect_err++; resolve(); });
    req.end();

    // Fire a ping once the request is presumably connected.
    setTimeout(async () => {
      const t0 = Date.now();
      const { ciphertext, nonce } = enc(key, `sse-ping-${t0}`);
      await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender: 'sse-probe', ciphertext, nonce }),
      }).catch(() => {});
    }, 200);
  });
}

// --- long-poll worker --------------------------------------------------
async function longPollWorker(roomId, key) {
  let afterSeq = 0;
  const started = Date.now();
  for (let i = 0; i < 3 && Date.now() - started < 10000; i++) {
    metrics.longpoll_cycles++;
    // Fire a send 500ms after we start each wait.
    const wantText = `lp-ping-${Date.now()}`;
    setTimeout(async () => {
      const { ciphertext, nonce } = enc(key, wantText);
      await fetchJson(`${BASE}/api/rooms/${roomId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender: 'lp-probe', ciphertext, nonce }),
      }).catch(() => {});
    }, 300);
    try {
      const r = await fetchJson(`${BASE}/api/rooms/${roomId}/wait?after=${afterSeq}&timeout=3`, { timeout: 10000 });
      if (r.status !== 200) { metrics.longpoll_errors++; continue; }
      const body = JSON.parse(r.body);
      if ((body.messages || []).length === 0) metrics.longpoll_empty_timeouts++;
      else metrics.longpoll_wakes++;
      for (const m of body.messages || []) {
        afterSeq = Math.max(afterSeq, m.seq);
        const pt = dec(key, m.ciphertext, m.nonce);
        if (pt === null) metrics.decrypt_fail++;
        else {
          const mx = /lp-ping-(\d+)/.exec(pt);
          if (mx) metrics.lat_longpoll.push(Date.now() - Number(mx[1]));
        }
      }
    } catch (_) {
      metrics.longpoll_errors++;
    }
  }
}

function p(arr, q) { if (!arr.length) return 'n/a'; const s = arr.slice().sort((a,b)=>a-b); return s[Math.min(s.length-1, Math.floor(s.length*q))] + 'ms'; }

function report() {
  const m = metrics;
  console.log(`\n── metrics @ ${new Date().toISOString()} ──`);
  console.log(`  rooms: ${m.rooms_created}`);
  console.log(`  POST: ok=${m.post_ok} 5xx=${m.post_5xx} 4xx=${m.post_4xx} err=${m.post_err}`);
  console.log(`  WS:   attempt=${m.ws_connect_attempts} ok=${m.ws_connect_ok} err=${m.ws_connect_err}  sent=${m.ws_msg_sent} recv=${m.ws_msg_recv}  p50=${p(m.lat_ws,0.5)} p95=${p(m.lat_ws,0.95)} p99=${p(m.lat_ws,0.99)} (n=${m.lat_ws.length})`);
  console.log(`  SSE:  attempt=${m.sse_connect_attempts} ok=${m.sse_connect_ok} err=${m.sse_connect_err}  recv=${m.sse_msg_recv} unexpected_disc=${m.sse_disconnects_unexpected}  p50=${p(m.lat_sse,0.5)} p95=${p(m.lat_sse,0.95)} (n=${m.lat_sse.length})`);
  console.log(`  LP:   cycles=${m.longpoll_cycles} wakes=${m.longpoll_wakes} empty=${m.longpoll_empty_timeouts} err=${m.longpoll_errors}  p50=${p(m.lat_longpoll,0.5)} p95=${p(m.lat_longpoll,0.95)} (n=${m.lat_longpoll.length})`);
  console.log(`  decrypt_fail=${m.decrypt_fail}`);
}

async function main() {
  console.log(`▶︎ Soak for ${MINUTES}min against ${BASE}`);
  const reporter = setInterval(report, 120_000);

  // Continuous loop.
  while (Date.now() < DEADLINE) {
    const { roomId, key } = newRoom();
    metrics.rooms_created++;

    // Fire all three workers in parallel on the same room.
    await Promise.all([
      wsWorker(roomId, key, `ws-${Math.random().toString(36).slice(2,6)}`),
      sseWorker(roomId, key),
      longPollWorker(roomId, key),
    ]).catch(() => {});

    await new Promise((r) => setTimeout(r, 500));
  }

  clearInterval(reporter);
  report();

  // Summary / pass-fail
  const m = metrics;
  const fail = m.post_5xx > 0 || m.post_err > 5 || m.sse_connect_err > 3 || m.ws_connect_err > 3;
  console.log(`\n══ ${fail ? '⚠ ISSUES DETECTED' : '✓ clean'} ══`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
