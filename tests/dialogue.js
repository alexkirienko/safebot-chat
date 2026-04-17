// Dialogue-mode stress test — two agents take turns asking each other simple
// questions and replying. Per turn we measure:
//   Δ_deliver   = when A sends → when B sees it
//   Δ_roundtrip = when A asks → when A sees B's reply
// Any message delivered out-of-order or late (>1s) is flagged.
//
// Usage: node tests/dialogue.js <base> <minutes> <pairs>

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');

const BASE = process.argv[2] || 'https://safebot.chat';
const MINUTES = Number(process.argv[3] || 60);
const PAIRS = Number(process.argv[4] || 3);
const DEADLINE = Date.now() + MINUTES * 60_000;

const QUESTIONS = [
  ['what is 7 plus 5?',           '12.'],
  ['capital of France?',           'Paris.'],
  ['color of the sky?',            'Blue.'],
  ['two plus two?',                'Four.'],
  ['name a prime number.',         '17.'],
  ['day after Monday?',            'Tuesday.'],
  ['square root of 81?',           '9.'],
  ['boiling point of water in C?', '100.'],
  ['fastest land animal?',         'Cheetah.'],
  ['largest ocean?',               'Pacific.'],
  ['year WW2 ended?',              '1945.'],
  ['planet closest to the sun?',   'Mercury.'],
];

function alpha(n) { const a='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; return Array.from(crypto.randomBytes(n),(b)=>a[b%a.length]).join(''); }
function fetchJson(url, opts={}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.request(url, { method: opts.method||'GET', headers: opts.headers||{}, timeout: opts.timeout||60000 }, (res) => {
      let data=''; res.on('data',c=>data+=c); res.on('end',()=>resolve({status:res.statusCode,body:data}));
    });
    req.on('error',reject); req.on('timeout',()=>{req.destroy(); reject(new Error('timeout'));});
    if (opts.body) req.write(opts.body);
    req.end();
  });
}
function enc(key, pt) { const nonce=nacl.randomBytes(24); const box=nacl.secretbox(util.decodeUTF8(pt),nonce,key); return {ciphertext:Buffer.from(box).toString('base64'),nonce:Buffer.from(nonce).toString('base64')}; }
function dec(key, c, n) { try { const pt=nacl.secretbox.open(Buffer.from(c,'base64'),Buffer.from(n,'base64'),key); return pt?util.encodeUTF8(pt):null; } catch(_) { return null; } }
function pct(arr, q) { if (!arr.length) return 0; const s=arr.slice().sort((a,b)=>a-b); return s[Math.min(s.length-1, Math.floor(s.length*q))]; }

class Agent {
  constructor(name, roomId, key) {
    this.name = name; this.roomId = roomId; this.key = key;
    this.base = `${BASE}/api/rooms/${roomId}`;
    this.afterSeq = 0;
    this.inbox = [];
    this._running = false;
  }
  async send(text) {
    const {ciphertext, nonce} = enc(this.key, text);
    const t0 = Date.now();
    const r = await fetchJson(`${this.base}/messages`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({sender: this.name, ciphertext, nonce}),
    });
    if (r.status !== 200) throw new Error(`POST ${r.status}`);
    return {t0, body: JSON.parse(r.body)};
  }
  startPolling() {
    this._running = true;
    (async () => {
      while (this._running) {
        try {
          const r = await fetchJson(`${this.base}/wait?after=${this.afterSeq}&timeout=20`, {timeout: 30000});
          const recvAt = Date.now();
          if (r.status !== 200) { await new Promise((r)=>setTimeout(r,200)); continue; }
          const body = JSON.parse(r.body);
          for (const m of body.messages||[]) {
            this.afterSeq = Math.max(this.afterSeq, m.seq);
            const pt = dec(this.key, m.ciphertext, m.nonce);
            if (pt === null) continue;
            this.inbox.push({seq: m.seq, sender: m.sender, text: pt, recvAt});
          }
        } catch (_) {
          await new Promise((r)=>setTimeout(r,300));
        }
      }
    })();
  }
  stop() { this._running = false; }
  async waitFor(predicate, timeoutMs = 8_000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const found = this.inbox.find(predicate);
      if (found) return found;
      await new Promise((r)=>setTimeout(r,8));
    }
    throw new Error('timeout waiting for message');
  }
}

const M = {
  pairs_started: 0,
  turns_completed: 0,
  turns_failed: 0,
  deliver: [],      // one-way delivery latency samples
  roundtrip: [],
  outOfOrder: 0,
  post_5xx: 0, post_err: 0,
  slowDeliveries: [],
};

async function runPair(pairId) {
  const roomId = alpha(6);
  const key = nacl.randomBytes(32);
  const A = new Agent(`pair${pairId}-A`, roomId, key);
  const B = new Agent(`pair${pairId}-B`, roomId, key);
  A.startPolling(); B.startPolling();
  M.pairs_started++;

  let turn = 0;
  while (Date.now() < DEADLINE) {
    const q = QUESTIONS[Math.floor(Math.random() * QUESTIONS.length)];
    turn++;
    try {
      const ask = await A.send(`Q${turn}: ${q[0]}`);
      const gotByB = await B.waitFor((m) => m.sender === A.name && m.text.startsWith(`Q${turn}:`));
      const deliverAB = gotByB.recvAt - ask.t0;
      M.deliver.push(deliverAB);
      if (deliverAB > 1000) M.slowDeliveries.push({pair: pairId, turn, ms: deliverAB, dir: 'A→B'});

      await new Promise((r) => setTimeout(r, 50));
      const reply = await B.send(`A${turn}: ${q[1]}`);
      const gotByA = await A.waitFor((m) => m.sender === B.name && m.text.startsWith(`A${turn}:`));
      const deliverBA = gotByA.recvAt - reply.t0;
      M.deliver.push(deliverBA);
      if (deliverBA > 1000) M.slowDeliveries.push({pair: pairId, turn, ms: deliverBA, dir: 'B→A'});

      M.roundtrip.push(gotByA.recvAt - ask.t0);

      // Strictly-increasing seq check on both agents' inboxes.
      for (const ag of [A, B]) {
        const seqs = ag.inbox.map((m) => m.seq);
        for (let i = 1; i < seqs.length; i++) if (seqs[i] < seqs[i-1]) { M.outOfOrder++; break; }
      }

      M.turns_completed++;
    } catch (e) {
      M.turns_failed++;
      if (/POST 5\d\d/.test(String(e.message))) M.post_5xx++;
      else M.post_err++;
    }

    if (turn % 8 === 0) { A.stop(); B.stop(); return; }
    await new Promise((r) => setTimeout(r, 100 + Math.random() * 200));
  }
  A.stop(); B.stop();
}

async function pairLoop(id) {
  while (Date.now() < DEADLINE) await runPair(id);
}

function report() {
  const now = new Date().toISOString().slice(11, 19);
  console.log(
    `[${now}]  turns=${M.turns_completed} fail=${M.turns_failed} ` +
    `deliver p50=${pct(M.deliver,0.5)}ms p95=${pct(M.deliver,0.95)}ms p99=${pct(M.deliver,0.99)}ms max=${M.deliver.length?Math.max(...M.deliver):0}ms  ` +
    `rt p50=${pct(M.roundtrip,0.5)}ms p95=${pct(M.roundtrip,0.95)}ms  ` +
    `5xx=${M.post_5xx} slow>1s=${M.slowDeliveries.length} OoO=${M.outOfOrder}`
  );
}

async function main() {
  console.log(`▶︎ Dialogue soak  ${PAIRS} pairs × ${MINUTES}min  base=${BASE}`);
  const reporter = setInterval(report, 30_000);
  await Promise.all(Array.from({length: PAIRS}, (_, i) => pairLoop(i + 1)));
  clearInterval(reporter);

  report();
  const d = M.deliver, r = M.roundtrip;
  const p99 = pct(d, 0.99);
  const failRate = M.turns_failed / Math.max(1, M.turns_completed + M.turns_failed);
  console.log(`\n══ SUMMARY ══`);
  console.log(`turns completed: ${M.turns_completed}`);
  console.log(`turns failed:    ${M.turns_failed} (${(failRate*100).toFixed(2)}%)`);
  console.log(`delivery ms:     p50=${pct(d,0.5)} p95=${pct(d,0.95)} p99=${p99} max=${d.length?Math.max(...d):0}  (n=${d.length})`);
  console.log(`roundtrip ms:    p50=${pct(r,0.5)} p95=${pct(r,0.95)} p99=${pct(r,0.99)}`);
  console.log(`deliveries >1s:  ${M.slowDeliveries.length}`);
  console.log(`out-of-order:    ${M.outOfOrder}`);
  console.log(`POST 5xx:        ${M.post_5xx}`);
  const pass = M.post_5xx === 0 && M.outOfOrder === 0 && p99 < 500 && failRate < 0.01;
  console.log(`\n${pass ? '✓ PASS' : '✗ FAIL'}`);
  process.exit(pass ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
