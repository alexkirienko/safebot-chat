// Orchestrates the SafeBot.Chat test suite:
//  1. Unit: crypto round-trip (Node-side, shared tweetnacl)
//  2. Server boot + basic HTTP
//  3. E2E via Playwright (two browsers + cross-talk)
//  4. Python SDK round-trip
//  5. No-logs audit

const { spawn, spawnSync } = require('child_process');
const path = require('path');
const http = require('http');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { chromium } = require('playwright');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const PORT = 3100;
const BASE = `http://127.0.0.1:${PORT}`;

let serverProc;
const results = [];

function log(...a) { console.log('[tests]', ...a); }
function pass(name) { results.push({ name, ok: true }); log('  ✓', name); }
function fail(name, err) { results.push({ name, ok: false, err: String(err && err.stack || err) }); log('  ✗', name, '\n', err && err.stack || err); }

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function startServer() {
  return new Promise((resolve, reject) => {
    serverProc = spawn(process.execPath, ['server/index.js'], {
      cwd: ROOT,
      env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let buf = '';
    serverProc.stdout.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('SafeBot.Chat listening')) resolve();
    });
    serverProc.stderr.on('data', (d) => process.stderr.write(d));
    serverProc.on('exit', (c) => reject(new Error(`server exited early: ${c}`)));
    setTimeout(() => reject(new Error('server start timeout')), 6000);
  });
}

function stopServer() {
  return new Promise((resolve) => {
    if (!serverProc) return resolve();
    serverProc.removeAllListeners('exit');
    serverProc.on('exit', () => resolve());
    serverProc.kill('SIGTERM');
    setTimeout(() => { try { serverProc.kill('SIGKILL'); } catch (_) {} resolve(); }, 1500);
  });
}

async function test(name, fn) {
  try { await fn(); pass(name); } catch (e) { fail(name, e); }
}

function randomKey() { return nacl.randomBytes(32); }
function encrypt(key, plaintext) {
  const nonce = nacl.randomBytes(24);
  const ct = nacl.secretbox(naclUtil.decodeUTF8(plaintext), nonce, key);
  return { ciphertext: Buffer.from(ct).toString('base64'), nonce: Buffer.from(nonce).toString('base64') };
}
function decrypt(key, ctB64, nonceB64) {
  const ct = Buffer.from(ctB64, 'base64');
  const nonce = Buffer.from(nonceB64, 'base64');
  const pt = nacl.secretbox.open(ct, nonce, key);
  if (!pt) return null;
  return naclUtil.encodeUTF8(pt);
}
function b64url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function httpJson(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({
      method,
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      headers: body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {},
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function unitTests() {
  log('UNIT: crypto round-trip');
  await test('encrypt/decrypt round-trip', () => {
    const k = randomKey();
    const { ciphertext, nonce } = encrypt(k, 'hello, agents 🔐');
    const back = decrypt(k, ciphertext, nonce);
    if (back !== 'hello, agents 🔐') throw new Error('mismatch');
  });
  await test('wrong-key decrypt returns null', () => {
    const k1 = randomKey(); const k2 = randomKey();
    const { ciphertext, nonce } = encrypt(k1, 'secret');
    const back = decrypt(k2, ciphertext, nonce);
    if (back !== null) throw new Error('should have failed');
  });
  await test('ciphertext is not plaintext', () => {
    const k = randomKey();
    const { ciphertext } = encrypt(k, 'the plaintext signature here');
    const raw = Buffer.from(ciphertext, 'base64').toString('utf8');
    if (raw.includes('plaintext')) throw new Error('looks like plaintext leaked');
  });
}

async function serverTests() {
  log('SERVER: HTTP surface');
  await test('GET / returns landing HTML', async () => {
    const r = await httpJson('GET', `${BASE}/`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/SafeBot/.test(r.body)) throw new Error('missing marker');
  });
  await test('GET /docs returns docs HTML', async () => {
    const r = await httpJson('GET', `${BASE}/docs`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/gents\. HTTP\. Ciphertext\./.test(r.body)) throw new Error('missing docs marker');
  });
  await test('GET /sdk/safebot.py serves the SDK', async () => {
    const r = await httpJson('GET', `${BASE}/sdk/safebot.py`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/from safebot import Room|class Room/.test(r.body)) throw new Error('does not look like the SDK');
    if (r.body.length < 1000) throw new Error('SDK body suspiciously small: ' + r.body.length);
  });
  await test('GET /sdk/codex_safebot.py serves the Codex bootstrap', async () => {
    const r = await httpJson('GET', `${BASE}/sdk/codex_safebot.py`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/codex mcp add|claim_task|launch a fresh Codex session/.test(r.body)) throw new Error('does not look like the Codex bootstrap');
    if (r.body.length < 1000) throw new Error('bootstrap body suspiciously small: ' + r.body.length);
  });
  await test('GET /board serves the kanban page', async () => {
    const r = await httpJson('GET', `${BASE}/board`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/board-parser\.js|BoardParser\.parse/.test(r.body)) throw new Error('kanban page missing parser wiring');
  });
  await test('GET /docs/BOARD.md serves the raw markdown', async () => {
    const r = await httpJson('GET', `${BASE}/docs/BOARD.md`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/^##\s+(DOING|INCOMING|DONE)/m.test(r.body)) throw new Error('no recognisable board sections in body');
  });
  await test('GET /api/health returns ok', async () => {
    const r = await httpJson('GET', `${BASE}/api/health`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    const j = JSON.parse(r.body);
    if (!j.ok) throw new Error('not ok');
  });
  await test('GET /room/:id serves room HTML', async () => {
    const r = await httpJson('GET', `${BASE}/room/ABCD`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/chat-list/.test(r.body)) throw new Error('room page marker missing');
  });
  await test('POST bad body → 400', async () => {
    const r = await httpJson('POST', `${BASE}/api/rooms/ABCD/messages`, JSON.stringify({ sender: 'x' }));
    if (r.status !== 400) throw new Error('status ' + r.status);
  });
  await test('GET /api/openapi.json returns valid spec', async () => {
    const r = await httpJson('GET', `${BASE}/api/openapi.json`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    const j = JSON.parse(r.body);
    if (j.openapi !== '3.1.0') throw new Error('wrong openapi version');
    if (!j.paths['/api/rooms/{roomId}/wait']) throw new Error('missing /wait endpoint in spec');
    if (!j.paths['/api/rooms/{roomId}/transcript']) throw new Error('missing /transcript in spec');
  });
  await test('GET /api/docs renders swagger UI', async () => {
    const r = await httpJson('GET', `${BASE}/api/docs`);
    if (r.status !== 200) throw new Error('status ' + r.status);
    if (!/swagger-ui/.test(r.body)) throw new Error('swagger not present');
  });
  await test('Status / transcript / wait round-trip', async () => {
    const roomId = 'LPT' + Math.random().toString(36).slice(2, 6).toUpperCase();
    const key = randomKey();
    // Status: no messages yet (new room).
    const s1 = await httpJson('GET', `${BASE}/api/rooms/${roomId}/status`);
    if (s1.status !== 200) throw new Error('status code: ' + s1.status);
    // Post a message.
    const { ciphertext, nonce } = encrypt(key, 'hello via long-poll');
    const post = await httpJson('POST', `${BASE}/api/rooms/${roomId}/messages`, JSON.stringify({ sender: 'probe', ciphertext, nonce }));
    if (post.status !== 200) throw new Error('post status: ' + post.status);
    const postJ = JSON.parse(post.body);
    if (!postJ.seq || postJ.seq < 1) throw new Error('no seq on post response');
    // Transcript since 0 should include our message.
    const t = await httpJson('GET', `${BASE}/api/rooms/${roomId}/transcript?after=0&limit=10`);
    const tJ = JSON.parse(t.body);
    if (!tJ.messages || tJ.messages.length !== 1) throw new Error('transcript count: ' + tJ.messages.length);
    const back = decrypt(key, tJ.messages[0].ciphertext, tJ.messages[0].nonce);
    if (back !== 'hello via long-poll') throw new Error('decrypt fail: ' + back);
    // Wait(after=seq) should block then return empty when no new msg arrives.
    const waitStart = Date.now();
    const w = await httpJson('GET', `${BASE}/api/rooms/${roomId}/wait?after=${tJ.last_seq}&timeout=2`);
    const waitEnd = Date.now();
    const wJ = JSON.parse(w.body);
    if (wJ.messages.length !== 0) throw new Error('wait returned stale messages');
    const elapsed = (waitEnd - waitStart) / 1000;
    if (elapsed < 1.5) throw new Error('wait returned too early (' + elapsed + 's)');
  });
  await test('POST valid ciphertext + SSE delivers it', async () => {
    const roomId = 'TST' + Math.random().toString(36).slice(2, 6).toUpperCase();
    const key = randomKey();
    const { ciphertext, nonce } = encrypt(key, 'hello over sse');
    // open SSE first
    const received = [];
    const sse = http.request({
      method: 'GET',
      hostname: '127.0.0.1',
      port: PORT,
      path: `/api/rooms/${roomId}/events`,
      headers: { Accept: 'text/event-stream' },
    });
    const sseDone = new Promise((resolve, reject) => {
      sse.on('response', (res) => {
        res.setEncoding('utf8');
        let buf = '';
        res.on('data', (chunk) => {
          buf += chunk;
          let idx;
          while ((idx = buf.indexOf('\n\n')) !== -1) {
            const frame = buf.slice(0, idx).trim();
            buf = buf.slice(idx + 2);
            if (frame.startsWith('data:')) {
              try {
                const j = JSON.parse(frame.slice(5).trim());
                received.push(j);
                if (j.type === 'message') { res.destroy(); resolve(); }
              } catch (_) {}
            }
          }
        });
        res.on('end', resolve);
        res.on('error', reject);
      });
      sse.on('error', reject);
    });
    sse.end();
    await sleep(150);
    const post = await httpJson('POST', `${BASE}/api/rooms/${roomId}/messages`, JSON.stringify({ sender: 'tester', ciphertext, nonce }));
    if (post.status !== 200) throw new Error('post status ' + post.status);
    await Promise.race([sseDone, sleep(2500)]);
    const msg = received.find((e) => e.type === 'message');
    if (!msg) throw new Error('no message event received');
    const back = decrypt(key, msg.ciphertext, msg.nonce);
    if (back !== 'hello over sse') throw new Error('decrypt mismatch: ' + back);
  });
}

async function e2eTests() {
  log('E2E: Playwright — two browsers');
  const browser = await chromium.launch();
  try {
    const ctxA = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    const ctxB = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    const pageA = await ctxA.newPage();
    const pageB = await ctxB.newPage();

    // Capture console.
    const logs = [];
    pageA.on('console', (m) => logs.push('A:' + m.text()));
    pageB.on('console', (m) => logs.push('B:' + m.text()));

    await pageA.goto(`${BASE}/`);
    await pageA.click('#open-call-hero');
    await pageA.waitForURL(/\/room\/[A-Z0-9]{4,}#k=/, { timeout: 5000 });
    const url = pageA.url();

    // Wait for fingerprint to render (chat is already the main view — no toggle needed).
    await pageA.waitForSelector('#rail-fp');
    await pageA.waitForFunction(() => {
      const el = document.getElementById('rail-fp');
      return el && el.textContent && el.textContent.trim() !== '— — — —';
    }, null, { timeout: 5000 });
    const fpA = (await pageA.textContent('#rail-fp') || '').trim();

    await pageB.goto(url);
    await pageB.waitForSelector('#rail-fp');
    await pageB.waitForFunction(() => {
      const el = document.getElementById('rail-fp');
      return el && el.textContent && el.textContent.trim() !== '— — — —';
    }, null, { timeout: 5000 });
    const fpB = (await pageB.textContent('#rail-fp') || '').trim();
    if (fpA !== fpB) throw new Error('fingerprints differ: ' + fpA + ' vs ' + fpB);

    await pageA.fill('#message', 'hello from A');
    await pageA.press('#message', 'Enter');

    await pageB.waitForSelector('.bubble__body', { timeout: 5000 });
    const text = await pageB.textContent('.bubble__body');
    if (!/hello from A/.test(text)) throw new Error('B did not receive A plaintext: ' + text);

    await pageB.fill('#message', 'hey A, this is B');
    await pageB.press('#message', 'Enter');
    await pageA.waitForFunction(() => document.querySelectorAll('.bubble__body').length >= 2, null, { timeout: 5000 });
    const texts = await pageA.$$eval('.bubble__body', (els) => els.map((e) => e.textContent));
    if (!texts.some((t) => /hey A, this is B/.test(t))) throw new Error('A did not receive B: ' + texts.join(' | '));

    // Copy menu — open the consolidated Copy dropdown and pick "Invite link".
    // (Previously there were five individual copy-for-X buttons; they now
    // live inside #copy-menu, triggered from #copy-menu-btn.)
    await pageA.click('#copy-menu-btn');
    await pageA.waitForSelector('#copy-menu:not([hidden])', { timeout: 2000 });
    await pageA.click('#copy-menu [data-copy-kind="invite"]');
    try {
      await pageA.waitForFunction(() => {
        const t = document.getElementById('toast');
        return t && t.classList.contains('show');
      }, null, { timeout: 2500 });
    } catch (_) {
      throw new Error('copy invite toast did not appear');
    }

    // Participants: both senders should appear in the right-rail list.
    const partsA = await pageA.$$eval('.people__row', (els) => els.length);
    if (partsA < 2) throw new Error('expected >=2 people rows on page A, got ' + partsA);

    pass('two browsers exchange plaintext through ciphertext relay');
    pass('room fingerprint matches across browsers');

    await browser.close();
  } catch (e) {
    await browser.close();
    throw e;
  }
}

async function e2eRoomUIChecks() {
  log('E2E: landing + room visual checks');
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'], viewport: { width: 1360, height: 900 } });
    const page = await ctx.newPage();
    await page.goto(`${BASE}/`);
    await test('landing: hero headline present', async () => {
      const t = await page.textContent('h1');
      if (!/Private meetings/i.test(t)) throw new Error('headline missing');
    });
    await test('landing: room mockup present', async () => {
      const c = await page.$('.mockup');
      if (!c) throw new Error('mockup missing');
      const tiles = await page.$$('.mockup__tile');
      if (tiles.length < 4) throw new Error('expected >=4 mockup tiles, got ' + tiles.length);
    });
    await test('landing: feature cards render', async () => {
      const cards = await page.$$('.card');
      if (cards.length < 3) throw new Error('expected >=3 cards, got ' + cards.length);
    });
    await test('landing: copy-snippet button flashes OK', async () => {
      await page.click('.copy-btn');
      await page.waitForFunction(() => {
        const b = document.querySelector('.copy-btn');
        return b && /copied/i.test(b.textContent || '');
      }, null, { timeout: 1500 });
    });

    // Screenshots for QA agent
    const screensDir = path.join(ROOT, 'tests', 'screenshots');
    if (!fs.existsSync(screensDir)) fs.mkdirSync(screensDir, { recursive: true });
    await page.screenshot({ path: path.join(screensDir, 'landing.png'), fullPage: true });

    // Room screenshot
    await page.goto(`${BASE}/`);
    await page.click('#open-call-hero');
    await page.waitForSelector('#message');
    await page.fill('#message', 'The sealed room preserves its secrets.');
    await page.press('#message', 'Enter');
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(screensDir, 'room.png'), fullPage: false });

    await page.goto(`${BASE}/docs`);
    await page.waitForSelector('h1');
    await page.screenshot({ path: path.join(screensDir, 'docs.png'), fullPage: true });

    await browser.close();
  } catch (e) {
    await browser.close();
    throw e;
  }
}

async function pythonSdkTest() {
  log('PYTHON SDK: round-trip via Python client');
  const venvPython = path.join(ROOT, '.venv', 'bin', 'python3');
  if (!fs.existsSync(venvPython)) {
    log('  ! skipping (no .venv found)');
    return;
  }
  // create room in browser to get a key + id
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.goto(`${BASE}/`);
    await page.click('#open-call-hero');
    await page.waitForURL(/\/room\//);
    const url = page.url();

    // Chat is the main view now — no toggle needed.
    const cli = spawnSync(venvPython, [
      path.join(ROOT, 'sdk', 'safebot.py'),
      url,
      '--name', 'claude-opus',
      '--say', 'Hello from the Python SDK.',
    ], { cwd: ROOT, encoding: 'utf8' });

    if (cli.status !== 0) {
      throw new Error('Python SDK CLI failed:\n' + (cli.stderr || cli.stdout));
    }

    await page.waitForSelector('.bubble__body', { timeout: 5000 });
    const texts = await page.$$eval('.bubble__body', (els) => els.map((e) => e.textContent));
    if (!texts.some((t) => /Hello from the Python SDK/.test(t))) {
      throw new Error('browser did not receive SDK message: ' + texts.join(' | '));
    }
    await browser.close();
    pass('Python SDK ⇒ browser: message decrypted correctly');
  } catch (e) {
    await browser.close();
    throw e;
  }
}

function noLogsAudit() {
  log('AUDIT: server does not log/persist message bodies');
  const serverSrc = fs.readFileSync(path.join(ROOT, 'server', 'index.js'), 'utf8');
  const banned = [
    { re: /fs\.(write|writeFile|append|appendFile|createWriteStream)\s*\(/, why: 'filesystem write' },
    { re: /require\(['"]sqlite3?['"]\)|require\(['"]better-sqlite3['"]\)|require\(['"]mongodb['"]\)|require\(['"]redis['"]\)|require\(['"]pg['"]\)/, why: 'DB import' },
    { re: /console\.log[^\n]*(body|plaintext|message\.ciphertext|msg\.ciphertext)/, why: 'logs message body' },
  ];
  for (const b of banned) {
    if (b.re.test(serverSrc)) throw new Error('server contains banned pattern: ' + b.why + ' (' + b.re + ')');
  }
  pass('server source passes no-logs audit');
}

async function e2eReplyConvergence() {
  log('E2E: reply-ref child-before-parent convergence');
  const browser = await chromium.launch();
  try {
    const page = await (await browser.newContext()).newPage();
    const crypto = require('node:crypto');
    const rid = 'RPLCONV' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const key = crypto.randomBytes(32).toString('base64url').replace(/=+$/, '');
    await page.goto(`${BASE}/room/${rid}#k=${key}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => !!(window.__safebotTest && window.__safebotTest.renderMessage), null, { timeout: 10000 });

    const ghost = crypto.randomUUID();
    const childId = crypto.randomUUID();

    // Case 1 — child first, parent unknown.
    await page.evaluate(({ childId, ghost }) => {
      window.__safebotTest.renderMessage({
        id: childId, seq: 1001, sender: 'bob', ts: Date.now(),
        text: 'replied before parent known', reply_to: ghost,
      });
    }, { childId, ghost });
    let s = await page.evaluate((childId) => {
      const el = document.querySelector(`.bubble[data-msg-id="${CSS.escape(childId)}"] .bubble__reply-ref`);
      return {
        isDead: el ? el.classList.contains('is-dead') : null,
        label: el && el.querySelector('.bubble__reply-ref__label') ? el.querySelector('.bubble__reply-ref__label').textContent : null,
        previewText: el && el.querySelector('.bubble__reply-ref__preview') ? el.querySelector('.bubble__reply-ref__preview').textContent : null,
      };
    }, childId);
    if (s.isDead) throw new Error('unknown-parent ref must not be marked dead');
    if (!/earlier message/i.test(s.label || '')) throw new Error('unknown-parent label: ' + JSON.stringify(s));
    if (s.previewText) throw new Error('unknown-parent ref leaked cached text: ' + s.previewText);
    pass('reply-ref: unknown parent → generic placeholder, no cached text');

    // Case 2 — parent becomes known, ref upgrades.
    await page.evaluate((ghost) => {
      window.__safebotTest.rememberMessage(
        { id: ghost, seq: 1000, sender: 'alice', ts: Date.now() - 1000 },
        'the original parent message text',
      );
    }, ghost);
    s = await page.evaluate((childId) => {
      const el = document.querySelector(`.bubble[data-msg-id="${CSS.escape(childId)}"] .bubble__reply-ref`);
      return {
        label: el && el.querySelector('.bubble__reply-ref__label') ? el.querySelector('.bubble__reply-ref__label').textContent : null,
        previewText: el && el.querySelector('.bubble__reply-ref__preview') ? el.querySelector('.bubble__reply-ref__preview').textContent : null,
        isDead: el ? el.classList.contains('is-dead') : null,
      };
    }, childId);
    if (s.isDead) throw new Error('upgraded ref must not be marked dead');
    if (!/alice/i.test(s.label || '')) throw new Error('upgraded ref missing parent sender: ' + JSON.stringify(s));
    if (!/original parent message/.test(s.previewText || '')) throw new Error('upgraded ref missing snippet: ' + JSON.stringify(s));
    pass('reply-ref: parent becomes known → upgrade to sender + snippet');

    // Case 3 — parent deleted, ref converges to deleted placeholder.
    await page.evaluate((ghost) => window.__safebotTest.applyDelete(ghost, 1000), ghost);
    s = await page.evaluate((childId) => {
      const el = document.querySelector(`.bubble[data-msg-id="${CSS.escape(childId)}"] .bubble__reply-ref`);
      return {
        label: el && el.querySelector('.bubble__reply-ref__label') ? el.querySelector('.bubble__reply-ref__label').textContent : null,
        previewText: el && el.querySelector('.bubble__reply-ref__preview') ? el.querySelector('.bubble__reply-ref__preview').textContent : null,
        isDead: el ? el.classList.contains('is-dead') : null,
      };
    }, childId);
    if (!s.isDead) throw new Error('ref must be marked dead after parent delete');
    if (!/deleted/i.test(s.label || '')) throw new Error('dead label: ' + JSON.stringify(s));
    if (s.previewText) throw new Error('dead ref must drop cached preview: ' + s.previewText);
    pass('reply-ref: parent delete → "deleted message" placeholder, no cached text');

    await browser.close();
  } catch (e) {
    await browser.close();
    throw e;
  }
}

async function e2eReactionsV1() {
  log('E2E: reactions v1 — state + dead-target rule');
  const browser = await chromium.launch();
  try {
    const page = await (await browser.newContext()).newPage();
    const crypto = require('node:crypto');
    const rid = 'RXV1' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const key = crypto.randomBytes(32).toString('base64url').replace(/=+$/, '');
    await page.goto(`${BASE}/room/${rid}#k=${key}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => !!(window.__safebotTest_reactions), null, { timeout: 10000 });

    const parentId = crypto.randomUUID();
    // Render a parent bubble so the DOM has something to hang reactions on.
    await page.evaluate((id) => {
      window.__safebotTest.renderMessage({ id, seq: 1, sender: 'alice', ts: Date.now(), text: 'hello' });
    }, parentId);

    // 1. Add two distinct actors with the same emoji → count = 2, no dupes.
    await page.evaluate((id) => {
      const R = window.__safebotTest_reactions;
      R.applyReact(id, '👍', 'add', 'alice');
      R.applyReact(id, '👍', 'add', 'bob');
      R.applyReact(id, '👍', 'add', 'alice');        // idempotent add
    }, parentId);
    let s = await page.evaluate((id) => {
      const el = document.querySelector(`.bubble[data-msg-id="${CSS.escape(id)}"]`);
      const pills = el ? Array.from(el.querySelectorAll('.bubble__react-pill')) : [];
      return pills.map((p) => ({
        emoji: (p.querySelector('.bubble__react-emoji') || {}).textContent,
        count: (p.querySelector('.bubble__react-count') || {}).textContent,
      }));
    }, parentId);
    if (s.length !== 1 || s[0].emoji !== '👍' || s[0].count !== '2') {
      throw new Error('unexpected pills after two distinct actors: ' + JSON.stringify(s));
    }
    pass('reactions: two distinct actors → single pill, count=2, idempotent add');

    // 2. Remove one actor → count drops to 1.
    await page.evaluate((id) => window.__safebotTest_reactions.applyReact(id, '👍', 'remove', 'bob'), parentId);
    s = await page.evaluate((id) => {
      const el = document.querySelector(`.bubble[data-msg-id="${CSS.escape(id)}"]`);
      const pills = el ? Array.from(el.querySelectorAll('.bubble__react-pill')) : [];
      return pills.map((p) => ({
        emoji: (p.querySelector('.bubble__react-emoji') || {}).textContent,
        count: (p.querySelector('.bubble__react-count') || {}).textContent,
      }));
    }, parentId);
    if (s.length !== 1 || s[0].count !== '1') throw new Error('remove did not decrement: ' + JSON.stringify(s));
    pass('reactions: remove one actor → count=1');

    // 3. Delete the target → react aggregate drops AND a later react
    //    envelope for the same id is ignored (deletedIds dominates).
    await page.evaluate((id) => window.__safebotTest.applyDelete(id, 1), parentId);
    await page.evaluate((id) => window.__safebotTest_reactions.applyReact(id, '❤️', 'add', 'eve'), parentId);
    const post = await page.evaluate((id) => {
      const R = window.__safebotTest_reactions;
      return {
        mapHas: R.reactionsByMsgId.has(id),
        bubbleStillInDom: !!document.querySelector(`.bubble[data-msg-id="${CSS.escape(id)}"]`),
      };
    }, parentId);
    if (post.mapHas) throw new Error('deletedIds must dominate: react state lingered after delete');
    pass('reactions: delete-target prunes aggregate and rejects new reactions');

    // 4. Hydrate from hist-summary for an already-deleted target → rejected.
    await page.evaluate((id) => {
      window.__safebotTest_reactions.hydrateReactions(id, { '🔥': ['carol'] });
    }, parentId);
    const afterHydrate = await page.evaluate((id) =>
      window.__safebotTest_reactions.reactionsByMsgId.has(id), parentId);
    if (afterHydrate) throw new Error('hist-summary hydrate must not resurrect reactions for deleted target');
    pass('reactions: hist-summary hydrate drops aggregate for already-deleted target');

    await browser.close();
  } catch (e) {
    await browser.close();
    throw e;
  }
}

async function main() {
  await startServer();
  try {
    await unitTests();
    await serverTests();
    await e2eTests();
    await e2eRoomUIChecks();
    await e2eReplyConvergence();
    await e2eReactionsV1();
    await pythonSdkTest();
    noLogsAudit();
  } finally {
    await stopServer();
  }

  const failed = results.filter((r) => !r.ok);
  console.log('\n=============================');
  console.log(`Results: ${results.length - failed.length}/${results.length} passed`);
  if (failed.length) {
    console.log('FAILED:');
    for (const f of failed) console.log(' -', f.name, '\n   ', f.err.split('\n')[0]);
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error('test runner crashed:', e);
  stopServer().then(() => process.exit(1));
});
