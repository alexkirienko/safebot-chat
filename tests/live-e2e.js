// Live end-to-end smoke test against https://safebot.chat.
// - Open landing, click "New meeting" → confirm it lands on /room/ID#k=
// - Open the same URL in a second browser context
// - Exchange encrypted messages (A→B, B→A), confirm plaintext decrypts
// - Confirm WSS through Cloudflare works (presence/delivery)
// - Confirm copy-invite toast appears

const { chromium } = require('playwright');

const BASE = process.argv[2] || 'https://safebot.chat';

async function main() {
  const browser = await chromium.launch();
  const ctxA = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const ctxB = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const A = await ctxA.newPage();
  const B = await ctxB.newPage();

  const fails = [];
  const pass = (n) => console.log('  ✓', n);
  const fail = (n, e) => { fails.push({ n, e: String(e) }); console.log('  ✗', n, '\n   ', String(e).split('\n')[0]); };
  const step = async (n, fn) => { try { await fn(); pass(n); } catch (e) { fail(n, e); } };

  console.log('Live E2E against', BASE);

  await step('landing loads', async () => {
    const r = await A.goto(BASE, { waitUntil: 'domcontentloaded', timeout: 15000 });
    if (r.status() !== 200) throw new Error('status ' + r.status());
    if (!/Private meetings/i.test(await A.textContent('h1'))) throw new Error('wrong headline');
  });

  await step('"New meeting" button creates room URL', async () => {
    await A.click('#open-call-hero');
    await A.waitForURL(new RegExp(`${BASE.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}\\/room\\/[A-Z0-9]{4,}#k=`), { timeout: 10000 });
  });

  const roomUrl = A.url();
  console.log('    room URL:', roomUrl);

  await step('room loads + fingerprint renders', async () => {
    await A.waitForSelector('#rail-fp');
    const fp = (await A.textContent('#rail-fp') || '').trim();
    if (!fp || fp === '— — — —') throw new Error('fingerprint empty');
  });

  await step('WSS status shows "End-to-end encrypted"', async () => {
    await A.waitForFunction(() => {
      const l = document.getElementById('status-label');
      return l && /encrypted/i.test(l.textContent || '');
    }, null, { timeout: 10000 });
  });

  await step('second browser joins same URL', async () => {
    await B.goto(roomUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
    await B.waitForSelector('#rail-fp');
    const fpA = (await A.textContent('#rail-fp') || '').trim();
    const fpB = (await B.textContent('#rail-fp') || '').trim();
    if (fpA !== fpB) throw new Error('fingerprint mismatch: ' + fpA + ' / ' + fpB);
  });

  await step('composer visible on both', async () => {
    // Chat-first layout has no dock button; the composer is always visible.
    await A.waitForSelector('#message', { timeout: 10000 });
    await B.waitForSelector('#message', { timeout: 10000 });
  });

  await step('A → B: plaintext travels through ciphertext relay', async () => {
    await A.fill('#message', 'hello B, over tunnel');
    await A.press('#message', 'Enter');
    await B.waitForSelector('.bubble__body', { timeout: 8000 });
    const t = await B.textContent('.bubble__body');
    if (!/hello B, over tunnel/.test(t)) throw new Error('B got: ' + t);
  });

  await step('B → A: reply round-trip', async () => {
    await B.fill('#message', 'received, A — tunnel works');
    await B.press('#message', 'Enter');
    await A.waitForFunction(() => document.querySelectorAll('.bubble__body').length >= 2, null, { timeout: 8000 });
    const texts = await A.$$eval('.bubble__body', (els) => els.map((e) => e.textContent));
    if (!texts.some((t) => /received, A/.test(t))) throw new Error('A missing reply: ' + texts.join(' | '));
  });

  await step('copy-invite toast appears', async () => {
    await A.click('#copy-join');
    await A.waitForFunction(() => {
      const t = document.getElementById('toast');
      return t && t.classList.contains('show');
    }, null, { timeout: 3000 });
  });

  await step('participants rail lists ≥ 2 people', async () => {
    // Chat-first UI shows participants in .people__row rows on the right rail.
    const n = await A.$$eval('.people__row', (els) => els.length);
    if (n < 2) throw new Error('only ' + n + ' participant rows');
  });

  await step('docs loads + all section anchors resolve', async () => {
    const P = await browser.newPage();
    const r = await P.goto(`${BASE}/docs`, { waitUntil: 'domcontentloaded', timeout: 15000 });
    if (r.status() !== 200) throw new Error('status ' + r.status());
    for (const id of ['urls', 'endpoints', 'sdk', 'privacy', 'limits', 'threat']) {
      const ok = await P.evaluate((x) => !!document.getElementById(x), id);
      if (!ok) throw new Error('missing #' + id);
    }
    await P.close();
  });

  await browser.close();
  console.log('\n' + (fails.length ? `FAILED: ${fails.length}` : 'All live E2E checks passed.'));
  if (fails.length) process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(2); });
