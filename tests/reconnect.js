// Reconnect resilience: simulate a browser that loses its WS connection
// during a conversation and verify that on re-open it catches up via the
// replay buffer (up to RECENT_MAX messages).

const { chromium } = require('playwright');
const crypto = require('crypto');
const nacl = require('tweetnacl');

const BASE = process.argv[2] || 'https://safebot.chat';

(async () => {
  const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const roomId = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
  const keyBytes = nacl.randomBytes(32);
  const keyB64u = Buffer.from(keyBytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const roomUrl = `${BASE}/room/${roomId}#k=${keyB64u}`;

  const browser = await chromium.launch();
  const a = await browser.newPage();
  const b = await browser.newPage();

  await a.goto(roomUrl);
  await b.goto(roomUrl);
  await a.waitForFunction(() => /encrypted/i.test((document.getElementById('status-label') || {}).textContent || ''), { timeout: 10000 });
  await b.waitForFunction(() => /encrypted/i.test((document.getElementById('status-label') || {}).textContent || ''), { timeout: 10000 });

  console.log('both pages online; closing B...');
  await b.context().setOffline(true);
  await new Promise((r) => setTimeout(r, 1500));

  // A sends 3 messages while B is offline.
  for (let i = 0; i < 3; i++) {
    await a.evaluate((i) => {
      const ta = document.getElementById('message');
      const form = document.getElementById('composer');
      ta.value = `offline-era-${i}`;
      form.requestSubmit();
    }, i);
    await new Promise((r) => setTimeout(r, 200));
  }

  console.log('bringing B back online...');
  await b.context().setOffline(false);

  // Wait until B receives at least 3 bubbles.
  await b.waitForFunction(() => document.querySelectorAll('.bubble__body').length >= 3, null, { timeout: 12000 });
  const texts = await b.$$eval('.bubble__body', (els) => els.map((e) => e.textContent));
  const missing = [0, 1, 2].filter((i) => !texts.some((t) => t.includes(`offline-era-${i}`)));
  if (missing.length) { console.log('✗ missing messages after reconnect:', missing); process.exit(1); }
  console.log('✓ B caught up via replay buffer — all 3 offline-era messages received');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
