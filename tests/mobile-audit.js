// Mobile audit — renders landing/docs/room across real phone/tablet viewports,
// takes screenshots, and runs basic interaction checks. Reports layout bugs
// (overflow, clipped buttons, unclickable elements, off-screen content).

const { chromium, devices } = require('playwright');
const fs = require('fs');
const path = require('path');

const BASE = process.argv[2] || 'https://safebot.chat';
const OUT = path.join(__dirname, 'screenshots', 'mobile');
if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, { recursive: true });

const PROFILES = [
  { name: 'iphone-se',   device: devices['iPhone SE'] },            // 375×667
  { name: 'iphone-14',   device: devices['iPhone 14'] },            // 390×844
  { name: 'pixel-7',     device: devices['Pixel 7'] },              // 412×915
  { name: 'ipad',        device: devices['iPad (gen 7)'] },         // 810×1080
  { name: 'galaxy-fold', viewport: { width: 280, height: 653 }, userAgent: devices['Pixel 5'].userAgent, deviceScaleFactor: 3, isMobile: true, hasTouch: true },
];

const bugs = [];
function flag(profile, page, msg, details) {
  bugs.push({ profile, page, msg, details });
  console.log(`  ✗ [${profile}/${page}] ${msg}` + (details ? `  — ${details}` : ''));
}
function pass(profile, page, msg) { console.log(`  ✓ [${profile}/${page}] ${msg}`); }

async function auditPage(browser, profile, path, name) {
  const ctx = profile.device
    ? await browser.newContext({ ...profile.device })
    : await browser.newContext({ viewport: profile.viewport, userAgent: profile.userAgent, deviceScaleFactor: profile.deviceScaleFactor, isMobile: profile.isMobile, hasTouch: profile.hasTouch });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(String(e)));

  try {
    const r = await page.goto(BASE + path, { waitUntil: 'domcontentloaded', timeout: 20000 });
    if (!r || r.status() !== 200) { flag(profile.name, name, 'non-200 response', r && r.status()); return; }
  } catch (e) {
    flag(profile.name, name, 'navigation failed', e.message); await ctx.close(); return;
  }
  await page.waitForTimeout(700);

  // Horizontal overflow check — no page should scroll sideways on mobile.
  const overflow = await page.evaluate(() => {
    const dw = document.documentElement.scrollWidth;
    const vw = window.innerWidth;
    return { dw, vw, overflow: dw - vw };
  });
  if (overflow.overflow > 2) {
    flag(profile.name, name, 'horizontal overflow', `scrollWidth=${overflow.dw} vw=${overflow.vw} excess=${overflow.overflow}px`);
  } else {
    pass(profile.name, name, `no horizontal overflow`);
  }

  // Every visible <button>/<a> must fit inside the viewport.
  const offscreen = await page.evaluate(() => {
    const out = [];
    const vw = window.innerWidth;
    for (const el of document.querySelectorAll('button, a')) {
      const s = getComputedStyle(el);
      if (s.display === 'none' || s.visibility === 'hidden') continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      if (r.left < -2 || r.right > vw + 2) {
        out.push({
          id: el.id || '', cls: (el.className || '').toString().slice(0, 40),
          tag: el.tagName, text: (el.textContent || '').trim().slice(0, 24),
          left: Math.round(r.left), right: Math.round(r.right), vw,
        });
      }
    }
    return out;
  });
  if (offscreen.length) {
    flag(profile.name, name, 'clipped buttons/links', JSON.stringify(offscreen.slice(0, 5)));
  } else {
    pass(profile.name, name, 'all buttons/links within viewport');
  }

  // JS errors on load?
  if (errs.length) flag(profile.name, name, 'page errors', errs.slice(0, 2).join(' | '));

  // Tap target sizes — any interactive element smaller than 36×36 on mobile is a warning.
  if (profile.name !== 'ipad') {
    const tiny = await page.evaluate(() => {
      const out = [];
      for (const el of document.querySelectorAll('button, a, input, textarea, [role=button]')) {
        const s = getComputedStyle(el);
        if (s.display === 'none' || s.visibility === 'hidden') continue;
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;
        if (r.width < 30 || r.height < 30) {
          out.push({ id: el.id || '', cls: (el.className || '').toString().slice(0, 30), w: Math.round(r.width), h: Math.round(r.height), text: (el.textContent || '').trim().slice(0, 20) });
        }
      }
      return out;
    });
    if (tiny.length) {
      flag(profile.name, name, 'tiny tap targets (<30px)', JSON.stringify(tiny.slice(0, 5)));
    }
  }

  await page.screenshot({ path: path_(`${profile.name}-${name}.png`), fullPage: false });
  await ctx.close();
}

function path_(f) { return path.join(OUT, f); }

async function main() {
  const browser = await chromium.launch();
  console.log('Mobile audit against', BASE);
  for (const prof of PROFILES) {
    console.log(`\n━━ ${prof.name} ${prof.device ? `(${prof.device.viewport.width}×${prof.device.viewport.height})` : `(${prof.viewport.width}×${prof.viewport.height})`}`);
    await auditPage(browser, prof, '/', 'landing');
    await auditPage(browser, prof, '/docs', 'docs');
    // Fresh room URL for each device so we can screenshot the initial invite state.
    const crypto = require('crypto');
    const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const roomId = Array.from(crypto.randomBytes(6), (b) => alpha[b % alpha.length]).join('');
    const key = crypto.randomBytes(32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    await auditPage(browser, prof, `/room/${roomId}#k=${key}`, 'room');
  }
  await browser.close();

  console.log(`\n━━━ ${bugs.length} issue(s) found`);
  if (bugs.length) {
    for (const b of bugs) console.log(`  · [${b.profile}/${b.page}] ${b.msg}${b.details ? '  — ' + b.details : ''}`);
    process.exit(1);
  }
  console.log('All mobile checks clean.');
}

main().catch((e) => { console.error(e); process.exit(2); });
