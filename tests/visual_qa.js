// Visual QA sweep for reply/reactions UI.
//
// Seeds a synthetic room with the representative states that the
// product actually ships, across three viewports (mobile / tablet /
// desktop). Dumps screenshots to /tmp/visual_qa_safebot/ AND
// programmatically asserts a set of cheap-to-check visual invariants:
//
//   - no horizontal overflow on the chat list at any viewport
//   - reply-preview text doesn't overflow the bubble
//   - reaction picker, when open, stays within viewport bounds
//   - pill contents render (non-zero bounding rect, visible text)
//   - focus-visible styling is reachable via keyboard
//
// Intended as an on-demand pass, not wired into `node tests/run.js`
// which is for the green/red CI loop. Run after product changes touch
// the room UI and read the JSON report that's written alongside the
// screenshots.

const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const BASE = process.env.SAFEBOT_BASE || 'https://safebot.chat';
const OUT_DIR = '/tmp/visual_qa_safebot';

const VIEWPORTS = [
  // hasTouch=true forces @media (hover: none) matching on the emulated
  // device so we actually exercise the mobile-UX CSS branch.
  { name: 'mobile',  width: 375,  height: 780, hasTouch: true },
  { name: 'tablet',  width: 768,  height: 1024, hasTouch: true },
  { name: 'desktop', width: 1440, height: 900 },
];

function ensureDir(p) {
  try { fs.mkdirSync(p, { recursive: true }); } catch (_) {}
}

async function seedRoom(page) {
  // Inject a realistic message set through the debug hook so the UI
  // renders without us having to drive two browsers.
  await page.evaluate(() => {
    const T = window.__safebotTest;
    const R = window.__safebotTest_reactions;
    const now = Date.now();
    const rootId = 'vqa-root';
    T.renderMessage({ id: rootId, seq: 1, sender: 'alice', ts: now - 120000, text: 'Short root message. 👋' });

    const longParentId = 'vqa-long-parent';
    T.renderMessage({ id: longParentId, seq: 2, sender: 'bob', ts: now - 100000,
      text: 'Long parent message: ' + 'x'.repeat(500) });

    const replyLongId = 'vqa-reply-long';
    T.renderMessage({ id: replyLongId, seq: 3, sender: 'carol', ts: now - 90000,
      text: 'Replying to the long parent', reply_to: longParentId });

    // Deep chain
    const chainA = 'vqa-chain-a';
    const chainB = 'vqa-chain-b';
    const chainC = 'vqa-chain-c';
    T.renderMessage({ id: chainA, seq: 4, sender: 'alice', ts: now - 70000, text: 'Thread starter' });
    T.renderMessage({ id: chainB, seq: 5, sender: 'bob',   ts: now - 60000, text: 'reply 1', reply_to: chainA });
    T.renderMessage({ id: chainC, seq: 6, sender: 'carol', ts: now - 50000, text: 'reply 2 (nested)', reply_to: chainB });

    // Deleted parent → child shows placeholder
    const delParent = 'vqa-del-parent';
    T.renderMessage({ id: delParent, seq: 7, sender: 'dave', ts: now - 40000, text: 'Will be deleted' });
    const delChild = 'vqa-del-child';
    T.renderMessage({ id: delChild, seq: 8, sender: 'eve', ts: now - 30000,
      text: 'Reply to deleted message', reply_to: delParent });
    T.applyDelete(delParent, 7);

    // Reactions: preset + custom text + many actors
    const rxId = 'vqa-rx';
    T.renderMessage({ id: rxId, seq: 9, sender: 'alice', ts: now - 20000, text: 'Message with reactions' });
    for (const a of ['alice', 'bob', 'carol']) R.applyReact(rxId, '👍', 'add', a);
    R.applyReact(rxId, '❤️', 'add', 'dave');
    R.applyReact(rxId, '🎉', 'add', 'eve');
    R.applyReact(rxId, 'ship', 'add', 'frank');
    for (const a of ['a','b','c','d','e','f','g']) R.applyReact(rxId, '😮', 'add', a);

    // TTL badge bubble (non-expired)
    const ttlId = 'vqa-ttl';
    T.renderMessage({ id: ttlId, seq: 10, sender: 'alice', ts: now, text: 'Disappearing soon',
      ttl_ms: 5 * 60 * 1000 });
  });
  // Give the layout a frame to settle + reactions row to paint.
  await page.waitForTimeout(200);
}

async function invariants(page, vp) {
  const findings = [];
  // 1. No horizontal overflow on the chat list at this viewport.
  const overflow = await page.evaluate(() => {
    const list = document.querySelector('#chat-list, .chat__list');
    if (!list) return { reason: 'no chat list' };
    return { scroll: list.scrollWidth, client: list.clientWidth };
  });
  if (overflow && overflow.scroll > overflow.client + 2) {
    findings.push({ severity: 'major', area: 'layout', viewport: vp.name,
      what: `chat list has horizontal overflow (scroll ${overflow.scroll} > client ${overflow.client})` });
  }

  // 2. Reply-preview VISUALLY doesn't bleed past its bubble. `scroll
  //    > client` alone doesn't mean a bug — ellipsis intentionally
  //    clips oversized content — so we check the rendered bounding
  //    rectangle of the preview against the containing bubble. A
  //    properly-ellipsized preview stays within the bubble's right
  //    edge even when the underlying content is longer.
  const replyOverflow = await page.evaluate(() => {
    const bad = [];
    for (const ref of document.querySelectorAll('.bubble__reply-ref')) {
      const prev = ref.querySelector('.bubble__reply-ref__preview');
      const bub = ref.closest('.bubble');
      if (!prev || !bub) continue;
      const pr = prev.getBoundingClientRect();
      const br = bub.getBoundingClientRect();
      // Allow a tiny sub-pixel tolerance.
      if (pr.right > br.right + 2) {
        bad.push({
          msgId: bub.dataset.msgId,
          previewRight: Math.round(pr.right),
          bubbleRight: Math.round(br.right),
        });
      }
    }
    return bad;
  });
  for (const b of replyOverflow) {
    findings.push({ severity: 'minor', area: 'reply-preview', viewport: vp.name,
      what: `preview bleeds past bubble right edge in ${b.msgId} (${b.previewRight} > ${b.bubbleRight})` });
  }

  // 3. Picker stays within viewport when opened. Open the picker on
  //    the reactions-test bubble and check bounding rect.
  await page.evaluate(() => {
    const el = document.querySelector('.bubble[data-msg-id="vqa-rx"] .bubble__react-btn');
    if (el) el.click();
  });
  await page.waitForTimeout(100);
  const clip = await page.evaluate(() => {
    const pick = document.querySelector('.bubble[data-msg-id="vqa-rx"] .bubble__react-picker');
    if (!pick) return { present: false };
    const r = pick.getBoundingClientRect();
    return {
      present: true,
      top: r.top, bottom: r.bottom, left: r.left, right: r.right,
      vw: window.innerWidth, vh: window.innerHeight,
    };
  });
  if (clip.present) {
    if (clip.top < 0 || clip.bottom > clip.vh) {
      findings.push({ severity: 'major', area: 'reaction-picker', viewport: vp.name,
        what: `picker clipped vertically: top=${clip.top}, bottom=${clip.bottom}, vh=${clip.vh}` });
    }
    if (clip.left < 0 || clip.right > clip.vw) {
      findings.push({ severity: 'major', area: 'reaction-picker', viewport: vp.name,
        what: `picker clipped horizontally: left=${clip.left}, right=${clip.right}, vw=${clip.vw}` });
    }
  } else {
    findings.push({ severity: 'minor', area: 'reaction-picker', viewport: vp.name,
      what: 'picker never opened on vqa-rx bubble' });
  }

  // 4. Pill contents visible — each .bubble__react-pill has non-zero
  //    width and the emoji + count spans have non-empty text.
  const emptyPills = await page.evaluate(() => {
    const bad = [];
    for (const p of document.querySelectorAll('.bubble__react-pill')) {
      const r = p.getBoundingClientRect();
      const emoji = p.querySelector('.bubble__react-emoji');
      const count = p.querySelector('.bubble__react-count');
      if (r.width < 8 || r.height < 8 || !emoji || !count
          || !(emoji.textContent || '').length || !(count.textContent || '').length) {
        bad.push({ w: r.width, h: r.height, emoji: emoji && emoji.textContent, count: count && count.textContent });
      }
    }
    return bad;
  });
  for (const b of emptyPills) {
    findings.push({ severity: 'minor', area: 'reaction-pill', viewport: vp.name,
      what: `pill hidden or empty: ${JSON.stringify(b)}` });
  }

  // 5. Focus outline is reachable on pill / react-btn / reply-btn.
  //    Keyboard Tab through the first few focusable nodes and check
  //    one of these shows a non-zero outlineWidth / boxShadow beyond
  //    the default. This is a weak check — we just confirm focus-
  //    visible styles produce SOME visible indicator.
  await page.keyboard.press('Escape'); // dismiss any open popover first
  await page.waitForTimeout(50);
  const focusProbe = await page.evaluate(() => {
    // Focus the first reaction pill if any.
    const pill = document.querySelector('.bubble__react-pill');
    if (!pill) return { tested: false };
    pill.focus();
    const cs = window.getComputedStyle(pill);
    return {
      tested: true,
      outlineWidth: cs.outlineWidth,
      outlineStyle: cs.outlineStyle,
      boxShadow: cs.boxShadow,
    };
  });
  if (focusProbe.tested && focusProbe.outlineStyle === 'none' && focusProbe.boxShadow === 'none') {
    findings.push({ severity: 'minor', area: 'focus', viewport: vp.name,
      what: 'reaction pill has no visible focus indicator (no outline AND no box-shadow)' });
  }

  // 6. Composer idle state — no empty `.replying-pill` strip visible
  //    when replyingTo is null. The pill uses display:flex at rule
  //    level, which previously overrode [hidden]{display:none}; the
  //    fix forces display:none via [hidden] override. Any regression
  //    would show a ~22px dark strip under the namechip — catch it
  //    by asserting computed display is 'none' on a fresh page.
  const pillIdle = await page.evaluate(() => {
    const pill = document.getElementById('replying-pill');
    if (!pill) return { reason: 'absent' };
    const cs = window.getComputedStyle(pill);
    const r = pill.getBoundingClientRect();
    return {
      hidden: pill.hidden,
      display: cs.display,
      h: r.height,
    };
  });
  if (pillIdle && pillIdle.hidden && pillIdle.display !== 'none') {
    findings.push({
      severity: 'major', area: 'composer-idle', viewport: vp.name,
      what: `empty .replying-pill is rendered even though hidden=true (display=${pillIdle.display}, height=${pillIdle.h}) — leaves a visible strip between namechip and message input`,
    });
  }

  return findings;
}

async function invariants_touchActions(page, vp) {
  // On touch viewports (hover:none), the × / ↩ / 😀 action icons on a
  // bubble must be visible without a hover event — operators tap, they
  // don't point. Desktop keeps the hover-reveal pattern.
  if (!vp.hasTouch) return [];
  const findings = [];
  const invis = await page.evaluate(() => {
    const bad = [];
    const sels = ['.bubble__del', '.bubble__reply-btn', '.bubble__react-btn'];
    for (const sel of sels) {
      const el = document.querySelector(`.bubble[data-msg-id="vqa-rx"] ${sel}`);
      if (!el) { bad.push({ sel, reason: 'absent' }); continue; }
      const op = parseFloat(window.getComputedStyle(el).opacity || '0');
      if (op < 0.5) bad.push({ sel, opacity: op });
    }
    return bad;
  });
  for (const b of invis) {
    findings.push({ severity: 'major', area: 'mobile-ux', viewport: vp.name,
      what: `touch-viewport bubble action ${b.sel} is hidden (${JSON.stringify(b)})` });
  }
  return findings;
}

async function main() {
  ensureDir(OUT_DIR);
  const report = { base: BASE, timestamp: new Date().toISOString(), viewports: [] };
  const browser = await chromium.launch();
  try {
    const roomId = 'VQA' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const key = crypto.randomBytes(32).toString('base64url').replace(/=+$/, '');
    const url = `${BASE}/room/${roomId}#k=${key}`;
    for (const vp of VIEWPORTS) {
      const ctx = await browser.newContext({
        viewport: { width: vp.width, height: vp.height },
        hasTouch: !!vp.hasTouch,
        isMobile: !!vp.hasTouch,
      });
      const page = await ctx.newPage();
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await page.waitForFunction(() => !!window.__safebotTest_reactions, null, { timeout: 10000 });
      await seedRoom(page);
      const findings = [
        ...(await invariants(page, vp)),
        ...(await invariants_touchActions(page, vp)),
      ];
      const shotPath = path.join(OUT_DIR, `vqa-${vp.name}.png`);
      await page.screenshot({ path: shotPath, fullPage: true });
      console.log(`  ✓ ${vp.name}  ${vp.width}x${vp.height}  screenshot → ${shotPath}  findings:${findings.length}`);
      for (const f of findings) console.log('    -', f.severity, f.area, '-', f.what);
      report.viewports.push({ viewport: vp, findings, screenshot: shotPath });
      await ctx.close();
    }
  } finally {
    await browser.close();
  }
  const reportPath = path.join(OUT_DIR, 'report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  const total = report.viewports.reduce((n, v) => n + v.findings.length, 0);
  console.log(`\nVisual QA complete. ${total} finding(s). Report: ${reportPath}`);
  process.exit(total > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
