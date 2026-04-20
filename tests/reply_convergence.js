// Browser regression for the child-before-parent reply-ref convergence
// case (codex-qa major on 206cf63).
//
// When a reply arrives before its target is known — which happens in
// practice when peer-history responses land in a different order than
// the original send order — the reply bubble must render a generic
// placeholder. Later, when the parent becomes known via a subsequent
// rememberMessage() call, the reply-ref must upgrade to show the real
// sender + snippet. Without the upgrade path, the reply stays
// permanently degraded.
//
// Runs against a live SafeBot instance (defaults to localhost:3123,
// override with SAFEBOT_BASE). Uses the `window.__safebotTest` debug
// namespace exposed from sdk/public/js/room.js to drive the UI under
// test without going through the real WS path.

const { chromium } = require('playwright');
const crypto = require('node:crypto');

const BASE = process.env.SAFEBOT_BASE || 'http://127.0.0.1:3123';

function rid() {
  return 'RPLCONV' + crypto.randomBytes(3).toString('hex').toUpperCase();
}
function keyFragment() {
  return crypto.randomBytes(32).toString('base64url').replace(/=+$/, '');
}

async function main() {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errs = [];
  const fail = (msg, e) => { errs.push(msg); console.log('  ✗', msg, e ? ('— ' + e.message) : ''); };
  const ok = (msg) => console.log('  ✓', msg);

  const roomUrl = `${BASE}/room/${rid()}#k=${keyFragment()}`;
  await page.goto(roomUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
  // Let room.js finish its async IDB + WS setup so __safebotTest is installed.
  await page.waitForFunction(() => !!(window.__safebotTest && window.__safebotTest.renderMessage), null, { timeout: 10000 });

  // 1. Inject a reply bubble BEFORE the parent is known.
  const ghost = crypto.randomUUID();
  const childId = crypto.randomUUID();
  await page.evaluate(({ childId, ghost }) => {
    window.__safebotTest.renderMessage({
      id: childId, seq: 1001, sender: 'bob', ts: Date.now(),
      text: 'replied before parent known', reply_to: ghost,
    });
  }, { childId, ghost });

  let refState = await page.evaluate((childId) => {
    const bubble = document.querySelector(`.bubble[data-msg-id="${CSS.escape(childId)}"]`);
    const ref = bubble && bubble.querySelector('.bubble__reply-ref');
    return {
      present: !!ref,
      isDead: ref ? ref.classList.contains('is-dead') : null,
      label: ref ? (ref.querySelector('.bubble__reply-ref__label') || {}).textContent : null,
      previewText: ref && ref.querySelector('.bubble__reply-ref__preview') ? ref.querySelector('.bubble__reply-ref__preview').textContent : null,
    };
  }, childId);

  if (!refState.present) fail('child reply-ref rendered');
  else if (refState.isDead) fail('child reply-ref should NOT be marked dead when parent is simply unknown');
  else if (!/earlier message/i.test(refState.label || '')) fail('unknown-parent placeholder label', new Error('got ' + JSON.stringify(refState)));
  else if (refState.previewText) fail('unknown-parent must not show any cached preview text');
  else ok('child reply rendered with "replying to an earlier message" placeholder before parent known');

  // 2. Now tell the client the parent exists. rememberMessage must
  //    trigger refreshReplyRefsPointingAt(parent.id) so the live ref
  //    upgrades to show real sender + snippet.
  await page.evaluate((ghost) => {
    window.__safebotTest.rememberMessage(
      { id: ghost, seq: 1000, sender: 'alice', ts: Date.now() - 1000 },
      'the original parent message text',
    );
  }, ghost);

  refState = await page.evaluate((childId) => {
    const bubble = document.querySelector(`.bubble[data-msg-id="${CSS.escape(childId)}"]`);
    const ref = bubble && bubble.querySelector('.bubble__reply-ref');
    return {
      label: ref && ref.querySelector('.bubble__reply-ref__label') ? ref.querySelector('.bubble__reply-ref__label').textContent : null,
      previewText: ref && ref.querySelector('.bubble__reply-ref__preview') ? ref.querySelector('.bubble__reply-ref__preview').textContent : null,
      isDead: ref ? ref.classList.contains('is-dead') : null,
    };
  }, childId);

  if (refState.isDead) fail('upgraded ref must not be marked dead');
  else if (!/@?alice|replying to alice/i.test(refState.label || '')) fail('upgraded ref should name the parent sender', new Error('got ' + JSON.stringify(refState)));
  else if (!/original parent message/.test(refState.previewText || '')) fail('upgraded ref should carry the parent snippet', new Error('got ' + JSON.stringify(refState)));
  else ok('child reply-ref upgraded to show parent sender + snippet after rememberMessage');

  // 3. Now delete the parent. The ref must converge on the deleted
  //    placeholder — no cached plaintext left on the child.
  await page.evaluate((ghost) => {
    window.__safebotTest.applyDelete(ghost, 1000);
  }, ghost);

  refState = await page.evaluate((childId) => {
    const bubble = document.querySelector(`.bubble[data-msg-id="${CSS.escape(childId)}"]`);
    const ref = bubble && bubble.querySelector('.bubble__reply-ref');
    return {
      label: ref && ref.querySelector('.bubble__reply-ref__label') ? ref.querySelector('.bubble__reply-ref__label').textContent : null,
      previewText: ref && ref.querySelector('.bubble__reply-ref__preview') ? ref.querySelector('.bubble__reply-ref__preview').textContent : null,
      isDead: ref ? ref.classList.contains('is-dead') : null,
    };
  }, childId);

  if (!refState.isDead) fail('ref must be marked dead after parent delete');
  else if (!/deleted/i.test(refState.label || '')) fail('dead-ref label should say "deleted message"', new Error('got ' + JSON.stringify(refState)));
  else if (refState.previewText) fail('dead ref must not keep showing cached plaintext preview');
  else ok('parent delete converges the ref on the "deleted message" placeholder with no cached text');

  await browser.close();
  if (errs.length) { console.log('\n' + errs.length + ' failure(s)'); process.exit(1); }
  console.log('\n3/3 passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
