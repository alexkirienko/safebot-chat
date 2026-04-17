// Link auditor — crawls SafeBot.Chat pages, extracts every href/src,
// and verifies each reaches its target. Runs against the live site.
//
// Usage: node tests/links.js [base-url]   (default: https://safebot.chat)

const { chromium } = require('playwright');

const BASE = process.argv[2] || 'https://safebot.chat';
const INTERNAL_HOSTS = new Set([new URL(BASE).host]);
const SKIP_EXTERNAL_HOSTS = new Set(['github.com']); // respond with 403/429 to HEAD sometimes
const TIMEOUT_MS = 10000;

const results = [];
function record(page, kind, target, status, note = '') {
  results.push({ page, kind, target, status, note });
}

async function httpCheck(url) {
  try {
    const res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (res.status === 405 || res.status === 403) {
      // Some endpoints reject HEAD; retry with GET.
      const g = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(TIMEOUT_MS) });
      return g.status;
    }
    return res.status;
  } catch (e) {
    return `ERR ${String(e.message || e).slice(0, 80)}`;
  }
}

async function crawl(pageName, url, browser) {
  console.log(`\n━━ ${pageName}  ${url}`);
  const page = await browser.newPage();
  const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT_MS });
  const status = resp ? resp.status() : 'no-response';
  record(pageName, 'page', url, status);
  if (status !== 200) { await page.close(); return; }

  // Wait for JS to settle (the mockup animation, decrypt anim, etc.).
  await page.waitForTimeout(600);

  // Collect: hrefs on <a>, srcs on <script>/<img>, hrefs on <link>.
  const refs = await page.evaluate(() => {
    const out = [];
    for (const a of document.querySelectorAll('a[href]')) out.push({ tag: 'a', url: a.getAttribute('href'), text: (a.textContent || '').trim().slice(0, 40) });
    for (const s of document.querySelectorAll('script[src]')) out.push({ tag: 'script', url: s.getAttribute('src') });
    for (const l of document.querySelectorAll('link[href]')) {
      // preconnect/dns-prefetch targets the host for TCP warmup, not a fetchable resource.
      const rel = (l.getAttribute('rel') || '').toLowerCase();
      if (rel.includes('preconnect') || rel.includes('dns-prefetch')) continue;
      out.push({ tag: 'link', url: l.getAttribute('href') });
    }
    for (const i of document.querySelectorAll('img[src]')) out.push({ tag: 'img', url: i.getAttribute('src') });
    return out;
  });

  // Also collect in-page anchor IDs so we can check #frag targets.
  const localIds = new Set(await page.$$eval('[id]', (els) => els.map((e) => e.id)));

  for (const r of refs) {
    const raw = r.url;
    if (!raw) continue;
    if (raw.startsWith('data:') || raw.startsWith('javascript:')) continue;

    if (raw.startsWith('mailto:')) {
      record(pageName, r.tag, raw, 'mailto', r.text || '');
      continue;
    }

    if (raw.startsWith('#')) {
      const id = raw.slice(1);
      if (!id) { record(pageName, r.tag, raw, 200, 'empty fragment'); continue; }
      if (localIds.has(id)) record(pageName, r.tag, raw, 200, 'anchor ok');
      else record(pageName, r.tag, raw, 'MISSING', `no element with id="${id}"`);
      continue;
    }

    // Resolve relative to page URL.
    let u;
    try { u = new URL(raw, url); } catch (_) { record(pageName, r.tag, raw, 'ERR', 'bad url'); continue; }

    // Internal fragment on a same-page link would be normalized to same path.
    if (u.origin === new URL(url).origin && u.pathname === new URL(url).pathname && u.hash) {
      const id = u.hash.slice(1);
      if (localIds.has(id)) record(pageName, r.tag, raw, 200, 'anchor ok');
      else record(pageName, r.tag, raw, 'MISSING', `no element with id="${id}"`);
      continue;
    }

    // Skip sites known to 4xx HEAD.
    if (SKIP_EXTERNAL_HOSTS.has(u.host)) {
      record(pageName, r.tag, raw, 'SKIPPED', 'external (not checked)');
      continue;
    }

    const code = await httpCheck(u.toString());
    record(pageName, r.tag, raw, code, r.text || '');
  }

  await page.close();
}

(async () => {
  const browser = await chromium.launch();

  await crawl('landing', `${BASE}/`, browser);
  await crawl('docs', `${BASE}/docs`, browser);

  // Room: make a realistic key so the page fully loads (not the bail branch).
  const nacl = require('tweetnacl');
  const b64u = Buffer.from(nacl.randomBytes(32)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await crawl('room', `${BASE}/room/AUDITR#k=${b64u}`, browser);

  await browser.close();

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Results:');
  const byStatus = {};
  for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  const fail = results.filter((r) => {
    if (typeof r.status === 'number') return r.status >= 400;
    return ['MISSING', 'no-response'].includes(r.status) || String(r.status).startsWith('ERR');
  });

  for (const r of results) {
    const mark = fail.includes(r) ? '✗' : '✓';
    const tag = String(r.tag || '').padEnd(6);
    const stat = String(r.status == null ? '?' : r.status).padEnd(8);
    console.log(`  ${mark} [${r.page}] ${tag} ${stat} ${r.target}${r.note ? '  — ' + r.note : ''}`);
  }

  console.log('\nBy status:', byStatus);
  if (fail.length) {
    console.log(`\nFAILURES (${fail.length}):`);
    for (const r of fail) console.log(`  - [${r.page}] ${r.target} → ${r.status}  ${r.note}`);
    process.exit(1);
  }
  console.log('\nAll links OK.');
})().catch((e) => { console.error(e); process.exit(2); });
