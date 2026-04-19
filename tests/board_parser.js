// Regression tests for public/js/board-parser.js.
//
// Three buckets per codex-reviewer's acceptance criteria:
//   1. mixed / invalid board syntax => parser returns empty, page falls back.
//   2. allowed vs blocked links in mdInlineToHtml (http/https/relative vs
//      javascript:/data:/mailto:).
//   3. expected card count on the live BOARD.md fixture.
//
// Run:  node tests/board_parser.js

const path = require('path');
const fs = require('fs');

const { parse, mdInlineToHtml } = require(path.join(__dirname, '..', 'public', 'js', 'board-parser.js'));

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log('  ✓', name); passed++; }
  catch (e) { console.log('  ✗', name); console.log('     ', e.message); failed++; }
}
function eq(a, b, msg) { if (a !== b) throw new Error(`${msg || ''} expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); }

// ---------- 1. parser fail-safe on malformed markdown ----------

test('empty string parses to 0 cards in every column', () => {
  const b = parse('');
  eq(b.doing.length, 0); eq(b.incoming.length, 0); eq(b.done.length, 0);
});

test('no ## headers anywhere → all items dropped, 0 cards', () => {
  const md = '# title\n\n- a lonely bullet\n- another one\n';
  const b = parse(md);
  eq(b.doing.length + b.incoming.length + b.done.length, 0);
});

test('wrong column names (## TODO, ## Progress) → 0 cards', () => {
  const md = '## TODO\n- foo\n## Progress\n- bar\n';
  const b = parse(md);
  eq(b.doing.length + b.incoming.length + b.done.length, 0);
});

test('bullets only under real ## DOING land in doing', () => {
  const md = '## DOING\n- alpha\n- beta\n';
  const b = parse(md);
  eq(b.doing.length, 2);
  eq(b.doing[0].body, 'alpha');
  eq(b.doing[1].body, 'beta');
});

test('### Pn subheader attaches priority to following INCOMING cards', () => {
  const md = [
    '## INCOMING',
    '### P0 — urgent',
    '- first p0',
    '- second p0',
    '### P1 — nice',
    '- first p1',
  ].join('\n');
  const b = parse(md);
  eq(b.incoming.length, 3);
  eq(b.incoming[0].pri, 'P0');
  eq(b.incoming[1].pri, 'P0');
  eq(b.incoming[2].pri, 'P1');
});

test('bullet continuation lines join onto the previous card', () => {
  const md = [
    '## DONE',
    '- first line',
    '  continues with more',
    '- second card',
  ].join('\n');
  const b = parse(md);
  eq(b.done.length, 2);
  eq(b.done[0].body, 'first line continues with more');
  eq(b.done[1].body, 'second card');
});

test('italic _placeholder_ is treated as a single-line card', () => {
  const md = '## DOING\n_Nothing active right now._\n';
  const b = parse(md);
  eq(b.doing.length, 1);
  eq(b.doing[0].body, 'Nothing active right now.');
});

// ---------- 2. mdInlineToHtml XSS hardening ----------

test('raw HTML tags are escaped, not rendered', () => {
  const out = mdInlineToHtml('<script>alert(1)</script>');
  if (out.includes('<script>')) throw new Error('raw <script> passed through: ' + out);
  if (!out.includes('&lt;script&gt;')) throw new Error('< not escaped: ' + out);
});

test('double-quote is escaped so href context cannot break out', () => {
  const out = mdInlineToHtml('a "b" c');
  if (!out.includes('&quot;')) throw new Error('" not escaped: ' + out);
});

test('**bold** becomes <strong>', () => {
  const out = mdInlineToHtml('**hi**');
  if (!/<strong>hi<\/strong>/.test(out)) throw new Error('bold not rendered: ' + out);
});

test('`code` becomes <code>', () => {
  const out = mdInlineToHtml('`x`');
  if (!/<code>x<\/code>/.test(out)) throw new Error('code not rendered: ' + out);
});

test('https:// link is allowed and produces <a href>', () => {
  const out = mdInlineToHtml('see [docs](https://example.com/x)');
  if (!/<a href="https:\/\/example\.com\/x" rel="noopener">docs<\/a>/.test(out))
    throw new Error('https link not emitted: ' + out);
});

test('http:// link is allowed and produces <a href>', () => {
  const out = mdInlineToHtml('see [local](http://127.0.0.1:8080)');
  if (!/<a href="http:\/\/127\.0\.0\.1:8080"/.test(out))
    throw new Error('http link not emitted: ' + out);
});

test('site-relative link ("/board") is allowed', () => {
  const out = mdInlineToHtml('see [here](/board)');
  if (!/<a href="\/board" rel="noopener">here<\/a>/.test(out))
    throw new Error('relative link not emitted: ' + out);
});

test('javascript: link is NOT rendered as <a> (XSS vector blocked)', () => {
  const out = mdInlineToHtml('[click](javascript:alert(1))');
  if (out.includes('<a '))       throw new Error('javascript: link leaked through: ' + out);
  if (out.includes('javascript:')) throw new Error('javascript: string still in output: ' + out);
  if (!out.includes('click'))    throw new Error('link text dropped: ' + out);
});

test('data: link is NOT rendered as <a>', () => {
  const out = mdInlineToHtml('[x](data:text/html,<script>1</script>)');
  if (out.includes('<a '))  throw new Error('data: link leaked: ' + out);
  if (out.includes('data:')) throw new Error('data: string leaked: ' + out);
});

test('mailto: link is NOT rendered as <a>', () => {
  const out = mdInlineToHtml('[mail](mailto:hi@example.com)');
  if (out.includes('<a ')) throw new Error('mailto: link leaked: ' + out);
});

test('bare < > inside link text are escaped, not rendered', () => {
  const out = mdInlineToHtml('[<b>x</b>](https://ex.com)');
  if (out.includes('<b>')) throw new Error('link text rendered as HTML: ' + out);
});

// ---------- 2b. sawSections drives partial-breakage fail-safe ----------

test('sawSections contains DOING/INCOMING/DONE when all three headers present', () => {
  const md = '## DOING\n- a\n## INCOMING\n- b\n## DONE\n- c\n';
  const b = parse(md);
  if (!b.sawSections.has('DOING'))    throw new Error('DOING missing from sawSections');
  if (!b.sawSections.has('INCOMING')) throw new Error('INCOMING missing');
  if (!b.sawSections.has('DONE'))     throw new Error('DONE missing');
});

test('partial breakage (## DOING renamed to ## TODO) leaves DOING out of sawSections', () => {
  // This is the exact scenario codex-reviewer caught: one header mutates,
  // the other two columns render fine, but the board shape silently lost
  // a section. fail-safe must fire off sawSections, not total card count.
  const md = '## TODO\n- lost card\n## INCOMING\n- still here\n## DONE\n- still here\n';
  const b = parse(md);
  if (b.sawSections.has('DOING')) throw new Error('DOING should NOT be in sawSections');
  if (!b.sawSections.has('TODO')) throw new Error('TODO header was not recorded');
  // Parser still returns the non-DOING cards intact.
  eq(b.doing.length, 0);
  eq(b.incoming.length, 1);
  eq(b.done.length, 1);
});

test('sawSections records case-normalized first word of each ## header', () => {
  const md = '## Process notes\n- foo\n## some-random-thing\n- bar\n';
  const b = parse(md);
  if (!b.sawSections.has('PROCESS')) throw new Error('Process not normalized: ' + [...b.sawSections]);
  if (!b.sawSections.has('SOME-RANDOM-THING')) throw new Error('some-random-thing missing: ' + [...b.sawSections]);
});

// ---------- 3. live BOARD.md fixture: expected shape ----------

test('live docs/BOARD.md parses to the expected column counts', () => {
  const md = fs.readFileSync(path.join(__dirname, '..', 'docs', 'BOARD.md'), 'utf8');
  const b = parse(md);
  if (b.doing.length === 0)     throw new Error('DOING column is empty');
  if (b.incoming.length === 0)  throw new Error('INCOMING column is empty');
  if (b.done.length === 0)      throw new Error('DONE column is empty');
  // Every INCOMING card should have a P0..P3 priority chip.
  for (const c of b.incoming) {
    if (!/^P[0-3]$/.test(c.pri || ''))
      throw new Error(`INCOMING card without priority: ${JSON.stringify(c)}`);
  }
  // At least the CI item must be present (the first thing we plan to ship next).
  if (!b.incoming.some((c) => /CI on push/i.test(c.body)))
    throw new Error('CI card missing from INCOMING');
});

console.log(`\n${passed}/${passed + failed} passed`);
process.exit(failed === 0 ? 0 : 1);
