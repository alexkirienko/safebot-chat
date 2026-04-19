// Board markdown parser + XSS-safe inline renderer.
// Pure functions, no DOM. Exposed both as a browser global (BoardParser)
// and as a CommonJS module so tests/board_parser.js can require it.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.BoardParser = factory();
}(typeof self !== 'undefined' ? self : this, function () {

  // Parse BOARD.md shape into {doing:[], incoming:[{pri,body}], done:[]}.
  // Recognises `## DOING | ## INCOMING | ## DONE` as columns, `### P0..P3`
  // as priority subheaders inside INCOMING, and either `-`/`*`/`N.` bullets
  // or italic `_…_` placeholders as cards. Bullet continuation lines join
  // onto the previous card until the next bullet or header.
  function parse(md) {
    const lines = md.split('\n');
    const out = { doing: [], incoming: [], done: [] };
    let section = null;
    let pri = null;
    let current = null;
    const push = (item) => {
      const body = item.body.trim();
      if (!body) return;
      if (section === 'DOING') out.doing.push({ body });
      else if (section === 'INCOMING') out.incoming.push({ body, pri: item.pri || pri || '' });
      else if (section === 'DONE') out.done.push({ body });
    };
    const flush = () => { if (current) { push(current); current = null; } };

    for (const raw of lines) {
      const line = raw.replace(/\s+$/, '');
      if (/^## DOING\b/.test(line)) { flush(); section = 'DOING'; pri = null; continue; }
      if (/^## INCOMING\b/.test(line)) { flush(); section = 'INCOMING'; pri = null; continue; }
      if (/^## DONE\b/.test(line)) { flush(); section = 'DONE'; pri = null; continue; }
      if (/^## /.test(line)) { flush(); section = null; pri = null; continue; }
      if (!section) continue;

      const h3 = line.match(/^###\s+(P[0-3])\b/);
      if (h3) { flush(); pri = h3[1]; continue; }
      if (/^### /.test(line)) { flush(); continue; }

      const bullet = line.match(/^\s*(?:[-*]|\d+\.)\s+(.+)$/);
      if (bullet) {
        flush();
        current = { body: bullet[1], pri: pri };
        continue;
      }

      if (/^_.+_$/.test(line)) {
        flush();
        current = { body: line.replace(/^_|_$/g, ''), pri: null };
        flush();
        continue;
      }

      if (current && line.trim()) {
        current.body += ' ' + line.trim();
      } else {
        flush();
      }
    }
    flush();
    return out;
  }

  // Escape everything first, then lift **bold**, `code`, and narrowly
  // permit [text](url) only where url starts with http://, https:// or
  // site-relative "/". Anything else (javascript:, data:, mailto:, etc.)
  // is rendered as plain text so a malicious BOARD.md cannot inject an
  // href attribute we haven't vetted.
  function mdInlineToHtml(s) {
    const esc = (x) => x
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    let h = esc(s);
    h = h.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
    h = h.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, txt, url) => {
      if (!/^(https?:\/\/|\/)/.test(url)) return txt;
      return '<a href="' + url + '" rel="noopener">' + txt + '</a>';
    });
    return h;
  }

  return { parse: parse, mdInlineToHtml: mdInlineToHtml };
}));
