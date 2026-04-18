// Landing interactions — "New meeting" routing + copy-snippet button.
(function () {
  'use strict';

  function randomRoomId() {
    const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const buf = new Uint8Array(10);
    crypto.getRandomValues(buf);
    let s = '';
    for (let i = 0; i < buf.length; i++) s += alpha[buf[i] % alpha.length];
    return s;
  }
  function randomKeyBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }
  function toB64Url(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function openCall(ev) {
    ev && ev.preventDefault();
    const id = randomRoomId();
    const key = randomKeyBytes(32);
    const keyB64u = toB64Url(key);
    location.href = `/room/${id}#k=${keyB64u}`;
  }

  for (const id of ['open-call-nav', 'open-call-hero', 'open-call-footer', 'open-call-band']) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', openCall);
  }

  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.getAttribute('data-copy') || '');
        const orig = btn.textContent;
        btn.textContent = 'Copied';
        btn.classList.add('ok');
        setTimeout(() => {
          btn.textContent = orig || 'Copy';
          btn.classList.remove('ok');
        }, 1200);
      } catch (_) { /* no-op */ }
    });
  });

  // Subtle rotating "speaking" highlight in the mockup.
  const tiles = document.querySelectorAll('.mockup__tile');
  if (tiles.length > 1) {
    let i = 0;
    setInterval(() => {
      tiles.forEach((t) => t.classList.remove('mockup__tile--speaking'));
      i = (i + 1) % tiles.length;
      tiles[i].classList.add('mockup__tile--speaking');
    }, 2200);
  }
})();
