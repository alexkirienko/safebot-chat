// Contact form modal. Triggered by any [data-open-contact] click (the
// footer Contact link). POSTs to /api/contact, which forwards to the
// operator's Telegram — no MX / SMTP / mailto required.
(function () {
  'use strict';

  const STYLES = `
    .contact-modal { position: fixed; inset: 0; z-index: 110; display: none; align-items: flex-end; justify-content: center; background: rgba(10,12,24,0.45); padding: 20px; }
    .contact-modal.show { display: flex; }
    .contact-card {
      width: min(480px, 100%); background: var(--surface, #fff); color: var(--text, #0D1020);
      border-radius: 18px; padding: 24px 24px 18px;
      box-shadow: 0 40px 80px -30px rgba(10,12,24,0.45);
      animation: contact-slide .22s cubic-bezier(.25,.8,.25,1);
    }
    @keyframes contact-slide { from { opacity: 0; transform: translateY(18px); } to { opacity: 1; transform: none; } }
    .contact-card h3 { margin: 0 0 6px; font-size: 20px; font-weight: 700; letter-spacing: -0.015em; }
    .contact-card p { margin: 0 0 14px; font-size: 13.5px; color: var(--text-2, #4B5266); }
    .contact-card label { display: block; font-size: 12px; font-weight: 600; color: var(--text-2, #4B5266); margin: 10px 0 4px; }
    .contact-card textarea, .contact-card input {
      width: 100%; box-sizing: border-box;
      font: 14px/1.45 'Geist', system-ui, sans-serif;
      border: 1px solid var(--border, #E4E7EF); border-radius: 10px;
      padding: 10px 12px; outline: none; background: var(--bg-2, #F6F7FB); color: inherit;
    }
    .contact-card textarea { min-height: 110px; resize: vertical; }
    .contact-card textarea:focus, .contact-card input:focus { border-color: var(--primary, #6D7CFF); background: var(--surface, #fff); }
    .contact-card .row { display: flex; gap: 10px; }
    .contact-card .row > * { flex: 1; }
    .contact-card .actions { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-top: 14px; }
    .contact-card .hint { font-size: 11.5px; color: var(--text-3, #7B8196); }
    .contact-card .submit { background: var(--primary, #6D7CFF); color: #fff; border: 0; padding: 10px 16px; border-radius: 999px; font-weight: 600; cursor: pointer; font-size: 14px; }
    .contact-card .submit:disabled { opacity: .6; cursor: not-allowed; }
    .contact-card .cancel { background: transparent; border: 0; color: var(--text-2, #4B5266); cursor: pointer; font-size: 13px; }
    .contact-card .done { color: var(--ok, #22C55E); font-weight: 600; padding: 20px 0; text-align: center; }
  `;
  const style = document.createElement('style'); style.textContent = STYLES; document.head.appendChild(style);

  const modal = document.createElement('div');
  modal.className = 'contact-modal';
  modal.innerHTML = `
    <div class="contact-card" role="dialog" aria-label="Contact">
      <h3>Get in touch</h3>
      <p>Message goes straight to the maintainer via Telegram. No email, no tracking.</p>
      <form id="contact-form">
        <label for="contact-message">Message</label>
        <textarea id="contact-message" name="message" minlength="3" maxlength="4000" required placeholder="Feedback, question, or just hello."></textarea>
        <div class="row">
          <div>
            <label for="contact-name">Name (optional)</label>
            <input id="contact-name" name="name" maxlength="200" />
          </div>
          <div>
            <label for="contact-email">Email (optional, for reply)</label>
            <input id="contact-email" name="email" type="email" maxlength="200" />
          </div>
        </div>
        <div class="actions">
          <span class="hint">Rate-limited. Also available via <code>POST /api/contact</code>.</span>
          <div>
            <button type="button" class="cancel" data-close>Cancel</button>
            <button type="submit" class="submit">Send</button>
          </div>
        </div>
        <div id="contact-done" class="done" style="display:none"></div>
      </form>
    </div>`;
  document.body.appendChild(modal);

  const form = modal.querySelector('#contact-form');
  const doneEl = modal.querySelector('#contact-done');
  const submit = modal.querySelector('.submit');

  function open() { modal.classList.add('show'); setTimeout(() => modal.querySelector('#contact-message').focus(), 100); }
  function close() { modal.classList.remove('show'); doneEl.style.display = 'none'; doneEl.style.color = ''; form.style.display = ''; form.reset(); submit.disabled = false; }

  document.addEventListener('click', (e) => {
    const trigger = e.target.closest('[data-open-contact]');
    if (trigger) { e.preventDefault(); open(); return; }
    if (e.target === modal || e.target.matches('[data-close]')) close();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('show')) close(); });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    submit.disabled = true;
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    try {
      const res = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        form.style.display = 'none';
        doneEl.style.display = 'block';
        doneEl.textContent = `✓ Thanks — message delivered (${String(data.id || '').slice(0, 8)}).`;
        setTimeout(close, 2000);
      } else {
        doneEl.style.display = 'block';
        doneEl.style.color = 'var(--danger, #EF4444)';
        doneEl.textContent = data.error ? `Error: ${data.error}` : `Error ${res.status}. Please retry.`;
        submit.disabled = false;
      }
    } catch (_) {
      doneEl.style.display = 'block';
      doneEl.style.color = 'var(--danger, #EF4444)';
      doneEl.textContent = 'Network error. Please retry.';
      submit.disabled = false;
    }
  });
})();
