// Floating "Report a bug" button + modal. Appears on every page that sources
// this script. POSTs to /api/report; the server handles logging + alerting.
(function () {
  'use strict';

  const STYLES = `
    .bug-fab {
      position: fixed; right: 18px; bottom: 18px; z-index: 60;
      display: inline-flex; align-items: center; gap: 8px;
      padding: 10px 14px; border-radius: 999px;
      background: var(--surface, #fff); color: var(--text, #0D1020);
      border: 1px solid var(--border, #E4E7EF);
      font: 500 13px/1 'Geist', system-ui, sans-serif;
      box-shadow: 0 10px 28px -14px rgba(10,12,24,0.28), 0 2px 4px rgba(10,12,24,0.06);
      cursor: pointer; transition: transform .1s ease, border-color .15s ease;
    }
    .bug-fab:hover { border-color: var(--border-2, #CFD4E0); }
    .bug-fab:active { transform: translateY(1px); }
    .bug-fab .glyph { font-size: 14px; }
    .bug-modal { position: fixed; inset: 0; z-index: 100; display: none; align-items: flex-end; justify-content: center; background: rgba(10,12,24,0.45); padding: 20px; }
    .bug-modal.show { display: flex; }
    .bug-card {
      width: min(520px, 100%); background: var(--surface, #fff); color: var(--text, #0D1020);
      border-radius: 18px; padding: 24px 24px 18px;
      box-shadow: 0 40px 80px -30px rgba(10,12,24,0.45);
      animation: bug-slide .22s cubic-bezier(.25,.8,.25,1);
    }
    @keyframes bug-slide { from { opacity: 0; transform: translateY(18px); } to { opacity: 1; transform: none; } }
    .bug-card h3 { margin: 0 0 6px; font-size: 20px; letter-spacing: -0.015em; font-weight: 700; }
    .bug-card p { margin: 0 0 14px; font-size: 13.5px; color: var(--text-2, #4B5266); }
    .bug-card label { display: block; font-size: 12px; font-weight: 600; color: var(--text-2, #4B5266); margin: 10px 0 4px; }
    .bug-card textarea, .bug-card input, .bug-card select {
      width: 100%; box-sizing: border-box;
      font: 14px/1.45 'Geist', system-ui, sans-serif;
      border: 1px solid var(--border, #E4E7EF); border-radius: 10px;
      padding: 10px 12px; outline: none; background: var(--bg-2, #F6F7FB); color: inherit;
    }
    .bug-card textarea { min-height: 100px; resize: vertical; }
    .bug-card textarea:focus, .bug-card input:focus, .bug-card select:focus { border-color: var(--primary, #6D7CFF); background: var(--surface, #fff); }
    .bug-card .row { display: flex; gap: 10px; }
    .bug-card .row > * { flex: 1; }
    .bug-card .actions { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-top: 14px; }
    .bug-card .hint { font-size: 11.5px; color: var(--text-3, #7B8196); }
    .bug-card .submit { background: var(--primary, #6D7CFF); color: #fff; border: 0; padding: 10px 16px; border-radius: 999px; font-weight: 600; cursor: pointer; font-size: 14px; }
    .bug-card .submit:disabled { opacity: .6; cursor: not-allowed; }
    .bug-card .cancel { background: transparent; border: 0; color: var(--text-2, #4B5266); cursor: pointer; font-size: 13px; }
    .bug-card .done { color: var(--ok, #22C55E); font-weight: 600; padding: 20px 0; text-align: center; }
    @media (max-width: 520px) { .bug-fab { bottom: 12px; right: 12px; padding: 10px 12px; } }
  `;

  const style = document.createElement('style'); style.textContent = STYLES; document.head.appendChild(style);

  const fab = document.createElement('button');
  fab.className = 'bug-fab';
  fab.type = 'button';
  fab.innerHTML = '<span class="glyph">🐛</span><span>Report a bug</span>';
  document.body.appendChild(fab);

  const modal = document.createElement('div');
  modal.className = 'bug-modal';
  modal.innerHTML = `
    <div class="bug-card" role="dialog" aria-label="Report a bug">
      <h3>Found something off?</h3>
      <p>Describe what happened and hit Send. It goes straight to the maintainer.</p>
      <form id="bug-form">
        <label for="bug-what">What went wrong</label>
        <textarea id="bug-what" name="what" minlength="5" maxlength="4000" required placeholder="Describe the behaviour you observed and what you expected."></textarea>

        <div class="row">
          <div>
            <label for="bug-severity">Severity</label>
            <select id="bug-severity" name="severity">
              <option value="low">Low</option>
              <option value="medium" selected>Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div>
            <label for="bug-where">Where (URL / endpoint — optional)</label>
            <input id="bug-where" name="where" maxlength="500" placeholder="/docs/agents" />
          </div>
        </div>

        <label for="bug-contact">Contact (optional)</label>
        <input id="bug-contact" name="contact" maxlength="200" placeholder="email / telegram / @handle" />

        <div class="actions">
          <span class="hint">Also available via <code>POST /api/report</code>.</span>
          <div>
            <button type="button" class="cancel" data-close>Cancel</button>
            <button type="submit" class="submit">Send report</button>
          </div>
        </div>
        <div id="bug-done" class="done" style="display:none"></div>
      </form>
    </div>`;
  document.body.appendChild(modal);

  const form = modal.querySelector('#bug-form');
  const doneEl = modal.querySelector('#bug-done');
  const submit = modal.querySelector('.submit');

  function open() { modal.classList.add('show'); setTimeout(() => modal.querySelector('#bug-what').focus(), 100); }
  function close() { modal.classList.remove('show'); doneEl.style.display = 'none'; form.style.display = ''; form.reset(); submit.disabled = false; }

  fab.addEventListener('click', open);
  modal.addEventListener('click', (e) => { if (e.target === modal || e.target.matches('[data-close]')) close(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('show')) close(); });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    submit.disabled = true;
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    // Extra context the user doesn't have to type: current URL, user-agent.
    payload.context = `page=${location.href}\nua=${navigator.userAgent}`;
    try {
      const res = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        form.style.display = 'none';
        doneEl.style.display = 'block';
        doneEl.textContent = `✓ Thanks — report ${String(data.id || '').slice(0, 8)} received.`;
        setTimeout(close, 2200);
      } else {
        doneEl.style.display = 'block';
        doneEl.style.color = 'var(--danger, #EF4444)';
        doneEl.textContent = data.error ? `Error: ${data.error}` : `Error ${res.status}. Please retry.`;
        submit.disabled = false;
      }
    } catch (err) {
      doneEl.style.display = 'block';
      doneEl.style.color = 'var(--danger, #EF4444)';
      doneEl.textContent = 'Network error. Please retry.';
      submit.disabled = false;
    }
  });
})();
