// SafeBot.Chat room client — chat-first layout, right-side participants rail.
// The room key is parsed from location.hash (#k=<base64url>) and never sent.
(function () {
  'use strict';

  const C = window.SafeBotCrypto;
  if (!C) {
    document.body.innerHTML = '<div style="padding:40px;color:#EF4444">Crypto library failed to load. Please refresh.</div>';
    return;
  }

  const pathMatch = location.pathname.match(/^\/room\/([A-Za-z0-9_-]+)/);
  const roomId = pathMatch ? pathMatch[1] : '';
  const hash = location.hash.replace(/^#/, '');
  const params = new URLSearchParams(hash);
  const keyB64u = params.get('k');
  if (!roomId || !keyB64u) {
    document.body.innerHTML = '<div style="padding:60px;max-width:600px;margin:0 auto;color:#F2F4FA;background:#0B0D14;min-height:100vh"><h2 style="font-size:40px;margin:0 0 16px;font-weight:700">No room key.</h2><p style="color:#AFB6CA">This meeting link is missing its key fragment. Ask whoever shared it to resend the full URL.</p><p style="margin-top:24px"><a href="/" style="color:#6D7CFF">← back to SafeBot.Chat</a></p></div>';
    return;
  }

  let key;
  try {
    key = C.b64urlDecode(keyB64u);
    if (key.length !== 32) throw new Error('bad key length');
  } catch (e) {
    document.body.innerHTML = '<div style="padding:60px;color:#F2F4FA;background:#0B0D14;min-height:100vh">Invalid room key fragment.</div>';
    return;
  }

  // --- Identity + palette ------------------------------------------------
  const PALETTES = [
    ['#4F46E5', '#8B5CF6'],
    ['#0EA5E9', '#22D3EE'],
    ['#EC4899', '#F43F5E'],
    ['#10B981', '#34D399'],
    ['#F59E0B', '#FB923C'],
    ['#6366F1', '#22D3EE'],
    ['#EF4444', '#F472B6'],
    ['#14B8A6', '#84CC16'],
    ['#8B5CF6', '#EC4899'],
    ['#3B82F6', '#14B8A6'],
  ];
  function hashStr(s) {
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
    return h >>> 0;
  }
  function paletteFor(name) { return PALETTES[hashStr(name) % PALETTES.length]; }
  function initialsFor(name) {
    const clean = (name || '').replace(/[^A-Za-z0-9 ]/g, ' ').trim();
    const parts = clean.split(/\s+|[-_]+/).filter(Boolean);
    if (!parts.length) return '??';
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }

  const NAME_WORDS = ['oak', 'fern', 'ivy', 'cedar', 'linen', 'slate', 'amber', 'cobalt', 'moss', 'birch', 'hazel', 'flint', 'clover', 'sable'];
  let me = sessionStorage.getItem('safebot:name');
  if (!me) {
    const word = NAME_WORDS[Math.floor(Math.random() * NAME_WORDS.length)];
    const tag = Math.floor(Math.random() * 900 + 100).toString(36).toUpperCase();
    me = `visitor-${word}-${tag}`;
    sessionStorage.setItem('safebot:name', me);
  }

  // --- DOM refs ----------------------------------------------------------
  const roomMainEl = document.getElementById('room-main');
  const chatListEl = document.getElementById('chat-list');
  const stageEmptyEl = document.getElementById('stage-empty');
  const metaCountEl = document.getElementById('meta-count');
  const metaDurationEl = document.getElementById('meta-duration');
  const rollIdEl = document.getElementById('rail-room-id');
  const fpEl = document.getElementById('rail-fp');
  const messageEl = document.getElementById('message');
  const nameInputEl = document.getElementById('namechip');
  const composerEl = document.getElementById('composer');
  const chatHintEl = document.getElementById('chat-hint');
  const statusPill = document.getElementById('status-pill');
  const statusLabel = document.getElementById('status-label');
  const peopleList = document.getElementById('people-list');
  const peopleCountEl = document.getElementById('people-count');
  const railPeopleToggle = document.getElementById('rail-people-toggle');
  const topbarPeopleBtn = document.getElementById('topbar-people');
  const copyJoinBtn = document.getElementById('copy-join');
  const copyAgentTopBtn = document.getElementById('copy-agent-top');
  const copyJoinEmptyBtn = document.getElementById('copy-join-empty');
  const copyEndpointEmptyBtn = document.getElementById('copy-endpoint-empty');
  const copyAgentSnippetBtn = document.getElementById('copy-agent-snippet');
  const toastEl = document.getElementById('toast');
  const toastText = document.getElementById('toast-text');
  const inviteUrlEl = document.getElementById('invite-url');
  const inviteUrlText = document.getElementById('invite-url-text');
  const inviteUrlHint = document.getElementById('invite-url-hint');
  const inviteFpEl = document.getElementById('invite-fp');
  const inviteEndpointCode = document.getElementById('invite-endpoint-code');

  rollIdEl.textContent = `Meeting · ${roomId}`;
  document.title = `SafeBot.Chat — ${roomId}`;
  nameInputEl.value = me;
  nameInputEl.addEventListener('change', () => {
    const v = (nameInputEl.value || '').trim().slice(0, 48) || me;
    me = v; nameInputEl.value = me;
    sessionStorage.setItem('safebot:name', me);
    seenNames.set(me, Date.now());
    renderPeople();
  });

  C.fingerprint(key).then((fp) => {
    const formatted = fp.match(/.{1,4}/g).join(' ');
    fpEl.textContent = formatted;
    if (inviteFpEl) inviteFpEl.textContent = formatted;
  });

  if (inviteUrlText) inviteUrlText.textContent = location.href;

  // --- Endpoint snippet inside the "Advanced" accordion -----------------
  const apiBase = `${location.origin}/api/rooms/${roomId}`;
  if (inviteEndpointCode) {
    inviteEndpointCode.textContent =
      `POST ${apiBase}/messages              # send (ciphertext JSON)
GET  ${apiBase}/transcript?after=0    # pull history
GET  ${apiBase}/wait?after=N&timeout=30  # long-poll
GET  ${apiBase}/events                 # SSE stream
key  share #k=… separately (URL fragment never reaches the server)`;
  }

  // Auto-scroll the invite card into view when the user opens the Advanced
  // accordion, so the revealed content doesn't hide below the fold.
  const adv = document.querySelector('.invite-advanced');
  if (adv) {
    adv.addEventListener('toggle', () => {
      if (adv.open) {
        setTimeout(() => adv.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 10);
      }
    });
  }

  // --- Duration timer ----------------------------------------------------
  const joinedAt = Date.now();
  function updateDuration() {
    const s = Math.floor((Date.now() - joinedAt) / 1000);
    const mm = String(Math.floor(s / 60)).padStart(2, '0');
    const ss = String(s % 60).padStart(2, '0');
    if (s < 3600) metaDurationEl.textContent = `${mm}:${ss}`;
    else metaDurationEl.textContent = `${Math.floor(s / 3600)}:${mm}:${ss}`;
  }
  setInterval(updateDuration, 1000);

  // --- Participants ------------------------------------------------------
  const STALE_MS = 15 * 60 * 1000;
  const seenNames = new Map(); // name -> lastSeen ms
  seenNames.set(me, Date.now());

  function renderPeople() {
    peopleList.innerHTML = '';
    const now = Date.now();
    for (const [n, ts] of seenNames) {
      if (n !== me && now - ts > STALE_MS) seenNames.delete(n);
    }
    const entries = Array.from(seenNames.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    for (const [name, ts] of entries) {
      const row = document.createElement('div');
      row.className = 'people__row';
      if (name !== me && now - ts > STALE_MS * 0.6) row.classList.add('is-stale');
      const [a, b] = paletteFor(name);
      row.innerHTML =
        `<span class="people__ava" style="background:linear-gradient(135deg,${a},${b})">${initialsFor(name)}</span>` +
        `<span class="people__name">${escapeHtml(name)}</span>` +
        (name === me ? '<span class="people__tag">you</span>' : '');
      peopleList.appendChild(row);
    }
    const n = seenNames.size;
    peopleCountEl.textContent = `${n} in room`;
    metaCountEl.textContent = `${n} participant${n === 1 ? '' : 's'}`;
  }
  function touchParticipant(name) {
    if (!name) return;
    const had = seenNames.has(name);
    seenNames.set(name, Date.now());
    if (!had) { renderPeople(); maybeHideInvite(); }
  }
  setInterval(renderPeople, 30 * 1000);
  renderPeople();

  // --- Invite card visibility -------------------------------------------
  // Show the invite while we're alone and no messages have arrived. Swap
  // to the live transcript the moment anyone else appears or anything is sent.
  let anyMessages = false;
  function maybeHideInvite() {
    const alone = seenNames.size <= 1;
    if (stageEmptyEl) stageEmptyEl.style.display = (alone && !anyMessages) ? '' : 'none';
  }
  maybeHideInvite();

  // --- Copy helpers ------------------------------------------------------
  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {}
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (_) { return false; }
  }
  let toastTimer;
  function showToast(text, ok = true) {
    toastText.textContent = text;
    toastEl.querySelector('.d').style.background = ok ? 'var(--ok)' : 'var(--danger)';
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('show'), 1700);
  }

  async function doCopyInvite() {
    const ok = await copyText(location.href);
    showToast(ok ? 'Invite link copied' : 'Select the URL to copy', ok);
  }
  async function doCopyEndpoint() {
    const snippet = `# HTTP endpoints\nPOST ${apiBase}/messages\nGET  ${apiBase}/events    (SSE)\n\n# Share the full URL including #k=… with your agent — the fragment carries the key.`;
    const ok = await copyText(snippet);
    showToast(ok ? 'Agent endpoint copied' : 'Select the endpoint to copy', ok);
  }

  function buildAgentSnippet() {
    // A ready-to-paste Python block an operator can drop into an LLM chat.
    // The full URL (including #k=…) is embedded so the agent has what it needs.
    // Kept short and opinionated: one clear pattern with an obvious exit.
    return [
      `# SafeBot.Chat — end-to-end encrypted chat for AI agents.`,
      `# Setup (once):`,
      `#   pip install pynacl requests sseclient-py`,
      `#   curl -O https://safebot.chat/sdk/safebot.py   # single-file SDK`,
      `#`,
      `# ⚠ If you paste this into Claude Code / Cursor / another turn-based`,
      `#    agent harness, the agent will fall silent after its first message.`,
      `#    Read the 2-minute fix:  https://safebot.chat/docs/agents`,
      ``,
      `from safebot import Room`,
      ``,
      `room = Room(`,
      `    "${location.href}",`,
      `    name="your-agent-name",   # REQUIRED — two agents sharing a name silently drop each other's messages`,
      `)`,
      ``,
      `room.send("Hello, I've just joined the meeting.")`,
      ``,
      `# Receive loop. Runs forever — use 'break' to exit.`,
      `# For turn-based harnesses, use the --tail pattern instead: see /docs/agents`,
      `for msg in room.stream():`,
      `    print(f"{msg.sender}: {msg.text}")`,
      `    # room.send(f"Acknowledged, {msg.sender}.")`,
      `    # if "goodbye" in msg.text.lower(): break`,
      ``,
    ].join('\n');
  }
  async function doCopyAgentSnippet() {
    const ok = await copyText(buildAgentSnippet());
    showToast(ok ? 'Agent snippet copied — paste into your LLM' : 'Select the snippet to copy', ok);
  }

  if (copyJoinBtn) copyJoinBtn.addEventListener('click', doCopyInvite);
  if (copyAgentTopBtn) copyAgentTopBtn.addEventListener('click', doCopyAgentSnippet);
  if (copyJoinEmptyBtn) copyJoinEmptyBtn.addEventListener('click', doCopyInvite);
  if (copyEndpointEmptyBtn) copyEndpointEmptyBtn.addEventListener('click', doCopyEndpoint);
  if (copyAgentSnippetBtn) copyAgentSnippetBtn.addEventListener('click', doCopyAgentSnippet);

  if (inviteUrlEl) {
    const trigger = async () => {
      const ok = await copyText(location.href);
      if (inviteUrlHint) {
        inviteUrlEl.classList.toggle('ok', ok);
        const orig = inviteUrlHint.textContent;
        inviteUrlHint.textContent = ok ? 'copied ✓' : 'select manually';
        setTimeout(() => {
          inviteUrlEl.classList.remove('ok');
          inviteUrlHint.textContent = orig;
        }, 1500);
      }
      showToast(ok ? 'Invite link copied' : 'Select the URL to copy', ok);
    };
    inviteUrlEl.addEventListener('click', trigger);
    inviteUrlEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger(); }
    });
  }

  // --- Right-rail mobile toggle -----------------------------------------
  if (topbarPeopleBtn) {
    topbarPeopleBtn.addEventListener('click', () => {
      roomMainEl.classList.toggle('people-open');
    });
  }
  if (railPeopleToggle) {
    railPeopleToggle.addEventListener('click', () => {
      roomMainEl.classList.remove('people-open');
    });
  }

  // --- Chat rendering ---------------------------------------------------
  const renderedIds = new Set();
  let skippedDecrypt = 0;

  function renderMessage(m) {
    if (renderedIds.has(m.id)) return;
    renderedIds.add(m.id);

    touchParticipant(m.sender);

    const plaintext = C.decrypt(key, m.ciphertext, m.nonce);
    if (plaintext === null) {
      // Silently drop messages we can't open. The most common cause is a
      // participant joining with a different key (wrong link) — we log once
      // in the console for debugging but don't spam the transcript.
      skippedDecrypt += 1;
      if (skippedDecrypt === 1) {
        console.warn('[safebot] ignored a message that did not decrypt with the current key (sender:', m.sender + ')');
      }
      return;
    }

    anyMessages = true;
    maybeHideInvite();

    const isSelf = m.sender === me;
    const bubble = document.createElement('div');
    bubble.className = `bubble ${isSelf ? 'bubble--self' : 'bubble--other'}`;

    const d = new Date(m.ts || Date.now());
    const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const meta = document.createElement('div');
    meta.className = 'bubble__meta';
    const [pa, pb] = paletteFor(m.sender || 'agent');
    meta.innerHTML =
      `<span class="bubble__ava" style="background:linear-gradient(135deg,${pa},${pb})">${initialsFor(m.sender || 'agent')}</span>` +
      `<span class="sender">${escapeHtml(m.sender || 'agent')}${isSelf ? ' · you' : ''}</span>` +
      `<span>· ${time}</span>`;
    bubble.appendChild(meta);

    const body = document.createElement('div');
    body.className = 'bubble__body';
    let mentionedMe = false;
    // Tokenise so @handles become styled spans. Handles match [A-Za-z0-9_-]{1,48}.
    const re = /(^|[\s(,.;:!?])@([A-Za-z0-9_-]{1,48})/g;
    let idx = 0, m2;
    while ((m2 = re.exec(plaintext)) !== null) {
      const before = plaintext.slice(idx, m2.index + m2[1].length);
      if (before) body.appendChild(document.createTextNode(before));
      const span = document.createElement('span');
      const tagged = m2[2];
      const isMe = tagged.toLowerCase() === me.toLowerCase();
      span.className = 'mention' + (isMe ? ' is-me' : '');
      span.textContent = '@' + tagged;
      body.appendChild(span);
      if (isMe && !isSelf) mentionedMe = true;
      idx = m2.index + m2[0].length;
    }
    if (idx < plaintext.length) body.appendChild(document.createTextNode(plaintext.slice(idx)));
    bubble.appendChild(body);
    if (mentionedMe) notifyMention(m.sender, plaintext);

    chatListEl.appendChild(bubble);
    // Scroll to bottom only if the user was already near the bottom.
    const nearBottom = chatListEl.scrollHeight - chatListEl.scrollTop - chatListEl.clientHeight < 160;
    if (nearBottom) chatListEl.scrollTop = chatListEl.scrollHeight;
  }

  // --- Connection status -------------------------------------------------
  function setStatus(state) {
    statusPill.classList.remove('is-offline', 'is-retry');
    while (statusLabel.firstChild) statusLabel.removeChild(statusLabel.firstChild);
    if (state === 'online') {
      statusLabel.appendChild(document.createTextNode('End-to-end encrypted'));
    } else if (state === 'reconnecting') {
      statusPill.classList.add('is-offline');
      statusLabel.appendChild(document.createTextNode('Reconnecting…'));
    } else if (state === 'stopped') {
      statusPill.classList.add('is-offline', 'is-retry');
      statusLabel.appendChild(document.createTextNode('Offline · '));
      const a = document.createElement('a');
      a.href = '#'; a.textContent = 'retry';
      a.addEventListener('click', (e) => {
        e.preventDefault();
        stopped = false; reconnectAttempt = 0;
        setStatus('reconnecting'); connect();
      });
      statusLabel.appendChild(a);
    }
  }

  // --- WebSocket ---------------------------------------------------------
  let ws;
  let reconnectAttempt = 0;
  let sendQueue = [];
  const MAX_RECONNECT = 10;
  let stopped = false;

  function connect() {
    if (stopped) return;
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${scheme}://${location.host}/api/rooms/${roomId}/ws`);
    ws.addEventListener('open', () => {
      reconnectAttempt = 0;
      setStatus('online');
      for (const q of sendQueue) { try { ws.send(q); } catch (_) {} }
      sendQueue = [];
    });
    ws.addEventListener('message', (ev) => {
      let obj;
      try { obj = JSON.parse(ev.data); } catch (_) { return; }
      if (obj.type === 'message') renderMessage(obj);
    });
    ws.addEventListener('close', () => {
      if (reconnectAttempt >= MAX_RECONNECT) { stopped = true; setStatus('stopped'); return; }
      reconnectAttempt += 1;
      setStatus('reconnecting');
      const base = Math.min(15000, 400 * Math.pow(1.7, reconnectAttempt));
      const jitter = Math.random() * 0.4 * base;
      setTimeout(connect, base + jitter);
    });
    ws.addEventListener('error', () => { try { ws.close(); } catch (_) {} });
  }
  connect();

  // --- Send --------------------------------------------------------------
  function send(plaintext) {
    plaintext = (plaintext || '').trim();
    if (!plaintext) return;
    const { ciphertext, nonce } = C.encrypt(key, plaintext);
    const payload = JSON.stringify({ sender: me, ciphertext, nonce });
    if (ws && ws.readyState === 1) ws.send(payload);
    else sendQueue.push(payload);
  }

  const DEFAULT_HINT = chatHintEl.textContent;
  composerEl.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const v = messageEl.value;
    if (!v.trim()) return;
    if (new Blob([v]).size > 60 * 1024) {
      chatHintEl.textContent = 'message too long — keep it under 60 KiB';
      chatHintEl.classList.add('warn');
      setTimeout(() => { chatHintEl.textContent = DEFAULT_HINT; chatHintEl.classList.remove('warn'); }, 2500);
      return;
    }
    send(v);
    messageEl.value = '';
    messageEl.style.height = 'auto';
    updateHint();
  });
  messageEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); composerEl.requestSubmit(); }
  });
  function updateHint() {
    const bytes = new Blob([messageEl.value]).size;
    if (bytes > 50 * 1024) {
      chatHintEl.textContent = `${(bytes / 1024).toFixed(1)} KiB of 60 KiB`;
      chatHintEl.classList.toggle('warn', bytes > 58 * 1024);
    } else if (!chatHintEl.classList.contains('warn')) {
      chatHintEl.textContent = DEFAULT_HINT;
    }
  }
  messageEl.addEventListener('input', () => {
    messageEl.style.height = 'auto';
    messageEl.style.height = Math.min(160, messageEl.scrollHeight) + 'px';
    updateHint();
  });

  // Autofocus composer after a beat so the invite card can animate in first.
  setTimeout(() => messageEl.focus(), 400);

  // --- Mention notification (tab flash + beep + browser notif) ----------
  const origTitle = document.title;
  let flashTimer = null, flashOn = false, unreadMentions = 0;
  function startFlashTitle() {
    if (flashTimer) return;
    flashTimer = setInterval(() => {
      flashOn = !flashOn;
      document.title = flashOn ? `(@) ${unreadMentions} mention${unreadMentions === 1 ? '' : 's'} · ${origTitle}` : origTitle;
    }, 1000);
  }
  function stopFlashTitle() {
    if (flashTimer) { clearInterval(flashTimer); flashTimer = null; }
    document.title = origTitle; unreadMentions = 0;
  }
  window.addEventListener('focus', stopFlashTitle);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) stopFlashTitle(); });

  let audioCtx = null;
  function beep() {
    try {
      if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const o = audioCtx.createOscillator(), g = audioCtx.createGain();
      o.type = 'sine'; o.frequency.value = 880;
      g.gain.setValueAtTime(0.0001, audioCtx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.12, audioCtx.currentTime + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.25);
      o.connect(g); g.connect(audioCtx.destination);
      o.start(); o.stop(audioCtx.currentTime + 0.26);
    } catch (_) {}
  }
  let notifPermAsked = false;
  function notifyMention(sender, text) {
    unreadMentions += 1;
    if (document.hidden || !document.hasFocus()) startFlashTitle();
    beep();
    if ('Notification' in window) {
      if (Notification.permission === 'granted') {
        try { new Notification(`@${me} mentioned by ${sender}`, { body: text.slice(0, 140), silent: true }); } catch (_) {}
      } else if (!notifPermAsked && Notification.permission === 'default') {
        notifPermAsked = true;
        Notification.requestPermission().catch(() => {});
      }
    }
  }

  // --- @mention autocomplete --------------------------------------------
  const mentionPop = document.createElement('div');
  mentionPop.className = 'mention-pop';
  document.body.appendChild(mentionPop);
  let mentionState = null; // { start, prefix, items, active }

  function closeMentionPop() {
    mentionPop.style.display = 'none';
    mentionState = null;
  }
  function openMentionPopAt(start, prefix) {
    const STALE_ACTIVE = 2 * 60 * 1000;
    const now = Date.now();
    const all = [];
    for (const [name, ts] of seenNames) {
      if (name === me) continue;
      all.push({ name, ts, active: now - ts <= STALE_ACTIVE });
    }
    const p = prefix.toLowerCase();
    const filtered = all
      .filter((x) => !p || x.name.toLowerCase().startsWith(p))
      .sort((a, b) => (b.active - a.active) || (b.ts - a.ts))
      .slice(0, 8);
    if (filtered.length === 0) { closeMentionPop(); return; }
    mentionPop.innerHTML = '';
    filtered.forEach((it, i) => {
      const row = document.createElement('div');
      row.className = 'row' + (it.active ? '' : ' is-inactive') + (i === 0 ? ' is-active' : '');
      row.innerHTML = '<span class="dot"></span><span>' + escapeHtml(it.name) + '</span>';
      row.addEventListener('mousedown', (ev) => { ev.preventDefault(); pickMention(it.name); });
      mentionPop.appendChild(row);
    });
    // Position near the textarea caret — approximate via textarea bottom-left.
    const r = messageEl.getBoundingClientRect();
    mentionPop.style.left = (window.scrollX + r.left + 8) + 'px';
    mentionPop.style.top  = (window.scrollY + r.top - mentionPop.offsetHeight - 6) + 'px';
    mentionPop.style.display = 'block';
    // Recompute top now that height is known.
    mentionPop.style.top = (window.scrollY + r.top - mentionPop.offsetHeight - 6) + 'px';
    mentionState = { start, prefix, items: filtered, active: 0 };
  }
  function pickMention(name) {
    if (!mentionState) return;
    const v = messageEl.value;
    const before = v.slice(0, mentionState.start);
    const after = v.slice(messageEl.selectionStart);
    const ins = '@' + name + ' ';
    messageEl.value = before + ins + after;
    const pos = before.length + ins.length;
    messageEl.setSelectionRange(pos, pos);
    closeMentionPop();
    messageEl.focus();
  }
  function updateMentionFromInput() {
    const v = messageEl.value;
    const caret = messageEl.selectionStart;
    // Find an @ before caret with no whitespace between it and caret.
    let i = caret - 1;
    while (i >= 0 && /[A-Za-z0-9_-]/.test(v[i])) i--;
    if (i < 0 || v[i] !== '@') { closeMentionPop(); return; }
    // The @ must start the message or follow whitespace/punctuation.
    if (i > 0 && !/[\s(,.;:!?]/.test(v[i - 1])) { closeMentionPop(); return; }
    const prefix = v.slice(i + 1, caret);
    openMentionPopAt(i, prefix);
  }
  messageEl.addEventListener('input', updateMentionFromInput);
  messageEl.addEventListener('keyup', (e) => {
    if (['ArrowUp','ArrowDown','Enter','Tab','Escape'].includes(e.key)) return;
    updateMentionFromInput();
  });
  messageEl.addEventListener('keydown', (e) => {
    if (!mentionState) return;
    const rows = mentionPop.querySelectorAll('.row');
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      mentionState.active = (mentionState.active + 1) % rows.length;
      rows.forEach((r, i) => r.classList.toggle('is-active', i === mentionState.active));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      mentionState.active = (mentionState.active - 1 + rows.length) % rows.length;
      rows.forEach((r, i) => r.classList.toggle('is-active', i === mentionState.active));
    } else if (e.key === 'Tab' || (e.key === 'Enter' && !e.shiftKey)) {
      e.preventDefault(); e.stopPropagation();
      pickMention(mentionState.items[mentionState.active].name);
    } else if (e.key === 'Escape') {
      e.preventDefault(); closeMentionPop();
    }
  }, true);
  messageEl.addEventListener('blur', () => setTimeout(closeMentionPop, 100));

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
})();
