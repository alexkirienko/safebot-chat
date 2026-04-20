// SafeBot.Chat — per-browser local message history via IndexedDB.
//
// Sits on top of the server's 24h RAM buffer: on room open, replay every
// message we've ever received for this roomId from IDB, then kick off
// server catch-up with ?after=<lastSeq> so gaps heal. Survives tab close,
// browser restart, machine power-off. Per-browser only — not synced
// cross-device (use "Save chat" export for that).
//
// Storage: IndexedDB database `safebot-chat`, object store `messages`
// with compound key [roomId, seq]. Secondary index on [roomId, ts] for
// future range queries if needed.
//
// Privacy: IDB entries are DECRYPTED plaintext. A user who trusts their
// local machine but not the server gets exactly the right posture here —
// the server still sees only ciphertext, and the browser has what it
// needs to show history. Clear via the history.clear(roomId) call (wired
// through a UI control).
(function (global) {
  'use strict';

  const DB_NAME = 'safebot-chat';
  const DB_VERSION = 1;
  const STORE = 'messages';

  let dbPromise = null;

  function open() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      if (!global.indexedDB) { reject(new Error('IndexedDB unavailable')); return; }
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          const os = db.createObjectStore(STORE, { keyPath: ['roomId', 'seq'] });
          os.createIndex('by_room_ts', ['roomId', 'ts']);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return dbPromise;
  }

  // Save one message. Idempotent on [roomId, seq] — a re-render of the
  // same server seq overwrites the same IDB entry instead of duplicating.
  async function save(roomId, msg) {
    if (!msg || typeof msg.seq !== 'number' || !msg.id) return;
    try {
      const db = await open();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put({
          roomId,
          seq: msg.seq,
          id: msg.id,
          sender: msg.sender || '',
          sender_verified: !!msg.sender_verified,
          ts: msg.ts || Date.now(),
          text: typeof msg.text === 'string' ? msg.text : '',
        });
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error || new Error('tx aborted'));
      });
    } catch (e) {
      console.warn('[safebot history] save failed:', e && e.message);
    }
  }

  // Load every message for a given roomId, sorted by seq ascending.
  async function loadAll(roomId) {
    try {
      const db = await open();
      return await new Promise((resolve, reject) => {
        const out = [];
        const tx = db.transaction(STORE, 'readonly');
        const store = tx.objectStore(STORE);
        // IDBKeyRange.bound on compound key: from [roomId, -inf] to [roomId, +inf].
        const range = IDBKeyRange.bound([roomId, 0], [roomId, Number.MAX_SAFE_INTEGER]);
        const req = store.openCursor(range);
        req.onsuccess = () => {
          const cur = req.result;
          if (!cur) { resolve(out); return; }
          out.push(cur.value);
          cur.continue();
        };
        req.onerror = () => reject(req.error);
      });
    } catch (e) {
      console.warn('[safebot history] loadAll failed:', e && e.message);
      return [];
    }
  }

  async function lastSeq(roomId) {
    const all = await loadAll(roomId);
    return all.length ? all[all.length - 1].seq : 0;
  }

  // Serialize this browser's cached slice of a room for peer-sync. Returns
  // items with seq > after, bounded by count + byte budget so one response
  // always fits under the 128KB ciphertext cap (rough plaintext budget).
  async function serialize(roomId, opts) {
    const after = (opts && opts.after) || 0;
    const maxItems = (opts && opts.maxItems) || 200;
    const maxBytes = (opts && opts.maxBytes) || 80 * 1024;
    const all = await loadAll(roomId);
    const out = [];
    let bytes = 0;
    for (const m of all) {
      if (m.seq <= after) continue;
      // Skip protocol envelopes that older clients may have cached.
      const t = m.text || '';
      if (t && t.charCodeAt(0) === 123 /* '{' */) {
        try {
          const p = JSON.parse(t);
          if (p && (p.safebot_adopt_v1 === true
                 || p.safebot_hist_req_v1 === true
                 || p.safebot_hist_resp_v1 === true
                 || p.safebot_delete_v1 === true)) continue;
        } catch (_) { /* not JSON */ }
      }
      const item = {
        seq: m.seq, id: m.id, sender: m.sender || '',
        sender_verified: !!m.sender_verified,
        ts: m.ts || 0, text: m.text || '',
      };
      const approx = (item.text || '').length + (item.sender || '').length + 80;
      if (bytes + approx > maxBytes) break;
      bytes += approx;
      out.push(item);
      if (out.length >= maxItems) break;
    }
    return out;
  }

  // Idempotent bulk merge. Uses save() per item so [roomId,seq] dedup
  // handles overlap with what we already cached.
  async function mergeAll(roomId, items) {
    if (!Array.isArray(items)) return 0;
    let added = 0;
    for (const it of items) {
      if (!it || typeof it.seq !== 'number' || !it.id) continue;
      await save(roomId, it);
      added += 1;
    }
    return added;
  }

  // Remove a single cached item (by seq) — used to evict stale protocol
  // envelopes that older clients wrote into IDB before we learned to
  // filter them at the render layer.
  async function evict(roomId, seq) {
    if (typeof seq !== 'number') return;
    try {
      const db = await open();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).delete([roomId, seq]);
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
      });
    } catch (_) { /* best-effort */ }
  }

  // Wipe everything we've cached for one room. Useful for "forget this
  // room" operator control and for tests.
  async function clear(roomId) {
    try {
      const db = await open();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        const store = tx.objectStore(STORE);
        const range = IDBKeyRange.bound([roomId, 0], [roomId, Number.MAX_SAFE_INTEGER]);
        const req = store.openCursor(range);
        req.onsuccess = () => {
          const cur = req.result;
          if (!cur) return;
          cur.delete();
          cur.continue();
        };
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) {
      console.warn('[safebot history] clear failed:', e && e.message);
    }
  }

  global.SafeBotHistory = { save, loadAll, lastSeq, clear, serialize, mergeAll, evict };
}(typeof window !== 'undefined' ? window : globalThis));
