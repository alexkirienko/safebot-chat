// SafeBot.Chat — browser Identity (Ed25519 + X25519).
//
// Generates, persists, and signs with a local Identity scoped to this
// browser origin. The private keys never leave the browser; register()
// only publishes the two public keys under the chosen @handle.
//
// Storage: localStorage key `safebot-identity` — a JSON blob with the
// handle and the 32-byte seeds (base64url). Small surface, easy for the
// user to clear via "Forget identity" (implemented in the UI).
(function (global) {
  'use strict';

  const nacl = global.nacl;
  const util = global.nacl && global.nacl.util;
  if (!nacl || !util) {
    console.error('[safebot] Identity init failed — TweetNaCl missing');
    return;
  }
  const SBC = global.SafeBotCrypto;
  if (!SBC || !SBC.b64urlEncode || !SBC.b64urlDecode) {
    console.error('[safebot] Identity init failed — SafeBotCrypto must load first');
    return;
  }
  // crypto.js only exposes base64url; standard base64 is needed for wire
  // format (server expects standard base64 for box_pub/sign_pub/sig). Local
  // tiny helpers.
  function b64Encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  const LS_KEY = 'safebot-identity';
  const HANDLE_REGEX = /^[a-z0-9][a-z0-9_-]{1,31}$/;

  function loadFromStorage() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return null;
      const j = JSON.parse(raw);
      if (!j.handle || !j.box_sk_b64u || !j.sign_seed_b64u) return null;
      return j;
    } catch (_) { return null; }
  }

  function saveToStorage(rec) {
    localStorage.setItem(LS_KEY, JSON.stringify(rec));
  }

  function clearStorage() {
    localStorage.removeItem(LS_KEY);
  }

  class Identity {
    constructor(record) {
      // record: {handle, box_sk_b64u, sign_seed_b64u}
      this.handle = record.handle;
      this._box_sk = SBC.b64urlDecode(record.box_sk_b64u);
      const seed = SBC.b64urlDecode(record.sign_seed_b64u);
      this._sign_kp = nacl.sign.keyPair.fromSeed(seed);
      const box_kp = nacl.box.keyPair.fromSecretKey(this._box_sk);
      this.box_pub_b64 = b64Encode(box_kp.publicKey);
      this.sign_pub_b64 = b64Encode(this._sign_kp.publicKey);
    }

    // Sign a room message envelope. Blob matches server verifyRoomSenderSig:
    //   "room-msg <roomId> <ts> <nonce> <sha256_hex(ciphertext)>"
    async signRoomMessage(roomId, ctB64) {
      const ts = Date.now();
      const nonce = SBC.b64urlEncode(nacl.randomBytes(18));
      const ctHashBytes = await crypto.subtle.digest('SHA-256', util.decodeUTF8(ctB64));
      const ctHashHex = Array.from(new Uint8Array(ctHashBytes))
        .map((b) => b.toString(16).padStart(2, '0')).join('');
      const blob = util.decodeUTF8(`room-msg ${roomId} ${ts} ${nonce} ${ctHashHex}`);
      const sig = nacl.sign.detached(blob, this._sign_kp.secretKey);
      return {
        sender_handle: this.handle,
        sender_ts: ts,
        sender_nonce: nonce,
        sender_sig: b64Encode(sig),
      };
    }

    // Register the two public keys on the server. Idempotent: 201 = created,
    // 409 = already-registered. Returns {ok, status}.
    async register(baseUrl) {
      const ts = Date.now();
      const blob = util.decodeUTF8(
        `register ${this.handle} ${ts} ${this.box_pub_b64} ${this.sign_pub_b64}`
      );
      const sig = nacl.sign.detached(blob, this._sign_kp.secretKey);
      const body = {
        handle: this.handle,
        box_pub: this.box_pub_b64,
        sign_pub: this.sign_pub_b64,
        register_ts: ts,
        register_sig: b64Encode(sig),
        meta: {},
      };
      const r = await fetch(`${baseUrl}/api/identity/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (r.status === 201 || r.status === 409) return { ok: true, status: r.status };
      const txt = await r.text().catch(() => '');
      return { ok: false, status: r.status, error: txt };
    }
  }

  // Export the localStorage record as a portable JSON string. The record
  // contains the two secret seeds, so anyone holding it can impersonate
  // the @handle — treat it like a private key file.
  function exportJson() {
    const rec = loadFromStorage();
    if (!rec) return null;
    return JSON.stringify(
      { safebot_identity_v1: true, ...rec },
      null,
      2,
    );
  }

  // Import a previously exported JSON string. Validates shape and returns
  // a live Identity. Does NOT re-register on the server — that happens
  // on the next send/register call if needed.
  function importJson(text) {
    let j;
    try { j = JSON.parse(text); } catch (_) { throw new Error('not valid JSON'); }
    if (!j.safebot_identity_v1) throw new Error('missing safebot_identity_v1 marker');
    if (!j.handle || !HANDLE_REGEX.test(j.handle)) throw new Error('bad handle');
    if (!j.box_sk_b64u || !j.sign_seed_b64u) throw new Error('missing key fields');
    const rec = { handle: j.handle, box_sk_b64u: j.box_sk_b64u, sign_seed_b64u: j.sign_seed_b64u };
    saveToStorage(rec);
    return new Identity(rec);
  }

  async function createAndRegister(handle, baseUrl) {
    if (!HANDLE_REGEX.test(handle)) throw new Error('handle must match ' + HANDLE_REGEX);
    const seed = nacl.randomBytes(32);
    const box_sk = nacl.randomBytes(32);
    const rec = {
      handle,
      box_sk_b64u: SBC.b64urlEncode(box_sk),
      sign_seed_b64u: SBC.b64urlEncode(seed),
    };
    const ident = new Identity(rec);
    const res = await ident.register(baseUrl);
    if (!res.ok) {
      if (res.status === 409) throw new Error('@' + handle + ' already taken — pick another');
      throw new Error('register failed (' + res.status + '): ' + (res.error || ''));
    }
    saveToStorage(rec);
    return ident;
  }

  function load() {
    const rec = loadFromStorage();
    return rec ? new Identity(rec) : null;
  }

  global.SafeBotIdentity = {
    load,
    createAndRegister,
    forget: clearStorage,
    validHandle: (h) => HANDLE_REGEX.test(h || ''),
    exportJson,
    importJson,
  };
}(typeof window !== 'undefined' ? window : globalThis));
