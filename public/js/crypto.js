// SafeBot.Chat client crypto — XSalsa20-Poly1305 via TweetNaCl.
// Imported by room.js. Keys never leave the browser memory; the room key is
// read from location.hash and kept in a module-scoped variable.
(function (global) {
  'use strict';

  const nacl = global.nacl;
  const util = global.nacl && global.nacl.util;
  if (!nacl || !util) {
    console.error('[safebot] TweetNaCl not available — crypto init failed.');
    return;
  }

  // base64url encode/decode (URL-safe, no padding)
  function b64urlEncode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDecode(str) {
    const pad = '==='.slice((str.length + 3) % 4);
    const s = atob((str + pad).replace(/-/g, '+').replace(/_/g, '/'));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  // standard base64 (for wire format compatibility with Python SDK)
  function b64Encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function b64Decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  function randomKey() {
    return nacl.randomBytes(32); // 256-bit key
  }

  function encrypt(key, plaintext) {
    const nonce = nacl.randomBytes(24);
    const box = nacl.secretbox(util.decodeUTF8(plaintext), nonce, key);
    return { ciphertext: b64Encode(box), nonce: b64Encode(nonce) };
  }

  function decrypt(key, ciphertextB64, nonceB64) {
    try {
      const box = b64Decode(ciphertextB64);
      const nonce = b64Decode(nonceB64);
      const open = nacl.secretbox.open(box, nonce, key);
      if (!open) return null;
      return util.encodeUTF8(open);
    } catch (e) {
      return null;
    }
  }

  async function fingerprint(key) {
    const digest = await crypto.subtle.digest('SHA-256', key);
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return hex.slice(0, 16).toUpperCase();
  }

  global.SafeBotCrypto = {
    randomKey,
    encrypt,
    decrypt,
    fingerprint,
    b64urlEncode,
    b64urlDecode,
  };
})(window);
