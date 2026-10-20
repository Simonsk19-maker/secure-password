/* sp-crypto.js — password generation + zero-knowledge encryption.
   Runs in the browser and in Node 18+ (both have globalThis.crypto.subtle).
   The one-time-link server only ever sees the ENCRYPTED blob; the key lives
   in the link's # fragment and never leaves the browser. */
(function (root) {
  'use strict';
  const subtle = globalThis.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---- base64url ----
  function b64u(bytes) {
    let s = '';
    const b = new Uint8Array(bytes);
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---- unbiased random integer in [0, max) ----
  function randInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    let x;
    do { globalThis.crypto.getRandomValues(buf); x = buf[0]; } while (x >= limit);
    return x % max;
  }

  // ---- password generators ----
  const SETS = {
    lower: 'abcdefghijkmnpqrstuvwxyz',          // no l,o
    upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',           // no I,O
    digits: '23456789',                          // no 0,1
    symbols: '!@#$%^&*-_=+?'
  };
  function generatePassword(opts) {
    opts = opts || {};
    const len = Math.max(4, Math.min(128, opts.length || 16));
    let pool = '';
    const groups = [];
    if (opts.lower !== false) { pool += SETS.lower; groups.push(SETS.lower); }
    if (opts.upper !== false) { pool += SETS.upper; groups.push(SETS.upper); }
    if (opts.digits !== false) { pool += SETS.digits; groups.push(SETS.digits); }
    if (opts.symbols) { pool += SETS.symbols; groups.push(SETS.symbols); }
    if (!pool) { pool = SETS.lower; groups.push(SETS.lower); }
    const chars = [];
    // guarantee at least one from each chosen group
    for (const g of groups) if (chars.length < len) chars.push(g[randInt(g.length)]);
    while (chars.length < len) chars.push(pool[randInt(pool.length)]);
    // shuffle (Fisher-Yates)
    for (let i = chars.length - 1; i > 0; i--) { const j = randInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
    return chars.join('');
  }
  function generatePassphrase(words, wordCount, opts) {
    opts = opts || {};
    const n = Math.max(3, Math.min(10, wordCount || 5));
    const sep = opts.separator != null ? opts.separator : '-';
    const picked = [];
    for (let i = 0; i < n; i++) {
      let w = words[randInt(words.length)];
      if (opts.capitalise) w = w.charAt(0).toUpperCase() + w.slice(1);
      picked.push(w);
    }
    let out = picked.join(sep);
    if (opts.number) { const num = randInt(90) + 10; out += sep + num; }  // a 2-digit number
    return out;
  }

  // ---- strength (bits of entropy) ----
  function poolSize(pw) {
    let s = 0;
    if (/[a-z]/.test(pw)) s += 26;
    if (/[A-Z]/.test(pw)) s += 26;
    if (/[0-9]/.test(pw)) s += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) s += 24;
    return s || 1;
  }
  function entropyBits(pw) { return Math.round(pw.length * Math.log2(poolSize(pw))); }
  function passphraseBits(listLen, wordCount) { return Math.round(wordCount * Math.log2(listLen)); }
  function rating(bits) {
    if (bits < 40) return { label: 'Weak', pct: Math.min(100, bits * 1.4), colour: '#b91c1c' };
    if (bits < 60) return { label: 'Fair', pct: Math.min(100, bits * 1.4), colour: '#b45309' };
    if (bits < 80) return { label: 'Strong', pct: Math.min(100, bits), colour: '#1d4ed8' };
    return { label: 'Very strong', pct: 100, colour: '#047857' };
  }

  // ---- zero-knowledge encryption for one-time links ----
  // Returns { blob, fragment }. Store `blob` on the server; put `fragment`
  // after # in the link. With a PIN, the recipient must also enter the PIN.
  async function encryptSecret(plaintext, pin) {
    const keyBytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveAesKey(keyBytes, salt, pin);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext));
    const blob = JSON.stringify({ v: 1, salt: b64u(salt), iv: b64u(iv), ct: b64u(ct), pin: pin ? 1 : 0 });
    return { blob, fragment: b64u(keyBytes) };
  }
  async function decryptSecret(blob, fragment, pin) {
    const o = JSON.parse(blob);
    const keyBytes = unb64u(fragment);
    const aesKey = await deriveAesKey(keyBytes, unb64u(o.salt), pin);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(o.iv) }, aesKey, unb64u(o.ct));
    return dec.decode(pt);
  }
  // key = HKDF(keyBytes); if a PIN is set, mix in PBKDF2(pin) so the link
  // alone isn't enough — the recipient also needs the PIN.
  async function deriveAesKey(keyBytes, salt, pin) {
    let material = keyBytes;
    if (pin) {
      const pk = await subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
      const pinBits = await subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, pk, 256);
      const mixed = new Uint8Array(64);
      mixed.set(keyBytes, 0); mixed.set(new Uint8Array(pinBits), 32);
      material = new Uint8Array(await subtle.digest('SHA-256', mixed));
    }
    return subtle.importKey('raw', material, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  const SP = {
    b64u, unb64u, randInt, generatePassword, generatePassphrase,
    entropyBits, passphraseBits, rating, encryptSecret, decryptSecret
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = SP;
  root.SP = SP;
})(typeof window !== 'undefined' ? window : globalThis);
