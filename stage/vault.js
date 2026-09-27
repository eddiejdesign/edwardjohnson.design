// Client side of scripts/vault.mjs. Protected pages and images are only
// ever served encrypted; this derives the key from the password, then
// decrypts page fragments and their assets in the browser.
//
// The derived AES key (never the password) is kept in sessionStorage so it
// lasts for this tab only and is gone when the tab closes.
(function () {
  var BASE = document.currentScript.src.replace(/vault\.js(\?.*)?$/, '');
  var VAULT = BASE + 'vault/';
  var KEY = 'vault.key';
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function b64(buf) {
    var s = '';
    new Uint8Array(buf).forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s);
  }

  function unb64(s) {
    return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); });
  }

  function storedKey() {
    try { return sessionStorage.getItem(KEY); } catch (e) { return null; }
  }

  async function fetchBytes(url) {
    var res = await fetch(url, { cache: 'no-cache' });
    if (!res.ok) throw new Error('vault: ' + res.status + ' ' + url);
    return new Uint8Array(await res.arrayBuffer());
  }

  async function open(key, bytes) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12));
  }

  var manifestP;
  function manifest() {
    manifestP = manifestP || fetch(VAULT + 'manifest.json', { cache: 'no-cache' }).then(function (r) { return r.json(); });
    return manifestP;
  }

  async function deriveAesBits(password, m) {
    var base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    var master = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: unb64(m.salt), iterations: m.iterations }, base, 256);
    var hkdf = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
    return crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('aes-gcm') }, hkdf, 256);
  }

  var keyP;
  function key() {
    var raw = storedKey();
    if (!raw) return Promise.reject(new Error('locked'));
    keyP = keyP || crypto.subtle.importKey('raw', unb64(raw), 'AES-GCM', false, ['decrypt']);
    return keyP;
  }

  var indexP;
  function index() {
    indexP = indexP || Promise.all([key(), manifest()]).then(async function (r) {
      return JSON.parse(dec.decode(await open(r[0], await fetchBytes(VAULT + r[1].index))));
    });
    return indexP;
  }

  async function unlock(password) {
    var m = await manifest();
    var bits = await deriveAesBits(password, m);
    var k = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']);
    try {
      if (dec.decode(await open(k, unb64(m.check))) !== 'vault-ok') return false;
    } catch (e) {
      return false;
    }
    try { sessionStorage.setItem(KEY, b64(bits)); } catch (e) {}
    keyP = Promise.resolve(k);
    return true;
  }

  function lock() {
    try { sessionStorage.removeItem(KEY); } catch (e) {}
  }

  // Send visitors without a key to the password page, returning them here after.
  function guard() {
    if (storedKey()) return true;
    location.replace(BASE + '?next=' + encodeURIComponent(location.pathname));
    return false;
  }

  var urlCache = {};
  async function assetUrl(rel) {
    if (!urlCache[rel]) {
      urlCache[rel] = Promise.all([key(), index()]).then(async function (r) {
        var entry = r[1].assets[rel];
        if (!entry) throw new Error('vault: unknown asset ' + rel);
        var data = await open(r[0], await fetchBytes(VAULT + entry.file));
        return URL.createObjectURL(new Blob([data], { type: entry.type }));
      });
    }
    return urlCache[rel];
  }

  function hydrate(el, attr) {
    var rel = el.getAttribute('data-vault-' + attr);
    return assetUrl(rel).then(function (url) {
      el.setAttribute(attr, url);
      el.removeAttribute('data-vault-' + attr);
      if (el.tagName === 'SOURCE') el.parentNode.load();
    });
  }

  // Decrypt page fragment `id` into `mount`. Asset references are swapped for
  // placeholders before the markup is live (so nothing requests plaintext
  // paths), then decrypted as they near the viewport.
  async function loadPage(id, mount) {
    var k = await key();
    var idx = await index();
    if (!idx.pages[id]) throw new Error('vault: unknown page ' + id);
    var html = dec.decode(await open(k, await fetchBytes(VAULT + idx.pages[id])));
    var tpl = document.createElement('template');
    tpl.innerHTML = html;
    var pending = [];
    ['src', 'poster'].forEach(function (attr) {
      tpl.content.querySelectorAll('[' + attr + '^="assets/"]').forEach(function (el) {
        el.setAttribute('data-vault-' + attr, el.getAttribute(attr));
        el.removeAttribute(attr);
        pending.push([el, attr]);
      });
    });
    var title = tpl.content.querySelector('[data-title]');
    if (title) document.title = title.getAttribute('data-title');
    mount.replaceChildren(tpl.content);

    var io = 'IntersectionObserver' in window && new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        io.unobserve(e.target);
        e.target._vault.forEach(function (attr) { hydrate(e.target, attr); });
      });
    }, { rootMargin: '1000px 0px' });
    pending.forEach(function (p) {
      var el = p[0];
      var target = el.tagName === 'SOURCE' ? el.parentNode : el;
      if (!io) return hydrate(el, p[1]);
      if (el.tagName === 'SOURCE') return hydrate(el, p[1]);
      (target._vault = target._vault || []).push(p[1]);
      io.observe(target);
    });
  }

  window.Vault = { unlock: unlock, lock: lock, guard: guard, loadPage: loadPage, unlocked: function () { return !!storedKey(); } };
})();
