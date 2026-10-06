#!/usr/bin/env node
// Encrypts the password-protected portfolio content.
//
//   VAULT_PASSWORD=... node scripts/vault.mjs pack      private/  -> stage/vault/
//   VAULT_PASSWORD=... node scripts/vault.mjs unpack    stage/vault/ -> private/
//   VAULT_PASSWORD=... NEW_VAULT_PASSWORD=... node scripts/vault.mjs rekey
//
// private/ holds the plaintext source and is gitignored — it must never be
// committed (the repo is public). Only the ciphertext in stage/vault/ is.
//
// Layout of private/:
//   pages/<id>.html   page fragments, loaded by the shell page with that id
//   assets/**         images/video referenced from pages as src="assets/..."
//
// Crypto: PBKDF2-SHA256 (600k iterations, random salt) -> 256-bit master
// secret -> HKDF into an AES-256-GCM key and an HMAC key. Each file's nonce
// and output name are HMACs of its plaintext, so re-packing unchanged
// content yields byte-identical files (no git churn) and never reuses a
// nonce across different plaintexts. File names reveal nothing about content.

import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const SRC = path.join(ROOT, 'private');
const OUT = path.join(ROOT, 'stage', 'vault');
const MANIFEST = path.join(OUT, 'manifest.json');
const ITERATIONS = 600000;
const CHECK_TEXT = 'vault-ok';

const MIME = {
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.gif': 'image/gif', '.svg': 'image/svg+xml',
  '.mp4': 'video/mp4', '.webm': 'video/webm',
};

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const hex = (buf) => Buffer.from(buf).toString('hex');

function die(msg) {
  console.error('vault: ' + msg);
  process.exit(1);
}

async function deriveKeys(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const master = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256);
  const hkdf = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
  const sub = async (info) => crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) }, hkdf, 256);
  const aes = await crypto.subtle.importKey('raw', await sub('aes-gcm'), 'AES-GCM', false, ['encrypt', 'decrypt']);
  const mac = await crypto.subtle.importKey('raw', await sub('hmac'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return { aes, mac };
}

async function hmac(keys, label, data) {
  const msg = new Uint8Array(label.length + 1 + data.length);
  msg.set(enc.encode(label + ':'), 0);
  msg.set(data, label.length + 1);
  return new Uint8Array(await crypto.subtle.sign('HMAC', keys.mac, msg));
}

async function seal(keys, data) {
  const iv = (await hmac(keys, 'iv', data)).slice(0, 12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, keys.aes, data));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  const name = hex((await hmac(keys, 'name', data)).slice(0, 12)) + '.bin';
  return { name, bytes: out };
}

async function open(keys, bytes) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, keys.aes, bytes.slice(12));
  return new Uint8Array(pt);
}

function readManifest() {
  return fs.existsSync(MANIFEST) ? JSON.parse(fs.readFileSync(MANIFEST, 'utf8')) : null;
}

async function keysFor(password, manifest) {
  const keys = await deriveKeys(password, unb64(manifest.salt), manifest.iterations);
  try {
    const text = dec.decode(await open(keys, unb64(manifest.check)));
    if (text !== CHECK_TEXT) throw new Error();
  } catch {
    die('wrong VAULT_PASSWORD for the existing vault (use `rekey` to change it)');
  }
  return keys;
}

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : e.name.startsWith('.') ? [] : [p];
  });
}

async function pack(password, { newSalt = false } = {}) {
  let manifest = readManifest();
  let keys;
  if (manifest && !newSalt) {
    keys = await keysFor(password, manifest);
  } else {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    keys = await deriveKeys(password, salt, ITERATIONS);
    const check = await seal(keys, enc.encode(CHECK_TEXT));
    manifest = { v: 1, iterations: ITERATIONS, salt: b64(salt), check: b64(check.bytes) };
  }

  fs.mkdirSync(OUT, { recursive: true });
  const written = new Set();
  const write = async (data) => {
    const { name, bytes } = await seal(keys, data);
    fs.writeFileSync(path.join(OUT, name), bytes);
    written.add(name);
    return name;
  };

  const index = { pages: {}, assets: {} };
  for (const file of walk(path.join(SRC, 'assets'))) {
    const rel = path.relative(SRC, file).split(path.sep).join('/');
    const type = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
    index.assets[rel] = { file: await write(fs.readFileSync(file)), type };
  }
  const pageFiles = walk(path.join(SRC, 'pages')).filter((f) => f.endsWith('.html'));
  if (!pageFiles.length) die('no pages found in private/pages/');
  for (const file of pageFiles) {
    const html = fs.readFileSync(file, 'utf8');
    for (const [, ref] of html.matchAll(/\s(?:src|poster)="(assets\/[^"]+)"/g)) {
      if (!index.assets[ref]) die(`${path.relative(ROOT, file)} references missing ${ref}`);
    }
    index.pages[path.basename(file, '.html')] = await write(enc.encode(html));
  }
  manifest.index = await write(enc.encode(JSON.stringify(index)));
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + '\n');

  let removed = 0;
  for (const name of fs.readdirSync(OUT)) {
    if (name.endsWith('.bin') && !written.has(name)) {
      fs.unlinkSync(path.join(OUT, name));
      removed++;
    }
  }
  console.log(`vault: packed ${Object.keys(index.pages).length} pages, ${Object.keys(index.assets).length} assets` +
    (removed ? `, removed ${removed} stale files` : ''));
}

async function unpack(password) {
  const manifest = readManifest();
  if (!manifest) die('no stage/vault/manifest.json to unpack');
  const keys = await keysFor(password, manifest);
  const read = async (name) => open(keys, new Uint8Array(fs.readFileSync(path.join(OUT, name))));
  const index = JSON.parse(dec.decode(await read(manifest.index)));
  const put = (rel, data) => {
    const dest = path.join(SRC, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, data);
  };
  for (const [id, name] of Object.entries(index.pages)) put(`pages/${id}.html`, await read(name));
  for (const [rel, { file }] of Object.entries(index.assets)) put(rel, await read(file));
  console.log(`vault: unpacked ${Object.keys(index.pages).length} pages, ${Object.keys(index.assets).length} assets into private/`);
}

const cmd = process.argv[2];
const password = process.env.VAULT_PASSWORD;
if (!password) die('set VAULT_PASSWORD');

if (cmd === 'pack') {
  await pack(password);
} else if (cmd === 'unpack') {
  await unpack(password);
} else if (cmd === 'rekey') {
  const next = process.env.NEW_VAULT_PASSWORD;
  if (!next) die('set NEW_VAULT_PASSWORD');
  await unpack(password);
  await pack(next, { newSalt: true });
} else {
  die('usage: node scripts/vault.mjs pack|unpack|rekey');
}
