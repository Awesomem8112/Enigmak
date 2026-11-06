#!/usr/bin/env node
/** Dual-message vectors and fail-closed malformed-input checks. */

'use strict';

const fs = require('fs');
const path = require('path');
const enigmak = require(path.join(__dirname, 'enigmak.js'));

const vectors = JSON.parse(fs.readFileSync(
  path.join(__dirname, '..', 'tests', 'dual_vectors.json'), 'utf8',
));
const WRONG_KEY = 'K6:2 204205 0 060';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertFailure(result, label) {
  assert(!result.success, `${label}: unexpectedly succeeded`);
  assert(!result.verified, `${label}: unexpectedly verified`);
  assert(result.plaintext === '', `${label}: exposed plaintext`);
  assert(result.error === 'Decryption failed.', `${label}: non-generic error`);
}

function mutateRaw(ciphertext, absoluteIndex, bit = 0x80) {
  const raw = Buffer.from(ciphertext, 'base64url');
  raw[absoluteIndex] ^= bit;
  return raw.toString('base64url');
}

const prefixes = new Set();
for (const [name, vector] of Object.entries(vectors)) {
  const bundle = enigmak.encryptDualMessage(
    vector.real_plaintext,
    vector.faux_plaintext,
    {
      realKeyStr: vector.real_key,
      fauxKeyStr: vector.faux_key,
      materialize: vector.materialize,
      envelopeNonce: Buffer.from(vector.nonce_hex, 'hex'),
    },
  );
  assert(bundle.ciphertext === vector.ciphertext, `${name}: pinned bytes differ`);

  const real = enigmak.decrypt(vector.ciphertext, vector.real_key);
  const faux = enigmak.decrypt(vector.ciphertext, vector.faux_key);
  assert(real.success && real.verified, `${name}: intended key failed`);
  assert(faux.success && faux.verified, `${name}: faux key failed`);
  assert(real.plaintext === vector.real_plaintext, `${name}: intended plaintext`);
  assert(faux.plaintext === vector.faux_plaintext, `${name}: faux plaintext`);
  assert(real.format === 'rc.9-dual-v1', `${name}: intended format`);
  assert(faux.format === 'rc.9-dual-v1', `${name}: faux format`);
  assertFailure(enigmak.decrypt(vector.ciphertext, WRONG_KEY), `${name}: wrong key`);
  prefixes.add(vector.ciphertext.slice(0, 4));
}
assert(prefixes.size > 1, 'dual vectors expose a fixed four-character prefix');

const vector = vectors.equal_lengths;
const raw = Buffer.from(vector.ciphertext, 'base64url');
const slotLength = (raw.length - 16) / 2;
const realSlot = (raw[0] & 1) === 0 ? 0 : 1;
const slotStart = 16 + realSlot * slotLength;
const positions = {
  control: slotStart,
  flags: slotStart + 4,
  length: slotStart + 5,
  inner: slotStart + 9,
  filler: slotStart + slotLength - 1,
};
for (const [name, position] of Object.entries(positions)) {
  assertFailure(
    enigmak.decrypt(mutateRaw(vector.ciphertext, position), vector.real_key),
    `tampered ${name}`,
  );
}

for (const malformed of [
  `AAAA${vector.ciphertext}`,
  vector.ciphertext.slice(0, -1),
  `${vector.ciphertext}!`,
  vector.ciphertext.slice(1),
  '',
]) {
  assertFailure(enigmak.decrypt(malformed, vector.real_key), 'malformed envelope');
}

console.log('JavaScript dual-message checks passed');
