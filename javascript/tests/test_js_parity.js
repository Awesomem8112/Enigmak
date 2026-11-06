#!/usr/bin/env node
/** Python ↔ JS parity checks for rc.9 features. */
const path = require('path');
const fs = require('fs');

const enigmak = require(path.join(__dirname, 'enigmak.js'));
const fixtures = JSON.parse(fs.readFileSync(
  path.join(__dirname, '..', 'tests', 'fixtures.json'), 'utf8',
));

const VECTOR1_KEY = fixtures.rc6_hidden_44.key;
const DECOY_COVER = 'Meeting moved to Tuesday';

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
}

for (const [name, fixture] of Object.entries(fixtures)) {
  const options = name === 'rc6_materialized_current' ? { materialize: true } : {};
  const result = enigmak.decrypt(fixture.ciphertext, fixture.key, options);
  assert(result.verified, `${name} did not verify: ${JSON.stringify(result)}`);
  assert(result.plaintext === fixture.plaintext, `${name} plaintext mismatch`);
  assert(result.format === fixture.format, `${name} format mismatch`);
}

const bundle = enigmak.encryptDecoyBundle('real secret', DECOY_COVER, {
  realKeyStr: VECTOR1_KEY,
  decoyKeyStr: fixtures.option_a_decoy.key,
});
const decoy = enigmak.decrypt(bundle.decoy.ciphertext, fixtures.option_a_decoy.key);
assert(decoy.verified && decoy.plaintext === DECOY_COVER, 'decoy round-trip');

const dualVectors = JSON.parse(fs.readFileSync(
  path.join(__dirname, '..', 'tests', 'dual_vectors.json'), 'utf8',
));
for (const [name, vector] of Object.entries(dualVectors)) {
  const dual = enigmak.encryptDualMessage(
    vector.real_plaintext,
    vector.faux_plaintext,
    {
      realKeyStr: vector.real_key,
      fauxKeyStr: vector.faux_key,
      materialize: vector.materialize,
      envelopeNonce: Buffer.from(vector.nonce_hex, 'hex'),
    },
  );
  assert(dual.ciphertext === vector.ciphertext, `${name} dual bytes drifted`);
  const real = enigmak.decrypt(vector.ciphertext, vector.real_key);
  const faux = enigmak.decrypt(vector.ciphertext, vector.faux_key);
  assert(real.verified && real.plaintext === vector.real_plaintext, `${name} intended`);
  assert(faux.verified && faux.plaintext === vector.faux_plaintext, `${name} faux`);
  assert(real.format === 'rc.9-dual-v1' && faux.format === 'rc.9-dual-v1', `${name} format`);
}

const ct1 = enigmak.encrypt('META_TEST', fixtures.rc6_variable_1.key);
const r1 = enigmak.decrypt(ct1, fixtures.rc6_variable_1.key);
assert(r1.verified && r1.plaintext === 'META_TEST', 'metadata ll=1');

console.log('JS parity checks passed');
