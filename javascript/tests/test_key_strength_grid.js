#!/usr/bin/env node
/** Hash exact BigInt key-family counts across every generated profile. */

'use strict';

const crypto = require('crypto');
const path = require('path');
const enigmak = require(path.join(__dirname, 'enigmak.js'));

const DIGITS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function base36(value, width) {
  return value.toString(36).toUpperCase().padStart(width, '0');
}

function profileKey(layouts, rotors, pairs, noncePresent) {
  const enabled = DIGITS.slice(0, layouts);
  const rotorText = '000'.repeat(rotors);
  let steck = '';
  for (let index = 0; index < pairs; index++) {
    steck += base36(index * 2, 2) + base36(index * 2 + 1, 2);
  }
  if (!steck) steck = '0';
  return `K6:${enabled} ${rotorText} ${steck} 001${noncePresent ? ' 0000000000' : ''}`;
}

const hash = crypto.createHash('sha256');
let count = 0;
const samples = [];
for (let layouts = 1; layouts <= 16; layouts++) {
  for (let rotors = 1; rotors <= 18; rotors++) {
    for (let pairs = 0; pairs <= 81; pairs++) {
      for (const noncePresent of [false, true]) {
        const strength = enigmak.calcKeyStrength(enigmak.parseKey(
          profileKey(layouts, rotors, pairs, noncePresent),
        ));
        const line = `${layouts},${rotors},${pairs},${Number(noncePresent)}:${strength.total}\n`;
        hash.update(line);
        count++;
        if (
          (layouts === 1 && rotors === 1 && pairs === 0)
          || (layouts === 16 && rotors === 18 && pairs === 81)
        ) {
          samples.push({
            layouts,
            rotors,
            pairs,
            noncePresent,
            total: strength.total.toString(),
            bits: strength.familyBits,
          });
        }
      }
    }
  }
}

process.stdout.write(JSON.stringify({
  count,
  digest: hash.digest('hex'),
  samples,
}));
