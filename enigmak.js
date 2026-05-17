/**
 * ENIGMAK v3.0.0-rc.5 - JavaScript module
 * 95-symbol multi-round substitution-permutation rotor cipher
 *
 * Usage (Node.js):
 *   const { encrypt, decrypt, generateKey, calcIoC } = require('./enigmak.js');
 *   const key = generateKey();
 *   const cipher = encrypt('Hello World!', key);
 *   const plain  = decrypt(cipher, key);
 *
 * Usage (ES module / browser):
 *   import { encrypt, decrypt, generateKey } from './enigmak.js';
 */

'use strict';

const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\\\',./' +
              '!@#$%^&*()_+{}|:"<>?`~' +
              'abcdefghijklmnopqrstuvwxyz ';
const N = ALPHA.length;
const N_BIG = BigInt(N);
const STEP_MASK_ACTIVE = 66;
const CHECKSUM_LEN = 10;
const LEN_FIELD_LEN = 4;
const MAX_PAD_LEN = 16;
const LEGACY_RC3_HEADER = 'E3|';
const RC4_FORMAT_TAG = 'H';
const RC4_VERSION_CHAR = '4';
const HIDDEN_METADATA_LEN = 1 + CHECKSUM_LEN;
const HIDDEN_CHUNK_LEN = 4;
const HIDDEN_SYMBOL_COUNT = HIDDEN_METADATA_LEN * HIDDEN_CHUNK_LEN;
const GENERIC_DECRYPT_ERROR = 'Decryption failed.';
const MAX_CORRUPT_LEN = 4096;
const MIN_GENERATED_KEY_BITS = 213.5;
const U64_MASK = (1n << 64n) - 1n;
const FNV64_OFFSET = 0xcbf29ce484222325n;
const FNV64_PRIME = 0x100000001b3n;
const STEP_MASK_SEED_CONST = 0x5a5a5a5aa55aa55an;
const TRANS_SEED_CONST = 0xdead1234cafebaben;
const LAYOUT_SEED_MIX = 0x9e3779b97f4a7c15n;
const LAYOUT_SEED_CONST = 0xabcd1234badc0ffen;
const WHITENING_SEED_CONST = 0xc0ffee42d15ea5e5n;
const ZERO_WIDTH_SYMBOLS = ['\u200B', '\u200C', '\u200D', '\u2060'];
const ZERO_WIDTH_SET = new Set(ZERO_WIDTH_SYMBOLS);
const ZERO_WIDTH_LABELS = Object.freeze({
  '\u200B': 'ZWSP',
  '\u200C': 'ZWNJ',
  '\u200D': 'ZWJ',
  '\u2060': 'WJ'
});
const CLIPBOARD_NORMALIZATION_MAP = Object.freeze({
  '\u2018': "'",
  '\u2019': "'",
  '\u201C': '"',
  '\u201D': '"',
  '\u2013': '-',
  '\u2014': '-',
  '\u2212': '-',
  '\u00A0': ' ',
  '\u2007': ' ',
  '\u202F': ' ',
  '\u2026': '...'
});

const LAYOUT_NAMES = ['QWERTY','Colemak','Colemak-DH','Dvorak','Workman',
                      'Norman','Asset','Halmak','AZERTY','QWERTZ'];

const LAYOUT_DEFS = {
  'QWERTY': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'qwertyuiop[]\\QWERTYUIOP{}|',
    home: "asdfghjkl;'ASDFGHJKL:\"",
    bot: 'zxcvbnm,./ZXCVBNM<>?',
  },
  'Colemak': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'qwfpgjluy;[]\\QWFPGJLUY:{}|',
    home: "arstdhneio'ARSTDHNEIO\"",
    bot: 'zxcvbkm,./ZXCVBKM<>?',
  },
  'Colemak-DH': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'qwfpbjluy;[]\\QWFPBJLUY:{}|',
    home: "arstgmneio'ARSTGMNEIO\"",
    bot: 'zxcdvkh,./ZXCDVKH<>?',
  },
  'Dvorak': {
    topTop: '`1234567890[]~!@#$%^&*(){}',
    top: "',.pyfgcrl/=\\\"<>PYFGCRL?+|",
    home: 'aoeuidhtns-AOEUIDHTNS_',
    bot: ';qjkxbmwvz:QJKXBMWVZ',
  },
  'Workman': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'qdrwbjfup;[]\\QDRWBJFUP:{}|',
    home: "ashtgyneoi'ASHTGYNEOI\"",
    bot: 'zxmcvkl,./ZXMCVKL<>?',
  },
  'Norman': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'qwdfkjurl;[]\\QWDFKJURL:{}|',
    home: "asetgynioh'ASETGYNIOH\"",
    bot: 'zxcvbpm,./ZXCVBPM<>?',
  },
  'Asset': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'qwjfgypul;[]\\QWJFGYPUL:{}|',
    home: "asetdhnior'ASETDHNIOR\"",
    bot: 'zxcvbkm,./ZXCVBKM<>?',
  },
  'Halmak': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'wlrbjzfuo;[]\\WLRBJZFUO:{}|',
    home: "shntmedaic'SHNTMEDAIC\"",
    bot: 'qgvxpky,./QGVXPKY<>?',
  },
  'AZERTY': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'azertyuiop[]\\AZERTYUIOP{}|',
    home: "qsdfghjkl;'QSDFGHJKL:\"",
    bot: 'wxcvbnm,./WXCVBNM<>?',
  },
  'QWERTZ': {
    topTop: '`1234567890-=~!@#$%^&*()_+',
    top: 'qwertzuiop[]\\QWERTZUIOP{}|',
    home: "asdfghjkl;'ASDFGHJKL:\"",
    bot: 'yxcvbnm,./YXCVBNM<>?',
  },
};

const QTT = '`1234567890-=~!@#$%^&*()_+';
const QT = 'qwertyuiop[]\\QWERTYUIOP{}|';
const QH = "asdfghjkl;'ASDFGHJKL:\"";
const QB = 'zxcvbnm,./ZXCVBNM<>?';

function buildMap(name) {
  const def = LAYOUT_DEFS[name];
  const map = {};
  [
    [QTT, 'topTop'],
    [QT, 'top'],
    [QH, 'home'],
    [QB, 'bot'],
  ].forEach(([ref, rowKey]) => {
    const row = def[rowKey];
    const refHalf = Math.floor(ref.length / 2);
    const half = Math.floor(row.length / 2);
    const refUnshifted = ref.slice(0, refHalf);
    const refShifted = ref.slice(refHalf);
    const layUnshifted = row.slice(0, half);
    const layShifted = row.slice(half);
    [...refUnshifted].forEach((q, i) => {
      const c = layUnshifted[i];
      if (c && ALPHA.includes(c)) map[q] = c;
    });
    [...refShifted].forEach((q, i) => {
      const c = layShifted[i];
      if (c && ALPHA.includes(c)) map[q] = c;
    });
  });
  return map;
}

const MAPS = {};
const INV_MAPS = {};
LAYOUT_NAMES.forEach((name) => {
  MAPS[name] = buildMap(name);
  INV_MAPS[name] = Object.fromEntries(Object.entries(MAPS[name]).map(([k, v]) => [v, k]));
});

function corruptBuffer() {
  let result = '';
  const arr = new Uint32Array(MAX_CORRUPT_LEN);
  getCryptoApi().getRandomValues(arr);
  for (let i = 0; i < MAX_CORRUPT_LEN; i++) {
    let value = arr[i] % 0x110000;
    if (value >= 0xd800 && value <= 0xdfff) value = 0xe000 + ((value - 0xd800) % 0x1900);
    result += String.fromCodePoint(value);
  }
  return result;
}

function randomPermutation() {
  const items = [...Array(N).keys()];
  const rng = getCryptoApi();
  for (let i = items.length - 1; i > 0; i--) {
    const j = randInt(rng, i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

function randomKeyInt(value) {
  const arr = new Uint32Array(2);
  getCryptoApi().getRandomValues(arr);
  const random = (BigInt(arr[0]) << 32n) | BigInt(arr[1]);
  return typeof value === 'bigint' ? random : Number(arr[0]);
}

function corruptKeyMaterial(keyMaterial) {
  if (!keyMaterial || typeof keyMaterial !== 'object') return;
  [
    'keySum', 'keySumLo', 'keySumHi', 'keySumFold', 'macSubkey', 'whiteningSeed', 'rounds',
    'key_sum', 'key_sum_lo', 'key_sum_hi', 'key_sum_fold', 'mac_subkey', 'whitening_seed',
  ].forEach((field) => {
    keyMaterial[field] = randomKeyInt(keyMaterial[field]);
  });
  keyMaterial.stepMask = Array.from({ length: N }, () => Boolean(randInt(getCryptoApi(), 2)));
  keyMaterial.step_mask = Array.from({ length: N }, () => Boolean(randInt(getCryptoApi(), 2)));
  keyMaterial.transPerm = randomPermutation();
  keyMaterial.invTransPerm = randomPermutation();
  keyMaterial.trans_perm = randomPermutation();
  keyMaterial.inv_trans_perm = randomPermutation();
  ['layoutMaps', 'invLayoutMaps', 'layout_maps', 'inv_layout_maps'].forEach((field) => {
    const maps = keyMaterial[field];
    if (!maps || typeof maps !== 'object') return;
    Object.keys(maps).forEach((name) => {
      maps[name] = {};
    });
  });
}

function corruptCipherState(cipherState) {
  if (!cipherState || typeof cipherState !== 'object') return;
  if (Array.isArray(cipherState.rotors)) {
    cipherState.rotors.forEach((rotor) => {
      if (rotor && typeof rotor === 'object') rotor.pos = randInt(getCryptoApi(), N);
    });
  }
  if (Object.prototype.hasOwnProperty.call(cipherState, 'steckMap')) cipherState.steckMap = {};
  if (Object.prototype.hasOwnProperty.call(cipherState, 'steck_map')) cipherState.steck_map = {};
  corruptKeyMaterial(cipherState.km);
}

function genericDecryptFailure(result, partialText = '', keyStr = null, keyMaterial = null, cipherState = null) {
  let partialPlaintext = partialText ?? result.plaintext ?? '';
  let corrupt = corruptBuffer();
  partialPlaintext = corrupt;
  corrupt = '';
  if (keyStr !== null && keyStr !== undefined) keyStr = corruptBuffer();
  corruptKeyMaterial(keyMaterial);
  corruptCipherState(cipherState);
  const failed = {
    ...result,
    plaintext: '',
    verified: false,
    success: false,
    checksumOk: false,
    paddingOk: false,
    metadataOk: false,
    versionOk: false,
    error: GENERIC_DECRYPT_ERROR,
  };
  ['payload', 'visiblePayload', 'hiddenCipher', 'hiddenPayload', 'padding', 'lengthField', 'version'].forEach((field) => {
    if (Object.prototype.hasOwnProperty.call(failed, field)) failed[field] = '';
  });
  return failed;
}

function finalizeDecryptResult(result, partialText = '', keyStr = null, keyMaterial = null, cipherState = null) {
  result.success = Boolean(result.verified);
  if (result.success) {
    result.error = null;
    return result;
  }
  return genericDecryptFailure(result, partialText, keyStr, keyMaterial, cipherState);
}

function hashStr32(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

function lcg64(v) {
  return (v * 6364136223846793005n + 1442695040888963407n) & U64_MASK;
}

function hashStr64(s) {
  const bytes = new TextEncoder().encode(s);
  let h = FNV64_OFFSET;
  for (const b of bytes) {
    h ^= BigInt(b);
    h = (h * FNV64_PRIME) & U64_MASK;
  }
  return h;
}

function deriveMacSubkey(keyStr) {
  // Separate MAC subkey prevents key reuse between encryption and authentication
  return hashStr64(keyStr + '\x01enigmak-mac').toString();
}

function shuffleIndicesWithSeed(size, seed) {
  const items = [...Array(size).keys()];
  let state = seed & U64_MASK;
  for (let i = items.length - 1; i > 0; i--) {
    state = lcg64(state ^ BigInt(i));
    const j = Number(state % BigInt(i + 1));
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

function rotorStateHash(rotors) {
  let h = FNV64_OFFSET;
  rotors.forEach((rotor, index) => {
    h ^= (BigInt(rotor.pos * 73 + index + 1)) & U64_MASK;
    h = (h * FNV64_PRIME) & U64_MASK;
  });
  return h;
}

function computeKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds) {
  const steckSum = steckPairs.reduce((acc, [a, b]) => {
    const ai = ALPHA.indexOf(a);
    const bi = ALPHA.indexOf(b);
    const lo = Math.min(ai, bi);
    const hi = Math.max(ai, bi);
    return acc + BigInt(lo * N + hi);
  }, 0n);
  const rotorSum = rotors.reduce((acc, rotor) => acc + BigInt(rotor.pos), 0n);
  const layoutSum = [...enabledLayouts].reduce((acc, name) => acc + BigInt(LAYOUT_NAMES.indexOf(name)), 0n);
  const rounds = Number((steckSum + rotorSum + layoutSum + BigInt(userRounds)) % 999n) + 1;
  const keySum = (steckSum * 31n + rotorSum * 17n + layoutSum * 13n) & U64_MASK;

  const stepPos = shuffleIndicesWithSeed(N, keySum ^ STEP_MASK_SEED_CONST);
  const stepMask = new Array(N).fill(false);
  stepPos.slice(0, STEP_MASK_ACTIVE).forEach((pos) => { stepMask[pos] = true; });

  const transPerm = shuffleIndicesWithSeed(N, keySum ^ TRANS_SEED_CONST);
  const invTransPerm = new Array(N);
  transPerm.forEach((value, index) => { invTransPerm[value] = index; });

  const layoutMaps = {};
  const invLayoutMaps = {};
  LAYOUT_NAMES.forEach((name, layoutIndex) => {
    const perm = shuffleIndicesWithSeed(
      N,
      (keySum ^ ((BigInt(layoutIndex + 1) * LAYOUT_SEED_MIX + LAYOUT_SEED_CONST) & U64_MASK)) & U64_MASK
    );
    const fwd = {};
    const inv = {};
    for (let i = 0; i < N; i++) {
      fwd[ALPHA[i]] = ALPHA[perm[i]];
      inv[ALPHA[perm[i]]] = ALPHA[i];
    }
    layoutMaps[name] = fwd;
    invLayoutMaps[name] = inv;
  });

  return {
    rounds,
    keySum,
    stepMask,
    transPerm,
    invTransPerm,
    layoutKeyBase: Number(keySum % N_BIG),
    layoutMaps,
    invLayoutMaps,
    whiteningSeed: (keySum ^ WHITENING_SEED_CONST) & U64_MASK,
  };
}

function keyedLayoutOffset(name, layoutKeyBase) {
  return (LAYOUT_NAMES.indexOf(name) * 7 + layoutKeyBase) % N;
}

function rotorShift(rotors) {
  let value = 0n;
  rotors.forEach((rotor, index) => {
    value += BigInt(rotor.pos) * (N_BIG ** BigInt(rotors.length - 1 - index));
  });
  return Number(value % N_BIG);
}

function advanceRotors(rotors, charIndex, stepMask) {
  if (!stepMask[charIndex % N]) return rotors.map((rotor) => ({ ...rotor }));
  const next = rotors.map((rotor) => ({ ...rotor }));
  next[next.length - 1].pos = (next[next.length - 1].pos + 1) % N;
  for (let i = next.length - 1; i > 0; i--) {
    if (next[i].pos === 0) next[i - 1].pos = (next[i - 1].pos + 1) % N;
  }
  return next;
}

function applyNonce(rotors, nonce) {
  if (!nonce) return rotors;
  return rotors.map((rotor, index) => {
    const offset = index < nonce.length ? ALPHA.indexOf(nonce[index]) : 0;
    return { ...rotor, pos: (rotor.pos + Math.max(offset, 0)) % N };
  });
}

function applyLayout(char, layoutName, shift, invert, layoutMaps, invLayoutMaps) {
  if (!invert) {
    let value = layoutMaps[layoutName]?.[char] ?? char;
    if (ALPHA.includes(value)) value = ALPHA[(ALPHA.indexOf(value) + shift) % N];
    return value;
  }
  let value = char;
  if (ALPHA.includes(value)) value = ALPHA[(ALPHA.indexOf(value) - shift + N * 100) % N];
  return invLayoutMaps[layoutName]?.[value] ?? value;
}

function plugFwd(char, layouts, layoutMaps) {
  let value = char;
  for (const name of layouts) value = layoutMaps[name]?.[value] ?? value;
  return value;
}

function plugInv(char, layouts, invLayoutMaps) {
  let value = char;
  for (let i = layouts.length - 1; i >= 0; i--) value = invLayoutMaps[layouts[i]]?.[value] ?? value;
  return value;
}

function createCipherState(steckPairs, rotors, enabledLayouts, userRounds, nonce = '') {
  const km = computeKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds);
  const steckMap = {};
  for (const char of ALPHA) steckMap[char] = char;
  steckPairs.forEach(([a, b]) => {
    steckMap[a] = b;
    steckMap[b] = a;
  });
  const enabledList = [...enabledLayouts];
  const rotorSet = new Set(rotors.map((rotor) => rotor.layout));
  const unusedLayouts = enabledList.filter((name) => !rotorSet.has(name));
  return {
    km,
    steckMap,
    enabledList,
    unusedLayouts,
    rotors: applyNonce(rotors.map((rotor) => ({ ...rotor })), nonce),
    whiteningState: km.whiteningSeed,
    alphaIndex: 0,
  };
}

function processSegment(text, state, decrypt = false) {
  const { km, steckMap, enabledList, unusedLayouts } = state;
  const layoutMaps = km.layoutMaps;
  const invLayoutMaps = km.invLayoutMaps;
  const rounds = km.rounds;
  let result = '';

  for (const char of text) {
    if (!ALPHA.includes(char)) {
      result += char;
      continue;
    }

    const ci = state.alphaIndex;
    const shiftSeed = rotorShift(state.rotors);
    const rsHash = rotorStateHash(state.rotors);
    const posOffset = Number((km.keySum * 37n + BigInt(ci) * 13n + rsHash) % N_BIG);
    const roundLayouts = [];
    const roundShifts = [];
    for (let r = 0; r < rounds; r++) {
      const layoutName = enabledList[r % enabledList.length];
      roundLayouts.push(layoutName);
      roundShifts.push((shiftSeed + r + ci + posOffset + keyedLayoutOffset(layoutName, km.layoutKeyBase)) % N);
    }
    const scrambleShifts = unusedLayouts.map((name, index) =>
      (shiftSeed + rounds + index + ci + posOffset + keyedLayoutOffset(name, km.layoutKeyBase)) % N
    );

    let value = char;
    if (!decrypt) {
      value = steckMap[value] ?? value;
      value = plugFwd(value, unusedLayouts, layoutMaps);
      for (let r = 0; r < rounds; r++) {
        value = applyLayout(value, roundLayouts[r], roundShifts[r], false, layoutMaps, invLayoutMaps);
      }
      if (ALPHA.includes(value)) value = ALPHA[km.transPerm[ALPHA.indexOf(value)]];
      unusedLayouts.forEach((name, index) => {
        value = applyLayout(value, name, scrambleShifts[index], false, layoutMaps, invLayoutMaps);
      });
      value = plugFwd(value, unusedLayouts, layoutMaps);
      value = steckMap[value] ?? value;
      state.whiteningState = lcg64(state.whiteningState);
      if (ALPHA.includes(value)) value = ALPHA[(ALPHA.indexOf(value) + Number(state.whiteningState % N_BIG)) % N];
    } else {
      state.whiteningState = lcg64(state.whiteningState);
      if (ALPHA.includes(value)) value = ALPHA[(ALPHA.indexOf(value) - Number(state.whiteningState % N_BIG) + N * 100) % N];
      value = steckMap[value] ?? value;
      value = plugInv(value, unusedLayouts, invLayoutMaps);
      for (let i = unusedLayouts.length - 1; i >= 0; i--) {
        value = applyLayout(value, unusedLayouts[i], scrambleShifts[i], true, layoutMaps, invLayoutMaps);
      }
      if (ALPHA.includes(value)) value = ALPHA[km.invTransPerm[ALPHA.indexOf(value)]];
      for (let r = rounds - 1; r >= 0; r--) {
        value = applyLayout(value, roundLayouts[r], roundShifts[r], true, layoutMaps, invLayoutMaps);
      }
      value = plugInv(value, unusedLayouts, invLayoutMaps);
      value = steckMap[value] ?? value;
    }

    result += value;
    state.rotors = advanceRotors(state.rotors, ci, km.stepMask);
    state.alphaIndex += 1;
  }

  return result;
}

function lcg32(v) {
  return (Math.imul(v, 1664525) + 1013904223) >>> 0;
}

function legacyRotorStateHash(rotors) {
  let h = 2166136261;
  for (const rotor of rotors) {
    h ^= rotor.pos * 73;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

function computeLegacyKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds) {
  const steckSum = steckPairs.reduce((acc, [a, b]) => {
    const ai = ALPHA.indexOf(a);
    const bi = ALPHA.indexOf(b);
    const lo = Math.min(ai, bi);
    const hi = Math.max(ai, bi);
    return acc + (lo * N + hi);
  }, 0);
  const rotorSum = rotors.reduce((acc, rotor) => acc + rotor.pos, 0);
  const layoutSum = [...enabledLayouts].reduce((acc, name) => acc + LAYOUT_NAMES.indexOf(name), 0);
  const rounds = ((steckSum + rotorSum + layoutSum + userRounds) % 999) + 1;
  const keySum = (steckSum * 31 + rotorSum * 17 + layoutSum * 13) >>> 0;

  const stepPos = [...Array(N).keys()];
  let state = (keySum ^ 0x5a5a5a5a) >>> 0;
  for (let i = N - 1; i > 0; i--) {
    state = lcg32(state);
    const j = state % (i + 1);
    [stepPos[i], stepPos[j]] = [stepPos[j], stepPos[i]];
  }
  const stepMask = new Array(N).fill(false);
  stepPos.slice(0, STEP_MASK_ACTIVE).forEach((pos) => { stepMask[pos] = true; });

  const transPerm = [...Array(N).keys()];
  state = (keySum ^ 0xdead1234) >>> 0;
  for (let i = N - 1; i > 0; i--) {
    state = lcg32(state);
    const j = state % (i + 1);
    [transPerm[i], transPerm[j]] = [transPerm[j], transPerm[i]];
  }
  const invTransPerm = new Array(N);
  transPerm.forEach((value, index) => { invTransPerm[value] = index; });

  const layoutMaps = {};
  const invLayoutMaps = {};
  LAYOUT_NAMES.forEach((name, layoutIndex) => {
    const perm = [...Array(N).keys()];
    let seed = ((keySum ^ (layoutIndex * 0x9E3779B9 + 0xABCD1234)) >>> 0);
    for (let i = N - 1; i > 0; i--) {
      seed = lcg32(seed);
      const j = seed % (i + 1);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    const fwd = {};
    const inv = {};
    for (let i = 0; i < N; i++) {
      fwd[ALPHA[i]] = ALPHA[perm[i]];
      inv[ALPHA[perm[i]]] = ALPHA[i];
    }
    layoutMaps[name] = fwd;
    invLayoutMaps[name] = inv;
  });

  return {
    rounds,
    keySum,
    stepMask,
    transPerm,
    invTransPerm,
    layoutKeyBase: keySum % N,
    layoutMaps,
    invLayoutMaps,
    whiteningSeed: (keySum ^ 0xC0FFEE42) >>> 0,
  };
}

function createLegacyCipherState(steckPairs, rotors, enabledLayouts, userRounds, nonce = '') {
  const km = computeLegacyKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds);
  const steckMap = {};
  for (const char of ALPHA) steckMap[char] = char;
  steckPairs.forEach(([a, b]) => {
    steckMap[a] = b;
    steckMap[b] = a;
  });
  const enabledList = [...enabledLayouts];
  const rotorSet = new Set(rotors.map((rotor) => rotor.layout));
  const unusedLayouts = enabledList.filter((name) => !rotorSet.has(name));
  return {
    km,
    steckMap,
    enabledList,
    unusedLayouts,
    rotors: applyNonce(rotors.map((rotor) => ({ ...rotor })), nonce),
    whiteningState: km.whiteningSeed,
    alphaIndex: 0,
  };
}

function processLegacySegment(text, state, decrypt = false) {
  const { km, steckMap, enabledList, unusedLayouts } = state;
  const layoutMaps = km.layoutMaps;
  const invLayoutMaps = km.invLayoutMaps;
  const rounds = km.rounds;
  let result = '';

  for (const char of text) {
    if (!ALPHA.includes(char)) {
      result += char;
      continue;
    }

    const ci = state.alphaIndex;
    const shiftSeed = rotorShift(state.rotors);
    const rsHash = legacyRotorStateHash(state.rotors);
    const posOffset = ((km.layoutKeyBase * 37 + ci * 13 + rsHash) >>> 0) % N;
    const roundLayouts = [];
    const roundShifts = [];
    for (let r = 0; r < rounds; r++) {
      const layoutName = enabledList[r % enabledList.length];
      roundLayouts.push(layoutName);
      roundShifts.push((shiftSeed + r + ci + posOffset + keyedLayoutOffset(layoutName, km.layoutKeyBase)) % N);
    }
    const scrambleShifts = unusedLayouts.map((name, index) =>
      (shiftSeed + rounds + index + ci + posOffset + keyedLayoutOffset(name, km.layoutKeyBase)) % N
    );

    let value = char;
    if (!decrypt) {
      value = steckMap[value] ?? value;
      value = plugFwd(value, unusedLayouts, layoutMaps);
      for (let r = 0; r < rounds; r++) {
        value = applyLayout(value, roundLayouts[r], roundShifts[r], false, layoutMaps, invLayoutMaps);
      }
      if (ALPHA.includes(value)) value = ALPHA[km.transPerm[ALPHA.indexOf(value)]];
      unusedLayouts.forEach((name, index) => {
        value = applyLayout(value, name, scrambleShifts[index], false, layoutMaps, invLayoutMaps);
      });
      value = plugFwd(value, unusedLayouts, layoutMaps);
      value = steckMap[value] ?? value;
      state.whiteningState = lcg32(state.whiteningState);
      if (ALPHA.includes(value)) value = ALPHA[(ALPHA.indexOf(value) + state.whiteningState % N) % N];
    } else {
      state.whiteningState = lcg32(state.whiteningState);
      if (ALPHA.includes(value)) value = ALPHA[(ALPHA.indexOf(value) - state.whiteningState % N + N * 100) % N];
      value = steckMap[value] ?? value;
      value = plugInv(value, unusedLayouts, invLayoutMaps);
      for (let i = unusedLayouts.length - 1; i >= 0; i--) {
        value = applyLayout(value, unusedLayouts[i], scrambleShifts[i], true, layoutMaps, invLayoutMaps);
      }
      if (ALPHA.includes(value)) value = ALPHA[km.invTransPerm[ALPHA.indexOf(value)]];
      for (let r = rounds - 1; r >= 0; r--) {
        value = applyLayout(value, roundLayouts[r], roundShifts[r], true, layoutMaps, invLayoutMaps);
      }
      value = plugInv(value, unusedLayouts, invLayoutMaps);
      value = steckMap[value] ?? value;
    }

    result += value;
    state.rotors = advanceRotors(state.rotors, ci, km.stepMask);
    state.alphaIndex += 1;
  }

  return result;
}

function encodeBase95Int(value, width) {
  if (value < 0) throw new Error('Base-95 encoding requires a non-negative integer');
  const chars = Array(width).fill('0');
  let current = value;
  for (let i = width - 1; i >= 0; i--) {
    chars[i] = ALPHA[current % N];
    current = Math.floor(current / N);
  }
  if (current !== 0) throw new Error(`Value exceeds ${width} base-95 characters`);
  return chars.join('');
}

function decodeBase95Int(text) {
  let value = 0;
  for (const char of text) {
    const index = ALPHA.indexOf(char);
    if (index < 0) throw new Error(`Non-alphabet character in base-95 field: ${JSON.stringify(char)}`);
    value = value * N + index;
  }
  return value;
}

function encodeLengthField(length) {
  return encodeBase95Int(length, LEN_FIELD_LEN);
}

function decodeLengthField(field) {
  if (field.length !== LEN_FIELD_LEN) throw new Error(`Length field must be ${LEN_FIELD_LEN} characters`);
  return decodeBase95Int(field);
}

function computeChecksum(checksumInput, keyStr, versionChar = RC4_VERSION_CHAR) {
  let out = '';
  let state = hashStr64(`${checksumInput}|${keyStr}|${versionChar}|chk64`);
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    state = lcg64(state ^ BigInt(i));
    out += ALPHA[Number(state % N_BIG)];
  }
  return out;
}

function computePaddingSeed(plaintext, keyStr, lenField = null, versionChar = RC4_VERSION_CHAR) {
  const field = lenField ?? encodeLengthField(plaintext.length);
  return computeChecksum(`${field}|${plaintext}`, keyStr, versionChar);
}

function computeRc3Checksum(plaintext, keyStr, lenField = null) {
  const field = lenField ?? encodeLengthField(plaintext.length);
  let out = '';
  let state = hashStr64(`${field}|${plaintext}|${keyStr}|chk64`);
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    state = lcg64(state ^ BigInt(i));
    out += ALPHA[Number(state % N_BIG)];
  }
  return out;
}

function legacyComputeChecksum(plaintext, keyStr) {
  let out = '';
  let state = hashStr64(`${plaintext}|${keyStr}|chk64`);
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    state = lcg64(state ^ BigInt(i));
    out += ALPHA[Number(state % N_BIG)];
  }
  return out;
}

function legacyChecksumPos(keyStr, totalLen) {
  return hashStr32(`${keyStr}chkpos`) % Math.max(1, totalLen - CHECKSUM_LEN);
}

function computePadLength(plaintext, keyStr, checksum, versionChar) {
  let length = Number(hashStr64(`${keyStr}|${plaintext}|${checksum}|${versionChar}|padlen`) % BigInt(MAX_PAD_LEN));
  if (plaintext.length === 0 && length === 0) length = 1;
  return length;
}

function generatePadding(plaintext, keyStr, checksum, versionChar, padLen = null) {
  const targetLen = padLen ?? computePadLength(plaintext, keyStr, checksum, versionChar);
  if (targetLen === 0) return '';
  let out = '';
  let state = hashStr64(`${keyStr}|${plaintext}|${checksum}|${versionChar}|padfill`);
  for (let i = 0; i < targetLen; i++) {
    state = lcg64(state ^ BigInt(i));
    out += ALPHA[Number(state % N_BIG)];
  }
  return out;
}

function computeRc3PadLength(plaintext, keyStr) {
  return Number(hashStr64(`${keyStr}|${plaintext}|padlen`) % BigInt(MAX_PAD_LEN));
}

function generateRc3Padding(plaintext, keyStr, padLen = null) {
  const targetLen = padLen ?? computeRc3PadLength(plaintext, keyStr);
  if (targetLen === 0) return '';
  let out = '';
  let state = hashStr64(`${keyStr}|${plaintext}|padfill`);
  for (let i = 0; i < targetLen; i++) {
    state = lcg64(state ^ BigInt(i));
    out += ALPHA[Number(state % N_BIG)];
  }
  return out;
}

function packRc4Payload(plaintext, keyStr) {
  const version = RC4_VERSION_CHAR;
  const lengthField = encodeLengthField(plaintext.length);
  const paddingSeed = computePaddingSeed(plaintext, keyStr, lengthField, version);
  const padding = generatePadding(plaintext, keyStr, paddingSeed, version);
  return {
    visiblePayload: RC4_FORMAT_TAG + lengthField + plaintext + padding,
    version,
    lengthField,
    padding,
    paddingSeed,
  };
}

function packRc3Payload(plaintext, keyStr) {
  const lengthField = encodeLengthField(plaintext.length);
  const checksum = computeRc3Checksum(plaintext, keyStr, lengthField);
  const padding = generateRc3Padding(plaintext, keyStr);
  return lengthField + plaintext + checksum + padding;
}

function unpackRc3Payload(payload, keyStr) {
  const minLen = LEN_FIELD_LEN + CHECKSUM_LEN;
  if (payload.length < minLen) {
    return {
      plaintext: '',
      verified: false,
      checksumOk: false,
      paddingOk: false,
      structureOk: false,
      lengthField: '',
      padding: '',
      error: GENERIC_DECRYPT_ERROR,
    };
  }

  const lengthField = payload.slice(0, LEN_FIELD_LEN);
  let plaintextLength;
  try {
    plaintextLength = decodeLengthField(lengthField);
  } catch (error) {
    return {
      plaintext: '',
      verified: false,
      checksumOk: false,
      paddingOk: false,
      structureOk: false,
      lengthField,
      padding: '',
      error: error.message,
    };
  }

  const remaining = payload.slice(LEN_FIELD_LEN);
  if (plaintextLength > remaining.length - CHECKSUM_LEN) {
    return {
      plaintext: '',
      verified: false,
      checksumOk: false,
      paddingOk: false,
      structureOk: false,
      lengthField,
      padding: '',
      error: `Length field decodes to ${plaintextLength}, but payload only has ${remaining.length} chars after the header`,
    };
  }

  const plaintext = remaining.slice(0, plaintextLength);
  const checksum = remaining.slice(plaintextLength, plaintextLength + CHECKSUM_LEN);
  const padding = remaining.slice(plaintextLength + CHECKSUM_LEN);
  const checksumOk = checksum === computeRc3Checksum(plaintext, keyStr, lengthField);
  const expectedPadLen = computeRc3PadLength(plaintext, keyStr);
  const expectedPadding = generateRc3Padding(plaintext, keyStr, expectedPadLen);
  const paddingOk = padding.length === expectedPadLen && padding === expectedPadding;
  return {
    plaintext,
    verified: checksumOk && paddingOk,
    checksumOk,
    paddingOk,
    structureOk: true,
    lengthField,
    padding,
    error: checksumOk && paddingOk ? null : GENERIC_DECRYPT_ERROR,
  };
}

function unpackRc4VisiblePayload(payload) {
  const minLen = 1 + LEN_FIELD_LEN;
  if (payload.length < minLen) {
    return {
      formatTag: '',
      plaintext: '',
      verified: false,
      structureOk: false,
      checksumOk: false,
      paddingOk: false,
      metadataOk: false,
      versionOk: false,
      lengthField: '',
      padding: '',
      error: GENERIC_DECRYPT_ERROR,
    };
  }

  const formatTag = payload[0];
  if (formatTag !== RC4_FORMAT_TAG) {
    return {
      formatTag,
      plaintext: '',
      verified: false,
      structureOk: false,
      checksumOk: false,
      paddingOk: false,
      metadataOk: false,
      versionOk: false,
      lengthField: '',
      padding: '',
      error: GENERIC_DECRYPT_ERROR,
    };
  }

  const lengthField = payload.slice(1, 1 + LEN_FIELD_LEN);
  let plaintextLength;
  try {
    plaintextLength = decodeLengthField(lengthField);
  } catch (error) {
    return {
      formatTag,
      plaintext: '',
      verified: false,
      structureOk: false,
      checksumOk: false,
      paddingOk: false,
      metadataOk: false,
      versionOk: false,
      lengthField,
      padding: '',
      error: error.message,
    };
  }

  const remaining = payload.slice(1 + LEN_FIELD_LEN);
  if (plaintextLength > remaining.length) {
    return {
      formatTag,
      plaintext: '',
      verified: false,
      structureOk: false,
      checksumOk: false,
      paddingOk: false,
      metadataOk: false,
      versionOk: false,
      lengthField,
      padding: '',
      error: `Length field decodes to ${plaintextLength}, but visible payload only has ${remaining.length} chars after the header`,
    };
  }

  return {
    formatTag,
    plaintext: remaining.slice(0, plaintextLength),
    padding: remaining.slice(plaintextLength),
    lengthField,
    structureOk: true,
    verified: false,
    checksumOk: false,
    paddingOk: false,
    metadataOk: false,
    versionOk: false,
    error: null,
  };
}

function keyedZeroWidthOrder(keyStr) {
  const symbols = [...ZERO_WIDTH_SYMBOLS];
  let state = hashStr64(`${keyStr}|zwperm`);
  for (let i = symbols.length - 1; i > 0; i--) {
    state = lcg64(state ^ BigInt(i));
    const j = Number(state % BigInt(i + 1));
    [symbols[i], symbols[j]] = [symbols[j], symbols[i]];
  }
  return symbols;
}

function encodeHiddenCarrierChars(hiddenCipher, keyStr) {
  const order = keyedZeroWidthOrder(keyStr);
  let out = '';
  for (const char of hiddenCipher) {
    const index = ALPHA.indexOf(char);
    if (index < 0) throw new Error(`Hidden metadata character is outside ALPHA: ${JSON.stringify(char)}`);
    const digits = [0, 0, 0, 0];
    let value = index;
    for (let i = digits.length - 1; i >= 0; i--) {
      digits[i] = value % 4;
      value = Math.floor(value / 4);
    }
    digits.forEach((digit) => { out += order[digit]; });
  }
  return out;
}

function injectHiddenCarriers(visibleCipher, carrierStream, keyStr) {
  const gapCount = visibleCipher.length + 1;
  const counts = new Array(gapCount).fill(0);
  let state = hashStr64(`${keyStr}|${visibleCipher.length}|zwscatter`);
  for (let i = 0; i < carrierStream.length; i++) {
    state = lcg64(state ^ BigInt(i));
    counts[Number(state % BigInt(gapCount))] += 1;
  }

  let cursor = 0;
  let out = '';
  for (let gap = 0; gap < gapCount; gap++) {
    if (counts[gap] > 0) {
      out += carrierStream.slice(cursor, cursor + counts[gap]);
      cursor += counts[gap];
    }
    if (gap < visibleCipher.length) out += visibleCipher[gap];
  }
  return out;
}

function extractCarrierInfo(text) {
  let visibleText = '';
  let carrierStream = '';
  const positions = [];
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (ZERO_WIDTH_SET.has(char)) {
      carrierStream += char;
      positions.push({ pos: i + 1, char });
    } else {
      visibleText += char;
    }
  }
  return {
    visibleText,
    carrierStream,
    hiddenCarrierCount: carrierStream.length,
    hiddenCarrierPositions: positions,
  };
}

function decodeHiddenCarrierStream(carrierStream, keyStr) {
  if (carrierStream.length % HIDDEN_CHUNK_LEN !== 0) {
    throw new Error(`Hidden metadata carrier count must be a multiple of ${HIDDEN_CHUNK_LEN}`);
  }
  const order = keyedZeroWidthOrder(keyStr);
  const reverse = new Map(order.map((symbol, index) => [symbol, index]));
  let out = '';
  for (let i = 0; i < carrierStream.length; i += HIDDEN_CHUNK_LEN) {
    let value = 0;
    for (let j = 0; j < HIDDEN_CHUNK_LEN; j++) {
      const digit = reverse.get(carrierStream[i + j]);
      if (digit === undefined) throw new Error('Unknown hidden metadata carrier symbol detected');
      value = value * 4 + digit;
    }
    if (value >= N) throw new Error(`Hidden metadata digit block decodes outside ALPHA: ${value}`);
    out += ALPHA[value];
  }
  return out;
}

function formatCipherChar(char) {
  if (ZERO_WIDTH_LABELS[char]) return ZERO_WIDTH_LABELS[char];
  if (char === ' ') return '[space]';
  if (char === '\n') return '\\n';
  if (char === '\r') return '\\r';
  if (char === '\t') return '\\t';
  return char;
}

function summarizeCipherIssues(entries) {
  const shown = entries.slice(0, 4).map(({ pos, char, replacement }) => {
    const base = `${formatCipherChar(char)}@${pos}`;
    return replacement === undefined ? base : `${base}->${formatCipherChar(replacement)}`;
  });
  if (entries.length > 4) shown.push(`+${entries.length - 4} more`);
  return shown.join(', ');
}

function analyzeCiphertext(text) {
  const nonAscii = [];
  const normalized = [];
  const controls = [];
  const hiddenCarriers = [];
  let outsideAlphabetCount = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (ALPHA.includes(char)) continue;
    if (ZERO_WIDTH_SET.has(char)) {
      hiddenCarriers.push({ pos: i + 1, char });
      continue;
    }
    outsideAlphabetCount++;
    if (Object.prototype.hasOwnProperty.call(CLIPBOARD_NORMALIZATION_MAP, char)) {
      normalized.push({ pos: i + 1, char, replacement: CLIPBOARD_NORMALIZATION_MAP[char] });
    }
    if (char === '\r' || char === '\n' || char === '\t') controls.push({ pos: i + 1, char });
    if (char.charCodeAt(0) > 127) {
      nonAscii.push({
        pos: i + 1,
        char,
        replacement: Object.prototype.hasOwnProperty.call(CLIPBOARD_NORMALIZATION_MAP, char)
          ? CLIPBOARD_NORMALIZATION_MAP[char]
          : undefined,
      });
    }
  }
  const warnings = [];
  if (normalized.length) warnings.push(`Suspicious clipboard-normalized punctuation: ${summarizeCipherIssues(normalized)}`);
  else if (nonAscii.length) warnings.push(`Non-ASCII ciphertext characters detected: ${summarizeCipherIssues(nonAscii)}`);
  if (controls.length) warnings.push(`Whitespace/control characters detected: ${summarizeCipherIssues(controls)}`);
  if (hiddenCarriers.length > 0 && hiddenCarriers.length % HIDDEN_CHUNK_LEN !== 0) {
    warnings.push(`Hidden metadata carrier count looks damaged: ${hiddenCarriers.length} markers`);
  }
  return {
    length: text.length,
    visibleLength: text.length - hiddenCarriers.length,
    outsideAlphabetCount,
    nonAscii,
    normalized,
    controls,
    hiddenCarriers,
    hiddenCarrierCount: hiddenCarriers.length,
    warnings,
  };
}

function parseKey(keyStr) {
  const parts = keyStr.trim().split(/\s+/);
  if (parts.length < 4 || parts.length > 5) throw new Error('Expected 4 or 5 space-separated sections');
  const [enabledStr, rotorStr, steckStr, roundsStr, nonceStr] = parts;
  const enabled = new Set([...enabledStr].map((char) => {
    const index = parseInt(char, 10);
    if (!Number.isInteger(index) || index < 0 || index >= LAYOUT_NAMES.length) {
      throw new Error(`Invalid enabled layout digit: ${JSON.stringify(char)}`);
    }
    return LAYOUT_NAMES[index];
  }));
  const rotors = [];
  if (!rotorStr || rotorStr.length % 3 !== 0) throw new Error('Rotor section must be groups of 3 digits');
  for (let i = 0; i < rotorStr.length; i += 3) {
    const layoutIndex = parseInt(rotorStr[i], 10);
    const pos = parseInt(rotorStr.slice(i + 1, i + 3), 10);
    if (!Number.isInteger(layoutIndex) || layoutIndex < 0 || layoutIndex >= LAYOUT_NAMES.length) {
      throw new Error(`Invalid rotor layout index at ${i}`);
    }
    if (!Number.isInteger(pos) || pos < 0 || pos >= N) {
      throw new Error(`Invalid rotor position at ${i + 1}`);
    }
    rotors.push({ layout: LAYOUT_NAMES[layoutIndex], pos });
  }
  const steckPairs = [];
  if (steckStr !== '0') {
    if (steckStr.length % 4 !== 0) throw new Error('Steck section must be groups of 4 digits');
    for (let i = 0; i < steckStr.length; i += 4) {
      const ai = parseInt(steckStr.slice(i, i + 2), 10);
      const bi = parseInt(steckStr.slice(i + 2, i + 4), 10);
      steckPairs.push([ALPHA[ai], ALPHA[bi]]);
    }
  }
  const userRounds = parseInt(roundsStr, 10);
  if (!Number.isInteger(userRounds) || userRounds < 1 || userRounds > 999) {
    throw new Error('Rounds section must be 001-999');
  }
  let nonce = '';
  if (nonceStr) {
    if (nonceStr.length % 2 !== 0) throw new Error('Nonce section must be groups of 2 digits');
    for (let i = 0; i < nonceStr.length; i += 2) {
      const index = parseInt(nonceStr.slice(i, i + 2), 10);
      nonce += ALPHA[index];
    }
  }
  return { enabled, rotors, steckPairs, userRounds, nonce, keyStr: keyStr.trim() };
}

function encodeKey(enabled, rotors, steckPairs, userRounds, nonce = '') {
  const enabledStr = [...enabled].map((name) => LAYOUT_NAMES.indexOf(name)).join('');
  const rotorStr = rotors.map((rotor) => `${LAYOUT_NAMES.indexOf(rotor.layout)}${String(rotor.pos).padStart(2, '0')}`).join('');
  const steckStr = steckPairs.length === 0 ? '0' : steckPairs.map(([a, b]) => {
    const lo = Math.min(ALPHA.indexOf(a), ALPHA.indexOf(b));
    const hi = Math.max(ALPHA.indexOf(a), ALPHA.indexOf(b));
    return `${String(lo).padStart(2, '0')}${String(hi).padStart(2, '0')}`;
  }).sort().join('');
  const roundsStr = String(userRounds).padStart(3, '0');
  const base = `${enabledStr} ${rotorStr} ${steckStr} ${roundsStr}`;
  if (!nonce) return base;
  const nonceStr = [...nonce].map((char) => String(ALPHA.indexOf(char)).padStart(2, '0')).join('');
  return `${base} ${nonceStr}`;
}

function encrypt(plaintext, keyStr) {
  const key = parseKey(keyStr);
  const payload = packRc4Payload(plaintext, key.keyStr);
  const state = createCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
  const visibleCipher = processSegment(payload.visiblePayload, state, false);
  const checksum = computeChecksum(visibleCipher, deriveMacSubkey(key.keyStr), payload.version);
  const hiddenCipher = processSegment(payload.version + checksum, state, false);
  const carrierStream = encodeHiddenCarrierChars(hiddenCipher, key.keyStr);
  return injectHiddenCarriers(visibleCipher, carrierStream, key.keyStr);
}

function decrypt(ciphertext, keyStr) {
  const diagnostics = analyzeCiphertext(ciphertext);
  const extracted = extractCarrierInfo(ciphertext);
  const visibleText = extracted.visibleText;
  const key = parseKey(keyStr);

  if (visibleText.startsWith(LEGACY_RC3_HEADER)) {
    const body = visibleText.slice(LEGACY_RC3_HEADER.length);
    const state = createLegacyCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
    const payload = processLegacySegment(body, state, true);
    const unpacked = unpackRc3Payload(payload, key.keyStr);
    const result = { ...unpacked, diagnostics, payload, format: 'rc.3' };
    return finalizeDecryptResult(result, result.plaintext || payload, key.keyStr, state.km, state);
  }

  const rc4State = createCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
  const visiblePayload = processSegment(visibleText, rc4State, true);
  const visibleFields = unpackRc4VisiblePayload(visiblePayload);
  if (visibleFields.structureOk && visibleFields.formatTag === RC4_FORMAT_TAG) {
    const baseResult = {
      plaintext: visibleFields.plaintext,
      verified: false,
      checksumOk: false,
      paddingOk: false,
      structureOk: true,
      metadataOk: false,
      versionOk: false,
      diagnostics,
      payload: visiblePayload,
      visiblePayload,
      format: 'rc.4-hidden',
      lengthField: visibleFields.lengthField,
      padding: visibleFields.padding,
    };

    if (extracted.hiddenCarrierCount === 0) {
      return genericDecryptFailure({
        ...baseResult,
      }, visibleFields.plaintext, key.keyStr, rc4State.km, rc4State);
    }

    if (extracted.hiddenCarrierCount !== HIDDEN_SYMBOL_COUNT) {
      return genericDecryptFailure({
        ...baseResult,
      }, visibleFields.plaintext, key.keyStr, rc4State.km, rc4State);
    }

    let hiddenCipher;
    try {
      hiddenCipher = decodeHiddenCarrierStream(extracted.carrierStream, key.keyStr);
    } catch (_) {
      return genericDecryptFailure({
        ...baseResult,
      }, visibleFields.plaintext, key.keyStr, rc4State.km, rc4State);
    }

    const hiddenPayload = processSegment(hiddenCipher, rc4State, true);
    if (hiddenPayload.length !== HIDDEN_METADATA_LEN) {
      return genericDecryptFailure({
        ...baseResult,
        hiddenCipher,
        hiddenPayload,
      }, visibleFields.plaintext, key.keyStr, rc4State.km, rc4State);
    }

    const version = hiddenPayload[0];
    const checksum = hiddenPayload.slice(1);
    const versionOk = version === RC4_VERSION_CHAR;
    const checksumOk = versionOk && checksum === computeChecksum(visibleText, deriveMacSubkey(key.keyStr), version);
    const paddingSeed = versionOk ? computePaddingSeed(visibleFields.plaintext, key.keyStr, visibleFields.lengthField, version) : '';
    const expectedPadLen = versionOk ? computePadLength(visibleFields.plaintext, key.keyStr, paddingSeed, version) : 0;
    const expectedPadding = versionOk ? generatePadding(visibleFields.plaintext, key.keyStr, paddingSeed, version, expectedPadLen) : '';
    const paddingOk = versionOk && visibleFields.padding.length === expectedPadLen && visibleFields.padding === expectedPadding;
    const verified = versionOk && checksumOk && paddingOk;
    const result = {
      ...baseResult,
      verified,
      checksumOk,
      paddingOk,
      metadataOk: true,
      versionOk,
      hiddenCipher,
      hiddenPayload,
      version,
      error: verified ? null : GENERIC_DECRYPT_ERROR,
    };
    return finalizeDecryptResult(result, visibleFields.plaintext, key.keyStr, rc4State.km, rc4State);
  }

  const pos = legacyChecksumPos(key.keyStr, visibleText.length);
  const checksum = visibleText.slice(pos, pos + CHECKSUM_LEN);
  const stripped = visibleText.slice(0, pos) + visibleText.slice(pos + CHECKSUM_LEN);
  const state = createLegacyCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
  const plaintext = processLegacySegment(stripped, state, true);
  const verified = checksum === legacyComputeChecksum(plaintext, key.keyStr);
  const result = {
    plaintext,
    verified,
    checksumOk: verified,
    paddingOk: true,
    structureOk: true,
    metadataOk: false,
    versionOk: false,
    diagnostics,
    payload: stripped,
    format: 'rc.2-legacy',
    error: verified ? null : GENERIC_DECRYPT_ERROR,
  };
  return finalizeDecryptResult(result, plaintext, key.keyStr, state.km, state);
}

function getCryptoApi() {
  if (globalThis.crypto?.getRandomValues) return globalThis.crypto;
  if (typeof window !== 'undefined' && window.crypto?.getRandomValues) return window.crypto;
  return require('crypto').webcrypto;
}

function randInt(rng, max) {
  if (max <= 0) throw new Error('randInt(max) requires max > 0');
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do { rng.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % max;
}

function randBelowBigInt(rng, max) {
  if (max <= 0n) throw new Error('randBelowBigInt(max) requires max > 0');
  const bits = max.toString(2).length;
  const byteLen = Math.ceil(bits / 8);
  const fullRange = 1n << BigInt(byteLen * 8);
  const cutoff = fullRange - (fullRange % max);
  const bytes = new Uint8Array(byteLen);
  while (true) {
    rng.getRandomValues(bytes);
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value < cutoff) return value % max;
  }
}

function shuffleWithRng(items, rng) {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = randInt(rng, i + 1);
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

function permutationCountBig(n, k) {
  let total = 1n;
  for (let i = 0; i < k; i++) total *= BigInt(n - i);
  return total;
}

function factorialBig(n) {
  let total = 1n;
  for (let i = 2; i <= n; i++) total *= BigInt(i);
  return total;
}

function steckPairingCountBig(alphaSize, pairCount) {
  if (pairCount === 0) return 1n;
  let total = 1n;
  let remaining = BigInt(alphaSize);
  for (let i = 0; i < pairCount; i++) {
    total *= (remaining * (remaining - 1n)) / 2n;
    remaining -= 2n;
  }
  return total / factorialBig(pairCount);
}

function profileWeight(layoutCount, rotorCount, steckCount, includeNonce) {
  const layoutCombos = permutationCountBig(10, layoutCount);
  const rotorCombos = BigInt(layoutCount * N) ** BigInt(rotorCount);
  const steckCombos = steckPairingCountBig(N, steckCount);
  const nonceCombos = includeNonce ? N_BIG ** 3n : 1n;
  return layoutCombos * rotorCombos * steckCombos * nonceCombos;
}

function chooseProfile(opts, rng) {
  const layoutChoices = opts.numLayouts == null ? [...Array(LAYOUT_NAMES.length).keys()].map((i) => i + 1) : [opts.numLayouts];
  const rotorChoices = opts.numRotors == null ? [...Array(13).keys()].map((i) => i + 1) : [opts.numRotors];
  const steckChoices = opts.numSteck == null ? [...Array(Math.floor(N / 2) + 1).keys()] : [opts.numSteck];
  const nonceChoices = opts.includeNonce == null ? [false, true] : [Boolean(opts.includeNonce)];
  return {
    layoutCount: layoutChoices[randInt(rng, layoutChoices.length)],
    rotorCount: rotorChoices[randInt(rng, rotorChoices.length)],
    steckCount: steckChoices[randInt(rng, steckChoices.length)],
    includeNonce: nonceChoices[randInt(rng, nonceChoices.length)],
  };
}

function sampleEnabledLayouts(layoutCount, rng) {
  return shuffleWithRng([...Array(LAYOUT_NAMES.length).keys()], rng).slice(0, layoutCount);
}

function sampleSteckPairs(pairCount, rng) {
  const chars = shuffleWithRng([...ALPHA], rng);
  return Array.from({ length: pairCount }, (_, index) => [chars[index * 2], chars[index * 2 + 1]]);
}

function generateKey(opts = {}) {
  const rng = getCryptoApi();
  const {
    numRotors = null,
    numSteck = null,
    numLayouts = null,
    userRounds = null,
    includeNonce = null,
  } = opts;

  if (numLayouts != null && (numLayouts < 1 || numLayouts > LAYOUT_NAMES.length)) {
    throw new Error(`numLayouts must be between 1 and ${LAYOUT_NAMES.length}`);
  }
  if (numRotors != null && (numRotors < 1 || numRotors > 13)) {
    throw new Error('numRotors must be between 1 and 13');
  }
  if (numSteck != null && (numSteck < 0 || numSteck > Math.floor(N / 2))) {
    throw new Error(`numSteck must be between 0 and ${Math.floor(N / 2)}`);
  }
  if (userRounds != null && (userRounds < 1 || userRounds > 999)) {
    throw new Error('userRounds must be between 1 and 999');
  }

  for (let attempt = 0; attempt < 10000; attempt++) {
    const profile = chooseProfile({ numRotors, numSteck, numLayouts, includeNonce }, rng);
    const enabledIndexes = sampleEnabledLayouts(profile.layoutCount, rng);
    const enabled = new Set(enabledIndexes.map((index) => LAYOUT_NAMES[index]));
    const rotors = Array.from({ length: profile.rotorCount }, () => ({
      layout: LAYOUT_NAMES[enabledIndexes[randInt(rng, enabledIndexes.length)]],
      pos: randInt(rng, N),
    }));
    const steckPairs = sampleSteckPairs(profile.steckCount, rng);
    const finalRounds = userRounds ?? (randInt(rng, 999) + 1);
    const nonce = profile.includeNonce
      ? Array.from({ length: 3 }, () => ALPHA[randInt(rng, N)]).join('')
      : '';
    const key = encodeKey(enabled, rotors, steckPairs, finalRounds, nonce);
    if (calcKeyStrength(parseKey(key)).familyBits >= MIN_GENERATED_KEY_BITS) return key;
  }
  throw new Error(`Unable to generate a key with at least ${MIN_GENERATED_KEY_BITS.toFixed(1)} bits using the requested constraints`);
}

function calcIoC(text) {
  const freq = {};
  for (const char of ALPHA) freq[char] = 0;
  for (const char of text) if (freq[char] !== undefined) freq[char] += 1;
  const length = Object.values(freq).reduce((acc, value) => acc + value, 0);
  if (length < 2) return 0;
  const numerator = Object.values(freq).reduce((acc, value) => acc + value * (value - 1), 0);
  return numerator / (length * (length - 1));
}

function combination(n, k) {
  if (k < 0 || k > n) return 0;
  if (k === 0 || k === n) return 1;
  let total = 1;
  const upper = Math.min(k, n - k);
  for (let i = 0; i < upper; i++) total = (total * (n - i)) / (i + 1);
  return Math.round(total);
}

function factorial(n) {
  let total = 1;
  for (let i = 2; i <= n; i++) total *= i;
  return total;
}

function calcKeyStrength(parsedKey) {
  const steckPairingCount = (alphaSize, numPairs) => {
    if (numPairs === 0) return 1;
    let total = 1;
    let remaining = alphaSize;
    for (let i = 0; i < numPairs; i++) {
      total *= combination(remaining, 2);
      remaining -= 2;
    }
    return Math.round(total / factorial(numPairs));
  };
  const enabledCount = parsedKey.enabled.size;
  let layoutCombos = 1;
  for (let i = 0; i < enabledCount; i++) layoutCombos *= (10 - i);
  const rotorCombos = Math.pow(enabledCount * N, parsedKey.rotors.length);
  const steckCombos = steckPairingCount(N, parsedKey.steckPairs.length);
  const roundCombos = 999;
  const nonceCombos = parsedKey.nonce ? Math.pow(N, 3) : 1;
  const total = layoutCombos * rotorCombos * steckCombos * roundCombos * nonceCombos;
  const km = computeKeyMaterial(parsedKey.steckPairs, parsedKey.rotors, parsedKey.enabled, parsedKey.userRounds);
  const familyBits = Math.log2(total);
  return {
    familyBits,
    bits: familyBits,
    total,
    components: {
      layouts: { count: layoutCombos, bits: Math.log2(layoutCombos) },
      rotors: { count: rotorCombos, bits: rotorCombos > 1 ? Math.log2(rotorCombos) : 0 },
      steck: { count: steckCombos, bits: steckCombos > 1 ? Math.log2(steckCombos) : 0 },
      rounds: { count: roundCombos, bits: Math.log2(roundCombos) },
      nonce: { count: nonceCombos, bits: nonceCombos > 1 ? Math.log2(nonceCombos) : 0 },
    },
    profile: {
      enabledLayouts: [...parsedKey.enabled],
      enabledCount: parsedKey.enabled.size,
      rotorCount: parsedKey.rotors.length,
      rotorLayouts: parsedKey.rotors.map((rotor) => rotor.layout),
      steckPairs: parsedKey.steckPairs.length,
      baseRounds: parsedKey.userRounds,
      finalRounds: km.rounds,
      noncePresent: Boolean(parsedKey.nonce),
      nonce: parsedKey.nonce || '-',
    },
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { encrypt, decrypt, generateKey, calcIoC, calcKeyStrength, parseKey, encodeKey, analyzeCiphertext, ALPHA, N };
} else if (typeof window !== 'undefined') {
  window.ENIGMAK = { encrypt, decrypt, generateKey, calcIoC, calcKeyStrength, parseKey, encodeKey, analyzeCiphertext, ALPHA, N };
}
