/**
 * ENIGMAK v3.0.0-rc.8 - JavaScript module
 * 162-symbol multi-round substitution-permutation rotor cipher
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

const LEGACY_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\\\',./' +
                     '!@#$%^&*()_+{}|:"<>?`~' +
                     'abcdefghijklmnopqrstuvwxyz ';
const EXTENDED_ALPHA = 'ÀàÁáÂâÃãÄäÅåÆæÇçÈèÉéÊêËëÌìÍíÎîÏïÐðÑñÒòÓóÔôÕõÖöØøÙùÚúÛûÜüÝýÞþßÿ¡¿Œœ';
const ALPHA = LEGACY_ALPHA + EXTENDED_ALPHA + '\n';
// NOTE: Newline (\n) at index 161 is permanently layout-unassigned (no physical
// QWERTY key produces it directly) but participates fully in all keyed
// permutations and cipher operations, so multi-line plaintext round-trips
// without special handling. Characters above index 94 (U+00C0 and beyond) are
// European extended characters that are assigned by the national language
// layouts added in rc.7 and participate in all cipher operations.
const LEGACY_N = LEGACY_ALPHA.length;
const N = ALPHA.length;
if (LEGACY_N !== 95 || N !== 162) throw new Error('ENIGMAK alphabet length mismatch');
const N_BIG = BigInt(N);
const LEGACY_N_BIG = BigInt(LEGACY_N);
const STEP_MASK_ACTIVE = 66;
const ROUND_MINIMUM = 10;
const CHECKSUM_LEN = 10;
const LEN_FIELD_LEN = 4;
const MAX_PAD_LEN = 16;
const LEGACY_RC3_HEADER = 'E3|';
const RC4_FORMAT_TAG = 'H';
const RC4_VERSION_CHAR = '4';
const RC6_VERSION_CHAR = '5';
const HIDDEN_METADATA_LEN = 1 + CHECKSUM_LEN;
const HIDDEN_CHUNK_LEN = 4;
const HIDDEN_SYMBOL_COUNT = HIDDEN_METADATA_LEN * HIDDEN_CHUNK_LEN;
const GENERIC_DECRYPT_ERROR = 'Decryption failed.';
const MAX_CORRUPT_LEN = 4096;
const MIN_GENERATED_KEY_BITS = 256;
const KEY_V6_PREFIX = 'K6:';
const K6_ENCRYPT_REQUIRED_ERROR = 'Encryption requires a K6: key. Legacy keys remain decrypt-only.';
const BASE36_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CARRIER_WILDCARD_DOMAIN = '|carrier-wildcards|';
const STREAM_SCHEDULE_DOMAIN = '|stream-schedule|';
const U64_MASK = (1n << 64n) - 1n;
const TWO_64 = 1n << 64n;
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
                      'Norman','Asset','Halmak','AZERTY','QWERTZ',
                      // National language layouts sourced from Microsoft Windows DLLs.
                      'Spanish','Swedish','Norwegian','Danish','Icelandic','Belgian'];
const LEGACY_LAYOUT_NAMES = LAYOUT_NAMES.slice(0, 10);

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
    topTop: '²&é"\'(-è_çà)=1234567890°+}',
    top:    'azertyuiop^£AZERTYUIOP¨$',
    home:   "qsdfghjklmù*QSDFGHJKLMµ",
    bot:    'wxcvbn?,;:WXCVBN.!/§',
  },
  'QWERTZ': {
    topTop: '^1234567890ß`°!"§$%&/()=?\\',
    top:    'qwertzuiopü+QWERTZUIOPÜ~',
    home:   "asdfghjklöä#ASDFGHJKLÖÄ'",
    bot:    'yxcvbnm,.-YXCVBNM;:_',
  },
  'Spanish': {
    topTop: "º1234567890'¡ª!\"·$%&/()=?¿",
    top:    'qwertyuiop`+QWERTYUIOP^*',
    home:   "asdfghjklñç'ASDFGHJKLÑÇ\"",
    bot:    'zxcvbnm,.-ZXCVBNM;:_',
  },
  'Swedish': {
    topTop: '½1234567890+`§!"#¤%&/()=?\\',
    top:    'qwertyuiopå^QWERTYUIOPÅ¨',
    home:   "asdfghjklöä'ASDFGHJKLÖÄ*",
    bot:    'zxcvbnm,.-ZXCVBNM;:_',
  },
  'Norwegian': {
    topTop: '§1234567890+`|!"#¤%&/()=?\\',
    top:    'qwertyuiopå^QWERTYUIOPÅ¨',
    home:   "asdfghjkløæ'ASDFGHJKLØÆ*",
    bot:    'zxcvbnm,.-ZXCVBNM;:_',
  },
  'Danish': {
    topTop: '§1234567890+`½!"#¤%&/()=?\\',
    top:    'qwertyuiopå^QWERTYUIOPÅ¨',
    home:   "asdfghjklæø'ASDFGHJKLÆØ*",
    bot:    'zxcvbnm,.-ZXCVBNM;:_',
  },
  'Icelandic': {
    topTop: '¨1234567890ö_°!"#$%&/()=?-\\',
    top:    'qwertyuiopð?QWERTYUIOPÐ~',
    home:   "asdfghjklæ´ASDFGHJKLÆ^",
    bot:    'zxcvbnm,.þZXCVBNM<>Þ',
  },
  'Belgian': {
    topTop: '²&é"\'(§è!çà)-`³1234567890°_',
    top:    'azertyuiop^$AZERTYUIOP¨£',
    home:   'qsdfghjklmù%QSDFGHJKLMùµ',
    bot:    'wxcvbn?,;:WXCVBN?./',
  },
};

const QTT = '`1234567890-=~!@#$%^&*()_+';
const QT = 'qwertyuiop[]\\QWERTYUIOP{}|';
const QH = "asdfghjkl;'ASDFGHJKL:\"";
const QB = 'zxcvbnm,./ZXCVBNM<>?';

function buildMap(name) {
  const def = LAYOUT_DEFS[name];
  const map = {};
  if (!def) return map;
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

// ---------------------------------------------------------------------------
// BLAKE3 (default "hash" mode) - zero-dependency from-scratch port.
// Used for all live rc.8 seed derivation. Validated against the official
// BLAKE3 test vectors. keyed_hash / derive_key modes are intentionally omitted.
// ---------------------------------------------------------------------------
const _BLAKE3_IV = [
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const _BLAKE3_MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const _BLAKE3_CHUNK_START = 1;
const _BLAKE3_CHUNK_END = 2;
const _BLAKE3_PARENT = 4;
const _BLAKE3_ROOT = 8;
const _BLAKE3_BLOCK_LEN = 64;
const _BLAKE3_CHUNK_LEN = 1024;

function _blake3Rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function _blake3G(state, a, b, c, d, mx, my) {
  state[a] = (state[a] + state[b] + mx) >>> 0;
  state[d] = _blake3Rotr((state[d] ^ state[a]) >>> 0, 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = _blake3Rotr((state[b] ^ state[c]) >>> 0, 12);
  state[a] = (state[a] + state[b] + my) >>> 0;
  state[d] = _blake3Rotr((state[d] ^ state[a]) >>> 0, 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = _blake3Rotr((state[b] ^ state[c]) >>> 0, 7);
}

function _blake3Round(state, m) {
  _blake3G(state, 0, 4, 8, 12, m[0], m[1]);
  _blake3G(state, 1, 5, 9, 13, m[2], m[3]);
  _blake3G(state, 2, 6, 10, 14, m[4], m[5]);
  _blake3G(state, 3, 7, 11, 15, m[6], m[7]);
  _blake3G(state, 0, 5, 10, 15, m[8], m[9]);
  _blake3G(state, 1, 6, 11, 12, m[10], m[11]);
  _blake3G(state, 2, 7, 8, 13, m[12], m[13]);
  _blake3G(state, 3, 4, 9, 14, m[14], m[15]);
}

function _blake3Compress(cv, blockWords, counter, blockLen, flags) {
  const counterLow = (counter >>> 0);
  const counterHigh = (Math.floor(counter / 4294967296) >>> 0);
  const state = [
    cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
    _BLAKE3_IV[0], _BLAKE3_IV[1], _BLAKE3_IV[2], _BLAKE3_IV[3],
    counterLow, counterHigh, blockLen >>> 0, flags >>> 0,
  ];
  let m = blockWords.slice(0, 16);
  for (let r = 0; r < 7; r++) {
    _blake3Round(state, m);
    if (r < 6) {
      const permuted = new Array(16);
      for (let i = 0; i < 16; i++) permuted[i] = m[_BLAKE3_MSG_PERMUTATION[i]];
      m = permuted;
    }
  }
  for (let i = 0; i < 8; i++) {
    state[i] = (state[i] ^ state[i + 8]) >>> 0;
    state[i + 8] = (state[i + 8] ^ cv[i]) >>> 0;
  }
  return state;
}

function _blake3WordsFromBlock(block) {
  const words = new Array(16);
  for (let i = 0; i < 16; i++) {
    const o = i * 4;
    words[i] = (block[o] | (block[o + 1] << 8) | (block[o + 2] << 16) | (block[o + 3] << 24)) >>> 0;
  }
  return words;
}

function _blake3ChunkOutput(chunk, chunkCounter) {
  let cv = _BLAKE3_IV.slice(0, 8);
  const blockCount = Math.max(1, Math.ceil(chunk.length / _BLAKE3_BLOCK_LEN));
  for (let i = 0; i < blockCount; i++) {
    const raw = chunk.slice(i * _BLAKE3_BLOCK_LEN, (i + 1) * _BLAKE3_BLOCK_LEN);
    const blockLen = raw.length;
    const block = new Uint8Array(_BLAKE3_BLOCK_LEN);
    block.set(raw);
    const words = _blake3WordsFromBlock(block);
    let flags = 0;
    if (i === 0) flags |= _BLAKE3_CHUNK_START;
    if (i === blockCount - 1) {
      flags |= _BLAKE3_CHUNK_END;
      return { cv, words, counter: chunkCounter, blockLen, flags };
    }
    cv = _blake3Compress(cv, words, chunkCounter, blockLen, flags).slice(0, 8);
  }
  return {
    cv, words: new Array(16).fill(0), counter: chunkCounter, blockLen: 0,
    flags: _BLAKE3_CHUNK_START | _BLAKE3_CHUNK_END,
  };
}

function _blake3ParentOutput(leftCv, rightCv) {
  return {
    cv: _BLAKE3_IV.slice(0, 8), words: leftCv.concat(rightCv), counter: 0,
    blockLen: _BLAKE3_BLOCK_LEN, flags: _BLAKE3_PARENT,
  };
}

function _blake3OutputCv(output) {
  return _blake3Compress(output.cv, output.words, output.counter, output.blockLen, output.flags).slice(0, 8);
}

function _blake3RootBytes(output, outLen) {
  const out = new Uint8Array(outLen);
  let written = 0;
  let outCounter = 0;
  while (written < outLen) {
    const words16 = _blake3Compress(output.cv, output.words, outCounter, output.blockLen, output.flags | _BLAKE3_ROOT);
    for (let i = 0; i < 16 && written < outLen; i++) {
      const w = words16[i];
      for (let b = 0; b < 4 && written < outLen; b++) {
        out[written++] = (w >>> (8 * b)) & 0xff;
      }
    }
    outCounter++;
  }
  return out;
}

function _blake3LargestPowerOfTwoLeq(n) {
  let p = 1;
  while ((p << 1) <= n) p <<= 1;
  return p;
}

function _blake3LeftLen(contentLen) {
  const fullChunks = Math.floor((contentLen - 1) / _BLAKE3_CHUNK_LEN);
  return _blake3LargestPowerOfTwoLeq(fullChunks) * _BLAKE3_CHUNK_LEN;
}

function _blake3HashRecurse(data, chunkCounter) {
  if (data.length <= _BLAKE3_CHUNK_LEN) {
    return _blake3ChunkOutput(data, chunkCounter);
  }
  const leftLen = _blake3LeftLen(data.length);
  const left = _blake3HashRecurse(data.slice(0, leftLen), chunkCounter);
  const right = _blake3HashRecurse(data.slice(leftLen), chunkCounter + (leftLen / _BLAKE3_CHUNK_LEN));
  return _blake3ParentOutput(_blake3OutputCv(left), _blake3OutputCv(right));
}

function blake3Hash(data, outLen) {
  if (outLen === undefined) outLen = 32;
  let bytes;
  if (typeof data === 'string') {
    bytes = new TextEncoder().encode(data);
  } else {
    bytes = data;
  }
  const output = _blake3HashRecurse(bytes, 0);
  return _blake3RootBytes(output, outLen);
}

function hashStr32(s) {
  // rc.8 live seed derivation: first 4 digest bytes, big-endian unsigned.
  const d = blake3Hash(s);
  return ((d[0] * 16777216) + (d[1] * 65536) + (d[2] * 256) + d[3]) >>> 0;
}

function lcg64(v) {
  return (v * 6364136223846793005n + 1442695040888963407n) & U64_MASK;
}

function hashStr64(s) {
  // rc.8 live seed derivation: first 8 digest bytes, big-endian unsigned.
  const d = blake3Hash(s);
  let h = 0n;
  for (let i = 0; i < 8; i++) h = (h << 8n) | BigInt(d[i]);
  return h;
}

// Frozen FNV-1a primitives for legacy decrypt paths (rc.4-hidden, rc.3, rc.2).
// These reproduce the pre-rc.8 hash behaviour so legacy ciphertext stays
// decryptable after the live pipeline moves to BLAKE3. They must never change.
const LEGACY_FNV64_OFFSET = FNV64_OFFSET;
const LEGACY_FNV64_PRIME = FNV64_PRIME;

function _legacyFnvHash64(s) {
  const bytes = new TextEncoder().encode(s);
  let h = LEGACY_FNV64_OFFSET;
  for (const b of bytes) {
    h ^= BigInt(b);
    h = (h * LEGACY_FNV64_PRIME) & U64_MASK;
  }
  return h;
}

function _legacyFnvHash32(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

function _legacyDeriveMacSubkey(keyStr) {
  // Frozen FNV copy of deriveMacSubkey for the rc.4-hidden decrypt path.
  return _legacyFnvHash64(keyStr + '\x01enigmak-mac').toString();
}

function _legacyComputePadLength(plaintext, keyStr, checksum, versionChar) {
  // Frozen FNV copy of computePadLength for the rc.4-hidden decrypt path.
  let length = Number(_legacyFnvHash64(`${keyStr}|${plaintext}|${checksum}|${versionChar}|padlen`) % BigInt(MAX_PAD_LEN));
  if (plaintext.length === 0 && length === 0) length = 1;
  return length;
}

function _legacyKeyedZeroWidthOrder(keyStr) {
  // Frozen FNV copy of keyedZeroWidthOrder for the rc.4-hidden decrypt path.
  const symbols = [...ZERO_WIDTH_SYMBOLS];
  let state = _legacyFnvHash64(`${keyStr}|zwperm`);
  for (let i = symbols.length - 1; i > 0; i--) {
    state = lcg64(state ^ BigInt(i));
    const j = Number(state % BigInt(i + 1));
    [symbols[i], symbols[j]] = [symbols[j], symbols[i]];
  }
  return symbols;
}

function _legacyDecodeHiddenCarrierStream(carrierStream, keyStr) {
  // Frozen FNV copy of decodeHiddenCarrierStream for the rc.4-hidden path.
  if (carrierStream.length % HIDDEN_CHUNK_LEN !== 0) {
    throw new Error(`Hidden metadata carrier count must be a multiple of ${HIDDEN_CHUNK_LEN}`);
  }
  const order = _legacyKeyedZeroWidthOrder(keyStr);
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

function deriveMacSubkey(keyStr) {
  // Separate MAC subkey prevents key reuse between encryption and authentication
  return hashStr64(keyStr + '\x01enigmak-mac').toString();
}

function encodeBase36Index(value, width) {
  if (value < 0) throw new Error('Base36 encoding requires a non-negative integer');
  const chars = new Array(width).fill('0');
  let current = value;
  for (let i = width - 1; i >= 0; i--) {
    chars[i] = BASE36_ALPHABET[current % 36];
    current = Math.floor(current / 36);
  }
  if (current !== 0) throw new Error(`Value exceeds ${width} base36 characters`);
  return chars.join('');
}

function decodeBase36Index(text) {
  let value = 0;
  for (const char of text.toUpperCase()) {
    const index = BASE36_ALPHABET.indexOf(char);
    if (index < 0) throw new Error(`Invalid base36 digit: ${JSON.stringify(char)}`);
    value = value * 36 + index;
  }
  return value;
}

function deriveCarrierWildcards(keyStr, carrierCount) {
  let seed = hashStr64(keyStr + CARRIER_WILDCARD_DOMAIN);
  const wildcards = [];
  for (let i = 0; i < carrierCount; i++) {
    seed = lcg64(seed ^ BigInt(i));
    wildcards.push(ALPHA[Number(seed % N_BIG)]);
  }
  return wildcards;
}

function deriveScheduleSeed(keyStr, plaintextLen) {
  return hashStr64(keyStr + STREAM_SCHEDULE_DOMAIN + String(plaintextLen));
}

function buildStreamSchedule(keyStr, plaintextLen, payloadLen) {
  const remaining = {
    payload: payloadLen,
    checksum: CHECKSUM_LEN,
    carrier: HIDDEN_SYMBOL_COUNT,
  };
  let state = deriveScheduleSeed(keyStr, plaintextLen);
  const schedule = [];
  const total = remaining.payload + remaining.checksum + remaining.carrier;
  for (let i = 0; i < total; i++) {
    state = lcg64(state ^ BigInt(i));
    const pick = Number(state % BigInt(total - i));
    let event;
    if (pick < remaining.checksum) event = 'checksum';
    else if (pick < remaining.checksum + remaining.carrier) event = 'carrier';
    else event = 'payload';
    remaining[event] -= 1;
    schedule.push(event);
  }
  return schedule;
}

function shuffleIndicesWithSeed(size, seed) {
  const items = [...Array(size).keys()];
  let state = seed & U64_MASK;
  for (let i = items.length - 1; i > 0; i--) {
    const limit = BigInt(i + 1);
    const threshold = TWO_64 - (TWO_64 % limit);
    do {
      state = lcg64(state);
    } while (state >= threshold);
    const j = Number(state % limit);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

function rotorStateHash(rotors) {
  // rc.8: BLAKE3-derived from a canonical rotor serialization. The legacy
  // rc.3/rc.4 paths keep their own frozen FNV copies of this function.
  const parts = rotors.map((rotor, index) => String(rotor.pos * 73 + index + 1));
  return hashStr64('rotor-state|' + parts.join('|'));
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
  const rounds = Math.max(Number((steckSum + rotorSum + layoutSum + BigInt(userRounds)) % 999n) + 1, ROUND_MINIMUM);
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

function legacyKeyedLayoutOffset(name, layoutKeyBase) {
  return (LEGACY_LAYOUT_NAMES.indexOf(name) * 7 + layoutKeyBase) % LEGACY_N;
}

function legacyRotorShift(rotors) {
  let value = 0n;
  rotors.forEach((rotor, index) => {
    value += BigInt(rotor.pos) * (LEGACY_N_BIG ** BigInt(rotors.length - 1 - index));
  });
  return Number(value % LEGACY_N_BIG);
}

function legacyAdvanceRotors(rotors, charIndex, stepMask) {
  if (!stepMask[charIndex % LEGACY_N]) return rotors.map((rotor) => ({ ...rotor }));
  const next = rotors.map((rotor) => ({ ...rotor }));
  next[next.length - 1].pos = (next[next.length - 1].pos + 1) % LEGACY_N;
  for (let i = next.length - 1; i > 0; i--) {
    if (next[i].pos === 0) next[i - 1].pos = (next[i - 1].pos + 1) % LEGACY_N;
  }
  return next;
}

function legacyApplyNonce(rotors, nonce) {
  if (!nonce) return rotors;
  return rotors.map((rotor, index) => {
    const offset = index < nonce.length ? LEGACY_ALPHA.indexOf(nonce[index]) : 0;
    return { ...rotor, pos: (rotor.pos + Math.max(offset, 0)) % LEGACY_N };
  });
}

function legacyApplyLayout(char, layoutName, shift, invert, layoutMaps, invLayoutMaps) {
  if (!invert) {
    let value = layoutMaps[layoutName]?.[char] ?? char;
    if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[(LEGACY_ALPHA.indexOf(value) + shift) % LEGACY_N];
    return value;
  }
  let value = char;
  if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[(LEGACY_ALPHA.indexOf(value) - shift + LEGACY_N * 100) % LEGACY_N];
  return invLayoutMaps[layoutName]?.[value] ?? value;
}

function legacyPlugFwd(char, layouts, layoutMaps) {
  let value = char;
  for (const name of layouts) value = layoutMaps[name]?.[value] ?? value;
  return value;
}

function legacyPlugInv(char, layouts, invLayoutMaps) {
  let value = char;
  for (let i = layouts.length - 1; i >= 0; i--) value = invLayoutMaps[layouts[i]]?.[value] ?? value;
  return value;
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
    const ai = LEGACY_ALPHA.indexOf(a);
    const bi = LEGACY_ALPHA.indexOf(b);
    const lo = Math.min(ai, bi);
    const hi = Math.max(ai, bi);
    return acc + (lo * LEGACY_N + hi);
  }, 0);
  const rotorSum = rotors.reduce((acc, rotor) => acc + rotor.pos, 0);
  const layoutSum = [...enabledLayouts].reduce((acc, name) => acc + LEGACY_LAYOUT_NAMES.indexOf(name), 0);
  const rounds = ((steckSum + rotorSum + layoutSum + userRounds) % 999) + 1;
  const keySum = (steckSum * 31 + rotorSum * 17 + layoutSum * 13) >>> 0;

  const stepPos = [...Array(LEGACY_N).keys()];
  let state = (keySum ^ 0x5a5a5a5a) >>> 0;
  for (let i = LEGACY_N - 1; i > 0; i--) {
    state = lcg32(state);
    const j = state % (i + 1);
    [stepPos[i], stepPos[j]] = [stepPos[j], stepPos[i]];
  }
  const stepMask = new Array(LEGACY_N).fill(false);
  stepPos.slice(0, STEP_MASK_ACTIVE).forEach((pos) => { stepMask[pos] = true; });

  const transPerm = [...Array(LEGACY_N).keys()];
  state = (keySum ^ 0xdead1234) >>> 0;
  for (let i = LEGACY_N - 1; i > 0; i--) {
    state = lcg32(state);
    const j = state % (i + 1);
    [transPerm[i], transPerm[j]] = [transPerm[j], transPerm[i]];
  }
  const invTransPerm = new Array(LEGACY_N);
  transPerm.forEach((value, index) => { invTransPerm[value] = index; });

  const layoutMaps = {};
  const invLayoutMaps = {};
  LEGACY_LAYOUT_NAMES.forEach((name, layoutIndex) => {
    const perm = [...Array(LEGACY_N).keys()];
    let seed = ((keySum ^ (layoutIndex * 0x9E3779B9 + 0xABCD1234)) >>> 0);
    for (let i = LEGACY_N - 1; i > 0; i--) {
      seed = lcg32(seed);
      const j = seed % (i + 1);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    const fwd = {};
    const inv = {};
    for (let i = 0; i < LEGACY_N; i++) {
      fwd[LEGACY_ALPHA[i]] = LEGACY_ALPHA[perm[i]];
      inv[LEGACY_ALPHA[perm[i]]] = LEGACY_ALPHA[i];
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
    layoutKeyBase: keySum % LEGACY_N,
    layoutMaps,
    invLayoutMaps,
    whiteningSeed: (keySum ^ 0xC0FFEE42) >>> 0,
  };
}

function createLegacyCipherState(steckPairs, rotors, enabledLayouts, userRounds, nonce = '') {
  const km = computeLegacyKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds);
  const steckMap = {};
  for (const char of LEGACY_ALPHA) steckMap[char] = char;
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
    rotors: legacyApplyNonce(rotors.map((rotor) => ({ ...rotor })), nonce),
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
    if (!LEGACY_ALPHA.includes(char)) {
      result += char;
      continue;
    }

    const ci = state.alphaIndex;
    const shiftSeed = legacyRotorShift(state.rotors);
    const rsHash = legacyRotorStateHash(state.rotors);
    const posOffset = ((km.layoutKeyBase * 37 + ci * 13 + rsHash) >>> 0) % LEGACY_N;
    const roundLayouts = [];
    const roundShifts = [];
    for (let r = 0; r < rounds; r++) {
      const layoutName = enabledList[r % enabledList.length];
      roundLayouts.push(layoutName);
      roundShifts.push((shiftSeed + r + ci + posOffset + legacyKeyedLayoutOffset(layoutName, km.layoutKeyBase)) % LEGACY_N);
    }
    const scrambleShifts = unusedLayouts.map((name, index) =>
      (shiftSeed + rounds + index + ci + posOffset + legacyKeyedLayoutOffset(name, km.layoutKeyBase)) % LEGACY_N
    );

    let value = char;
    if (!decrypt) {
      value = steckMap[value] ?? value;
      value = legacyPlugFwd(value, unusedLayouts, layoutMaps);
      for (let r = 0; r < rounds; r++) {
        value = legacyApplyLayout(value, roundLayouts[r], roundShifts[r], false, layoutMaps, invLayoutMaps);
      }
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[km.transPerm[LEGACY_ALPHA.indexOf(value)]];
      unusedLayouts.forEach((name, index) => {
        value = legacyApplyLayout(value, name, scrambleShifts[index], false, layoutMaps, invLayoutMaps);
      });
      value = legacyPlugFwd(value, unusedLayouts, layoutMaps);
      value = steckMap[value] ?? value;
      state.whiteningState = lcg32(state.whiteningState);
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[(LEGACY_ALPHA.indexOf(value) + state.whiteningState % LEGACY_N) % LEGACY_N];
    } else {
      state.whiteningState = lcg32(state.whiteningState);
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[(LEGACY_ALPHA.indexOf(value) - state.whiteningState % LEGACY_N + LEGACY_N * 100) % LEGACY_N];
      value = steckMap[value] ?? value;
      value = legacyPlugInv(value, unusedLayouts, invLayoutMaps);
      for (let i = unusedLayouts.length - 1; i >= 0; i--) {
        value = legacyApplyLayout(value, unusedLayouts[i], scrambleShifts[i], true, layoutMaps, invLayoutMaps);
      }
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[km.invTransPerm[LEGACY_ALPHA.indexOf(value)]];
      for (let r = rounds - 1; r >= 0; r--) {
        value = legacyApplyLayout(value, roundLayouts[r], roundShifts[r], true, layoutMaps, invLayoutMaps);
      }
      value = legacyPlugInv(value, unusedLayouts, invLayoutMaps);
      value = steckMap[value] ?? value;
    }

    result += value;
    state.rotors = legacyAdvanceRotors(state.rotors, ci, km.stepMask);
    state.alphaIndex += 1;
  }

  return result;
}

function rc4LegacyRotorStateHash(rotors) {
  let h = FNV64_OFFSET;
  rotors.forEach((rotor, index) => {
    h ^= (BigInt(rotor.pos * 73 + index + 1)) & U64_MASK;
    h = (h * FNV64_PRIME) & U64_MASK;
  });
  return h;
}

function computeRc4LegacyKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds) {
  const steckSum = steckPairs.reduce((acc, [a, b]) => {
    const ai = LEGACY_ALPHA.indexOf(a);
    const bi = LEGACY_ALPHA.indexOf(b);
    const lo = Math.min(ai, bi);
    const hi = Math.max(ai, bi);
    return acc + BigInt(lo * LEGACY_N + hi);
  }, 0n);
  const rotorSum = rotors.reduce((acc, rotor) => acc + BigInt(rotor.pos), 0n);
  const layoutSum = [...enabledLayouts].reduce((acc, name) => acc + BigInt(LEGACY_LAYOUT_NAMES.indexOf(name)), 0n);
  const rounds = Number((steckSum + rotorSum + layoutSum + BigInt(userRounds)) % 999n) + 1;
  const keySum = (steckSum * 31n + rotorSum * 17n + layoutSum * 13n) & U64_MASK;

  const stepPos = shuffleIndicesWithSeed(LEGACY_N, keySum ^ STEP_MASK_SEED_CONST);
  const stepMask = new Array(LEGACY_N).fill(false);
  stepPos.slice(0, STEP_MASK_ACTIVE).forEach((pos) => { stepMask[pos] = true; });

  const transPerm = shuffleIndicesWithSeed(LEGACY_N, keySum ^ TRANS_SEED_CONST);
  const invTransPerm = new Array(LEGACY_N);
  transPerm.forEach((value, index) => { invTransPerm[value] = index; });

  const layoutMaps = {};
  const invLayoutMaps = {};
  LEGACY_LAYOUT_NAMES.forEach((name, layoutIndex) => {
    const perm = shuffleIndicesWithSeed(
      LEGACY_N,
      (keySum ^ ((BigInt(layoutIndex + 1) * LAYOUT_SEED_MIX + LAYOUT_SEED_CONST) & U64_MASK)) & U64_MASK
    );
    const fwd = {};
    const inv = {};
    for (let i = 0; i < LEGACY_N; i++) {
      fwd[LEGACY_ALPHA[i]] = LEGACY_ALPHA[perm[i]];
      inv[LEGACY_ALPHA[perm[i]]] = LEGACY_ALPHA[i];
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
    layoutKeyBase: Number(keySum % LEGACY_N_BIG),
    layoutMaps,
    invLayoutMaps,
    whiteningSeed: (keySum ^ WHITENING_SEED_CONST) & U64_MASK,
  };
}

function createRc4LegacyCipherState(steckPairs, rotors, enabledLayouts, userRounds, nonce = '') {
  const km = computeRc4LegacyKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds);
  const steckMap = {};
  for (const char of LEGACY_ALPHA) steckMap[char] = char;
  steckPairs.forEach(([a, b]) => {
    steckMap[a] = b;
    steckMap[b] = a;
  });
  const enabledList = [...enabledLayouts].filter((name) => LEGACY_LAYOUT_NAMES.includes(name));
  const rotorSet = new Set(rotors.map((rotor) => rotor.layout));
  const unusedLayouts = enabledList.filter((name) => !rotorSet.has(name));
  return {
    km,
    steckMap,
    enabledList,
    unusedLayouts,
    rotors: legacyApplyNonce(rotors.map((rotor) => ({ ...rotor })), nonce),
    whiteningState: km.whiteningSeed,
    alphaIndex: 0,
  };
}

function processRc4LegacySegment(text, state, decrypt = false) {
  const { km, steckMap, enabledList, unusedLayouts } = state;
  const layoutMaps = km.layoutMaps;
  const invLayoutMaps = km.invLayoutMaps;
  const rounds = km.rounds;
  let result = '';

  for (const char of text) {
    if (!LEGACY_ALPHA.includes(char)) {
      result += char;
      continue;
    }

    const ci = state.alphaIndex;
    const shiftSeed = legacyRotorShift(state.rotors);
    const rsHash = rc4LegacyRotorStateHash(state.rotors);
    const posOffset = Number((km.keySum * 37n + BigInt(ci) * 13n + rsHash) % LEGACY_N_BIG);
    const roundLayouts = [];
    const roundShifts = [];
    for (let r = 0; r < rounds; r++) {
      const layoutName = enabledList[r % enabledList.length];
      roundLayouts.push(layoutName);
      roundShifts.push((shiftSeed + r + ci + posOffset + legacyKeyedLayoutOffset(layoutName, km.layoutKeyBase)) % LEGACY_N);
    }
    const scrambleShifts = unusedLayouts.map((name, index) =>
      (shiftSeed + rounds + index + ci + posOffset + legacyKeyedLayoutOffset(name, km.layoutKeyBase)) % LEGACY_N
    );

    let value = char;
    if (!decrypt) {
      value = steckMap[value] ?? value;
      value = legacyPlugFwd(value, unusedLayouts, layoutMaps);
      for (let r = 0; r < rounds; r++) {
        value = legacyApplyLayout(value, roundLayouts[r], roundShifts[r], false, layoutMaps, invLayoutMaps);
      }
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[km.transPerm[LEGACY_ALPHA.indexOf(value)]];
      unusedLayouts.forEach((name, index) => {
        value = legacyApplyLayout(value, name, scrambleShifts[index], false, layoutMaps, invLayoutMaps);
      });
      value = legacyPlugFwd(value, unusedLayouts, layoutMaps);
      value = steckMap[value] ?? value;
      state.whiteningState = lcg64(state.whiteningState);
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[(LEGACY_ALPHA.indexOf(value) + Number(state.whiteningState % LEGACY_N_BIG)) % LEGACY_N];
    } else {
      state.whiteningState = lcg64(state.whiteningState);
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[(LEGACY_ALPHA.indexOf(value) - Number(state.whiteningState % LEGACY_N_BIG) + LEGACY_N * 100) % LEGACY_N];
      value = steckMap[value] ?? value;
      value = legacyPlugInv(value, unusedLayouts, invLayoutMaps);
      for (let i = unusedLayouts.length - 1; i >= 0; i--) {
        value = legacyApplyLayout(value, unusedLayouts[i], scrambleShifts[i], true, layoutMaps, invLayoutMaps);
      }
      if (LEGACY_ALPHA.includes(value)) value = LEGACY_ALPHA[km.invTransPerm[LEGACY_ALPHA.indexOf(value)]];
      for (let r = rounds - 1; r >= 0; r--) {
        value = legacyApplyLayout(value, roundLayouts[r], roundShifts[r], true, layoutMaps, invLayoutMaps);
      }
      value = legacyPlugInv(value, unusedLayouts, invLayoutMaps);
      value = steckMap[value] ?? value;
    }

    result += value;
    state.rotors = legacyAdvanceRotors(state.rotors, ci, km.stepMask);
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

function encodeLegacyBase95Int(value, width) {
  if (value < 0) throw new Error('Base-95 encoding requires a non-negative integer');
  const chars = Array(width).fill('0');
  let current = value;
  for (let i = width - 1; i >= 0; i--) {
    chars[i] = LEGACY_ALPHA[current % LEGACY_N];
    current = Math.floor(current / LEGACY_N);
  }
  if (current !== 0) throw new Error(`Value exceeds ${width} base-95 characters`);
  return chars.join('');
}

function decodeLegacyBase95Int(text) {
  let value = 0;
  for (const char of text) {
    const index = LEGACY_ALPHA.indexOf(char);
    if (index < 0) throw new Error(`Non-alphabet character in legacy base-95 field: ${JSON.stringify(char)}`);
    value = value * LEGACY_N + index;
  }
  return value;
}

function encodeLegacyLengthField(length) {
  return encodeLegacyBase95Int(length, LEN_FIELD_LEN);
}

function decodeLegacyLengthField(field) {
  if (field.length !== LEN_FIELD_LEN) throw new Error(`Length field must be ${LEN_FIELD_LEN} characters`);
  return decodeLegacyBase95Int(field);
}

function computeLegacyAlphabetChecksum(checksumInput, keyStr, versionChar = RC4_VERSION_CHAR) {
  let out = '';
  let state = _legacyFnvHash64(`${checksumInput}|${keyStr}|${versionChar}|chk64`);
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    state = lcg64(state ^ BigInt(i));
    out += LEGACY_ALPHA[Number(state % LEGACY_N_BIG)];
  }
  return out;
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
  const field = lenField ?? encodeLegacyLengthField(plaintext.length);
  let out = '';
  let state = _legacyFnvHash64(`${field}|${plaintext}|${keyStr}|chk64`);
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    state = lcg64(state ^ BigInt(i));
    out += LEGACY_ALPHA[Number(state % LEGACY_N_BIG)];
  }
  return out;
}

function legacyComputeChecksum(plaintext, keyStr) {
  let out = '';
  let state = _legacyFnvHash64(`${plaintext}|${keyStr}|chk64`);
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    state = lcg64(state ^ BigInt(i));
    out += LEGACY_ALPHA[Number(state % LEGACY_N_BIG)];
  }
  return out;
}

function legacyChecksumPos(keyStr, totalLen) {
  return _legacyFnvHash32(`${keyStr}chkpos`) % Math.max(1, totalLen - CHECKSUM_LEN);
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

function computeLegacyPaddingSeed(plaintext, keyStr, lenField = null, versionChar = RC4_VERSION_CHAR) {
  const field = lenField ?? encodeLegacyLengthField(plaintext.length);
  return computeLegacyAlphabetChecksum(`${field}|${plaintext}`, keyStr, versionChar);
}

function generateLegacyPadding(plaintext, keyStr, checksum, versionChar, padLen = null) {
  const targetLen = padLen ?? _legacyComputePadLength(plaintext, keyStr, checksum, versionChar);
  if (targetLen === 0) return '';
  let out = '';
  let state = _legacyFnvHash64(`${keyStr}|${plaintext}|${checksum}|${versionChar}|padfill`);
  for (let i = 0; i < targetLen; i++) {
    state = lcg64(state ^ BigInt(i));
    out += LEGACY_ALPHA[Number(state % LEGACY_N_BIG)];
  }
  return out;
}

function computeRc3PadLength(plaintext, keyStr) {
  return Number(_legacyFnvHash64(`${keyStr}|${plaintext}|padlen`) % BigInt(MAX_PAD_LEN));
}

function generateRc3Padding(plaintext, keyStr, padLen = null) {
  const targetLen = padLen ?? computeRc3PadLength(plaintext, keyStr);
  if (targetLen === 0) return '';
  let out = '';
  let state = _legacyFnvHash64(`${keyStr}|${plaintext}|padfill`);
  for (let i = 0; i < targetLen; i++) {
    state = lcg64(state ^ BigInt(i));
    out += LEGACY_ALPHA[Number(state % LEGACY_N_BIG)];
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

function packRc6Payload(plaintext, keyStr) {
  const version = RC6_VERSION_CHAR;
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
  const lengthField = encodeLegacyLengthField(plaintext.length);
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
    plaintextLength = decodeLegacyLengthField(lengthField);
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

function unpackRc4LegacyVisiblePayload(payload) {
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
    plaintextLength = decodeLegacyLengthField(lengthField);
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

function tryDecodeRc6Metadata(carrierStream, keyStr) {
  if (carrierStream.length !== HIDDEN_SYMBOL_COUNT) return null;
  let metadata;
  try {
    metadata = decodeHiddenCarrierStream(carrierStream, keyStr);
  } catch (_) {
    return null;
  }
  if (metadata.length !== HIDDEN_METADATA_LEN || metadata[0] !== RC6_VERSION_CHAR) return null;
  return metadata;
}

function keyedVisibleCarrierAlphabet(keyStr) {
  // Visible carrier alphabet for materialized metadata: keyed order of A,B,C,D.
  // Same Fisher-Yates-with-seed structure as keyedZeroWidthOrder, so the
  // 4 carrier digit symbols rotate per key just like the zero-width digits do.
  const symbols = [ALPHA[0], ALPHA[1], ALPHA[2], ALPHA[3]];
  let state = hashStr64(`${keyStr}|matperm`);
  for (let i = symbols.length - 1; i > 0; i--) {
    state = lcg64(state ^ BigInt(i));
    const j = Number(state % BigInt(i + 1));
    [symbols[i], symbols[j]] = [symbols[j], symbols[i]];
  }
  return symbols;
}

function encodeVisibleCarrierChars(metadata, keyStr) {
  const order = keyedVisibleCarrierAlphabet(keyStr);
  let out = '';
  for (const char of metadata) {
    const index = ALPHA.indexOf(char);
    if (index < 0) throw new Error(`Materialized metadata character is outside ALPHA: ${JSON.stringify(char)}`);
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

function decodeVisibleCarrierStream(stream, keyStr) {
  if (stream.length % HIDDEN_CHUNK_LEN !== 0) {
    throw new Error(`Materialized metadata carrier count must be a multiple of ${HIDDEN_CHUNK_LEN}`);
  }
  const order = keyedVisibleCarrierAlphabet(keyStr);
  const reverse = new Map(order.map((symbol, index) => [symbol, index]));
  let out = '';
  for (let i = 0; i < stream.length; i += HIDDEN_CHUNK_LEN) {
    let value = 0;
    for (let j = 0; j < HIDDEN_CHUNK_LEN; j++) {
      const digit = reverse.get(stream[i + j]);
      if (digit === undefined) throw new Error('Unknown materialized metadata carrier symbol detected');
      value = value * 4 + digit;
    }
    if (value >= N) throw new Error(`Materialized metadata digit block decodes outside ALPHA: ${value}`);
    out += ALPHA[value];
  }
  return out;
}

function encryptRc6Stream(plaintext, key, materialize = false) {
  const payload = packRc6Payload(plaintext, key.keyStr);
  const checksum = computeChecksum(payload.visiblePayload, deriveMacSubkey(key.keyStr), payload.version);
  const carrierStream = materialize
    ? encodeVisibleCarrierChars(payload.version + checksum, key.keyStr)
    : encodeHiddenCarrierChars(payload.version + checksum, key.keyStr);
  const schedule = buildStreamSchedule(key.keyStr, plaintext.length, payload.visiblePayload.length);
  const wildcards = materialize ? null : deriveCarrierWildcards(key.keyStr, HIDDEN_SYMBOL_COUNT);
  const state = createCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);

  let payloadIndex = 0;
  let checksumIndex = 0;
  let carrierIndex = 0;
  let out = '';
  for (const event of schedule) {
    if (event === 'payload') {
      out += processSegment(payload.visiblePayload[payloadIndex], state, false);
      payloadIndex++;
    } else if (event === 'checksum') {
      out += processSegment(checksum[checksumIndex], state, false);
      checksumIndex++;
    } else {
      if (materialize) {
        out += processSegment(carrierStream[carrierIndex], state, false);
      } else {
        processSegment(wildcards[carrierIndex], state, false);
        out += carrierStream[carrierIndex];
      }
      carrierIndex++;
    }
  }
  return out;
}

function attemptDecryptRc6Stream(ciphertext, key, diagnostics, plaintextLen, materialize = false) {
  let visibleLen = 0;
  let payloadLen;
  if (materialize) {
    visibleLen = ciphertext.length;
    payloadLen = visibleLen - CHECKSUM_LEN - HIDDEN_SYMBOL_COUNT;
  } else {
    for (const char of ciphertext) if (!ZERO_WIDTH_SET.has(char)) visibleLen++;
    payloadLen = visibleLen - CHECKSUM_LEN;
  }
  if (payloadLen < 1 + LEN_FIELD_LEN) return null;
  const schedule = buildStreamSchedule(key.keyStr, plaintextLen, payloadLen);
  if (schedule.length !== ciphertext.length) return null;

  const wildcards = materialize ? null : deriveCarrierWildcards(key.keyStr, HIDDEN_SYMBOL_COUNT);
  const state = createCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
  let payload = '';
  let checksum = '';
  let carrierStream = '';
  let visibleCarrierStream = '';
  let carrierIndex = 0;

  for (let i = 0; i < schedule.length; i++) {
    const event = schedule[i];
    const char = ciphertext[i];
    if (event === 'carrier') {
      if (carrierIndex >= HIDDEN_SYMBOL_COUNT) return null;
      if (materialize) {
        if (!ALPHA.includes(char)) return null;
        const value = processSegment(char, state, true);
        visibleCarrierStream += value;
      } else {
        if (!ZERO_WIDTH_SET.has(char)) return null;
        processSegment(wildcards[carrierIndex], state, true);
        carrierStream += char;
      }
      carrierIndex++;
      continue;
    }

    if (ZERO_WIDTH_SET.has(char) || !ALPHA.includes(char)) return null;
    const value = processSegment(char, state, true);
    if (event === 'checksum') checksum += value;
    else payload += value;
  }
  if (carrierIndex !== HIDDEN_SYMBOL_COUNT) return null;

  let metadata;
  if (materialize) {
    try {
      metadata = decodeVisibleCarrierStream(visibleCarrierStream, key.keyStr);
    } catch (_) {
      return null;
    }
  } else {
    metadata = tryDecodeRc6Metadata(carrierStream, key.keyStr);
    if (!metadata) return null;
  }
  const visibleFields = unpackRc4VisiblePayload(payload);
  if (!visibleFields.structureOk || visibleFields.formatTag !== RC4_FORMAT_TAG) return null;
  if (visibleFields.plaintext.length !== plaintextLen) return null;

  const version = metadata[0];
  const metadataChecksum = metadata.slice(1);
  const expectedChecksum = computeChecksum(payload, deriveMacSubkey(key.keyStr), version);
  const paddingSeed = computePaddingSeed(visibleFields.plaintext, key.keyStr, visibleFields.lengthField, version);
  const expectedPadLen = computePadLength(visibleFields.plaintext, key.keyStr, paddingSeed, version);
  const expectedPadding = generatePadding(visibleFields.plaintext, key.keyStr, paddingSeed, version, expectedPadLen);
  const versionOk = version === RC6_VERSION_CHAR;
  const checksumOk = versionOk && checksum === expectedChecksum && metadataChecksum === checksum;
  const paddingOk = versionOk && visibleFields.padding.length === expectedPadLen && visibleFields.padding === expectedPadding;
  const verified = versionOk && checksumOk && paddingOk;
  if (!verified) return null;

  const result = {
    plaintext: visibleFields.plaintext,
    verified: true,
    checksumOk,
    paddingOk,
    structureOk: true,
    metadataOk: true,
    versionOk,
    diagnostics,
    payload,
    visiblePayload: payload,
    format: 'rc.6-stream',
    materialize,
    lengthField: visibleFields.lengthField,
    padding: visibleFields.padding,
    hiddenPayload: metadata,
    version,
    error: null,
  };
  return finalizeDecryptResult(result, visibleFields.plaintext, key.keyStr, state.km, state);
}

function decryptRc6Stream(ciphertext, key, diagnostics, extracted, materialize = false) {
  let visibleLen;
  let payloadLen;
  if (materialize) {
    if (extracted.hiddenCarrierCount !== 0) return null;
    for (const char of ciphertext) if (!ALPHA.includes(char)) return null;
    visibleLen = ciphertext.length;
    payloadLen = visibleLen - CHECKSUM_LEN - HIDDEN_SYMBOL_COUNT;
  } else {
    if (extracted.hiddenCarrierCount !== HIDDEN_SYMBOL_COUNT) return null;
    if (!tryDecodeRc6Metadata(extracted.carrierStream, key.keyStr)) return null;
    visibleLen = extracted.visibleText.length;
    payloadLen = visibleLen - CHECKSUM_LEN;
  }
  if (payloadLen < 1 + LEN_FIELD_LEN) return null;

  for (let padLen = 0; padLen < MAX_PAD_LEN; padLen++) {
    const plaintextLen = payloadLen - (1 + LEN_FIELD_LEN) - padLen;
    if (plaintextLen < 0) continue;
    const result = attemptDecryptRc6Stream(ciphertext, key, diagnostics, plaintextLen, materialize);
    if (result && result.success) return result;
  }
  return null;
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
  const wideKey = enabledStr.startsWith(KEY_V6_PREFIX);
  const enabledToken = wideKey ? enabledStr.slice(KEY_V6_PREFIX.length) : enabledStr;
  const enabled = new Set([...enabledToken].map((char) => {
    const index = wideKey ? decodeBase36Index(char) : parseInt(char, 10);
    if (!Number.isInteger(index) || index < 0 || index >= LAYOUT_NAMES.length) {
      throw new Error(`Invalid enabled layout digit: ${JSON.stringify(char)}`);
    }
    return LAYOUT_NAMES[index];
  }));
  const rotors = [];
  if (!rotorStr || rotorStr.length % 3 !== 0) throw new Error('Rotor section must be groups of 3 digits');
  for (let i = 0; i < rotorStr.length; i += 3) {
    const layoutIndex = wideKey ? decodeBase36Index(rotorStr[i]) : parseInt(rotorStr[i], 10);
    const pos = wideKey ? decodeBase36Index(rotorStr.slice(i + 1, i + 3)) : parseInt(rotorStr.slice(i + 1, i + 3), 10);
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
      const ai = wideKey ? decodeBase36Index(steckStr.slice(i, i + 2)) : parseInt(steckStr.slice(i, i + 2), 10);
      const bi = wideKey ? decodeBase36Index(steckStr.slice(i + 2, i + 4)) : parseInt(steckStr.slice(i + 2, i + 4), 10);
      if (!Number.isInteger(ai) || !Number.isInteger(bi) || ai < 0 || bi < 0 || ai >= N || bi >= N) {
        throw new Error('Steck section contains an out-of-range alphabet index');
      }
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
      const index = wideKey ? decodeBase36Index(nonceStr.slice(i, i + 2)) : parseInt(nonceStr.slice(i, i + 2), 10);
      if (!Number.isInteger(index) || index < 0 || index >= N) throw new Error('Nonce section contains an out-of-range alphabet index');
      nonce += ALPHA[index];
    }
  }
  return { enabled, rotors, steckPairs, userRounds, nonce, keyStr: keyStr.trim() };
}

function encodeKey(enabled, rotors, steckPairs, userRounds, nonce = '') {
  const enabledStr = KEY_V6_PREFIX + [...enabled].map((name) => encodeBase36Index(LAYOUT_NAMES.indexOf(name), 1)).join('');
  const rotorStr = rotors.map((rotor) =>
    `${encodeBase36Index(LAYOUT_NAMES.indexOf(rotor.layout), 1)}${encodeBase36Index(rotor.pos, 2)}`
  ).join('');
  const steckStr = steckPairs.length === 0 ? '0' : steckPairs.map(([a, b]) => {
    const lo = Math.min(ALPHA.indexOf(a), ALPHA.indexOf(b));
    const hi = Math.max(ALPHA.indexOf(a), ALPHA.indexOf(b));
    return `${encodeBase36Index(lo, 2)}${encodeBase36Index(hi, 2)}`;
  }).sort().join('');
  const roundsStr = String(userRounds).padStart(3, '0');
  const base = `${enabledStr} ${rotorStr} ${steckStr} ${roundsStr}`;
  if (!nonce) return base;
  const nonceStr = [...nonce].map((char) => encodeBase36Index(ALPHA.indexOf(char), 2)).join('');
  return `${base} ${nonceStr}`;
}

// ── v2.0.0 legacy decryption (self-contained, decrypt-only) ──────────────────
// A complete reimplementation of the v2.0.0 cipher pipeline so rc.7 can recover
// ciphertexts produced by v2.0.0. None of these symbols are reused by rc.6+; they
// share only the variable-name patterns of the v2.0.0 source.

const V200_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\\\',./' + '!@#$%^&*()_+{}|:"<>?`~';
const V200_N = 68;
const V200_CHECKSUM_LEN = 4;
const V200_FNV_OFFSET = 2166136261;
const V200_FNV_PRIME = 16777619;
const V200_LCG_MULT = 1664525;
const V200_LCG_INC = 1013904223;
const V200_LCG_MASK = 0xFFFFFFFF;
const V200_STEP_MASK_ACTIVE = 47;
const V200_LAYOUT_NAMES = ['QWERTY','Colemak','Colemak-DH','Dvorak','Workman',
                           'Norman','Asset','Halmak','AZERTY','QWERTZ'];
const V200_LAYOUT_DEFS = {
  'QWERTY':    { top: 'QWERTYUIOP', home: 'ASDFGHJKL;', bot: 'ZXCVBNM' },
  'Colemak':   { top: 'QWFPGJLUY;', home: 'ARSTDHNEIO', bot: 'ZXCVBKM' },
  'Colemak-DH':{ top: 'QWFPBJLUY;', home: 'ARSTGMNEIO', bot: 'ZXCDVKH' },
  'Dvorak':    { top: "',.PYFGCRL", home: 'AOEUIDHTNS', bot: ';QJKXBM' },
  'Workman':   { top: 'QDRWBJFUP;', home: 'ASHTGYNEOI', bot: 'ZXMCVKL' },
  'Norman':    { top: 'QWDFKJURL;', home: 'ASETGYNIOH', bot: 'ZXCVBPM' },
  'Asset':     { top: 'QWJFGYPUL;', home: 'ASETDHNIOR', bot: 'ZXCVBKM' },
  'Halmak':    { top: 'WLRBJZFUO;', home: 'SHNTMEDAIC', bot: 'QGVXPKY' },
  'AZERTY':    { top: 'AZERTYUIOP', home: 'QSDFGHJKL;', bot: 'WXCVBNM' },
  'QWERTZ':    { top: 'QWERTZUIOP', home: 'ASDFGHJKL;', bot: 'YXCVBNM' },
};
const V200_QWERTY_TOP = 'QWERTYUIOP';
const V200_QWERTY_HOME = 'ASDFGHJKL;';
const V200_QWERTY_BOT = 'ZXCVBNM';

function v200HashStr(s) {
  let h = V200_FNV_OFFSET;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, V200_FNV_PRIME) >>> 0;
  }
  return h;
}

function v200Lcg(v) {
  return (Math.imul(v, V200_LCG_MULT) + V200_LCG_INC) >>> 0;
}

function v200RotorStateHash(rotors) {
  let h = V200_FNV_OFFSET;
  for (const r of rotors) {
    h ^= (r.pos * 73) >>> 0;
    h = Math.imul(h, V200_FNV_PRIME) >>> 0;
  }
  return h;
}

function v200ComputeKeyMaterial(steckPairs, rotors, enabled, userRounds) {
  let S = 0;
  for (const [a, b] of steckPairs) {
    const ai = V200_ALPHA.indexOf(a), bi = V200_ALPHA.indexOf(b);
    S += Math.min(ai, bi) * V200_N + Math.max(ai, bi);
  }
  const R = rotors.reduce((acc, r) => acc + r.pos, 0);
  const L = enabled.reduce((acc, n) => acc + V200_LAYOUT_NAMES.indexOf(n), 0);
  const rounds = ((S + R + L + userRounds) % 999) + 1;
  const keySum = ((Math.imul(S, 31) + Math.imul(R, 17) + Math.imul(L, 13)) >>> 0);

  const stepPos = [...Array(V200_N).keys()];
  let v = (keySum ^ 0x5A5A5A5A) >>> 0;
  for (let i = V200_N - 1; i > 0; i--) {
    v = v200Lcg(v);
    const j = v % (i + 1);
    [stepPos[i], stepPos[j]] = [stepPos[j], stepPos[i]];
  }
  const stepMask = new Array(V200_N).fill(false);
  for (let i = 0; i < V200_STEP_MASK_ACTIVE; i++) stepMask[stepPos[i]] = true;

  const transPerm = [...Array(V200_N).keys()];
  v = (keySum ^ 0xDEAD1234) >>> 0;
  for (let i = V200_N - 1; i > 0; i--) {
    v = v200Lcg(v);
    const j = v % (i + 1);
    [transPerm[i], transPerm[j]] = [transPerm[j], transPerm[i]];
  }
  const invTransPerm = new Array(V200_N);
  for (let i = 0; i < V200_N; i++) invTransPerm[transPerm[i]] = i;

  const layoutKeyBase = keySum % V200_N;

  const layoutMaps = {};
  const invLayoutMaps = {};
  V200_LAYOUT_NAMES.forEach((name, li) => {
    const perm = [...Array(V200_N).keys()];
    let v2 = (keySum ^ (Math.imul(li, 0x9E3779B9) + 0xABCD1234)) >>> 0;
    for (let i = V200_N - 1; i > 0; i--) {
      v2 = v200Lcg(v2);
      const j = v2 % (i + 1);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    const fwd = {}, inv = {};
    for (let i = 0; i < V200_N; i++) {
      fwd[V200_ALPHA[i]] = V200_ALPHA[perm[i]];
      inv[V200_ALPHA[perm[i]]] = V200_ALPHA[i];
    }
    layoutMaps[name] = fwd;
    invLayoutMaps[name] = inv;
  });

  const whiteningSeed = (keySum ^ 0xC0FFEE42) >>> 0;
  return { rounds, keySum, stepMask, transPerm, invTransPerm, layoutKeyBase, layoutMaps, invLayoutMaps, whiteningSeed };
}

function v200KeyedLayoutOffset(name, layoutKeyBase) {
  return (V200_LAYOUT_NAMES.indexOf(name) * 7 + layoutKeyBase) % V200_N;
}

function v200RotorShift(rotors) {
  let val = 0n;
  const Nb = BigInt(V200_N);
  rotors.forEach((r, i) => { val += BigInt(r.pos) * (Nb ** BigInt(rotors.length - 1 - i)); });
  return Number(val % Nb);
}

function v200AdvanceRotors(rotors, charIdx, stepMask) {
  if (!stepMask[charIdx % V200_N]) return rotors.map(r => ({ ...r }));
  const rs = rotors.map(r => ({ ...r }));
  rs[rs.length - 1].pos = (rs[rs.length - 1].pos + 1) % V200_N;
  for (let i = rs.length - 1; i > 0; i--) {
    if (rs[i].pos === 0) rs[i - 1].pos = (rs[i - 1].pos + 1) % V200_N;
  }
  return rs;
}

function v200ApplyNonce(rotors, nonce) {
  if (!nonce) return rotors.map(r => ({ ...r }));
  return rotors.map((r, i) => {
    const off = i < nonce.length ? V200_ALPHA.indexOf(nonce[i]) : 0;
    return { ...r, pos: (r.pos + (off < 0 ? 0 : off)) % V200_N };
  });
}

function v200ApplyLayout(c, name, shift, invert, lm, ilm) {
  if (!invert) {
    let x = lm[name][c] ?? c;
    if (V200_ALPHA.includes(x)) x = V200_ALPHA[(V200_ALPHA.indexOf(x) + shift) % V200_N];
    return x;
  }
  let x = c;
  if (V200_ALPHA.includes(x)) x = V200_ALPHA[((V200_ALPHA.indexOf(x) - shift) % V200_N + V200_N) % V200_N];
  return ilm[name][x] ?? x;
}

function v200PlugFwd(c, layouts, lm) {
  for (const n of layouts) c = lm[n][c] ?? c;
  return c;
}

function v200PlugInv(c, layouts, ilm) {
  for (let i = layouts.length - 1; i >= 0; i--) c = ilm[layouts[i]][c] ?? c;
  return c;
}

function v200Process(text, key, decryptFlag, variant) {
  const km = v200ComputeKeyMaterial(key.steckPairs, key.rotors, key.enabled, key.userRounds);
  const rds = km.rounds;
  const steckMap = {};
  for (const ch of V200_ALPHA) steckMap[ch] = ch;
  for (const [a, b] of key.steckPairs) { steckMap[a] = b; steckMap[b] = a; }
  const rotorSet = new Set(key.rotors.map(r => r.layout));
  const el = [...key.enabled];
  const unused = el.filter(n => !rotorSet.has(n));
  let rs = v200ApplyNonce(key.rotors, key.nonce);
  const lm = km.layoutMaps;
  const ilm = km.invLayoutMaps;
  let wstate = km.whiteningSeed;
  let result = '';
  let ci = 0;
  for (const c of text) {
    const ch = (c >= 'a' && c <= 'z') ? c.toUpperCase() : c;
    if (!V200_ALPHA.includes(ch)) { result += c; continue; }
    const ss = v200RotorShift(rs);
    const stepLayouts = [];
    for (let r = 0; r < rds; r++) stepLayouts.push(el[r % el.length]);
    const rsHash = v200RotorStateHash(rs);
    let posOffset;
    if (variant === 'py') {
      posOffset = ((km.keySum * 37 + ci * 13 + rsHash) % V200_N + V200_N) % V200_N;
    } else {
      posOffset = ((Math.imul(km.layoutKeyBase, 37) + ci * 13 + rsHash) >>> 0) % V200_N;
    }
    const stepShifts = stepLayouts.map((lay, r) =>
      (ss + r + ci + posOffset + v200KeyedLayoutOffset(lay, km.layoutKeyBase)) % V200_N);
    const scrambleShifts = unused.map((u, i) =>
      (ss + rds + i + ci + posOffset + v200KeyedLayoutOffset(u, km.layoutKeyBase)) % V200_N);
    let x = ch;
    if (!decryptFlag) {
      x = steckMap[x];
      x = v200PlugFwd(x, unused, lm);
      for (let r = 0; r < rds; r++) x = v200ApplyLayout(x, stepLayouts[r], stepShifts[r], false, lm, ilm);
      if (V200_ALPHA.includes(x)) x = V200_ALPHA[km.transPerm[V200_ALPHA.indexOf(x)]];
      for (let i = 0; i < unused.length; i++) x = v200ApplyLayout(x, unused[i], scrambleShifts[i], false, lm, ilm);
      x = v200PlugFwd(x, unused, lm);
      x = steckMap[x];
      wstate = v200Lcg(wstate);
      x = V200_ALPHA[(V200_ALPHA.indexOf(x) + wstate % V200_N) % V200_N];
    } else {
      wstate = v200Lcg(wstate);
      x = V200_ALPHA[((V200_ALPHA.indexOf(x) - wstate % V200_N) % V200_N + V200_N) % V200_N];
      x = steckMap[x];
      x = v200PlugInv(x, unused, ilm);
      for (let i = unused.length - 1; i >= 0; i--) x = v200ApplyLayout(x, unused[i], scrambleShifts[i], true, lm, ilm);
      if (V200_ALPHA.includes(x)) x = V200_ALPHA[km.invTransPerm[V200_ALPHA.indexOf(x)]];
      for (let r = rds - 1; r >= 0; r--) x = v200ApplyLayout(x, stepLayouts[r], stepShifts[r], true, lm, ilm);
      x = v200PlugInv(x, unused, ilm);
      x = steckMap[x];
    }
    result += x;
    rs = v200AdvanceRotors(rs, ci, km.stepMask);
    ci++;
  }
  return result;
}

function v200ComputeChecksum(plaintext, keyStr) {
  const h1 = v200HashStr(plaintext + '|' + keyStr + '|chk1');
  const h2 = v200HashStr(plaintext + '|' + keyStr + '|chk2');
  let v = (h1 ^ ((h2 << 16) >>> 0)) >>> 0;
  let out = '';
  for (let i = 0; i < V200_CHECKSUM_LEN; i++) {
    v = v200Lcg(v);
    out += V200_ALPHA[v % V200_N];
  }
  return out;
}

function v200ChecksumPos(keyStr, totalLen) {
  const h = v200HashStr(keyStr + 'chkpos');
  return h % Math.max(1, totalLen - V200_CHECKSUM_LEN);
}

function v200StripChecksum(ciphertext, keyStr) {
  const pos = v200ChecksumPos(keyStr, ciphertext.length);
  const chk = ciphertext.slice(pos, pos + V200_CHECKSUM_LEN);
  const stripped = ciphertext.slice(0, pos) + ciphertext.slice(pos + V200_CHECKSUM_LEN);
  return { stripped, chk };
}

function v200SentenceCaseForChecksum(text) {
  const lower = text.toLowerCase();
  if (!lower) return lower;
  return lower[0].toUpperCase() + lower.slice(1);
}

function v200VerifyChecksum(chk, stripped, plaintext, keyStr) {
  if (chk === v200ComputeChecksum(stripped, keyStr)) return 'stripped';
  if (chk === v200ComputeChecksum(plaintext, keyStr)) return 'plain';
  const folded = v200SentenceCaseForChecksum(plaintext);
  if (chk === v200ComputeChecksum(folded, keyStr)) return 'sentence';
  return null;
}

function v200ParseKey(keyStr) {
  if (keyStr.trim().split(/\s+/)[0].startsWith(KEY_V6_PREFIX)) return null;
  const parts = keyStr.trim().split(/\s+/);
  if (parts.length !== 4 && parts.length !== 5) return null;
  const [enabledStr, rotorStr, steckStr, uStr] = parts;
  const nonceStr = parts.length === 5 ? parts[4] : '';
  try {
    const enabledIndices = [...enabledStr].map(c => Number(c));
    if (enabledIndices.length === 0 || enabledIndices.some(i => !Number.isInteger(i) || i >= V200_LAYOUT_NAMES.length || i < 0)) return null;
    const enabled = enabledIndices.map(i => V200_LAYOUT_NAMES[i]);
    if (rotorStr.length === 0 || rotorStr.length % 3 !== 0) return null;
    const rotors = [];
    for (let i = 0; i < rotorStr.length; i += 3) {
      const lidx = Number(rotorStr[i]);
      const pos = Number(rotorStr.slice(i + 1, i + 3));
      if (!Number.isInteger(lidx) || !Number.isInteger(pos) || lidx >= V200_LAYOUT_NAMES.length || pos >= V200_N) return null;
      rotors.push({ layout: V200_LAYOUT_NAMES[lidx], pos });
    }
    const steckPairs = [];
    if (steckStr !== '0') {
      if (steckStr.length % 4 !== 0) return null;
      for (let i = 0; i < steckStr.length; i += 4) {
        const ai = Number(steckStr.slice(i, i + 2));
        const bi = Number(steckStr.slice(i + 2, i + 4));
        if (!Number.isInteger(ai) || !Number.isInteger(bi) || ai >= V200_N || bi >= V200_N) return null;
        steckPairs.push([V200_ALPHA[ai], V200_ALPHA[bi]]);
      }
    }
    const userRounds = Number(uStr);
    if (!Number.isInteger(userRounds)) return null;
    let nonce = '';
    if (nonceStr) {
      if (nonceStr.length % 2 !== 0) return null;
      for (let i = 0; i < nonceStr.length; i += 2) {
        const idx = Number(nonceStr.slice(i, i + 2));
        if (!Number.isInteger(idx) || idx >= V200_N) return null;
        nonce += V200_ALPHA[idx];
      }
    }
    return { enabled, rotors, steckPairs, userRounds, nonce, keyStr: keyStr.trim() };
  } catch (_) {
    return null;
  }
}

function v200TryDecrypt(ciphertext, keyStr) {
  for (const ch of ciphertext) {
    const isPrintable = ch >= ' ' && ch <= '~';
    if (isPrintable && !V200_ALPHA.includes(ch) && ch !== ' ') return null;
  }
  const key = v200ParseKey(keyStr);
  if (key === null) return null;
  if (ciphertext.length <= V200_CHECKSUM_LEN) return null;
  for (const variant of ['py', 'js']) {
    try {
      const { stripped, chk } = v200StripChecksum(ciphertext, key.keyStr);
      const plaintext = v200Process(stripped, key, true, variant);
      const verifyMode = v200VerifyChecksum(chk, stripped, plaintext, key.keyStr);
      if (verifyMode !== null) return { plaintext, variant, verifyMode };
    } catch (_) {
      continue;
    }
  }
  return null;
}

function encodeV200KeyString(parsed) {
  const enabledList = [...parsed.enabled];
  if (enabledList.length === 0) return null;
  const enabledStr = enabledList.map((name) => {
    const idx = V200_LAYOUT_NAMES.indexOf(name);
    if (idx < 0) return null;
    return String(idx);
  });
  if (enabledStr.some((value) => value === null)) return null;

  let rotorStr = '';
  for (const rotor of parsed.rotors) {
    const lidx = V200_LAYOUT_NAMES.indexOf(rotor.layout);
    if (lidx < 0 || rotor.pos >= V200_N || !enabledList.includes(rotor.layout)) return null;
    rotorStr += `${lidx}${String(rotor.pos).padStart(2, '0')}`;
  }
  if (!rotorStr) return null;

  let steckStr = '0';
  if (parsed.steckPairs.length > 0) {
    steckStr = '';
    for (const [a, b] of parsed.steckPairs) {
      const ai = V200_ALPHA.indexOf(a);
      const bi = V200_ALPHA.indexOf(b);
      if (ai < 0 || bi < 0) return null;
      steckStr += `${String(ai).padStart(2, '0')}${String(bi).padStart(2, '0')}`;
    }
  }

  const roundsStr = String(parsed.userRounds).padStart(3, '0');
  let key = `${enabledStr.join('')} ${rotorStr} ${steckStr} ${roundsStr}`;
  if (parsed.nonce) {
    let nonceStr = '';
    for (const ch of parsed.nonce) {
      const idx = V200_ALPHA.indexOf(ch);
      if (idx < 0) return null;
      nonceStr += String(idx).padStart(2, '0');
    }
    key += ` ${nonceStr}`;
  }
  return key;
}

function collectV200KeyCandidates(keyStr, extraCandidates = []) {
  const candidates = [];
  const seen = new Set();
  const add = (value) => {
    const trimmed = (value || '').trim();
    if (!trimmed || seen.has(trimmed)) return;
    seen.add(trimmed);
    candidates.push(trimmed);
  };
  add(keyStr);
  for (const value of extraCandidates) add(value);
  if (v200ParseKey(keyStr)) add(keyStr);
  try {
    add(encodeV200KeyString(parseKey(keyStr)));
  } catch (_) {}
  return candidates;
}

function v200TryDecryptWithCandidates(ciphertext, keyStr, extraCandidates = []) {
  for (const candidate of collectV200KeyCandidates(keyStr, extraCandidates)) {
    const result = v200TryDecrypt(ciphertext, candidate);
    if (result !== null) return { ...result, keyStr: candidate };
  }
  return null;
}

function finalizeV200DecryptResult(v200Result, diagnostics, visibleText) {
  return finalizeDecryptResult({
    plaintext: v200Result.plaintext,
    verified: true,
    checksumOk: true,
    paddingOk: true,
    structureOk: true,
    metadataOk: true,
    versionOk: true,
    lengthField: '',
    padding: '',
    error: null,
    format: 'v2.0.0-legacy',
    variant: v200Result.variant,
    diagnostics,
    payload: visibleText,
  }, v200Result.plaintext, v200Result.keyStr, {}, { km: {}, rotors: [] });
}


function encrypt(plaintext, keyStr, opts) {
  if (!keyStr.trim().split(/\s+/)[0].startsWith(KEY_V6_PREFIX)) {
    throw new Error(K6_ENCRYPT_REQUIRED_ERROR);
  }
  const materialize = !!(opts && opts.materialize);
  const key = parseKey(keyStr);
  return encryptRc6Stream(plaintext, key, materialize);
}

function decrypt(ciphertext, keyStr, opts) {
  const materialize = !!(opts && opts.materialize);
  const extraKeyCandidates = (opts && opts.keyCandidates) || [];
  const diagnostics = analyzeCiphertext(ciphertext);
  const extracted = extractCarrierInfo(ciphertext);
  const visibleText = extracted.visibleText;

  const v200Result = v200TryDecryptWithCandidates(visibleText, keyStr, extraKeyCandidates);
  if (v200Result !== null) {
    return finalizeV200DecryptResult(v200Result, diagnostics, visibleText);
  }

  const key = parseKey(keyStr);

  if (materialize) {
    const rc6Result = decryptRc6Stream(ciphertext, key, diagnostics, extracted, true);
    if (rc6Result !== null) return rc6Result;
    return genericDecryptFailure({
      plaintext: '',
      verified: false,
      checksumOk: false,
      paddingOk: false,
      structureOk: false,
      metadataOk: false,
      versionOk: false,
      diagnostics,
      payload: '',
      visiblePayload: '',
      format: 'rc.6-stream',
      materialize: true,
      error: GENERIC_DECRYPT_ERROR,
    }, '', key.keyStr);
  }

  const rc6Result = decryptRc6Stream(ciphertext, key, diagnostics, extracted);
  if (rc6Result !== null) return rc6Result;
  if (tryDecodeRc6Metadata(extracted.carrierStream, key.keyStr)) {
    return genericDecryptFailure({
      plaintext: '',
      verified: false,
      checksumOk: false,
      paddingOk: false,
      structureOk: false,
      metadataOk: true,
      versionOk: true,
      diagnostics,
      payload: '',
      visiblePayload: '',
      format: 'rc.6-stream',
      error: GENERIC_DECRYPT_ERROR,
    }, '', key.keyStr);
  }

  if (visibleText.startsWith(LEGACY_RC3_HEADER)) {
    const body = visibleText.slice(LEGACY_RC3_HEADER.length);
    const state = createLegacyCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
    const payload = processLegacySegment(body, state, true);
    const unpacked = unpackRc3Payload(payload, key.keyStr);
    const result = { ...unpacked, diagnostics, payload, format: 'rc.3' };
    return finalizeDecryptResult(result, result.plaintext || payload, key.keyStr, state.km, state);
  }

  let rc4State;
  let visiblePayload;
  let visibleFields;
  try {
    rc4State = createRc4LegacyCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
    visiblePayload = processRc4LegacySegment(visibleText, rc4State, true);
    visibleFields = unpackRc4LegacyVisiblePayload(visiblePayload);
  } catch (_) {
    rc4State = null;
    visiblePayload = '';
    visibleFields = { structureOk: false };
  }
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
      hiddenCipher = _legacyDecodeHiddenCarrierStream(extracted.carrierStream, key.keyStr);
    } catch (_) {
      return genericDecryptFailure({
        ...baseResult,
      }, visibleFields.plaintext, key.keyStr, rc4State.km, rc4State);
    }

    const hiddenPayload = processRc4LegacySegment(hiddenCipher, rc4State, true);
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
    const checksumOk = versionOk && checksum === computeLegacyAlphabetChecksum(visibleText, _legacyDeriveMacSubkey(key.keyStr), version);
    const paddingSeed = versionOk ? computeLegacyPaddingSeed(visibleFields.plaintext, key.keyStr, visibleFields.lengthField, version) : '';
    const expectedPadLen = versionOk ? _legacyComputePadLength(visibleFields.plaintext, key.keyStr, paddingSeed, version) : 0;
    const expectedPadding = versionOk ? generateLegacyPadding(visibleFields.plaintext, key.keyStr, paddingSeed, version, expectedPadLen) : '';
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
  let state;
  let plaintext;
  let verified;
  try {
    state = createLegacyCipherState(key.steckPairs, key.rotors, key.enabled, key.userRounds, key.nonce);
    plaintext = processLegacySegment(stripped, state, true);
    verified = checksum === legacyComputeChecksum(plaintext, key.keyStr);
  } catch (_) {
    state = { km: {}, rotors: [] };
    plaintext = '';
    verified = false;
  }
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
  const layoutCombos = permutationCountBig(LAYOUT_NAMES.length, layoutCount);
  const rotorCombos = BigInt(layoutCount * N) ** BigInt(rotorCount);
  const steckCombos = steckPairingCountBig(N, steckCount);
  const nonceCombos = includeNonce ? N_BIG ** 3n : 1n;
  return layoutCombos * rotorCombos * steckCombos * nonceCombos;
}

function chooseProfile(opts, rng) {
  const layoutChoices = opts.numLayouts == null ? [...Array(LAYOUT_NAMES.length).keys()].map((i) => i + 1) : [opts.numLayouts];
  const rotorChoices = opts.numRotors == null ? [...Array(18).keys()].map((i) => i + 1) : [opts.numRotors];
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
  if (numRotors != null && (numRotors < 1 || numRotors > 18)) {
    throw new Error('numRotors must be between 1 and 18');
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
  for (let i = 0; i < enabledCount; i++) layoutCombos *= (LAYOUT_NAMES.length - i);
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

const ENIGMAK_EXPORTS = { encrypt, decrypt, generateKey, calcIoC, calcKeyStrength, parseKey, encodeKey, analyzeCiphertext, ALPHA, N };
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ENIGMAK_EXPORTS;
}
if (typeof window !== 'undefined') {
  window.ENIGMAK = ENIGMAK_EXPORTS;
}
