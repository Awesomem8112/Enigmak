/**
 * ENIGMAK v3.0.0-rc.3 - JavaScript module
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

// ── Alphabet ──────────────────────────────────────────────────────────────────
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\\\',./' +
              '!@#$%^&*()_+{}|:"<>?`~' +
              'abcdefghijklmnopqrstuvwxyz ';
const N = ALPHA.length; // 95
const STEP_MASK_ACTIVE = 66;
const CHECKSUM_LEN = 10;
const CIPHERTEXT_HEADER = 'E3|';
const LEN_FIELD_LEN = 4;
const MAX_PAD_LEN = 16;
const U64_MASK = (1n << 64n) - 1n;
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
  'QWERTY':    {top:'QWERTYUIOP', home:'ASDFGHJKL;', bot:'ZXCVBNM'},
  'Colemak':   {top:'QWFPGJLUY;', home:'ARSTDHNEIO', bot:'ZXCVBKM'},
  'Colemak-DH':{top:'QWFPBJLUY;', home:'ARSTGMNEIO', bot:'ZXCDVKH'},
  'Dvorak':    {top:"',.PYFGCRL", home:'AOEUIDHTNS', bot:';QJKXBM'},
  'Workman':   {top:'QDRWBJFUP;', home:'ASHTGYNEOI', bot:'ZXMCVKL'},
  'Norman':    {top:'QWDFKJURL;', home:'ASETGYNIOH', bot:'ZXCVBPM'},
  'Asset':     {top:'QWJFGYPUL;', home:'ASETDHNIOR', bot:'ZXCVBKM'},
  'Halmak':    {top:'WLRBJZFUO;', home:'SHNTMEDAIC', bot:'QGVXPKY'},
  'AZERTY':    {top:'AZERTYUIOP', home:'QSDFGHJKL;', bot:'WXCVBNM'},
  'QWERTZ':    {top:'QWERTZUIOP', home:'ASDFGHJKL;', bot:'YXCVBNM'},
};

const QT='QWERTYUIOP', QH='ASDFGHJKL;', QB='ZXCVBNM';

function buildMap(n) {
  const d = LAYOUT_DEFS[n], m = {};
  [...QT].forEach((q,i) => { if (d.top[i] && ALPHA.includes(d.top[i].toUpperCase())) m[q] = d.top[i].toUpperCase(); });
  [...QH].forEach((q,i) => { if (d.home[i] && ALPHA.includes(d.home[i].toUpperCase())) m[q] = d.home[i].toUpperCase(); });
  [...QB].forEach((q,i) => { if (d.bot[i] && ALPHA.includes(d.bot[i].toUpperCase())) m[q] = d.bot[i].toUpperCase(); });
  return m;
}

const MAPS = {}, INV_MAPS = {};
LAYOUT_NAMES.forEach(n => {
  MAPS[n] = buildMap(n);
  INV_MAPS[n] = Object.fromEntries(Object.entries(MAPS[n]).map(([k,v]) => [v,k]));
});

// ── Utilities ─────────────────────────────────────────────────────────────────
function hashStr(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

function lcg(v) { return (Math.imul(v, 1664525) + 1013904223) >>> 0; }
function lcg64(v) { return (v * 6364136223846793005n + 1442695040888963407n) & U64_MASK; }

function hashStr64(s) {
  const bytes = new TextEncoder().encode(s);
  let h = 0xcbf29ce484222325n;
  for (const b of bytes) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & U64_MASK;
  }
  return h;
}

function rotorStateHash(rotors) {
  let h = 2166136261;
  for (const r of rotors) {
    h ^= r.pos * 73;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

// ── Key material derivation ───────────────────────────────────────────────────
function computeKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds) {
  const S = steckPairs.reduce((a,[x,y]) => {
    const ai = ALPHA.indexOf(x), bi = ALPHA.indexOf(y);
    return a + (ai < bi ? ai*N+bi : bi*N+ai);
  }, 0);
  const R = rotors.reduce((a,r) => a + r.pos, 0);
  const L = [...enabledLayouts].reduce((a,n) => a + LAYOUT_NAMES.indexOf(n), 0);
  const rounds = ((S + R + L + userRounds) % 999) + 1;
  const keySum = ((S*31 + R*17 + L*13) >>> 0);

  const stepPos = [...Array(N).keys()];
  let v = (keySum ^ 0x5A5A5A5A) >>> 0;
  for (let i=N-1;i>0;i--) { v=lcg(v); const j=v%(i+1); [stepPos[i],stepPos[j]]=[stepPos[j],stepPos[i]]; }
  const stepMask = new Array(N).fill(false);
  stepPos.slice(0,STEP_MASK_ACTIVE).forEach(p => stepMask[p] = true);

  const transPerm = [...Array(N).keys()];
  v = (keySum ^ 0xDEAD1234) >>> 0;
  for (let i=N-1;i>0;i--) { v=lcg(v); const j=v%(i+1); [transPerm[i],transPerm[j]]=[transPerm[j],transPerm[i]]; }
  const invTransPerm = new Array(N);
  transPerm.forEach((x,i) => invTransPerm[x] = i);

  // Key-derived layout permutations -- replaces fixed keyboard layout wirings
  const layoutMaps = {}, invLayoutMaps = {};
  LAYOUT_NAMES.forEach((name, li) => {
    const perm = [...Array(N).keys()];
    let v2 = ((keySum ^ (li * 0x9E3779B9 + 0xABCD1234)) >>> 0);
    for (let i=N-1;i>0;i--) { v2=((v2*1664525)+1013904223)>>>0; const j=v2%(i+1); [perm[i],perm[j]]=[perm[j],perm[i]]; }
    const fwd={}, inv={};
    for (let i=0;i<N;i++) { fwd[ALPHA[i]]=ALPHA[perm[i]]; inv[ALPHA[perm[i]]]=ALPHA[i]; }
    layoutMaps[name]=fwd; invLayoutMaps[name]=inv;
  });

  const whiteningState = (keySum ^ 0xC0FFEE42) >>> 0;
  return { rounds, stepMask, transPerm, invTransPerm, layoutKeyBase: keySum % N, keySum, whiteningState, layoutMaps, invLayoutMaps };
}

function keyedLayoutOffset(n, b) { return (LAYOUT_NAMES.indexOf(n)*7 + b) % N; }

function rotorShift(rs) {
  let val = 0n;
  const Nb = BigInt(N);
  rs.forEach((r,i) => { val += BigInt(r.pos) * (Nb ** BigInt(rs.length-1-i)); });
  return Number(val % Nb);
}

function advanceRotors(rs, ci, stepMask) {
  if (!stepMask[ci % N]) return rs.map(r => ({...r}));
  const nrs = rs.map(r => ({...r}));
  nrs[nrs.length-1].pos = (nrs[nrs.length-1].pos + 1) % N;
  for (let i=nrs.length-1;i>0;i--) { if (nrs[i].pos===0) nrs[i-1].pos=(nrs[i-1].pos+1)%N; }
  return nrs;
}

function applyNonce(rotors, nonce) {
  if (!nonce) return rotors;
  return rotors.map((r,i) => {
    const off = i < nonce.length ? ALPHA.indexOf(nonce[i]) : 0;
    return {...r, pos: (r.pos + (off < 0 ? 0 : off)) % N};
  });
}

function applyLayout(c, n, s, inv, lm, ilm) {
  if (!inv) {
    let x = lm[n]?.[c] ?? c;
    if (ALPHA.includes(x)) x = ALPHA[(ALPHA.indexOf(x)+s) % N];
    return x;
  } else {
    let x = c;
    if (ALPHA.includes(x)) x = ALPHA[(ALPHA.indexOf(x)-s+N*100) % N];
    x = ilm[n]?.[x] ?? x;
    return x;
  }
}

function plugFwd(c, ls, lm) { let x=c; for (const n of ls) x=lm[n]?.[x]??x; return x; }
function plugInv(c, ls, ilm) { let x=c; for (let i=ls.length-1;i>=0;i--) x=ilm[ls[i]]?.[x]??x; return x; }

// ── Core process ──────────────────────────────────────────────────────────────
function _process(text, steckPairs, rotors, enabledLayouts, userRounds, nonce='', decrypt=false) {
  const km = computeKeyMaterial(steckPairs, rotors, enabledLayouts, userRounds);
  const rds = km.rounds;
  const smMap = {}; for (const c of ALPHA) smMap[c] = c;
  steckPairs.forEach(([a,b]) => { smMap[a]=b; smMap[b]=a; });
  const applySteck = c => smMap[c] ?? c;
  const rotorSet = new Set(rotors.map(r => r.layout));
  const el = [...enabledLayouts];
  const unused = el.filter(n => !rotorSet.has(n));
  let rs = applyNonce(rotors.map(r => ({...r})), nonce);
  // Position whitening: LCG stream, period 2^32 -- breaks mod-N periodicity
  let wstate = km.whiteningState;
  const lm = km.layoutMaps, ilm = km.invLayoutMaps;
  let result = '', ci = 0;

  for (const c of text) {
    if (!ALPHA.includes(c)) { result += c; continue; }
    const ss = rotorShift(rs);
    const rL = [], rS = [];
    // Position offset: rotor state feedback breaks monocharacter oracle
    const rsHash = rotorStateHash(rs);
    const posOffset = ((km.layoutKeyBase * 37 + ci * 13 + rsHash) >>> 0) % N;
    for (let r=0;r<rds;r++) {
      const lay = el[r % el.length]; rL.push(lay);
      rS.push((ss + r + ci + posOffset + keyedLayoutOffset(lay, km.layoutKeyBase)) % N);
    }
    const sS = unused.map((_,i) => (ss+rds+i+ci+posOffset+keyedLayoutOffset(unused[i],km.layoutKeyBase))%N);
    let x = c;
    if (!decrypt) {
      x=applySteck(x); x=plugFwd(x,unused,lm);
      for (let r=0;r<rds;r++) x=applyLayout(x,rL[r],rS[r],false,lm,ilm);
      if (ALPHA.includes(x)) x=ALPHA[km.transPerm[ALPHA.indexOf(x)]];
      unused.forEach((n,i) => { x=applyLayout(x,n,sS[i],false,lm,ilm); });
      x=plugFwd(x,unused,lm); x=applySteck(x);
      // Position whitening (encrypt: add LCG offset)
      wstate=((wstate*1664525)+1013904223)>>>0;
      if(ALPHA.includes(x)) x=ALPHA[(ALPHA.indexOf(x)+wstate%N)%N];
    } else {
      // Position whitening (decrypt: subtract LCG offset first)
      wstate=((wstate*1664525)+1013904223)>>>0;
      if(ALPHA.includes(x)) x=ALPHA[(ALPHA.indexOf(x)-wstate%N+N*100)%N];
      x=applySteck(x); x=plugInv(x,unused,ilm);
      for (let i=unused.length-1;i>=0;i--) x=applyLayout(x,unused[i],sS[i],true,lm,ilm);
      if (ALPHA.includes(x)) x=ALPHA[km.invTransPerm[ALPHA.indexOf(x)]];
      for (let r=rds-1;r>=0;r--) x=applyLayout(x,rL[r],rS[r],true,lm,ilm);
      x=plugInv(x,unused,ilm); x=applySteck(x);
    }
    result += x;
    rs = advanceRotors(rs, ci, km.stepMask); ci++;
  }
  return result;
}

// ── Checksum helpers ──────────────────────────────────────────────────────────
function _runChecksumCharsJS(chk, wstate, rs, km, steckPairs, rotors, enabledLayouts, enc) {
  const smMap = {}; for (const c of ALPHA) smMap[c]=c;
  steckPairs.forEach(([a,b])=>{smMap[a]=b;smMap[b]=a;});
  const applySteckL = c => smMap[c]??c;
  const rotorSet = new Set(rotors.map(r=>r.layout));
  const el = [...enabledLayouts];
  const unused = el.filter(n=>!rotorSet.has(n));
  const lm=km.layoutMaps, ilm=km.invLayoutMaps;
  const rds=km.rounds;
  let result='', ci2=0;
  for (const c of chk) {
    if (!ALPHA.includes(c)){result+=c;continue;}
    const ss=rotorShift(rs);
    const rL=[],rS=[];
    for(let r=0;r<rds;r++){
      const lay=el[r%el.length];rL.push(lay);
      const rsH=_rotorStateHashJS(rs);
      const posOff=(km.keySum*37+ci2*13+rsH)%N;
      rS.push((ss+r+ci2+posOff+keyedLayoutOffset(lay,km.layoutKeyBase))%N);
    }
    const rsH2=_rotorStateHashJS(rs);
    const posOff2=(km.keySum*37+ci2*13+rsH2)%N;
    const sS=unused.map((_,i)=>(ss+rds+i+ci2+posOff2+keyedLayoutOffset(unused[i],km.layoutKeyBase))%N);
    let x=c;
    if(enc){
      x=applySteckL(x);x=plugFwd(x,unused,lm);
      for(let r=0;r<rds;r++)x=applyLayout(x,rL[r],rS[r],false,lm,ilm);
      if(ALPHA.includes(x))x=ALPHA[km.transPerm[ALPHA.indexOf(x)]];
      unused.forEach((n,i)=>{x=applyLayout(x,n,sS[i],false,lm,ilm);});
      x=plugFwd(x,unused,lm);x=applySteckL(x);
      wstate=((wstate*1664525)+1013904223)>>>0;
      x=ALPHA[(ALPHA.indexOf(x)+wstate%N)%N];
    } else {
      wstate=((wstate*1664525)+1013904223)>>>0;
      x=ALPHA[(ALPHA.indexOf(x)-wstate%N+N*100)%N];
      x=applySteckL(x);x=plugInv(x,unused,ilm);
      for(let i=unused.length-1;i>=0;i--)x=applyLayout(x,unused[i],sS[i],true,lm,ilm);
      if(ALPHA.includes(x))x=ALPHA[km.invTransPerm[ALPHA.indexOf(x)]];
      for(let r=rds-1;r>=0;r--)x=applyLayout(x,rL[r],rS[r],true,lm,ilm);
      x=plugInv(x,unused,ilm);x=applySteckL(x);
    }
    result+=x;
    rs=advanceRotors(rs,ci2,km.stepMask);ci2++;
  }
  return result;
}

function _rotorStateHashJS(rs) {
  let h=2166136261;
  for(const r of rs){h^=r.pos*73;h=(Math.imul(h,16777619))>>>0;}
  return h;
}

// ── Checksum ──────────────────────────────────────────────────────────────────
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
  for (const ch of text) {
    const idx = ALPHA.indexOf(ch);
    if (idx < 0) throw new Error(`Non-alphabet character in base-95 field: ${JSON.stringify(ch)}`);
    value = value * N + idx;
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

function computeChecksum(plaintext, keyStr, lenField = null) {
  const field = lenField ?? encodeLengthField(plaintext.length);
  let out = '';
  let v = hashStr64(field + '|' + plaintext + '|' + keyStr + '|chk64');
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    v = lcg64(v ^ BigInt(i));
    out += ALPHA[Number(v % BigInt(N))];
  }
  return out;
}

function legacyComputeChecksum(plaintext, keyStr) {
  let out = '';
  let v = hashStr64(plaintext + '|' + keyStr + '|chk64');
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    v = lcg64(v ^ BigInt(i));
    out += ALPHA[Number(v % BigInt(N))];
  }
  return out;
}

function legacyChecksumPos(keyStr, totalLen) {
  return hashStr(keyStr + 'chkpos') % Math.max(1, totalLen - CHECKSUM_LEN);
}

function computePadLength(plaintext, keyStr) {
  return Number(hashStr64(keyStr + '|' + plaintext + '|padlen') % BigInt(MAX_PAD_LEN));
}

function generatePadding(plaintext, keyStr, padLen = null) {
  const targetLen = padLen ?? computePadLength(plaintext, keyStr);
  if (targetLen === 0) return '';
  let out = '';
  let v = hashStr64(keyStr + '|' + plaintext + '|padfill');
  for (let i = 0; i < targetLen; i++) {
    v = lcg64(v ^ BigInt(i));
    out += ALPHA[Number(v % BigInt(N))];
  }
  return out;
}

function packRc3Payload(plaintext, keyStr) {
  const lenField = encodeLengthField(plaintext.length);
  const checksum = computeChecksum(plaintext, keyStr, lenField);
  const padding = generatePadding(plaintext, keyStr);
  return lenField + plaintext + checksum + padding;
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
      error: `Payload too short for rc.3 package (${payload.length} chars)`,
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
  const checksumOk = checksum === computeChecksum(plaintext, keyStr, lengthField);
  const expectedPadLen = computePadLength(plaintext, keyStr);
  const expectedPadding = generatePadding(plaintext, keyStr, expectedPadLen);
  const paddingOk = padding.length === expectedPadLen && padding === expectedPadding;
  return {
    plaintext,
    verified: checksumOk && paddingOk,
    checksumOk,
    paddingOk,
    structureOk: true,
    lengthField,
    padding,
    error: checksumOk && paddingOk ? null : 'Checksum or padding verification failed',
  };
}

function formatCipherChar(ch) {
  if (ch === ' ') return '[space]';
  if (ch === '\n') return '\\n';
  if (ch === '\r') return '\\r';
  if (ch === '\t') return '\\t';
  return ch;
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
  let outsideAlphabetCount = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ALPHA.includes(ch)) continue;
    outsideAlphabetCount++;
    if (Object.prototype.hasOwnProperty.call(CLIPBOARD_NORMALIZATION_MAP, ch)) {
      normalized.push({ pos: i + 1, char: ch, replacement: CLIPBOARD_NORMALIZATION_MAP[ch] });
    }
    if (ch === '\r' || ch === '\n' || ch === '\t') controls.push({ pos: i + 1, char: ch });
    if (ch.charCodeAt(0) > 127) {
      nonAscii.push({
        pos: i + 1,
        char: ch,
        replacement: Object.prototype.hasOwnProperty.call(CLIPBOARD_NORMALIZATION_MAP, ch)
          ? CLIPBOARD_NORMALIZATION_MAP[ch]
          : undefined
      });
    }
  }
  const warnings = [];
  if (normalized.length) warnings.push(`Suspicious clipboard-normalized punctuation: ${summarizeCipherIssues(normalized)}`);
  else if (nonAscii.length) warnings.push(`Non-ASCII ciphertext characters detected: ${summarizeCipherIssues(nonAscii)}`);
  if (controls.length) warnings.push(`Whitespace/control characters detected: ${summarizeCipherIssues(controls)}`);
  return { length: text.length, outsideAlphabetCount, nonAscii, normalized, controls, warnings };
}

// ── Key parsing / encoding ────────────────────────────────────────────────────
function parseKey(keyStr) {
  const parts = keyStr.trim().split(/\s+/);
  if (parts.length < 4 || parts.length > 5) throw new Error('Expected 4 or 5 space-separated sections');
  const [enabledStr, rotorStr, steckStr, uStr, nonceStr] = parts;
  const enabled = new Set([...enabledStr].map(c => LAYOUT_NAMES[parseInt(c)]));
  const rotors = [];
  for (let i=0;i<rotorStr.length;i+=3)
    rotors.push({layout: LAYOUT_NAMES[parseInt(rotorStr[i])], pos: parseInt(rotorStr.slice(i+1,i+3))});
  const steckPairs = [];
  if (steckStr !== '0') {
    for (let i=0;i<steckStr.length;i+=4)
      steckPairs.push([ALPHA[parseInt(steckStr.slice(i,i+2))], ALPHA[parseInt(steckStr.slice(i+2,i+4))]]);
  }
  const userRounds = parseInt(uStr);
  let nonce = '';
  if (nonceStr) for (let i=0;i<nonceStr.length;i+=2) nonce+=ALPHA[parseInt(nonceStr.slice(i,i+2))];
  return { enabled, rotors, steckPairs, userRounds, nonce, keyStr: keyStr.trim() };
}

function encodeKey(enabled, rotors, steckPairs, userRounds, nonce='') {
  const enabledStr = [...enabled].map(n => LAYOUT_NAMES.indexOf(n)).join('');
  const rotorStr   = rotors.map(r => `${LAYOUT_NAMES.indexOf(r.layout)}${String(r.pos).padStart(2,'0')}`).join('');
  const steckStr   = steckPairs.length === 0 ? '0' :
    steckPairs.map(([a,b]) => {
      const lo=Math.min(ALPHA.indexOf(a),ALPHA.indexOf(b));
      const hi=Math.max(ALPHA.indexOf(a),ALPHA.indexOf(b));
      return String(lo).padStart(2,'0')+String(hi).padStart(2,'0');
    }).sort().join('');
  const uStr = String(userRounds).padStart(3,'0');
  const base = `${enabledStr} ${rotorStr} ${steckStr} ${uStr}`;
  if (nonce) {
    const ns = [...nonce].map(c => String(ALPHA.indexOf(c)).padStart(2,'0')).join('');
    return `${base} ${ns}`;
  }
  return base;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Encrypt plaintext with the given key string.
 * Returns ciphertext with an rc.3 header and encrypted package body.
 */
function encrypt(plaintext, keyStr) {
  const k = parseKey(keyStr);
  const payload = packRc3Payload(plaintext, k.keyStr);
  const cipher = _process(payload, k.steckPairs, k.rotors, k.enabled, k.userRounds, k.nonce, false);
  return CIPHERTEXT_HEADER + cipher;
}

/**
 * Decrypt ciphertext with the given key string.
 * Returns { plaintext, verified } where verified indicates checksum status.
 */
function decrypt(ciphertext, keyStr) {
  const diagnostics = analyzeCiphertext(ciphertext);
  const k = parseKey(keyStr);
  if (ciphertext.startsWith(CIPHERTEXT_HEADER)) {
    const body = ciphertext.slice(CIPHERTEXT_HEADER.length);
    const payload = _process(body, k.steckPairs, k.rotors, k.enabled, k.userRounds, k.nonce, true);
    const unpacked = unpackRc3Payload(payload, k.keyStr);
    return { ...unpacked, diagnostics, payload, format: 'rc.3' };
  }
  const pos = legacyChecksumPos(k.keyStr, ciphertext.length);
  const chk = ciphertext.slice(pos, pos + CHECKSUM_LEN);
  const stripped = ciphertext.slice(0, pos) + ciphertext.slice(pos + CHECKSUM_LEN);
  const plaintext = _process(stripped, k.steckPairs, k.rotors, k.enabled, k.userRounds, k.nonce, true);
  const verified = chk === legacyComputeChecksum(plaintext, k.keyStr);
  return {
    plaintext,
    verified,
    checksumOk: verified,
    paddingOk: true,
    structureOk: true,
    diagnostics,
    payload: stripped,
    format: 'rc.2-legacy',
    error: verified ? null : 'Checksum mismatch',
  };
}

/**
 * Generate a random key string.
 */
function generateKey(opts = {}) {
  const crypto = typeof window !== 'undefined' ? window.crypto : require('crypto').webcrypto;
  const rand = (max) => {
    if (max <= 0) throw new Error('rand(max) requires max > 0');
    const limit = Math.floor(0x100000000 / max) * max;
    const a = new Uint32Array(1);
    do { crypto.getRandomValues(a); } while (a[0] >= limit);
    return a[0] % max;
  };
  const shuffle = (items) => {
    const copy = [...items];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = rand(i + 1);
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  };
  const choice = (items) => items[rand(items.length)];
  const {
    numRotors = null,
    numSteck = null,
    numLayouts = null,
    userRounds = null,
    includeNonce = null,
  } = opts;
  const finalLayouts = numLayouts ?? (rand(LAYOUT_NAMES.length) + 1);
  const finalRotors = numRotors ?? (rand(13) + 1);
  const finalSteck = numSteck ?? rand(Math.floor(N / 2) + 1);
  const finalRounds = userRounds ?? (rand(999) + 1);
  const useNonce = includeNonce ?? Boolean(rand(2));
  if (finalLayouts < 1 || finalLayouts > LAYOUT_NAMES.length) throw new Error(`numLayouts must be between 1 and ${LAYOUT_NAMES.length}`);
  if (finalRotors < 1 || finalRotors > 13) throw new Error('numRotors must be between 1 and 13');
  if (finalSteck < 0 || finalSteck > Math.floor(N / 2)) throw new Error(`numSteck must be between 0 and ${Math.floor(N / 2)}`);
  if (finalRounds < 1 || finalRounds > 999) throw new Error('userRounds must be between 1 and 999');
  const layoutIdxs = shuffle([...Array(10).keys()]).slice(0, finalLayouts);
  const enabled = new Set(layoutIdxs.map(i=>LAYOUT_NAMES[i]));
  const rotors = Array.from({length:finalRotors}, ()=>({
    layout: LAYOUT_NAMES[choice(layoutIdxs)],
    pos: rand(N)
  }));
  const chars = shuffle([...ALPHA]);
  const steckPairs = Array.from({length:finalSteck},(_,i)=>[chars[i*2],chars[i*2+1]]);
  const nonceChars = useNonce ? [ALPHA[rand(N)], ALPHA[rand(N)], ALPHA[rand(N)]] : [];
  return encodeKey(enabled, rotors, steckPairs, finalRounds, nonceChars.join(''));
}

/**
 * Calculate Index of Coincidence for a string.
 */
function calcIoC(text) {
  const freq = {}; for (const c of ALPHA) freq[c]=0;
  for (const c of text) if (freq[c]!==undefined) freq[c]++;
  const L = Object.values(freq).reduce((a,b)=>a+b,0);
  if (L < 2) return 0;
  const num = Object.values(freq).reduce((a,n)=>a+n*(n-1),0);
  return num/(L*(L-1));
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
  const k = parsedKey.enabled.size;
  let layoutCombos = 1;
  for (let i = 0; i < k; i++) layoutCombos *= (10 - i);
  const rotorCombos = Math.pow(k * N, parsedKey.rotors.length);
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
      rotorLayouts: parsedKey.rotors.map(r => r.layout),
      steckPairs: parsedKey.steckPairs.length,
      baseRounds: parsedKey.userRounds,
      finalRounds: km.rounds,
      noncePresent: Boolean(parsedKey.nonce),
      nonce: parsedKey.nonce || '-',
    },
  };
}

function combination(n, k) {
  if (k < 0 || k > n) return 0;
  if (k === 0 || k === n) return 1;
  let r = 1;
  const upper = Math.min(k, n - k);
  for (let i = 0; i < upper; i++) r = (r * (n - i)) / (i + 1);
  return Math.round(r);
}

function factorial(n) { let r = 1; for (let i = 2; i <= n; i++) r *= i; return r; }

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { encrypt, decrypt, generateKey, calcIoC, calcKeyStrength, parseKey, encodeKey, analyzeCiphertext, ALPHA, N };
} else if (typeof window !== 'undefined') {
  window.ENIGMAK = { encrypt, decrypt, generateKey, calcIoC, calcKeyStrength, parseKey, encodeKey, analyzeCiphertext, ALPHA, N };
}
