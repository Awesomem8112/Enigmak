/**
 * ENIGMAK v2.0.0-rc.3 - JavaScript module
 * 68-symbol multi-round substitution-permutation rotor cipher
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
              '!@#$%^&*()_+{}|:"<>?`~';
const N = ALPHA.length; // 68

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
  stepPos.slice(0,47).forEach(p => stepMask[p] = true);

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
  return { rounds, stepMask, transPerm, invTransPerm, layoutKeyBase: keySum % N, whiteningState, layoutMaps, invLayoutMaps };
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
    const ch = (c >= 'a' && c <= 'z') ? c.toUpperCase() : c;
    if (!ALPHA.includes(ch)) { result += c; continue; }
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
    let x = ch;
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

// ── Checksum ──────────────────────────────────────────────────────────────────
const CHECKSUM_LEN = 4;

function computeChecksum(plaintext, keyStr) {
  const h1 = hashStr(plaintext + '|' + keyStr + '|chk1');
  const h2 = hashStr(plaintext + '|' + keyStr + '|chk2');
  let out = '', v = (h1 ^ (h2 << 16)) >>> 0;
  for (let i=0;i<CHECKSUM_LEN;i++) { v=lcg(v); out+=ALPHA[v%N]; }
  return out;
}

function checksumPos(keyStr, totalLen) {
  return hashStr(keyStr + 'chkpos') % Math.max(1, totalLen - CHECKSUM_LEN);
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
 * Returns ciphertext with embedded checksum.
 */
function encrypt(plaintext, keyStr) {
  const k = parseKey(keyStr);
  const cipher = _process(plaintext, k.steckPairs, k.rotors, k.enabled, k.userRounds, k.nonce, false);
  const chk = computeChecksum(plaintext, k.keyStr);
  const pos = checksumPos(k.keyStr, cipher.length + CHECKSUM_LEN);
  return cipher.slice(0, pos) + chk + cipher.slice(pos);
}

/**
 * Decrypt ciphertext with the given key string.
 * Returns { plaintext, verified } where verified indicates checksum status.
 */
function decrypt(ciphertext, keyStr) {
  const k = parseKey(keyStr);
  const pos = checksumPos(k.keyStr, ciphertext.length);
  const chk = ciphertext.slice(pos, pos + CHECKSUM_LEN);
  const stripped = ciphertext.slice(0, pos) + ciphertext.slice(pos + CHECKSUM_LEN);
  const plaintext = _process(stripped, k.steckPairs, k.rotors, k.enabled, k.userRounds, k.nonce, true);
  const expected = computeChecksum(plaintext, k.keyStr);
  return { plaintext, verified: chk === expected };
}

/**
 * Generate a random key string.
 */
function generateKey(opts = {}) {
  const { numRotors=3, numSteck=8, numLayouts=4, userRounds=null } = opts;
  const crypto = typeof window !== 'undefined' ? window.crypto : require('crypto').webcrypto;
  const rand = (max) => { const a=new Uint32Array(1); crypto.getRandomValues(a); return a[0]%max; };
  const layoutIdxs = [...Array(10).keys()].sort(()=>rand(2)-1).slice(0,numLayouts);
  const enabled = new Set(layoutIdxs.map(i=>LAYOUT_NAMES[i]));
  const rotors = Array.from({length:numRotors}, ()=>({
    layout: LAYOUT_NAMES[layoutIdxs[rand(numLayouts)]],
    pos: rand(N)
  }));
  const chars = [...ALPHA].sort(()=>rand(2)-1);
  const steckPairs = Array.from({length:numSteck},(_,i)=>[chars[i*2],chars[i*2+1]]);
  const u = userRounds ?? (rand(999)+1);
  const nonceChars = [ALPHA[rand(N)],ALPHA[rand(N)],ALPHA[rand(N)]];
  return encodeKey(enabled, rotors, steckPairs, u, nonceChars.join(''));
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
  // Calculate theoretical keyspace in bits
  const C = (n, k) => { if (k > n || k < 0) return 0; if (k === 0 || k === n) return 1; let r = 1; for (let i = 0; i < k; i++) r = r * (n - i) / (i + 1); return Math.round(r); };
  const layoutCombos = C(10, parsedKey.enabled.size);
  const rotorCombos = Math.pow(10 * N, parsedKey.rotors.length);
  let steckCombos = 1;
  let remaining = N;
  for (let i = 0; i < parsedKey.steckPairs.length; i++) {
    steckCombos *= C(remaining, 2);
    remaining -= 2;
  }
  if (parsedKey.steckPairs.length > 0) steckCombos = Math.round(steckCombos / factorial(parsedKey.steckPairs.length));
  const roundCombos = 999;
  const nonceCombos = parsedKey.nonce ? Math.pow(N, 3) : 1;
  const total = layoutCombos * rotorCombos * steckCombos * roundCombos * nonceCombos;
  const bits = Math.log2(total);
  return { bits, total };
}

function factorial(n) { let r = 1; for (let i = 2; i <= n; i++) r *= i; return r; }

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { encrypt, decrypt, generateKey, calcIoC, calcKeyStrength, parseKey, encodeKey, ALPHA, N };
} else if (typeof window !== 'undefined') {
  window.ENIGMAK = { encrypt, decrypt, generateKey, calcIoC, calcKeyStrength, parseKey, encodeKey, ALPHA, N };
}
