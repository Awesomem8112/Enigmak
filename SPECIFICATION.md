# ENIGMAK v3.0.0-rc.2 Formal Specification

## 1. Overview

ENIGMAK is a symmetric, stateful, character-by-character
substitution-permutation rotor cipher operating over a 95-symbol ASCII
alphabet. It combines:

- a steckerbrett
- keyed layout permutations
- multi-round shifted substitution
- keyed diffusion
- state-dependent offsets
- position whitening
- a keyed embedded checksum

## 2. Alphabet

The alphabet `Sigma` is:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./!@#$%^&*()_+{}|:"<>?`~abcdefghijklmnopqrstuvwxyz[space]
```

Index ranges:

```text
 0-25  : A-Z
26     : ;
27-36  : 0-9
37-67  : - = [ ] \ ' , . / ! @ # $ % ^ & * ( ) _ + { } | : " < > ? ` ~
68-93  : a-z
94     : [space]
```

`N = 95`

Characters not in `Sigma` pass through unchanged and do not advance the rotor
state.

## 3. Layout Labels

The implementation uses ten stable layout labels:

```text
0 QWERTY
1 Colemak
2 Colemak-DH
3 Dvorak
4 Workman
5 Norman
6 Asset
7 Halmak
8 AZERTY
9 QWERTZ
```

These names no longer act as raw ergonomic substitution tables in the
cryptographic core. Instead, each label seeds an independent key-derived
permutation of the full 95-symbol alphabet.

## 4. Key Structure

A key has four required sections and one optional nonce section:

```text
[enabled] [rotors] [steck] [U] [nonce?]
```

### 4.1 Enabled layouts

`enabled` is an ordered sequence of distinct layout digits from `0..9`.

Example:

```text
0538
```

### 4.2 Rotors

`rotors` is a concatenation of triples:

```text
{layoutDigit}{position2digits}
```

Each rotor position is in `00..94`.

### 4.3 Steckerbrett

`steck` is either:

- `0` when no pairs are present, or
- a concatenation of quadruples:

```text
{lo2digits}{hi2digits}
```

Where each pair refers to two alphabet indices and `lo < hi`.

Maximum stecker pairs: `47`

### 4.4 User rounds

`U` is a 3-digit integer in `001..999`.

### 4.5 Nonce

`nonce` is optional and encodes alphabet indices as concatenated 2-digit
values. Built-in generators currently emit 3 nonce characters.

## 5. Derived Key Material

Let:

- `S` = normalized stecker sum
- `R` = rotor position sum
- `L` = enabled-layout index sum
- `U` = user-selected base rounds

### 5.1 Stecker sum

For each pair `(a, b)`:

```text
ai = index(a)
bi = index(b)
S += min(ai, bi) * N + max(ai, bi)
```

### 5.2 Rotor sum

```text
R = sum(rotor.pos)
```

### 5.3 Enabled-layout sum

```text
L = sum(layoutIndex)
```

### 5.4 Final round count

```text
rounds = ((S + R + L + U) mod 999) + 1
```

### 5.5 Key sum

```text
keySum = (S*31 + R*17 + L*13) mod 2^32
```

## 6. Step Mask

The step mask is derived by Fisher-Yates shuffling `[0..N-1]` with a 32-bit
LCG seeded from:

```text
seed = keySum XOR 0x5A5A5A5A
```

LCG:

```text
v = (v * 1664525 + 1013904223) mod 2^32
```

Exactly `66` positions are marked active, giving a `66/95` stepping mask.

## 7. Diffusion Permutation

The diffusion permutation is another Fisher-Yates shuffle over `[0..N-1]`
using:

```text
seed = keySum XOR 0xDEAD1234
```

This produces:

- `transPerm` for encryption
- `invTransPerm` for decryption

The permutation length is `95`.

## 8. Keyed Layout Permutations

For layout label `li` in `0..9`, derive a full-alphabet permutation using:

```text
seed = keySum XOR (li * 0x9E3779B9 + 0xABCD1234)
```

This yields:

- `layoutMaps[name]`
- `invLayoutMaps[name]`

Both are full bijections over the 95-symbol alphabet.

Also derive:

```text
layoutKeyBase = keySum mod N
keyedLayoutOffset(name) = (layoutIndex(name) * 7 + layoutKeyBase) mod N
```

## 9. Rotor Mechanics

### 9.1 Nonce application

Before processing characters, adjust each rotor position:

```text
rotor[i].pos = (rotor[i].pos + nonceIndex(i)) mod N
```

Where `nonceIndex(i)` is the alphabet index of nonce character `i`, or `0`
when no nonce character exists at that position.

### 9.2 Combined rotor shift

Treat the rotor register as a base-95 number:

```text
shift = sum(rotor[i].pos * N^(r-1-i)) mod N
```

### 9.3 Rotor-state hash

For the current rotor state:

```text
h = 2166136261
for each rotor:
    h = (h XOR (rotor.pos * 73)) * 16777619 mod 2^32
```

### 9.4 Position offset

```text
posOffset = (keySum * 37 + ci * 13 + rotorStateHash) mod N
```

This makes per-character shifts depend on both absolute position and the live
rotor state.

### 9.5 Rotor advance

After each processed in-alphabet character:

- if `stepMask[ci mod N]` is false, do not advance
- otherwise increment the rightmost rotor
- propagate carries left on rollover

## 10. Plugboard And Scramble Sets

Let:

- `enabledList` = enabled layouts in key order
- `rotorSet` = layout names currently assigned to rotors
- `unusedLayouts` = enabled layouts not currently assigned to any rotor

Plugboard forward:

```text
plugFwd(x) = apply layoutMaps for unusedLayouts in order, no shifts
```

Plugboard inverse:

```text
plugInv(x) = apply invLayoutMaps for unusedLayouts in reverse order, no shifts
```

## 11. Per-Character Encryption

For each in-alphabet plaintext character `x` at in-alphabet position `ci`:

1. Compute `ss = rotorShift(state)`.
2. Compute `posOffset`.
3. Build round layouts:

```text
roundLayout[r] = enabledList[r mod len(enabledList)]
roundShift[r]  = (ss + r + ci + posOffset + keyedLayoutOffset(roundLayout[r])) mod N
```

4. Build scramble shifts for `unusedLayouts`:

```text
scrambleShift[i] = (ss + rounds + i + ci + posOffset +
                    keyedLayoutOffset(unusedLayouts[i])) mod N
```

5. Apply:

```text
x = steck(x)
x = plugFwd(x)
for each round r:
    x = layoutMaps[roundLayout[r]][x]
    x = Sigma[(index(x) + roundShift[r]) mod N]
x = Sigma[transPerm[index(x)]]
for each unused layout i:
    x = layoutMaps[unusedLayouts[i]][x]
    x = Sigma[(index(x) + scrambleShift[i]) mod N]
x = plugFwd(x)
x = steck(x)
```

6. Apply position whitening:

```text
whiteningState = lcg32(whiteningState)
x = Sigma[(index(x) + (whiteningState mod N)) mod N]
```

7. Advance rotors.

## 12. Per-Character Decryption

For each in-alphabet ciphertext character `x` at in-alphabet position `ci`:

1. Compute the same `ss`, `posOffset`, round layouts, and scramble shifts.
2. Remove whitening first:

```text
whiteningState = lcg32(whiteningState)
x = Sigma[(index(x) - (whiteningState mod N)) mod N]
```

3. Apply:

```text
x = steck(x)
x = plugInv(x)
for unused layouts in reverse order:
    x = Sigma[(index(x) - scrambleShift[i]) mod N]
    x = invLayoutMaps[unusedLayouts[i]][x]
x = Sigma[invTransPerm[index(x)]]
for rounds in reverse order:
    x = Sigma[(index(x) - roundShift[r]) mod N]
    x = invLayoutMaps[roundLayout[r]][x]
x = plugInv(x)
x = steck(x)
```

4. Advance rotors.

## 13. Position Whitening

Initial whitening seed:

```text
whiteningSeed = keySum XOR 0xC0FFEE42
```

32-bit LCG:

```text
lcg32(v) = (v * 1664525 + 1013904223) mod 2^32
```

## 14. Checksum

### 14.1 Checksum generation

Checksum length:

```text
CHECKSUM_LEN = 10
```

Use 64-bit FNV-1a over UTF-8 bytes:

```text
h = 0xCBF29CE484222325
for each byte b:
    h = (h XOR b) * 0x100000001B3 mod 2^64
```

Seed input:

```text
plaintext + "|" + keyStr + "|chk64"
```

Then emit 10 symbols with a 64-bit LCG:

```text
lcg64(v) = (v * 6364136223846793005 + 1442695040888963407) mod 2^64

v = hash64(seedInput)
for i in 0..9:
    v = lcg64(v XOR i)
    checksum[i] = Sigma[v mod N]
```

### 14.2 Checksum position

The insertion position is derived from the ASCII key string with 32-bit FNV-1a:

```text
pos = hash32(keyStr + "chkpos") mod max(1, totalLen - CHECKSUM_LEN)
```

### 14.3 Ciphertext layout

Encryption inserts the 10-character checksum at `pos` inside the ciphertext.

Decryption:

- removes 10 characters from the same derived position when the input length is
  greater than `CHECKSUM_LEN`
- decrypts the stripped ciphertext
- recomputes the expected checksum from the recovered plaintext
- compares extracted and expected checksum strings

## 15. Key Fingerprint

Fingerprint generation uses 32-bit FNV-1a plus the 32-bit LCG over the
character set `A-Z0-9`:

```text
seed = hash32(keyStr + "fp")
for i in 0..3:
    seed = lcg32(seed)
    fingerprint[i] = charset[seed mod 36]
```

Fingerprint length: `4`

## 16. Keyspace

At maximum built-in configuration:

- enabled layouts: all 10
- rotors: 13
- stecker pairs: 47
- user rounds: 999 possibilities
- nonce: 3 characters when generated by built-in tools

Approximate total:

```text
4.528 x 10^128
```

Approximate strength:

```text
427 bits
```

## 17. Current Limits

- Non-ASCII / Unicode characters are still passthrough in `rc.2`.
- The checksum is not a replacement for researched authenticated encryption.
- Key reuse creates correlated ciphertext and should be avoided.
- No formal audit has been completed.
