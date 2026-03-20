# ENIGMAK v1.0.0 - Formal Specification

## 1. Overview

ENIGMAK is a symmetric, stateful, character-by-character substitution cipher operating over a 68-symbol alphabet. It combines a multi-rotor substitution mechanism with a plugboard, steckerbrett, diffusion transposition, and key-derived irregular stepping.

---

## 2. Alphabet

The alphabet Σ consists of 68 characters, indexed 0–67:

```
Index  0– 25: A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Index  26:    ;
Index  27– 36: 0 1 2 3 4 5 6 7 8 9
Index  37– 67: - = [ ] \ ' , . / ! @ # $ % ^ & * ( ) _ + { } | : " < > ? ` ~
```

N = |Σ| = 68

---

## 3. Keyboard Layouts

Ten physical keyboard layouts serve as substitution tables. Each maps the 30 standard QWERTY positions (10 top row + 10 home row + 7 bottom row + semicolon) to characters in Σ.

```
Layout 0  QWERTY      Top: QWERTYUIOP  Home: ASDFGHJKL;  Bot: ZXCVBNM
Layout 1  Colemak     Top: QWFPGJLUY;  Home: ARSTDHNEIO  Bot: ZXCVBKM
Layout 2  Colemak-DH  Top: QWFPBJLUY;  Home: ARSTGMNEIO  Bot: ZXCDVKH
Layout 3  Dvorak      Top: ;VZPYFGCRL  Home: AOEUIDHTNS  Bot: QJKXBMWVZ
Layout 4  Workman     Top: QDRWBJFUP;  Home: ASHTGYNEOI  Bot: ZXMCVKL
Layout 5  Norman      Top: QWDFKJURL;  Home: ASETGYNIOH  Bot: ZXCVBPM
Layout 6  Asset       Top: QWJFGYPUL;  Home: ASETDHNIOR  Bot: ZXCVBKM
Layout 7  Halmak      Top: WLRBJZFUO;  Home: SHNTMEDAIC  Bot: QGVXPKY
Layout 8  AZERTY      Top: AZERTYUIOP  Home: QSDFGHJKL;  Bot: WXCVBNM
Layout 9  QWERTZ      Top: QWERTZUIOP  Home: ASDFGHJKL;  Bot: YXCVBNM
```

For layout L, define:
- `sub_L(c)` - substitution mapping: physical QWERTY key c → layout L output
- `sub_L⁻¹(c)` - inverse substitution

---

## 4. Key Structure

A key consists of five components:

| Component | Description | Range |
|-----------|-------------|-------|
| E | Ordered set of enabled layout indices | Subset of {0..9}, |E| ≥ 1 |
| ρ | Sequence of r rotors, each (layout_index, position) | r ∈ {1..13}, position ∈ {0..67} |
| σ | Steckerbrett: set of k character-pair swaps | k ∈ {0..34}, pairs disjoint |
| U | User-set base round count | U ∈ {1..999} |
| η | Nonce (optional): sequence of characters from Σ | Length 0–13 |

**Key string format:** `[E] [ρ] [σ] [U] [η?]`
- E: layout indices concatenated (e.g. `1234`)
- ρ: triples of `{layout_digit}{pos_2digit}` concatenated (e.g. `102031`)
- σ: quadruples of `{lo_2digit}{hi_2digit}` concatenated, or `0` (e.g. `0621`)
- U: 3-digit zero-padded integer
- η: pairs of 2-digit character indices concatenated (optional)

---

## 5. Key Material Derivation

### 5.1 Steckerbrett sum

For each pair (a, b) in σ, let aᵢ = Σ.index(a), bᵢ = Σ.index(b):

```
S = Σ (min(aᵢ, bᵢ) × N + max(aᵢ, bᵢ))
```

Pair ordering is normalized - min/max ensures click order does not affect S.

### 5.2 Rotor position sum

```
R = Σ pos(ρᵢ)
```

### 5.3 Layout index sum

```
L = Σ index(eⱼ) for eⱼ ∈ E
```

### 5.4 Final round count

```
rounds = ((S + R + L + U) mod 999) + 1
```

### 5.5 Key hash

```
keySum = (S×31 + R×17 + L×13) mod 2³²
```

### 5.6 Step mask (Fisher-Yates, seed = keySum XOR 0x5A5A5A5A)

Produces a 68-element boolean mask with exactly 47 true positions using an LCG-seeded Fisher-Yates shuffle:

```
v = keySum XOR 0x5A5A5A5A
pos = [0, 1, ..., N-1]
for i = N-1 downto 1:
    v = (v × 1664525 + 1013904223) mod 2³²
    j = v mod (i+1)
    swap(pos[i], pos[j])
stepMask[pos[0..46]] = true
```

### 5.7 Diffusion permutation (Fisher-Yates, seed = keySum XOR 0xDEAD1234)

Produces a keyed 68-position permutation π and its inverse π⁻¹:

```
v = keySum XOR 0xDEAD1234
perm = [0, 1, ..., N-1]
for i = N-1 downto 1:
    v = (v × 1664525 + 1013904223) mod 2³²
    j = v mod (i+1)
    swap(perm[i], perm[j])
π = perm
π⁻¹[π[i]] = i for all i
```

### 5.8 Layout key base

```
layoutKeyBase = keySum mod N
```

### 5.9 Keyed layout offset

For layout with index l:

```
offset(l) = (l × 7 + layoutKeyBase) mod N
```

---

## 6. Rotor Mechanics

### 6.1 Nonce application

If nonce η is present, adjust each rotor's starting position:

```
pos'(ρᵢ) = (pos(ρᵢ) + Σ.index(η[i])) mod N
```

for i ∈ {0..|ρ|-1} where η[i] is the i-th nonce character (0 if i ≥ |η|).

### 6.2 Combined rotor shift

For rotor state [ρ₀, ρ₁, ..., ρ_{r-1}]:

```
shift = (Σ pos(ρᵢ) × N^(r-1-i)) mod N
```

Computed in arbitrary-precision arithmetic to avoid float overflow.

### 6.3 Rotor advance

After processing character at position ci:
- If `stepMask[ci mod N]` is false: rotors do not advance
- Otherwise: rightmost rotor increments; carries propagate left on rollover (odometer)

---

## 7. Encryption Pipeline

For each character c in plaintext:

1. **Fold case:** if c ∈ {a..z}, replace with c.toUpperCase()
2. **Passthrough:** if c ∉ Σ, output c unchanged, do not advance rotors
3. **Compute shift:** ss = combined rotor shift
4. **Build round parameters:**
   - For round r ∈ {0..rounds-1}: layout = E[r mod |E|], shift_r = (ss + r + offset(layout)) mod N
5. **Build scramble parameters:**
   - unusedLayouts = E \ {layouts assigned to rotors}
   - For i ∈ {0..|unused|-1}: scramble_shift_i = (ss + rounds + i + offset(unused[i])) mod N
6. **Apply steckerbrett in:** c ← σ(c)
7. **Apply plugboard forward:** c ← sub_{unused[0]}(sub_{unused[1]}(...(c)...))
8. **Apply rotor rounds:** for r = 0 to rounds-1: c ← Σ[(Σ.index(sub_{layout_r}(c)) + shift_r) mod N]
9. **Apply diffusion:** c ← Σ[π[Σ.index(c)]]
10. **Apply scramble:** for i = 0 to |unused|-1: c ← Σ[(Σ.index(sub_{unused[i]}(c)) + scramble_shift_i) mod N]
11. **Apply plugboard inverse:** reverse of step 7
12. **Apply steckerbrett out:** c ← σ(c) (same map, symmetric)
13. **Advance rotors**

---

## 8. Decryption Pipeline

Reverse of encryption - all operations inverted in reverse order:

1. Fold case
2. Passthrough check
3. Compute shift
4. Build round/scramble parameters (identical to encryption)
5. Apply steckerbrett in
6. Apply plugboard inverse
7. Apply scramble inverse (reversed, inverse shifts)
8. Apply diffusion inverse: c ← Σ[π⁻¹[Σ.index(c)]]
9. Apply rotor rounds inverse (reversed, inverse substitutions)
10. Apply plugboard forward
11. Apply steckerbrett out
12. Advance rotors

---

## 9. Message Authentication

### 9.1 Checksum computation

```
h1 = FNV1a(plaintext || "|" || keyStr || "|chk1")
h2 = FNV1a(plaintext || "|" || keyStr || "|chk2")
v = (h1 XOR (h2 << 16)) mod 2³²
for i = 0 to 3:
    v = (v × 1664525 + 1013904223) mod 2³²
    checksum[i] = Σ[v mod N]
```

Checksum length = 4 characters.

### 9.2 Checksum position

```
pos = FNV1a(keyStr || "chkpos") mod max(1, |ciphertext+checksum| - 4)
```

The 4-character checksum is inserted at position `pos` within the ciphertext.

### 9.3 FNV-1a hash primitive

```
h = 2166136261
for each byte b in input:
    h = (h XOR b) × 16777619 mod 2³²
```

---

## 10. Key Fingerprint

```
h = FNV1a(keyStr || "fp")
v = h
for i = 0 to 3:
    v = (v × 1664525 + 1013904223) mod 2³²
    fingerprint[i] = charset[v mod 36]    // charset = A-Z0-9
```

---

## 11. Keyspace

Maximum configuration (34 steck pairs, 13 rotors, 10 layouts, U ∈ {1..999}):

```
|Steck(68,34)| × |Rotors| × |Layouts| × 999
= 7.515×10⁵² × 6.657×10³⁵ × 9,864,100 × 999
≈ 4.929 × 10⁹⁸
```

Approximate key strength: 325 bits at maximum configuration.

---

## 12. Security Notes

- **No reflector:** Characters can encrypt to themselves
- **No algebraic shortcut** known for the full pipeline
- **Keyboard layout bias:** Layout substitution tables were designed for ergonomic typing, not cryptographic uniformity - theoretical non-uniformity may exist at high character counts
- **Key reuse:** Two messages under the same key produce correlated ciphertext; key reuse is strongly discouraged
- **Monocharacter oracle:** Encrypting a single repeated character under chosen-plaintext reveals rotor cycle structure
- **Not formally audited:** This specification has not undergone professional cryptanalytic review
