# ENIGMAK v3.0.0-rc.6 Formal Specification

## 1. Overview

ENIGMAK is a symmetric, stateful, character-by-character
substitution-permutation rotor cipher. Release candidate `v3.0.0-rc.6` emits new
ciphertext in the **`rc.6-stream`** format, which combines:

- a 161-symbol alphabet
- a steckerbrett (up to 80 pairs)
- keyed full-alphabet layout permutations (16 layout labels)
- multi-round shifted substitution
- keyed 161-position diffusion
- rotor-state feedback
- position whitening
- a visible encrypted payload body (`H` format tag)
- **10** scattered encrypted checksum characters in the stream
- hidden metadata (version + checksum) encoded as **44** zero-width carriers
- key-derived phantom advancement at carrier positions

Decryptors must also accept older `rc.4-hidden`, headed `rc.3`, and legacy
`rc.2` ciphertext.

## 2. Alphabet

`LEGACY_ALPHA` is the original 95-symbol printable ASCII set. `EXTENDED_ALPHA`
adds 66 European extended characters. The active alphabet is:

```text
ALPHA = LEGACY_ALPHA + EXTENDED_ALPHA
N = 161
```

Characters outside `ALPHA` pass through unchanged during `process_segment` and do
not advance rotor state. Implementations targeting `rc.6-stream` decryption
must reject any visible non-carrier stream character outside `ALPHA`.

Extended characters (index 95 and above) participate in stecker, diffusion,
whitening, and keyed layout permutations. Static ergonomic keyboard-layout
substitution tables currently map only the legacy 95-symbol set; extended
characters remain layout-unassigned until a later release.

## 3. Layout Labels

Sixteen stable layout labels exist:

```text
0  QWERTY
1  Colemak
2  Colemak-DH
3  Dvorak
4  Workman
5  Norman
6  Asset
7  Halmak
8  AZERTY
9  QWERTZ
10 Spanish      (reserved; keyed perm only)
11 Swedish      (reserved)
12 Norwegian    (reserved)
13 Danish       (reserved)
14 Icelandic    (reserved)
15 Belgian      (reserved)
```

Each label seeds an independent key-derived permutation of the full `ALPHA`.
Static `LAYOUT_DEFS` tables cover the first ten ergonomic layouts for tooling;
they do not define the active cipher path.

## 4. Key Format

A key has four required sections and one optional nonce section:

```text
[enabled] [rotors] [steck] [U] [nonce?]
```

### 4.1 K6 wide keys (current default)

Generated keys use a `K6:` prefix on the enabled-layout section and base36
indices elsewhere:

- `enabled`: `K6:` followed by one base36 digit per enabled layout index
- `rotors`: groups of `[layout:1 base36][position:2 base36]`
- `steck`: `0` or sorted groups of `[A:2 base36][B:2 base36]`
- `U`: base rounds `001..999`
- `nonce`: optional; each alphabet symbol encoded as one 2-digit base36 index

Example default key:

```text
K6:0 000 0 001
```

### 4.2 Legacy digit keys

Keys without the `K6:` prefix remain parseable:

- `enabled`: distinct layout digits `0..9`
- `rotors` / `steck` / `nonce`: decimal digit encoding with the same section
  boundaries

## 5. Derived Quantities

Let:

- `S` = normalized stecker sum over `ALPHA` indices
- `R` = rotor position sum
- `L` = enabled-layout index sum
- `U` = user rounds

The live round count is:

```text
rounds = max(((S + R + L + U) mod 999) + 1, ROUND_MINIMUM)
```

with `ROUND_MINIMUM = 10`.

The current-path key sum is:

```text
keySum = (S*31 + R*17 + L*13) mod 2^64
```

Current-path derivation uses 64-bit state for:

- rotor-state hashing
- step-mask seeding (`STEP_MASK_ACTIVE = 66` positions of `N`)
- diffusion permutation seeding
- per-layout permutation seeding
- whitening stream seeding
- stream schedule seeding
- carrier wildcard seeding
- hidden carrier digit permutation and scatter seeds

Legacy decrypt paths retain their historical 32-bit or 95-symbol rules where
required for compatibility.

## 6. Encryption Pipeline

For each in-alphabet character, the current core applies:

```text
1. Steckerbrett in
2. Plugboard forward through unused keyed layouts
3. rounds of keyed rotor/layout substitutions
4. Keyed N-position diffusion permutation
5. Scramble through unused keyed layouts
6. Plugboard forward again
7. Steckerbrett out
8. Position whitening offset
9. Rotor advancement (irregular step mask)
```

## 7. RC.6 Stream Packaging

### 7.1 Visible payload (before stream scheduling)

```text
[format_tag:1][len_field:4][plaintext][padding:0..16]
```

- `format_tag` = `H` (`RC4_FORMAT_TAG`)
- `len_field` = 4 base-95 (`N`) characters encoding plaintext length
- `padding` = deterministic keyed padding (0..`MAX_PAD_LEN`, with empty
  plaintext forced to at least one padding symbol)

`pack_rc6_payload` uses hidden metadata version character `5` (`RC6_VERSION_CHAR`).

### 7.2 Checksum

A 10-character checksum is derived from the **visible payload ciphertext**
(after packing, before stream scheduling) using `deriveMacSubkey(keyStr)` and
version `5`.

### 7.3 Hidden metadata

Logical hidden content:

```text
[version:1][checksum:10]
```

Version character for new messages: `5`.

Each hidden alphabet character encodes to four base-4 digits, then maps through
a keyed permutation of:

```text
U+200B  U+200C  U+200D  U+2060
```

Total carriers per message:

```text
11 * 4 = 44
```

### 7.4 Stream schedule

Let:

- `P` = `len(visible_payload)`
- `T` = `len(plaintext)`

Build a keyed schedule containing exactly:

- `P` payload events
- `10` checksum events
- `44` carrier events

Total stream length = `P + 10 + 44`.

Schedule seed:

```text
hash64(keyStr + "|stream-schedule|" + str(T))
```

### 7.5 Phantom wildcards

For each carrier event, derive a wildcard alphabet symbol from:

```text
hash64(keyStr + "|carrier-wildcards|")
```

Encrypt or decrypt that wildcard through `process_segment` to advance state,
then emit (encrypt) or read (decrypt) the corresponding zero-width carrier
symbol. Do not output the wildcard itself.

### 7.6 Encryption walk

Initialize cipher state from the parsed key. For each scheduled event in order:

- **payload**: append `process_segment(payload[i])`
- **checksum**: append `process_segment(checksum[i])`
- **carrier**: `process_segment(wildcard[i])`, append `carrier_stream[i]`

## 8. Decryption Order

Decryptors must attempt formats in this order:

1. headed **`rc.3`** if visible text begins with `E3|`
2. **`rc.6-stream`**
3. **`rc.4-hidden`**
4. legacy **`rc.2`**

### 8.1 RC.3 path

Remove `E3|`, decrypt body with legacy 95-symbol path, parse
`[len_field][plaintext][checksum][padding]`, verify checksum and padding.

### 8.2 RC.6-stream path

1. Extract zero-width carriers; require count `44` and decodable metadata with
   version `5`.
2. Let `visible_len` = count of non-carrier characters; `payload_len` =
   `visible_len - 10`.
3. Brute `pad_len` in `0..MAX_PAD_LEN` to recover `plaintext_len`.
4. Rebuild schedule from `(plaintext_len, payload_len)`; require
   `len(schedule) == len(ciphertext)`.
5. Walk stream: decrypt payload and checksum symbols; at carriers, decrypt
   wildcard then record carrier symbol.
6. Unpack visible payload; verify scattered checksum, hidden metadata checksum,
   version, and padding.

On failure, return public error `Decryption failed.` with blank plaintext per
Section 11.

### 8.3 RC.4-hidden path

Strip carriers, decrypt visible body with 95-symbol legacy path, parse visible
payload, require 44 carriers, decrypt hidden metadata continuing cipher state,
verify version `4`, checksum, and padding.

### 8.4 RC.2 legacy path

Locate keyed visible checksum insertion, remove 10 checksum characters, decrypt
stripped body, verify legacy checksum.

## 9. Key Generation

Default key generation:

1. sample profile dimensions from allowed ranges (or caller constraints)
2. sample concrete layouts, rotors, stecker pairs, rounds, and optional nonce
3. compute key-family strength
4. accept only if family bits `>= 256`

Allowed ranges:

- enabled layouts: `1..16` distinct labels
- rotors: `1..18`
- stecker pairs: `0..80` (`N // 2`)
- user rounds: `1..999`
- nonce: optional, three alphabet symbols when present

If constraints make the floor impossible, generation must fail.

## 10. Diagnostics

Implementations should report:

- hidden carrier count (expect `44` on valid new messages)
- suspicious clipboard-normalized punctuation
- control-character presence in ciphertext
- generic decryption failure without exposing verification details

## 11. Failure Hygiene

On failed verification:

- return public error `Decryption failed.`
- blank public plaintext fields
- corrupt an internal fixed-length buffer of exactly **4096** characters
- corrupt accessible key material and cipher state before returning
- clear browser/Electron decrypt outputs before decrypt work; write plaintext
  only after explicit verification success

## 12. Python CLI Input Modes

- `decrypt --from-clipboard KEY`
- `ioc --from-clipboard`
- `interactive`
- bare `python enigmak.py` starts interactive mode

Interactive encryption must copy exact ciphertext to the system clipboard when
possible.

## 13. Limits

- The checksum is an integrity signal, not authenticated encryption.
- ENIGMAK is not formally audited.
- `rc.6-stream` round-trip requires plaintext and ciphertext stream symbols
  (except carriers) to remain inside `ALPHA`.
