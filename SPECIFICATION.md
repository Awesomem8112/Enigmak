# ENIGMAK v3.0.0-rc.8 Formal Specification

## 1. Overview

ENIGMAK is a symmetric, stateful, character-by-character
substitution-permutation rotor cipher. Release candidate `v3.0.0-rc.8` emits new
ciphertext with API format label **`rc.6-stream`** and hidden metadata version
character **`5`**. This current stream format combines:

- a 162-symbol alphabet
- a steckerbrett (up to 80 pairs)
- keyed full-alphabet layout permutations (16 layout labels)
- multi-round shifted substitution
- keyed 162-position diffusion
- rotor-state feedback
- position whitening
- a visible encrypted payload body (`H` format tag)
- **10** scattered encrypted checksum characters in the stream
- hidden metadata (version + checksum) encoded as **44** zero-width carriers
- key-derived phantom advancement at carrier positions
- an opt-in materialized metadata carrier mode

Decryptors must also accept older `rc.4-hidden`, headed `rc.3`, legacy `rc.2`,
and original `v2.0.0-legacy` ciphertext.

## 2. Alphabet

`LEGACY_ALPHA` is the original 95-symbol printable ASCII set. `EXTENDED_ALPHA`
adds 66 European extended characters. Newline is appended as a first-class
symbol. The active alphabet is:

```text
ALPHA = LEGACY_ALPHA + EXTENDED_ALPHA + "\n"
N = 162
```

Characters outside `ALPHA` pass through unchanged during `process_segment` and do
not advance rotor state. Implementations targeting `rc.6-stream` decryption must
reject any visible non-carrier stream character outside `ALPHA`.

Extended characters and newline participate in stecker, diffusion, whitening,
and keyed layout permutations.

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
10 Spanish
11 Swedish
12 Norwegian
13 Danish
14 Icelandic
15 Belgian
```

Each label seeds an independent key-derived permutation of the full `ALPHA`.
Static `LAYOUT_DEFS` tables cover all 16 labels for tooling; keyed
full-alphabet permutations define the active cipher path.

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

As of `v3.0.0-rc.8`, every seed that previously used the FNV-1a string hash is
now produced by an embedded, zero-dependency BLAKE3 hash. `hash_str64` returns
the first 8 bytes of the 32-byte BLAKE3 digest and `hash_str32` returns the
first 4 bytes, both as big-endian unsigned integers; the BLAKE3 `hash` mode is
validated against the official BLAKE3 test vectors. This covers rotor-state
hashing, the MAC subkey, the stream schedule seed, carrier wildcard derivation,
the hidden-carrier digit permutation and scatter seeds, and the checksum and
padding seeds. The arithmetic `keySum` and the permutation seeds derived from
it (step mask, diffusion, per-layout, whitening) are unchanged. The rc.4-hidden,
rc.3, rc.2, and `v2.0.0-legacy` decrypt paths keep frozen FNV-1a copies so older
ciphertext stays decryptable. Because the wire format is unchanged, rc.8
ciphertext differs from rc.7 for the same key only because the seed values
differ.

Current keyed shuffles use rejection-sampling Fisher-Yates over 64-bit random
state so Python and JavaScript avoid modulo bias and produce identical
permutations for the same seed and size.

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

## 7. Current Stream Packaging

### 7.1 Visible payload (before stream scheduling)

```text
[format_tag:1][len_field:4][plaintext][padding:0..16]
```

- `format_tag` = `H` (`RC4_FORMAT_TAG`)
- `len_field` = 4 active-`ALPHA` characters encoding plaintext length
- `padding` = deterministic keyed padding (0..`MAX_PAD_LEN`, with empty
  plaintext forced to at least one padding symbol)

`pack_rc6_payload` uses hidden metadata version character `5`
(`RC6_VERSION_CHAR`).

### 7.2 Checksum

A 10-character checksum is derived from the **packed visible payload** (the `H`
tag, length field, plaintext, and padding before stream scheduling) using
`deriveMacSubkey(keyStr)` and version `5`.

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

### 7.3.1 Materialized metadata

Materialized metadata is optional. When enabled, the same 44 metadata carrier
events are represented as visible `ALPHA` characters in a keyed `A,B,C,D`
alphabet and are encrypted as normal stream participants. When disabled, carrier
events use zero-width code points and advance state through phantom wildcards.

The version character, checksum calculation, event counts, and hidden metadata
content are unchanged. Sender and receiver must use the same materialize setting.

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

The schedule is a deterministic keyed walk over remaining event counts. At each
stream index, `LCG64` advances the schedule state and selects one of the
remaining event classes. Implementations may materialize the resulting event
list, but encryption and decryption must be able to reproduce the same event at
the same position without ciphertext lookahead.

### 7.5 Phantom wildcards

For each zero-width carrier event, derive a wildcard alphabet symbol from:

```text
hash64(keyStr + "|carrier-wildcards|")
```

Encrypt or decrypt that wildcard through `process_segment` to advance state,
then emit (encrypt) or read (decrypt) the corresponding zero-width carrier
symbol. Do not output the wildcard itself, and do not use the zero-width code
point as the rotor contribution.

### 7.6 Encryption walk

Initialize cipher state from the parsed key. For each scheduled event in order:

- **payload**: append `process_segment(payload[i])`
- **checksum**: append `process_segment(checksum[i])`
- **carrier**: `process_segment(wildcard[i])`, append `carrier_stream[i]`

For materialized carrier mode, the carrier stream character itself is processed
through `process_segment` and appended.

## 8. Decryption Order

Decryptors must attempt formats in this order:

1. headed **`rc.3`** if visible text begins with `E3|`
2. **`rc.6-stream`** materialized mode when explicitly requested
3. **`rc.6-stream`** zero-width carrier mode
4. **`rc.4-hidden`**
5. legacy **`rc.2`**
6. original **`v2.0.0-legacy`**

### 8.1 RC.3 path

Remove `E3|`, decrypt body with legacy 95-symbol path, parse
`[len_field][plaintext][checksum][padding]`, verify checksum and padding.

### 8.2 RC.6-stream path

1. In zero-width mode, extract zero-width carriers; require count `44` and
   decodable metadata with version `5`.
2. In materialized mode, require every ciphertext symbol to be in `ALPHA`; the
   receiver must have explicitly selected materialized mode.
3. Let `visible_len` = count of non-carrier characters in zero-width mode, or
   total ciphertext length in materialized mode. Let `payload_len` =
   `visible_len - 10` in zero-width mode or `visible_len - 10 - 44` in
   materialized mode.
4. Brute `pad_len` in `0..MAX_PAD_LEN` to recover `plaintext_len`.
5. Rebuild schedule from `(plaintext_len, payload_len)`; require
   `len(schedule) == len(ciphertext)`.
6. Walk stream: decrypt payload and checksum symbols; at zero-width carriers,
   decrypt the wildcard then record the carrier symbol. At materialized carriers,
   decrypt the carrier symbol and record the resulting metadata digit.
7. Unpack visible payload; verify scattered checksum, hidden metadata checksum,
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
- materialized metadata mode when requested
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
- The API format label remains `rc.6-stream` for the version-5 stream wire
  format introduced before RC7.
