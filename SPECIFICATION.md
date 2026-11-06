# ENIGMAK v3.0.0-rc.9 Formal Specification

## 1. Overview

ENIGMAK is a symmetric, stateful, character-by-character
substitution-permutation rotor cipher. Release candidate `v3.0.0-rc.9` emits new
ciphertext with API format label **`rc.6-stream`** and hidden metadata version
character **`5`**. This current stream format combines:

- a 162-symbol alphabet
- a steckerbrett (up to 81 pairs)
- keyed full-alphabet layout permutations (16 layout labels)
- multi-round shifted substitution
- keyed 162-position diffusion
- rotor-state feedback
- position whitening
- a visible encrypted payload body (`H` format tag)
- **10** scattered encrypted checksum characters in the stream
- hidden metadata (version + checksum) encoded as **key-derived** zero-width
  carriers (`logical_len * 4`; legacy 44-carrier ciphertext still decrypts)
- key-derived phantom advancement at carrier positions
- an opt-in materialized metadata carrier mode
- optional prefix-free dual-message envelopes (`rc.9-dual-v1`)

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

As of `v3.0.0-rc.9`, live pseudorandom output no longer uses LCG64/LCG32
stepping. Each domain-tagged seed string derives a 32-byte ChaCha20 key through
`blake3_hash(seed, 32)`, and a `Chacha20Stream` object produces keystream bytes
interpreted as big-endian `next_u64()` / `next_u32()` values. This covers
permutation shuffles, stream schedule draws (with rejection sampling), carrier
wildcards, checksum and padding expansion, carrier alphabet ordering, and
whitening. The rc.4-hidden, rc.3, and rc.2 decrypt paths keep frozen LCG copies.
Because the wire format is unchanged, rc.9 ciphertext differs from rc.8 for the
same key because every pseudorandom draw changes.

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

Logical hidden content length is **key-derived** on the live encrypt path:

```text
logical_len = 1 + (hash64(keyStr + "|meta-len|") % (N - 1))   // 1 .. N-1
carrier_count = logical_len * 4
```

At `N = 162`, logical length ranges **1–161** and carrier count ranges **4–644**.
Every length in that range has equal probability (~`1/(N-1)`) under uniform keys.

`build_metadata_payload` encodes exactly `logical_len` logical characters:

| `logical_len` | Payload |
|---------------|---------|
| `1` | `version` only |
| `2..10` | `version` + first `logical_len - 1` checksum chars |
| `>= 11` | `version` + full `checksum` + keyed filler for remaining chars (`"|meta-fill|"`) |

Each hidden alphabet character encodes to four base-4 digits, then maps through
a keyed permutation of:

```text
U+200B  U+200C  U+200D  U+2060
```

**Legacy branch:** if observed carrier count equals `LEGACY_HIDDEN_SYMBOL_COUNT`
(44), decrypt uses the frozen 11-logical-char path (version + full checksum) even
when the key would derive a different count on encrypt.

**Decrypt gate:** `effective_metadata_carrier_count(keyStr, observed)` returns
44 when `observed == 44`, else the key-derived count when it matches `observed`,
else fails closed.

### 7.3.1 Materialized metadata

Materialized metadata is optional. When enabled, the same key-derived metadata
carrier events are represented as visible `ALPHA` characters in a keyed
`A,B,C,D` alphabet and are encrypted as normal stream participants. When
disabled, carrier events use zero-width code points and advance state through
phantom wildcards.

The version character, checksum calculation, and tiered hidden metadata rules
are unchanged. Sender and receiver must use the same materialize setting.

### 7.4 Stream schedule

Let:

- `P` = `len(visible_payload)`
- `T` = `len(plaintext)`
- `C` = `derive_metadata_carrier_count(keyStr)` on encrypt, or
  `effective_metadata_carrier_count(keyStr, observed)` on decrypt

Build a keyed schedule containing exactly:

- `P` payload events
- `10` checksum events
- `C` carrier events

Total stream length = `P + 10 + C`.

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

1. original **`v2.0.0-legacy`** when the visible body is printable in that alphabet
2. **`rc.6-stream`** materialized mode when explicitly requested
3. **`rc.6-stream`** zero-width carrier mode
4. a bounded prefix-free **`rc.9-dual-v1`** probe after modern rc.6 fails
5. headed **`rc.3`** if visible text begins with `E3|`
6. **`rc.4-hidden`**
7. legacy **`rc.2`**

A failed structural rc.4 parse must continue to the dual probe if that probe
has not already run. Dual decryption never depends on a public prefix.

### 8.1 RC.3 path

Remove `E3|`, decrypt body with legacy 95-symbol path, parse
`[len_field][plaintext][checksum][padding]`, verify checksum and padding.

### 8.2 RC.6-stream path

1. In zero-width mode, extract zero-width carriers. Accept the key-derived
   carrier count, the prior modulo-derived count, or the historical 44-carrier
   count when the metadata decodes with version `5`.
2. In materialized mode, require every ciphertext symbol to be in `ALPHA`; the
   receiver must have explicitly selected materialized mode.
3. Let `visible_len` = count of non-carrier characters in zero-width mode, or
   total ciphertext length in materialized mode. Let `payload_len` =
   `visible_len - 10` in zero-width mode or
   `visible_len - 10 - carrier_count` in materialized mode.
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

### 8.5 Dual-message path (`rc.9-dual-v1`)

1. Reject encoded text longer than the 1 MiB-per-slot bound before decoding.
2. Decode unpadded canonical base64url of `nonce[16] || slot0 || slot1`.
3. Unwrap both equal-length slots with the supplied key. Internal magic exists
   only inside wrapped bytes; there is no public prefix.
4. Compare regenerated filler, then decrypt the inner UTF-8 `rc.6-stream`
   ciphertext with dual recursion disabled.
5. Accept exactly one fully verified inner result. Ambiguous or empty matches
   fail closed with the generic public error.

## 9. Key Generation

Default key generation:

1. sample profile dimensions from allowed ranges (or caller constraints)
2. sample concrete layouts, rotors, stecker pairs, rounds, and optional nonce
3. compute key-family strength
4. accept only if family bits `>= 256`

Allowed ranges:

- enabled layouts: `1..16` distinct labels
- rotors: `1..18`
- stecker pairs: `0..81` (`N // 2`)
- user rounds: `1..999`
- nonce: optional, **five** alphabet symbols when generated by default (`NONCE_LEN = 5`); parsing accepts any even-length nonce section including legacy three-symbol nonces

If constraints make the floor impossible, generation must fail.

## 10. Diagnostics

Implementations should report:

- hidden carrier count (key-derived on new messages; legacy 44-carrier ciphertext still accepted)
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

## 13. Dual messages (`rc.9-dual-v1`)

`encrypt_dual_message` / `encryptDualMessage` emits **one** prefix-free
ciphertext and two independently generated `K6:` keys:

```text
ciphertext = unpadded_base64url(nonce[16] || slot0 || slot1)
slot       = ChaCha20XOR(magic[4] || flags[1] || inner_len_be[4]
                         || utf8(inner_rc6) || keyed_filler)
```

- There is no public magic, header, or delimiter in the emitted ciphertext.
  Internal magic exists only inside key-wrapped slot bytes.
- Slot order is randomized from the nonce low bit. Decrypt tries both slots
  and accepts exactly one fully verified inner `rc.6-stream` result.
- Filler is regenerated and compared before inner parsing. Tampered filler
  fails closed.
- Slot size is bounded at 1 MiB; encoded length is rejected before allocation.
- Returned format is `rc.9-dual-v1`. The result does not report which slot
  matched.
- The wrapper is framing/privacy, not AEAD.

CLI: `encrypt-dual REAL --faux-plaintext FAUX` with optional supplied keys,
`--materialize`, `--json`, `--bundle-out`, `--faux-out`, `--faux-only`, and
mutually exclusive clipboard options. `--faux-only` / `--faux-out` must not
print the intended key.

## 13.1 Deprecated Option A decoy bundles

`encrypt_decoy_bundle` / `encryptDecoyBundle` and `encrypt-decoy` remain
available as two independent ciphertexts. They are not the dual-slot format.

## 14. Limits

- The checksum is an integrity signal, not authenticated encryption.
- ENIGMAK is not formally audited.
- `rc.6-stream` round-trip requires plaintext and ciphertext stream symbols
  (except carriers) to remain inside `ALPHA`.
- Dual ciphertext reports `rc.9-dual-v1`. The wrapper is not AEAD; size and
  base64url statistics can distinguish it from ordinary messages.
- The single-message API format label remains `rc.6-stream` for the version-5
  stream wire format introduced before RC7.
