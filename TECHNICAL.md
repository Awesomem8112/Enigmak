# ENIGMAK Technical Notes

This document describes the current `v3.0.0-rc.8` design at a high level. Its
active new-message API format label is `rc.6-stream`, with hidden metadata
version character `5`. It complements `SPECIFICATION.md`, not replaces it.

## Current Snapshot

The current release candidate uses:

- a **162-symbol** alphabet: 95 legacy printable ASCII symbols, 66 European
  extended characters, plus newline (`N = 162`)
- literal space as a first-class cipher symbol
- newline as a first-class cipher symbol for multi-line plaintext
- **1–18 rotors** with a **`66/162`** irregular step mask
- up to **`N // 2` (80)** stecker pairs
- **16** keyed layout labels, including the national layouts added in RC7
- keyed full-alphabet layout permutations
- keyed **162-position** diffusion
- rotor-state feedback in position offsets
- position whitening
- **`rc.6-stream`** ciphertext with scattered encrypted checksum characters
- hidden metadata (version + checksum) encoded as **44** zero-width carriers
- key-derived **phantom** rotor advancement at carrier positions
- opt-in materialized carrier mode for transports that strip zero-width text
- **64-bit** seeded derivation on the active emit/decrypt path
- random key generation with a **256-bit** family acceptance floor
- backward-compatible decrypt for `rc.4-hidden`, headed `rc.3`, legacy `rc.2`,
  and original `v2.0.0-legacy` ciphertext

## Why The Stream Format Changed The Wire Format

`rc.4-hidden` kept checksum and carrier structure outside the main cipher
stream. Its visible checksum placement created a reusable prefix pattern for a
given key, and zero-width carriers were injected after the visible encryption
walk instead of participating in it.

`rc.6-stream` keeps the visible payload packing (`H` tag, length field,
plaintext, keyed padding) and hidden metadata semantics (version `5` plus 10
checksum symbols), but changes how output is walked:

1. Build a keyed schedule of **payload**, **checksum**, and **carrier** events.
2. Encrypt payload and checksum symbols through the full cipher pipeline.
3. At each carrier event, advance state with a key-derived **wildcard** symbol,
   then emit one zero-width carrier symbol.
4. Scatter **10** checksum ciphertext characters among visible payload
   characters instead of appending hidden checksum only after the visible body.

Practical consequences:

- no fixed visible checksum prefix exists
- every payload, checksum, and hidden carrier event advances stream state
- tampering with a single visible checksum character or any carrier must fail
  verification

The runtime format label remains `rc.6-stream` because this stream wire format
was introduced in RC6. RC7 keeps hidden version character `5` while changing
other current-path derivation details.

## Stream Layout

Logical content before scheduling:

```text
visible payload: [format_tag:1][len_field:4][plaintext][padding:0..16]
checksum body:   10 symbols derived from visible ciphertext + MAC subkey
hidden metadata: [version:1][checksum:10] -> 44 zero-width carriers
```

The emitted stream length is:

```text
len(visible_payload) + 10 + 44
```

Schedule order is keyed by `plaintext length`, `visible payload length`, and the
serialized key string. Implementations may materialize the schedule as a table,
but it must be reproducible as a deterministic stream walk.

### Schedule seed

The stream schedule seed is domain-separated from the main cipher seed:

```text
hash64(keyStr + "|stream-schedule|" + str(plaintext_len))
```

As of `v3.0.0-rc.8`, `hash64` and `hash32` are backed by an embedded,
zero-dependency BLAKE3 hash (default `hash` mode): `hash64` is the first 8
bytes of the 32-byte digest and `hash32` is the first 4 bytes, both big-endian
unsigned. Earlier release candidates used FNV-1a here; the legacy decrypt paths
keep frozen FNV-1a copies.

The schedule advances with `LCG64`, mixing in the current stream index, and
selects among the remaining payload, checksum, and carrier event counts. Python
integer arithmetic and JavaScript `BigInt` arithmetic must agree exactly.

### Phantom wildcards

Carrier positions do not contain alphabet ciphertext. To keep rotor, whitening,
and index state aligned, encrypt and decrypt each call `process_segment` on a
key-derived wildcard alphabet character and discard the result, then read or
write the zero-width carrier.

Wildcard assignment is also domain-separated:

```text
hash64(keyStr + "|carrier-wildcards|")
```

Each carrier gets one deterministic `ALPHA` wildcard. The zero-width code point
itself never advances rotor state.

### Zero-width carriers

Carrier alphabet (fixed):

```text
U+200B  U+200C  U+200D  U+2060
```

Each hidden metadata alphabet symbol becomes four base-4 digits mapped through a
keyed permutation of those four code points.

### Materialized carriers

Materialized metadata is an opt-in transport mode. The same 44 metadata carrier
events are emitted as visible `ALPHA` characters in a keyed `A,B,C,D` alphabet
and are encrypted through `process_segment` instead of being emitted as
zero-width markers. The hidden version character remains `5`, and sender and
receiver must use the same materialize setting.

## Key Format (K6)

Generated keys use a `K6:` prefix and base36 indices so rotor positions above 99
and layout indices above 9 are representable:

```text
K6:0 000 0 001
```

Legacy digit-only keys without the `K6:` prefix remain parseable for
compatibility testing.

## Derived Rounds Floor

User rounds `U` still feed the round-count formula, but the implementation now
enforces:

```text
rounds = max(((S + R + L + U) mod 999) + 1, ROUND_MINIMUM)
```

with `ROUND_MINIMUM = 10`.

## 64-Bit Current Path

The active rc.8 path uses 64-bit state for:

- rotor-state hash (BLAKE3-derived)
- key sum (arithmetic, not hashed)
- step-mask seeding
- diffusion permutation seeding
- per-layout permutation seeding
- whitening stream
- stream schedule and carrier-wildcard seeds (BLAKE3-derived)
- hidden carrier digit permutation (BLAKE3-derived)

The `hash64` / `hash32` seed values are produced by the embedded BLAKE3 hash as
of `v3.0.0-rc.8` (see the schedule-seed note above); the `keySum` and the
permutation seeds derived from it remain plain 64-bit arithmetic. Legacy `rc.3`,
`rc.4-hidden`, and `rc.2` decrypt paths retain their historical derivation rules
(frozen FNV-1a) on the 95-symbol legacy alphabet where required.

## Keygen

Default key generation:

1. samples profile dimensions (layout count, rotor count, stecker count, nonce
   flag) from allowed ranges
2. samples concrete layouts, rotors, stecker pairs, rounds, and nonce values
3. rejects candidates below **256** family bits

## Decryption Order

Decryptors attempt formats in this order:

1. headed **`rc.3`** (`E3|...`)
2. **`rc.6-stream`** materialized mode when explicitly requested
3. **`rc.6-stream`** default zero-width carrier mode (44 carriers, hidden
   metadata version `5`)
4. **`rc.4-hidden`** (44 carriers, hidden metadata version `4`)
5. legacy **`rc.2`** visible checksum insertion
6. original **`v2.0.0-legacy`** ciphertext

## Browser And Python Interfaces

Shared behavior across browser HTML, `enigmak.js`, docs mirror, Electron, and
Python CLI:

- default key `K6:0 000 0 001` (QWERTY only, one rotor at `00`, no stecker, rounds
  `001`, no nonce)
- diagnostics for hidden carrier counts and clipboard normalization warnings
- materialized metadata toggle or `--materialize` flag for carrier-hostile
  transports
- fail-closed decrypt output (blank plaintext + `Decryption failed.` on failure)
- fixed **4096**-character internal corruption buffer on failure paths
- Python `decrypt --from-clipboard`, `ioc --from-clipboard`, and interactive
  mode with exact ciphertext clipboard copy on encrypt

## Compatibility

- New ciphertext from this build is **`rc.6-stream`** with hidden metadata
  version `5`.
- The wire format version is unchanged from RC6, but RC7 ciphertext is not
  compatible with RC6 builds because the active alphabet and keyed permutation
  derivation changed.
- This build still decrypts `rc.4-hidden`, `rc.3`, `rc.2`, and
  `v2.0.0-legacy` ciphertext.

## Remaining Limits

- Characters outside `ALPHA` are not reliable for `rc.6-stream` round-trip on the
  current decrypt path even though encrypt may pass them through.
- The checksum is not authenticated encryption.
- ENIGMAK still needs formal review.
