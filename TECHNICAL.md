# ENIGMAK Technical Notes

This document describes the current `v3.0.0-rc.6` design at a high level. Its
active new-message format is `rc.6-stream`. It complements `SPECIFICATION.md`,
not replaces it.

## Current Snapshot

The current release candidate uses:

- a **161-symbol** alphabet: 95 legacy printable ASCII symbols plus 66 European
  extended characters (`N = 161`)
- literal space as a first-class cipher symbol
- **1–18 rotors** with a **`66/161`** irregular step mask
- up to **`N // 2` (80)** stecker pairs
- **16** keyed layout labels (10 ergonomic definitions plus 6 reserved national
  labels)
- keyed full-alphabet layout permutations
- keyed **161-position** diffusion
- rotor-state feedback in position offsets
- position whitening
- **`rc.6-stream`** ciphertext with scattered encrypted checksum characters
- hidden metadata (version + checksum) encoded as **44** zero-width carriers
- key-derived **phantom** rotor advancement at carrier positions
- **64-bit** seeded derivation on the active emit/decrypt path
- random key generation with a **256-bit** family acceptance floor
- backward-compatible decrypt for `rc.4-hidden`, headed `rc.3`, and legacy `rc.2`

## Why RC.6 Changed The Wire Format

`rc.4-hidden` encrypted the visible body first, then continued cipher state into
a separate hidden metadata block. Checksum characters were not scattered through
the visible stream.

`rc.6-stream` keeps the same visible payload packing (`H` tag, length field,
plaintext, keyed padding) and the same hidden metadata semantics (version `5`
plus 10 checksum symbols), but changes how output is walked:

1. Build a keyed schedule of **payload**, **checksum**, and **carrier** events.
2. Encrypt payload and checksum symbols through the full cipher pipeline.
3. At each carrier event, advance state with a key-derived **wildcard** symbol,
   then emit one zero-width carrier symbol.
4. Scatter **10** checksum ciphertext characters among visible payload
   characters instead of appending hidden checksum only after the visible body.

Practical consequence: tampering with a single visible checksum character or any
carrier must fail verification, not just tampering with a trailing metadata block.

## RC.6 Stream Layout

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

Schedule order is keyed by `plaintext length` and `visible payload length`.

### Phantom wildcards

Carrier positions do not contain alphabet ciphertext. To keep rotor, whitening,
and index state aligned, encrypt and decrypt each call `process_segment` on a
key-derived wildcard alphabet character and discard the result, then read or
write the zero-width carrier.

### Zero-width carriers

Carrier alphabet (fixed):

```text
U+200B  U+200C  U+200D  U+2060
```

Each hidden metadata alphabet symbol becomes four base-4 digits mapped through a
keyed permutation of those four code points.

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

The active `rc.6` path uses 64-bit state for:

- rotor-state hash
- key sum
- step-mask seeding
- diffusion permutation seeding
- per-layout permutation seeding
- whitening stream
- stream schedule and carrier-wildcard seeds
- hidden carrier digit permutation

Legacy `rc.3`, `rc.4-hidden`, and `rc.2` decrypt paths retain their historical
derivation rules on the 95-symbol legacy alphabet where required.

## Keygen

Default key generation:

1. samples profile dimensions (layout count, rotor count, stecker count, nonce
   flag) from allowed ranges
2. samples concrete layouts, rotors, stecker pairs, rounds, and nonce values
3. rejects candidates below **256** family bits

## Decryption Order

Decryptors attempt formats in this order:

1. headed **`rc.3`** (`E3|...`)
2. **`rc.6-stream`** (44 carriers, hidden metadata version `5`)
3. **`rc.4-hidden`** (44 carriers, hidden metadata version `4`)
4. legacy **`rc.2`** visible checksum insertion

## Browser And Python Interfaces

Shared behavior across browser HTML, `enigmak.js`, docs mirror, Electron, and
Python CLI:

- default key `K6:0 000 0 001` (QWERTY only, one rotor at `00`, no stecker, rounds
  `001`, no nonce)
- diagnostics for hidden carrier counts and clipboard normalization warnings
- fail-closed decrypt output (blank plaintext + `Decryption failed.` on failure)
- fixed **4096**-character internal corruption buffer on failure paths
- Python `decrypt --from-clipboard`, `ioc --from-clipboard`, and interactive
  mode with exact ciphertext clipboard copy on encrypt

## Compatibility

- New ciphertext from this build is **`rc.6-stream`** and is not decryptable by
  `rc.5` emitters.
- This build still decrypts `rc.4-hidden`, `rc.3`, and `rc.2` ciphertext.

## Remaining Limits

- Characters outside `ALPHA` are not reliable for `rc.6-stream` round-trip on the
  current decrypt path even though encrypt may pass them through.
- Extended alphabet symbols are not yet mapped in static ergonomic layout tables.
- The checksum is not authenticated encryption.
- ENIGMAK still needs formal review.
