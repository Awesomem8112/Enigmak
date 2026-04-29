# ENIGMAK

ENIGMAK is a custom multi-round substitution-permutation rotor cipher with a
95-symbol ASCII alphabet.

## Security Disclaimer

ENIGMAK has not undergone formal cryptanalytic review. Do not use it for
classified, medical, legal, financial, or life-critical communications. For
those purposes, use AES-256 or another formally audited standard.

## Current Protocol Snapshot

The current workspace target is `v3.0.0-rc.4`. Its active new-message format
is `rc.4-hidden`, which uses:

- a 95-symbol alphabet with lowercase and literal space
- 1-13 rotors with a `66/95` irregular step mask
- up to 47 stecker pairs
- keyed full-alphabet layout permutations
- keyed 95-position diffusion
- 64-bit seeded state for all current deterministic key-derived math
- rotor-state feedback in position offsets
- position whitening
- a visible encrypted body with no `E3|` prefix
- hidden encrypted metadata carrying version + checksum as zero-width markers
- deterministic keyed padding that depends on plaintext, key, checksum, and version
- weighted uniform key generation over concrete valid keys
- backward-compatible decrypt support for headed `rc.3` and legacy `rc.2`

## Features

- **Hidden metadata format** - new ciphertext looks plain, but carries `rc.4`
  versioning and checksum data in scattered zero-width markers.
- **Backward-compatible decryption** - decryptors still accept old `E3|`
  `rc.3` messages and legacy unheaded `rc.2` ciphertext.
- **64-bit keyed core** - current key-derived permutation seeding, step mask
  seeding, whitening, rotor-state hashing, and related state all use 64-bit
  arithmetic in the active `rc.4` emit path.
- **1-13 rotors** - irregular key-derived stepping with a `66/95` mask.
- **Steckerbrett** - up to 47 symmetric character-pair swaps.
- **10 keyed layout permutations** - stable layout labels seed independent
  key-derived permutations of the full alphabet.
- **Key-derived rounds** - `1-999` rounds via `((S + R + L + U) mod 999) + 1`.
- **Weighted random keygen** - default keygen samples profiles in proportion to
  their true concrete key counts instead of repeating a fixed-shape family.
- **Copy diagnostics** - browser, JS, and Python builds detect hidden carrier
  counts, suspicious clipboard normalization, and likely stripped metadata.
- **Fully offline** - browser file, Python CLI, and JS module work with no
  network dependency.

## Quick Start

1. Open `enigmak.html`, or use the Python CLI or JS module.
2. Generate or import a key.
3. Encrypt plaintext to produce an `rc.4-hidden` ciphertext.
4. Use `Copy exact output` or another lossless plain-text path when moving
   ciphertext. New messages contain invisible zero-width markers that must be
   preserved exactly.
5. Share the nonce alongside the ciphertext when one is present.

## Ciphertext Format

New `rc.4-hidden` ciphertext has two layers:

```text
visible body: [format_tag:1][len_field:4][plaintext][padding:1..16]
hidden meta:  [version:1][checksum:10]
```

The visible body is encrypted directly. The hidden metadata is encrypted by
continuing the same cipher state after the visible body, then encoding those
11 encrypted characters into `44` zero-width carrier symbols chosen from:

```text
\u200B \u200C \u200D \u2060
```

Those carriers are scattered across the visible ciphertext. Removing them turns
a valid `rc.4-hidden` message into a verification failure.

## Key Format

The serialized key format is unchanged:

```text
[enabled] [rotors] [steck] [U] [nonce?]
```

Example default HTML key:

```text
0 000 0 001
```

## Key Strength And Keygen

Built-in tools show theoretical key-family size in bits plus the current key
profile. Default keygen now:

1. chooses `(enabledCount, rotorCount, steckCount, noncePresent)` by exact
   concrete key count weight
2. samples uniformly within that chosen profile

This removes the old fixed `151.5` bit pattern caused by repeatedly generating
the same key shape.

## Browser UI

The root browser build, docs mirror, and Electron HTML build now:

- default to `QWERTY` only, one rotor at `00`, no steck pairs, rounds `001`,
  and no nonce
- expose collapsible `Layouts`, `Rotors`, `Steckerbrett`, and `Key` panels
- warn when hidden carrier counts look damaged or metadata appears stripped

## Desktop App

See [electron/](electron/) for the Electron wrapper. The desktop build ships
the same machine UI and `rc.4` runtime bundle as the root `enigmak.html`.

## Security Notes

- Generate a fresh key for each message or session.
- Use the nonce whenever you include one.
- Never transmit keys through the same channel as ciphertext.
- Verify the key fingerprint verbally before use.
- The checksum helps detect wrong-key and corruption cases, but it is not a
  replacement for researched authenticated encryption.
- Non-ASCII / Unicode characters still pass through unchanged.

## GitHub Pages

The mirrored browser copy lives in [docs/index.html](docs/index.html).

## Contributing

Cryptanalytic review, implementation audits, specification improvements, and
test-suite contributions are welcome.

## License

MIT License. See [LICENSE](LICENSE).
