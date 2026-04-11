# ENIGMAK

ENIGMAK is a custom multi-round substitution-permutation rotor cipher with a
95-symbol ASCII alphabet.

## Security Disclaimer

ENIGMAK has not undergone formal cryptanalytic review. Do not use it for
classified, medical, legal, financial, or life-critical communications. For
those purposes, use AES-256 or another formally audited standard.

## Current Protocol Snapshot

The current `v3.0.0-rc.2` branch encrypts over a 95-symbol alphabet:

- `A-Z`
- `a-z`
- digits `0-9`
- punctuation from the built-in alphabet
- literal space

This fixes the old word-boundary leak because spaces now move through the
cipher pipeline like any other symbol.

## Features

- **95-symbol alphabet** - uppercase, lowercase, digits, punctuation, and
  space are all first-class cipher symbols.
- **1-13 rotors** - irregular key-derived stepping with a `66/95` mask.
- **Steckerbrett** - up to 47 symmetric character-pair swaps.
- **10 keyed layout permutations** - layout names act as stable labels for
  independent key-derived permutations of the full alphabet.
- **Key-derived rounds** - `1-999` rounds via `((S + R + L + U) mod 999) + 1`.
- **Diffusion layer** - keyed 95-position transposition.
- **Rotor-state feedback** - per-character offsets depend on the live rotor
  state as well as position and key material.
- **Position whitening** - a key-derived LCG offset is applied per position.
- **Nonce support** - built-in generators emit a 3-character nonce.
- **64-bit checksum** - ciphertext carries a 64-bit keyed checksum encoded as
  10 base-95 characters at a key-derived position.
- **Key fingerprint** - 4-character verbal verification code.
- **Passphrase encoding** - word-based rendering of numeric-space key strings.
- **Fully offline** - browser file, Python CLI, and JS module work with no
  network dependency.

## Keyspace

Maximum configuration is approximately `4.528 x 10^128` possible keys, or
about `427` bits.

## Quick Start

1. Open `enigmak.html` in a modern browser, or use the Python / JS modules.
2. Generate or import a key.
3. Encrypt plaintext to produce ciphertext with an embedded 10-character
   checksum.
4. Share the nonce alongside the ciphertext when one is present.

## Desktop App

See [electron/](electron/) for the Electron wrapper. The desktop build ships
the same machine UI as the root `enigmak.html`.

Before building, run `npm audit` inside `electron/` to check the desktop
wrapper's dependency tree. The cipher implementations themselves
(`enigmak.html`, `enigmak.js`, `python/enigmak.py`) do not depend on npm.

## Architecture

Per-character encryption pipeline:

```text
1. Steckerbrett in
2. Plugboard forward (unused keyed layouts)
3. N rotor rounds
4. Diffusion
5. Scramble (unused keyed layouts with shifts)
6. Plugboard forward again
7. Steckerbrett out
8. Position whitening
```

Decryption reverses the same operations in reverse order. Before decryption,
the implementation removes the 10-character checksum from its key-derived
position and verifies it after plaintext recovery.

There is no reflector. A character may encrypt to itself depending on state.

## Key Format

Keys use the numeric-space format:

```text
[enabled] [rotors] [steck] [U] [nonce?]
```

- `enabled` - distinct layout digit indices concatenated in order
- `rotors` - repeated `{layoutDigit}{position2digits}` triples
- `steck` - repeated `{lo2digits}{hi2digits}` pairs, or `0`
- `U` - 3-digit base round count
- `nonce` - optional 3-digit alphabet indices concatenated

Built-in tools currently generate a 3-character nonce.

## Security Notes

- Generate a fresh key for each message or session.
- Use the nonce every time you encrypt a message.
- Never transmit keys through the same channel as ciphertext.
- Verify the key fingerprint verbally before use.
- The checksum helps detect wrong-key and corruption cases, but it is not a
  replacement for researched authenticated encryption.
- Non-ASCII / Unicode characters still pass through unchanged in `rc.2`.

## GitHub Pages

The mirrored browser copy lives in [docs/index.html](docs/index.html).

## Contributing

Cryptanalytic review, implementation audits, specification improvements, and
test-suite contributions are welcome.

## License

MIT License. See [LICENSE](LICENSE).
