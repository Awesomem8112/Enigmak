# ENIGMAK

ENIGMAK is a custom multi-round substitution-permutation rotor cipher with a
95-symbol ASCII alphabet.

## Security Disclaimer

ENIGMAK has not undergone formal cryptanalytic review. Do not use it for
classified, medical, legal, financial, or life-critical communications. For
those purposes, use AES-256 or another formally audited standard.

## Current Protocol Snapshot

The current `v3.0.0-rc.3` branch uses:

- a 95-symbol alphabet with lowercase and literal space
- 1-13 rotors with a `66/95` irregular step mask
- up to 47 stecker pairs
- keyed full-alphabet layout permutations
- keyed 95-position diffusion
- rotor-state feedback in position offsets
- position whitening
- versioned ciphertext with an `E3|` header
- an encrypted 64-bit checksum carried inside the rc.3 payload
- deterministic keyed padding to hide exact plaintext length within a 16-character window
- full-random default key generation in Python, JS, and HTML
- browser, JS, and Python warnings for suspicious clipboard-normalized punctuation

## Features

- **95-symbol alphabet** - uppercase, lowercase, digits, punctuation, and
  space are all first-class cipher symbols.
- **Versioned ciphertext** - new messages begin with `E3|`, and decryptors
  keep a legacy fallback for unheaded `rc.2` ciphertext.
- **Encrypted package body** - the rc.3 body encrypts the plaintext length
  field, plaintext, checksum, and keyed padding together.
- **1-13 rotors** - irregular key-derived stepping with a `66/95` mask.
- **Steckerbrett** - up to 47 symmetric character-pair swaps.
- **10 keyed layout permutations** - layout names act as stable labels for
  independent key-derived permutations of the full alphabet.
- **Key-derived rounds** - `1-999` rounds via `((S + R + L + U) mod 999) + 1`.
- **Diffusion layer** - keyed 95-position transposition.
- **Rotor-state feedback** - per-character offsets depend on the live rotor
  state as well as position and key material.
- **Position whitening** - a key-derived LCG offset is applied per position.
- **Nonce support** - built-in generators optionally emit a 3-character nonce.
- **Key fingerprint** - 4-character verbal verification code.
- **Passphrase encoding** - word-based rendering of numeric-space key strings.
- **Fully offline** - browser file, Python CLI, and JS module work with no
  network dependency.

## Quick Start

1. Open `enigmak.html`, or use the Python CLI or JS module.
2. Generate or import a key.
3. Encrypt plaintext to produce an `E3|` ciphertext.
4. Use `Copy exact output` or another plain-text path when moving ciphertext.
   ENIGMAK output is punctuation-heavy, and dropping even one character can
   desync the rest of decryption.
5. Share the nonce alongside the ciphertext when one is present.

## Ciphertext Format

New `rc.3` ciphertexts look like:

```text
E3|<encrypted-body>
```

The encrypted body contains:

```text
[len_field:4][plaintext][checksum:10][padding:0..15]
```

All four parts are encrypted together. This removes the old raw checksum block
from visible ciphertext and hides exact plaintext length within a 16-character
window.

Decryptors still accept unheaded `rc.2` ciphertext by using the legacy
checksum-strip path.

## Key Strength Display

Built-in tools now show two views:

- **Key family strength** - the theoretical brute-force size of the key family
  implied by the current key shape
- **Current key profile** - enabled-layout count, rotor count, steck pair
  count, rounds, and nonce presence for the exact serialized key

This means repeated keys are no longer expected to all report the same value
unless they really share the same shape.

## Desktop App

See [electron/](electron/) for the Electron wrapper. The desktop build ships
the same machine UI as the root `enigmak.html`.

Before building, run `npm audit` inside `electron/` to check the desktop
wrapper's dependency tree. The cipher implementations themselves
(`enigmak.html`, `enigmak.js`, `python/enigmak.py`) do not depend on npm.

## Security Notes

- Generate a fresh key for each message or session.
- Use the nonce whenever you include one.
- Never transmit keys through the same channel as ciphertext.
- Verify the key fingerprint verbally before use.
- The checksum helps detect wrong-key and corruption cases, but it is not a
  replacement for researched authenticated encryption.
- Browser and CLI decrypt paths warn about suspicious clipboard-normalized
  punctuation, non-ASCII paste issues, and likely transfer damage.
- Non-ASCII / Unicode characters still pass through unchanged in `rc.3`.

## Remaining v3.0.0 Roadmap

Completed through `rc.3`:

- lowercase alphabet support
- encrypted space handling
- 64-bit checksum
- ciphertext version header
- encrypted checksum packaging
- exact-length leak mitigation
- full-random default keygen
- clipboard-corruption safeguards

Still planned for v3.0.0:

- non-ASCII / Unicode support
- `deriveSeed` replacement with a proper password-based KDF
- photo / file encryption
- `utils.js` refactor
- remaining security test suite items
- meet-in-the-middle investigation

Likely v4 or later:

- steganography
- authenticated encryption research
- key exchange research
- block cipher mode research
- post-quantum components

## GitHub Pages

The mirrored browser copy lives in [docs/index.html](docs/index.html).

## Contributing

Cryptanalytic review, implementation audits, specification improvements, and
test-suite contributions are welcome.

## License

MIT License. See [LICENSE](LICENSE).
