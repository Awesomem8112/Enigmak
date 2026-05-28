# ENIGMAK

ENIGMAK is a custom multi-round substitution-permutation rotor cipher with a
161-symbol alphabet.

## Security Disclaimer

ENIGMAK has not undergone formal cryptanalytic review. Do not use it for
classified, medical, legal, financial, or life-critical communications. For
those purposes, use AES-256 or another formally audited standard.

## Current Protocol Snapshot

The current workspace target is `v3.0.0-rc.6`. Its active new-message format
is `rc.6-stream`, which uses:

- a 161-symbol alphabet with printable ASCII plus European extended characters
- 1-18 rotors with a `66/161` irregular step mask
- up to 80 stecker pairs
- keyed full-alphabet layout permutations
- keyed 161-position diffusion
- 64-bit seeded state for all current deterministic key-derived math
- rotor-state feedback in position offsets
- position whitening
- a visible encrypted body with no `E3|` prefix
- scattered encrypted checksum characters
- hidden metadata carrying version + checksum as zero-width markers
- key-derived phantom rotor advancement at zero-width marker positions
- deterministic keyed padding that depends on plaintext, key, checksum, and version
- random key generation with a `256` bit minimum acceptance floor
- backward-compatible decrypt support for `rc.4-hidden`, headed `rc.3`, and legacy `rc.2`
- generic public decryption failures with no partial plaintext returned
- fixed-length 4096-character internal corruption buffers on decrypt failure

## Features

- **Stream format** - new ciphertext uses `rc.6-stream`, with encrypted checksum
  characters scattered through the stream and zero-width carriers advanced by
  deterministic phantom characters.
- **Backward-compatible decryption** - decryptors still accept old `E3|`
  `rc.3` messages, legacy unheaded `rc.2` ciphertext, and `rc.4-hidden`
  ciphertext from rc.4 and rc.5.
- **64-bit keyed core** - current key-derived permutation seeding, step mask
  seeding, whitening, rotor-state hashing, and related state all use 64-bit
  arithmetic in the active `rc.6` emit path.
- **1-18 rotors** - irregular key-derived stepping with a `66/161` mask.
- **Steckerbrett** - up to 80 symmetric character-pair swaps.
- **16 keyed layout permutations** - stable layout labels seed independent
  key-derived permutations of the full alphabet.
- **Key-derived rounds** - `10-999` rounds via a named `ROUND_MINIMUM` floor.
- **Random high-strength keygen** - default keygen samples random key profiles
  and rejects candidates below `256` family bits.
- **Copy diagnostics** - browser, JS, and Python builds detect hidden carrier
  counts, suspicious clipboard normalization, and likely stripped metadata.
- **Shell-safe CLI input** - Python decrypt and IoC commands can read directly
  from the clipboard, bare `python enigmak.py` opens interactive mode, and
  interactive encryption copies exact ciphertext to the clipboard.
- **Generic failure surface** - failed decrypts return `Decryption failed.`
  and blank plaintext while preserving broad diagnostics.
- **Fully offline** - browser file, Python CLI, and JS module work with no
  network dependency.

## Quick Start

1. Open `enigmak.html`, or use the Python CLI or JS module.
2. Generate or import a key.
3. Encrypt plaintext to produce an `rc.6-stream` ciphertext.
4. Use `Copy exact output`, Python interactive clipboard copy, or another lossless plain-text path when moving
   ciphertext. New messages contain invisible zero-width markers that must be
   preserved exactly.
5. Share the nonce alongside the ciphertext when one is present.

Python CLI alternatives for shell-sensitive ciphertext:

```bash
python enigmak.py decrypt --from-clipboard "KEY STRING"
python enigmak.py ioc --from-clipboard
python enigmak.py interactive
```

## Ciphertext Format

New `rc.6-stream` ciphertext has one scheduled stream:

```text
payload events:  [format_tag:1][len_field:4][plaintext][padding]
checksum events: [checksum:10]
carrier events:  [version:1][checksum:10] encoded as 44 zero-width symbols
```

Payload characters, checksum characters, and zero-width carriers are walked in
a deterministic key-derived schedule. Payload and checksum characters are
encrypted through the full cipher pipeline. Each zero-width carrier advances the
rotor state with a key-derived phantom alphabet character before the carrier is
emitted.

Zero-width carriers are chosen from:

```text
\u200B \u200C \u200D \u2060
```

Removing a checksum character or carrier turns a valid `rc.6-stream` message
into a verification failure.

## Key Format

The serialized key format keeps the same sections, but rc.6 keys use a `K6:`
prefix and base36 alphabet indexes so positions above 99 and layouts above 9
can be represented:

```text
[enabled] [rotors] [steck] [U] [nonce?]
```

Example default HTML key:

```text
K6:0 000 0 001
```

## Key Strength And Keygen

Built-in tools show theoretical key-family size in bits plus the current key
profile. Default keygen now samples random profile dimensions, samples a random
concrete key inside that profile, and accepts it only when the resulting key
family is at least `256` bits. This removes the old fixed `151.5` bit pattern
without forcing every generated key into the same maximum-strength shape.

## Browser UI

The root browser build, docs mirror, and Electron HTML build now:

- default to `QWERTY` only, one rotor at `00`, no steck pairs, rounds `001`,
  and no nonce
- expose collapsible `Layouts`, `Rotors`, `Steckerbrett`, and `Key` panels
- warn when hidden carrier counts look damaged or metadata appears stripped
- let plaintext and ciphertext boxes resize vertically

## Desktop App

See [electron/](electron/) for the Electron wrapper. The desktop build ships
the same machine UI and `rc.6-stream` runtime bundle as the
root `enigmak.html`.

## Security Notes

- Generate a fresh key for each message or session.
- Use the nonce whenever you include one.
- Never transmit keys through the same channel as ciphertext.
- Verify the key fingerprint verbally before use.
- The checksum helps detect wrong-key and corruption cases, but it is not a
  replacement for researched authenticated encryption.
- Failed decrypts deliberately corrupt an internal fixed 4096-character buffer
  and then clear plaintext outputs. This is a local fail-closed hygiene measure,
  not a substitute for authenticated encryption.
- European extended characters in the alphabet encrypt directly. Other
  non-alphabet Unicode characters still pass through unchanged.

## GitHub Pages

The mirrored browser copy lives in [docs/index.html](docs/index.html).

## Contributing

Cryptanalytic review, implementation audits, specification improvements, and
test-suite contributions are welcome.

## License

MIT License. See [LICENSE](LICENSE).
