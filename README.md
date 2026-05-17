# ENIGMAK

ENIGMAK is a custom multi-round substitution-permutation rotor cipher with a
95-symbol ASCII alphabet.

## Security Disclaimer

ENIGMAK has not undergone formal cryptanalytic review. Do not use it for
classified, medical, legal, financial, or life-critical communications. For
those purposes, use AES-256 or another formally audited standard.

## Current Protocol Snapshot

The current workspace target is `v3.0.0-rc.5`. Its active new-message format
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
- random key generation with a `213.5` bit minimum acceptance floor
- backward-compatible decrypt support for headed `rc.3` and legacy `rc.2`
- generic public decryption failures with no partial plaintext returned
- fixed-length 4096-character internal corruption buffers on decrypt failure

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
- **Random high-strength keygen** - default keygen samples random key profiles
  and rejects candidates below `213.5` family bits.
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
3. Encrypt plaintext to produce an `rc.4-hidden` ciphertext.
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
profile. Default keygen now samples random profile dimensions, samples a random
concrete key inside that profile, and accepts it only when the resulting key
family is at least `213.5` bits. This removes the old fixed `151.5` bit pattern
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
the same machine UI and `rc.4-hidden` wire-compatible runtime bundle as the
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
- Non-ASCII / Unicode characters still pass through unchanged.

## GitHub Pages

The mirrored browser copy lives in [docs/index.html](docs/index.html).

## Contributing

Cryptanalytic review, implementation audits, specification improvements, and
test-suite contributions are welcome.

## License

MIT License. See [LICENSE](LICENSE).
