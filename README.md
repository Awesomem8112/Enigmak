# ENIGMAK

ENIGMAK is a custom multi-round substitution-permutation rotor cipher with a
162-symbol alphabet.

## Security Disclaimer

ENIGMAK has not undergone formal cryptanalytic review. Do not use it for
classified, medical, legal, financial, or life-critical communications. For
those purposes, use AES-256 or another formally audited standard.

## Current Protocol Snapshot

The current workspace target is `v3.0.0-rc.9`. Its active new-message API
format label is still `rc.6-stream`, with hidden metadata version character
`5`. This is the version-5 stream wire format carried forward into rc.9, and it
uses:

- a 162-symbol alphabet with printable ASCII, European extended characters, and `\n`
- 1-18 rotors with a `66/162` irregular step mask
- up to 81 stecker pairs
- keyed full-alphabet layout permutations
- keyed 162-position diffusion
- BLAKE3-derived seeds for domain-tagged ChaCha20 key derivation (32-byte digest
  output), replacing direct LCG seed integers from rc.8
- ChaCha20 keystream for all live permutation, scheduling, wildcard, checksum,
  padding, carrier-order, and whitening pseudorandom output
- rotor-state feedback in position offsets
- position whitening
- a visible encrypted body with no `E3|` prefix
- scattered encrypted checksum characters
- hidden metadata carrying version + checksum as zero-width markers
- key-derived phantom rotor advancement at zero-width marker positions
- an opt-in materialized carrier mode for transports that strip zero-width text
- deterministic keyed padding that depends on plaintext, key, checksum, and version
- random key generation with a `256` bit minimum acceptance floor
- backward-compatible decrypt support for `rc.4-hidden`, headed `rc.3`, and legacy `rc.2`
- generic public decryption failures with no partial plaintext returned
- fixed-length 4096-character internal corruption buffers on decrypt failure

## Features

- **Stream format** - new ciphertext uses `rc.6-stream`, with encrypted checksum
  characters scattered through the stream and zero-width carriers advanced by
  deterministic phantom characters. There is no fixed visible checksum prefix.
- **Materialized metadata option** - the same stream format can emit key-derived
  metadata carriers as visible `ALPHA` characters for storage systems that strip
  zero-width text. Sender and receiver must use the same setting.
- **Dual messages** - optional intended and faux plaintexts produce one
  prefix-free ciphertext and two independently generated keys. Either key
  returns its own fully verified plaintext; unrelated keys fail generically.
- **Deprecated Option A decoy bundles** - the old two-ciphertext API remains
  available for compatibility, but it is not the same-blob dual format.
- **Backward-compatible decryption** - decryptors still accept old `E3|`
  `rc.3` messages, legacy unheaded `rc.2` ciphertext, and `rc.4-hidden`
  ciphertext from rc.4 and rc.5.
- **ChaCha20 CSPRNG** - as of rc.9, key-derived permutation shuffling, stream
  schedule draws, carrier wildcards, checksum and padding expansion, carrier
  alphabet ordering, and whitening all consume RFC 8439 ChaCha20 keystream from
  an embedded zero-dependency implementation (validated against the official RFC
  8439 block-function test vector) with BLAKE3-derived 32-byte stream keys.
  Legacy rc.4/rc.3/rc.2 decrypt paths keep frozen LCG copies.
- **BLAKE3 seed derivation** - as of rc.8, domain separation and MAC subkey
  derivation use an embedded zero-dependency BLAKE3 hash (validated against the
  official BLAKE3 test vectors) instead of FNV-1a. Legacy rc.4/rc.3/rc.2 and
  v2.0.0 decrypt paths keep frozen FNV-1a.
- **1-18 rotors** - irregular key-derived stepping with a `66/162` mask.
- **Steckerbrett** - up to 81 symmetric character-pair swaps.
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
5. Turn on materialized metadata only when the receiver will use the same
   setting.
6. Share the nonce alongside the ciphertext when one is present.

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
carrier events:  [version:1][checksum:10][optional filler] encoded as
                 logical_len * 4 zero-width symbols
```

Payload characters, checksum characters, and zero-width carriers are walked in
a deterministic key-derived schedule. Payload and checksum characters are
encrypted through the full cipher pipeline. Each zero-width carrier advances the
rotor state with a key-derived phantom alphabet character before the carrier is
emitted. Because checksum characters and carriers participate in the same walk,
the old fixed checksum-prefix structure is gone.

Zero-width carriers are chosen from:

```text
\u200B \u200C \u200D \u2060
```

Removing a checksum character or carrier turns a valid `rc.6-stream` message
into a verification failure.

When materialized metadata is enabled, the carrier events are emitted as
visible `ALPHA` characters instead of zero-width markers and are encrypted as
normal stream participants. Toggle mismatches fail closed.

## Dual Ciphertext

With an optional faux plaintext, ENIGMAK generates two independent `K6:` keys
and one prefix-free ciphertext. The outer text is unpadded base64url of a
16-byte nonce plus two equal-length wrapped slots. There is no public magic
string; any recognizable prefix can appear only by coincidence. Decrypt tries
the supplied key against both slots, then requires a complete inner
`rc.6-stream` verification. The returned format label is `rc.9-dual-v1`.

The wrapper is a framing layer, not authenticated encryption. Length and
base64url statistics can still distinguish dual ciphertext from ordinary
messages.

```bash
python python/enigmak.py encrypt-dual "INTENDED" --faux-plaintext "COVER"
python python/enigmak.py decrypt CIPHERTEXT "KEY STRING"
python scripts/verify.py
```

## Key Format

The serialized key format keeps the same sections, but current keys use a `K6:`
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
- expose a materialized metadata checkbox with a receiver-must-match hint
- let plaintext and ciphertext boxes resize vertically
- generate one shared dual ciphertext plus intended-recipient and faux keys
  without silently regenerating those keys on every keystroke

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
- Failed decrypts perform a fixed 4096-character local work pass and then clear
  plaintext outputs. This is fail-closed hygiene, not guaranteed memory
  overwrite and not a substitute for authenticated encryption.
- European extended characters in the alphabet encrypt directly. Other
  non-alphabet Unicode characters still pass through unchanged.

## GitHub Pages

The mirrored browser copy lives in [docs/index.html](docs/index.html).

## Contributing

Cryptanalytic review, implementation audits, specification improvements, and
test-suite contributions are welcome.

## License

MIT License. See [LICENSE](LICENSE).
