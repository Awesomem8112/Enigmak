# ENIGMAK

A custom multi-round substitution-permutation rotor cipher with a 68-symbol alphabet.

## ⚠️ Security Disclaimer

ENIGMAK has **not** undergone formal cryptanalytic review. Do not use it for classified, medical, legal, financial, or life-critical communications. For those purposes, use AES-256 or another formally audited standard. ENIGMAK is provided for educational, research, and general personal use.

## What is ENIGMAK?

ENIGMAK is a browser-based cipher machine inspired by the historical Enigma rotor machine but built on a fundamentally different and significantly stronger architecture. It runs entirely offline as a single HTML file - no installation, no server, no network requests.

## Features

- **68-symbol alphabet** - A–Z, digits, semicolon, and all standard special characters
- **1–13 rotors** with irregular key-derived stepping (47/68 mask)
- **Steckerbrett** - up to 34 symmetric character-pair swaps
- **Dynamic plugboard/scramble** from unused keyboard layouts
- **10 keyboard layouts** as substitution tables (QWERTY, Colemak, Colemak-DH, Dvorak, Workman, Norman, Asset, Halmak, AZERTY, QWERTZ)
- **Key-derived rounds** - 1–999 via `((S + R + L + U) mod 999) + 1`
- **Diffusion layer** - keyed 68-position transposition
- **Nonce** — prevents identical plaintexts producing identical ciphertexts
- **Message authentication** - key-derived checksum embedded at key-derived position
- **Key fingerprint** - 4-character verbal verification code
- **Passphrase encoding** - word-based key representation
- **ASCII only** - supports the 68-symbol ASCII alphabet. Non-ASCII characters (Cyrillic, Chinese, accented Latin, etc.) pass through unencrypted.
- **Live IoC display** - real-time statistical quality indicator
- **Decrypt mode warning** - full-screen amber tint
- **Fully offline** - single HTML file, no dependencies

## Keyspace

~4.929 × 10⁹⁸ (98-digit number) at maximum configuration.

## Quick Start

1. Download `enigmak.html`
2. Open it in any modern browser
3. No installation required - works fully offline

## GitHub.io

See the [GitHub.io](https://awesomem8112.github.io/Enigmak/) site to see how Enigmak works before downloading.

## Desktop App

See the [Electron wrapper](electron/) for a standalone desktop application (Windows, macOS, Linux).

## Architecture

```
Per-character encryption pipeline:
1. Steckerbrett in       (symmetric swap)
2. Plugboard forward     (unused layouts)
3. N rotor rounds        (keyed shifts + layout offsets)
4. Diffusion             (keyed 68-position transposition)
5. Scramble              (unused layouts, keyed shifts)
6. Plugboard inverse
7. Steckerbrett out      (symmetric swap)
```

**No reflector** - a character can encrypt to itself. No periodic structure.

## Key Format

Space-separated numeric format:
```
[enabled] [rotors] [steck] [U] [nonce?]
```

- `enabled` - layout digit indices concatenated
- `rotors` - 1-digit layout + 2-digit position per rotor
- `steck` - 4-digit pairs (2+2 char indices), `0` if none
- `U` - 3-digit base round count (001–999)
- `nonce` - 2-digit char indices concatenated (optional)

## Security Notes

- Never reuse a key across multiple messages
- Never transmit a key through the same channel as ciphertext
- Use the nonce for every message
- The keyboard layouts serving as rotor wirings are publicly known — all security rests on the key
- Formal cryptanalytic review has not been completed

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Cryptanalytic review, implementation audits, and formal specification contributions are welcome. Please open an issue before submitting large changes.
