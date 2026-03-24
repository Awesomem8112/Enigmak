# Changelog

## v1.0.0 - Initial Public Release

### Cipher
- 68-symbol alphabet (A–Z, ;, 0–9, special characters)
- 1-13 rotors with key-derived irregular stepping (47/68 mask)
- Steckerbrett: up to 34 symmetric character-pair swaps
- Dynamic plugboard/scramble from unused keyboard layouts
- 10 keyboard layouts as substitution tables
- Key-derived rounds: ((S + R + L + U) mod 999) + 1
- Diffusion layer: keyed 68-position transposition
- Keyed layout offsets
- No reflector

### Features
- Nonce / message indicator
- Message authentication checksum (key-derived position)
- Key fingerprint (4-character verbal verification)
- Passphrase word encoding (190-word pool, 11 pools)
- Live IoC display with colour thresholds
- Key strength estimator (bits)
- Decrypt mode full-screen amber warning
- Collapsible process visualiser
- Passphrase import/export
- Legacy key format compatibility
- TOR browser compatibility
- Electron desktop wrapper

### Keyspace
~4.929 × 10⁹⁸ at maximum configuration (325 bits)
