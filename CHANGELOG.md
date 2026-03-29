## v2.0.0-rc.3.1 - Release Candidate 3.1 (not officially released)

### Updates
- **Electron updated to v41.1.0** (from v28.3.3) - latest stable release.
  Includes Chromium 146.0.7680.166 and Node.js 24.14.0.
- **electron-builder updated to v26.8.1** (from v24.13.3).
- **Windows arm64 build target added** to package.json.
- **About dialog updated** to reflect v2.0.0-rc.3.1, 68-symbol alphabet,
  and correct keyspace (~4.929 x 10^98).

### Security Fix
- **Checksum now encrypted** using continuation of cipher state after the main
  message. Previously the checksum was inserted raw at a key-derived position.
  Now the 4 checksum characters are run through the full cipher pipeline starting
  from where the main message left off, making them statistically identical to
  any other 4 characters in the ciphertext.

### UX
- **Lowercase warning added** - a visible warning appears when lowercase input
  is detected, noting that lowercase letters are folded to uppercase and
  case-sensitive content (URLs, passwords) may not decrypt identically.

---

## v2.0.0-rc.3 - Release Candidate 3 (not officially released)

### Breaking Change
- Ciphertexts from v2.0.0-rc.2 and earlier are not compatible with rc.3.

### Security Fix
- **Rotor state feedback in position offsets** fixes monocharacter oracle.
  Each character's round and scramble shifts now incorporate a digest of the
  current rotor state (FNV-1a hash) combined with position and key material.
  This creates a cryptographic feedback loop: rotor state after character N
  influences offsets for character N+1. Encrypting repeated characters
  (plaintext "AAAA") now produces different rotor query indices across runs,
  preventing cycle extraction even under worst-case settings (1 layout, 1 rotor,
  0 stecker pairs, 1 round).

### New Features
- **Command-line key strength calculation** (Python CLI: `enigmak.py keystrength <key>`).
  Calculates theoretical keyspace in bits across layouts, rotors, stecker pairs,
  rounds, and optional nonce. Available in Python, JavaScript, and HTML versions.

### Fixes
- **calc_key_strength permutation fix** - layout keyspace now correctly uses ordered
  permutations P(10,k) instead of combinations C(10,k). Layout order matters in ENIGMAK -
  enabling Colemak then Dvorak produces different ciphertext than Dvorak then Colemak.
  Previous versions understated key strength for this component.
- **Supply chain security note added to README** - warns users to run npm audit before
  building the Electron wrapper.
- **layout_bias_check.py restored** - file dropped in rc.2.
- **Python files moved to python/ folder** - `enigmak.py` and `layout_bias_check.py` now live in `python/` for cleaner project structure.

---

## v2.0.0-rc.2 - Release Candidate 2 (not officially released)

### Breaking Change
- Ciphertexts from v2.0.0-rc.1 and earlier are not compatible with rc.2.

### Security Fix
- **Key-derived layout permutations** replace fixed keyboard layout wirings.
  Each of the 10 layouts now generates a unique bijective permutation of the
  68-character alphabet seeded from key material
  (seed = keySum XOR (layoutIndex * 0x9E3779B9 + 0xABCD1234)).
  This eliminates the ergonomic typing bias present in QWERTY, Colemak, Dvorak
  etc. that could introduce non-uniform substitution at scale.
  Cross-key top-5 character overlap drops to 0/5 (consistent with random).

---

## v2.0.0-rc.1 - Release Candidate (not officially released)

### Breaking Change
- Ciphertexts produced by v1.0.0 are not compatible with v2.0.0-rc.1.
  Keys are unchanged; messages must be re-encrypted.

### Security Fix
- **Position whitening layer added** to fix confirmed chosen-plaintext periodicity leak.
  A key-derived LCG stream (seed = keySum XOR 0xC0FFEE42) now XORs a unique offset
  into every character position. This eliminates the mod-N bucket distribution bias
  (L1 ~0.025 in v1.0.0, now ~0.385+ consistent with random noise).
  Credit: r/cryptography community (March 2026).

### Also fixes
- Step mask leakage under chosen-plaintext is eliminated as a side effect of the
  position whitening layer masking per-position rotor state correlation.

---

# Changelog

## v1.0.0 - Initial Public Release

### Cipher
- 68-symbol alphabet (A–Z, ;, 0–9, special characters)
- 1–13 rotors with key-derived irregular stepping (47/68 mask)
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
