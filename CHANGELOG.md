## v3.0.0-rc.7 - Release Candidate 7

### Highlights
- **Rejection-sampling Fisher-Yates** - `shuffle_indices_with_seed` now uses
  uniform rejection sampling against the `2^64` threshold instead of biased
  modulo reduction, removing a small but measurable bias from every
  key-derived permutation. Python and JavaScript implementations produce
  identical shuffles for the same seed and size.
- **Newline joins ALPHA** - `\n` is appended at index 161, expanding the
  active alphabet to 162 symbols. Multi-line plaintext now participates in
  all cipher operations and round-trips cleanly without special handling.
- **Six new national layouts** - `Spanish`, `Swedish`, `Norwegian`,
  `Danish`, `Icelandic`, and `Belgian` are now full `LAYOUT_DEFS` entries
  with their distinctive character maps (e.g. Norwegian's `ø` and Danish's
  `æ` next to L, Icelandic's `þ`/`ð`, Belgian AZERTY's Q/A and W/Z swap).
- **Expanded QWERTZ and AZERTY** - both existing European layouts now ship
  with full top-top rows, punctuation, and their extended-European
  characters (German ß/ö/ä/ü; French é/è/ç/à/ù).
- **v2.0.0 legacy decrypt** - a self-contained `v2.0.0-legacy` decrypt path
  recovers ciphertext produced by the original v2.0.0 Python and v2.0.0
  JavaScript builds. The path uses dedicated `V200_*` constants and tries
  both historical `pos_offset` variants. v2.0.0 keys are still rejected by
  the K6-only encrypt enforcement.
- **Materialized metadata toggle** - encrypt and decrypt now accept a
  `materialize` boolean. When ON, the 44 metadata carriers are emitted as
  visible ALPHA characters in a keyed `A,B,C,D` alphabet, so ciphertext
  survives databases and APIs that strip zero-width characters. Toggle
  mismatches fail closed and never fall through to legacy decrypt paths.
  CLI exposes `--materialize`, interactive mode prompts before encrypt or
  decrypt, and the browser, Electron, and docs builds expose a checkbox
  with a "Receiver must use the same setting" hint.

### Compatibility
- All existing rc.6 keys continue to parse. New keyed permutations differ
  from rc.6 because of the rejection-sampling change, so rc.7 ciphertext
  is not decryptable by rc.6 builds, and vice versa.
- The wire format and hidden metadata version character `5` are unchanged. The
  active API format label remains `rc.6-stream`.
- The default carrier mode remains zero-width hidden carriers; the
  materialized path is strictly opt-in.
- The new v2.0.0-legacy decrypt path is purely additive and never affects
  rc.6 or later message decoding.

---

## v3.0.0-rc.6 - Release Candidate 6

### Highlights
- **New rc.6 stream format** - new ciphertext now emits as `rc.6-stream`
  with version character `5`. The rc.4-hidden decrypt path remains available
  for rc.4 and rc.5 ciphertext.
- **Round floor** - derived key material now enforces `ROUND_MINIMUM = 10`
  so weak key compositions cannot collapse below ten rounds.
- **European extended alphabet** - the active alphabet expands to 161
  characters, adding accented letters, Nordic letters, inverted Spanish
  punctuation, and OE ligatures. These characters participate in the cipher
  while remaining layout-unassigned until a later release.
- **Reserved national layouts** - `Spanish`, `Swedish`, `Norwegian`,
  `Danish`, `Icelandic`, and `Belgian` are reserved in `LAYOUT_NAMES`.
- **Carrier phantom advancement** - zero-width carrier positions now advance
  cipher state through key-derived phantom alphabet characters.
- **Scattered encrypted checksum** - the checksum is encrypted into visible
  stream positions instead of being carried as a fixed prefix.
- **K6 key encoding** - generated keys now use a `K6:` prefix with base36
  indexes so 161 alphabet positions and 16 layout names are representable.
- **256-bit keygen floor** - default random key generation now rejects
  candidates below `256` family bits (raised from `213.5`).

### Compatibility
- New rc.6 ciphertext is not decryptable by rc.5 builds.
- This build decrypts rc.4-hidden ciphertext through a preserved 95-symbol
  legacy path.
- Headed rc.3 and legacy rc.2 decrypt support remain in place.

---

## v3.0.0-rc.5 - Release Candidate 5

### Highlights
- **Wire-compatible rc.5 hardening** - new ciphertext remains `rc.4-hidden`
  with hidden version character `4`, so rc.4 and rc.5 ciphertext are identical
  on the wire.
- **Shell-safe Python input** - `decrypt` and `ioc` now support
  `--from-clipboard`, bare `python enigmak.py` opens interactive mode, and
  interactive encryption writes exact ciphertext to the system clipboard so
  zero-width metadata survives copy/paste.
- **Generic decrypt failures** - Python, JS, browser, and Electron runtimes now
  return `Decryption failed.` with blank plaintext on failed verification.
- **Failure-path buffer corruption** - partial decrypted buffers are overwritten
  internally before failed decrypts return. The corruption buffer is fixed at
  exactly 4096 characters regardless of message length, and HTML/Electron
  outputs clear immediately on failed or thrown decrypt paths.
- **Fail-closed browser and Electron decrypt UI** - tampered visible or hidden
  ciphertext no longer leaves stale plaintext in the output textarea.
- **Random keygen floor** - default key generation now samples random key
  profiles and accepts only keys with at least 213.5 family bits, eliminating
  repeated fixed-strength key shapes.
- **Expanded static layout definitions** - the reserved layout maps now cover
  number rows, brackets, quotes, and punctuation without changing active cipher
  logic.

### UX
- Plaintext and ciphertext textareas resize vertically in the root, docs, and
  Electron HTML builds.
- Electron and CLI branding now reports `v3.0.0-rc.5`.
- `layout_bias_check.py` now checks rc.5 layout bijectivity, keygen variation,
  the 213.5-bit generated-key floor, fixed corruption length, and tamper
  fail-closed behavior.

---

## v3.0.0-rc.4 - Release Candidate 4 (not officially released)

### Highlights
- **Synced rc.4 runtime bundle** - the root browser build, mirrored docs build,
  Electron HTML build, JS module, and Python CLI now all ship the same
  `rc.4-hidden` encryption and verification behavior.

### Breaking Change
- Newly emitted ciphertext now uses the `rc.4-hidden` format instead of the
  visible `E3|` `rc.3` header path. New encryption output is intentionally not
  forward-compatible with `rc.3` emitters.

### New Features
- **Hidden metadata ciphertext** - new messages hide version + checksum data as
  scattered zero-width carrier symbols instead of exposing a visible version
  header.
- **Visible body packaging** - the active visible payload is now
  `[format_tag:1][len_field:4][plaintext][padding]`.
- **Continued-state hidden metadata** - hidden metadata encryption continues
  directly from the visible-body cipher state instead of using a separate
  visible package path.
- **Version-aware copy diagnostics** - browser, JS, and Python builds now
  surface hidden-carrier counts and warn when metadata appears stripped.
- **Accordion browser UI** - Layouts, Rotors, Steckerbrett, and Key are now
  expanded-by-default collapsible panels in the root, docs, and Electron HTML
  builds.

### Security / Core Updates
- **64-bit current-path derivation** - current key-derived rotor-state hashing,
  permutation seeding, step-mask seeding, whitening, and related seeded math
  now use 64-bit state in JS and Python.
- **Checksum-driven padding** - visible padding now depends on plaintext, key,
  checksum, and version, and new messages always emit at least one visible
  padding character.
- **Hidden carrier encoding** - each hidden metadata character is encoded into
  four zero-width symbols from `U+200B`, `U+200C`, `U+200D`, and `U+2060`
  using a keyed permutation.
- **Concrete-key-weighted keygen** - default keygen in Python, JS, and HTML now
  samples profiles by exact concrete key count before sampling within the chosen
  profile.

### Compatibility
- Decryptors still accept headed `rc.3` ciphertext through the legacy path.
- Decryptors still accept legacy unheaded `rc.2` ciphertext through the old
  checksum-strip fallback.
- Stripping zero-width metadata from new ciphertext now fails explicitly as
  `Hidden metadata missing or stripped from ciphertext`.

### UX
- HTML defaults now start at `0 000 0 001`.
- The old marketing tagline was removed from the HTML builds.
- `Copy exact output` messaging now emphasizes preserving invisible metadata.

---

## v3.0.0-rc.3 - Release Candidate 3 (not officially released)

### Breaking Change
- Ciphertexts from `v3.0.0-rc.2` and earlier are not forward-compatible with
  the new default emit path. New encryption now writes the versioned `E3|`
  format with an encrypted payload package.

### New Features
- **Versioned ciphertext header** - new messages begin with `E3|`.
- **Encrypted checksum packaging** - plaintext length field, plaintext,
  64-bit checksum, and deterministic keyed padding are now encrypted together
  instead of exposing a raw checksum block inside visible ciphertext.
- **Exact-length leak mitigation** - keyed padding now hides exact plaintext
  length within a 16-character window.
- **Full-random default keygen** - Python, JS, and HTML key generation now
  randomize the full valid key shape instead of reusing a fixed 4-layout /
  3-rotor / 8-steck profile.
- **Dual key-strength view** - built-in tools now separate key family strength
  from the current key profile so repeated fixed-shape values no longer look
  mysterious.

### Updates
- Legacy unheaded `rc.2` ciphertext still decrypts through a fallback path.
- Clipboard-corruption safeguards are now treated as a shipped cross-program
  feature across HTML, JS, Python, docs, and Electron.
- Python help text now lists `keystrength` in the top usage block.
- Browser UI now exposes a one-click `Random Key` action.
- Browser, docs, and Electron HTML copies are synced from the same root
  machine file.
- The top-level docs now reflect the current remaining `v3.0.0` roadmap:
  Unicode support, proper passphrase KDF work, photo/file encryption,
  `utils.js` refactor, remaining security tests, and MITM investigation.

---

## v3.0.0-rc.2 - Release Candidate 2 (not officially released)

### Breaking Change
- Ciphertexts from v3.0.0-rc.1 and earlier are not compatible with rc.2.
  The alphabet has been expanded from 94 to 95 symbols and the checksum
  format has changed. Existing messages must be re-encrypted.

### New Features
- **Space added to alphabet** - spaces now go through the full cipher
  pipeline as regular symbols instead of passing through unchanged.
- **Word boundary leakage removed** - because spaces are now encrypted,
  ciphertext no longer exposes plaintext word lengths.
- **Checksum upgraded to 64-bit** - ciphertext now carries a 64-bit
  checksum encoded as 10 base-95 characters, improving integrity checks.

### Updates
- Step mask updated from 65/94 to 66/95 (same ~69% ratio maintained).
- Max steck pairs remains 47.
- IoC floor drops from 1/94 (0.01064) to 1/95 (0.01053).
- Keyspace at maximum configuration: ~4.528 x 10^128 (~427 bits).
- HTML, JS, and Python now warn on suspicious clipboard-normalized punctuation,
  non-ASCII ciphertext paste issues, and checksum mismatches that may come from
  dropped punctuation during transfer.
- Browser output copy now reports the exact character count and is labeled as
  the safe path for preserving punctuation-heavy ciphertext.
- Electron About dialog updated to reflect 95-symbol alphabet and new keyspace.
- docs/ and Electron HTML copies synced to the root machine so all shipped
  interfaces use the same 95-symbol alphabet and 64-bit checksum.

---

## v3.0.0-rc.1 - Release Candidate 1 (not officially released)

### Breaking Change
- Ciphertexts from v2.0.0 and earlier are not compatible with v3.0.0.
  The alphabet has been expanded from 68 to 94 symbols. All existing
  messages must be re-encrypted.

### New Features
- **Lowercase letters added to alphabet** - a-z are now first-class cipher
  symbols. N increases from 68 to 94. Lowercase and uppercase are fully
  distinct: "hello" and "HELLO" produce different ciphertext.
- **Case-sensitive content now survives encryption** - URLs, passwords, and
  mixed-case strings decrypt identically to their original form.

### Updates
- Step mask updated from 47/68 to 65/94 (same ~69% ratio maintained).
- Max steck pairs increases from 34 to 47.
- IoC floor drops from 1/68 (0.01471) to 1/94 (0.01064).
- Keyspace at maximum configuration: ~4.024 x 10^126 (~421 bits).
- Lowercase warning removed from HTML (no longer needed).
- Electron About dialog updated to reflect 94-symbol alphabet and new keyspace.

---

## v2.0.0 - Official Release

### Breaking Change
- Ciphertexts from v1.0.0 are not compatible with v2.0.0. Keys are unchanged;
  messages encrypted under v1.0.0 must be re-encrypted.

### Security Fixes (consolidated from rc.1 through rc.3.1)

- **Position whitening layer** (rc.1) - a key-derived LCG stream (seed = keySum XOR
  0xC0FFEE42, period 2^32) applies a unique offset to every character position.
  Eliminates the confirmed chosen-plaintext periodicity leak present in v1.0.0,
  where bucketing ciphertext by position modulo 68 revealed measurable
  distribution bias (L1 ~0.025 in v1.0.0, now ~0.42+ consistent with random
  noise). Step mask leakage eliminated as a side effect.
  Credit: r/cryptography community, March 2026.

- **Key-derived layout permutations** (rc.2) - the ten keyboard layouts (QWERTY,
  Colemak, Dvorak, etc.) no longer use fixed ergonomic wirings as substitution
  tables. Each layout now derives a unique bijective permutation of all 68
  characters from key material (seed = keySum XOR (layoutIndex * 0x9E3779B9 +
  0xABCD1234)). Eliminates keyboard layout bias: cross-key top-5 character
  overlap drops to 0/5, consistent with random. All 10 permutations verified
  bijective by layout_bias_check.py.

- **Rotor state feedback in position offsets** (rc.3) - each character's round and
  scramble shifts now incorporate an FNV-1a digest of the current rotor state
  combined with absolute position and key material. Creates a cryptographic
  feedback loop where rotor state after character N influences offsets for
  character N+1. Eliminates the monocharacter oracle: encrypting repeated
  characters no longer produces extractable cycle structure, even under
  worst-case settings (1 layout, 1 rotor, 0 steck pairs, 1 round).

### New Features

- **Key strength calculator** - theoretical keyspace in bits, broken down by
  component: layouts (ordered permutations P(10,k)), rotors ((10 * 68)^n),
  steckerbrett pairs, rounds (999), and optional nonce (68^3). Available in
  the HTML machine, Python CLI (`enigmak.py keystrength <key>`), and JS module.

- **Dedicated bias checker** (`python/layout_bias_check.py`) - five-test suite
  verifying layout map bijectivity, frequency uniformity, cross-key
  independence, inter-layout independence, and elimination of v1.0.0 identity
  mapping bias. All five tests pass; old v1.0.0 wirings fail three of five.

- **Electron desktop wrapper updated** to v41.1.0 (Chromium 146, Node.js
  24.14.0) with electron-builder 26.8.1. Windows arm64 build target added.
  About dialog updated with correct version, 68-symbol alphabet, and keyspace.

### Fixes

- **calc_key_strength permutation formula** - was using C(10,k) unordered
  combinations; corrected to P(10,k) ordered permutations. Layout order matters
  in ENIGMAK -- Colemak then Dvorak produces different ciphertext than Dvorak
  then Colemak. Previous formula understated keyspace by up to 24x for 4
  layouts.

- **Dvorak layout definition corrected** - top row now correctly maps as
  `',.PYFGCRL`, home row `AOEUIDHTNS`, bottom row `;QJKXBM`.

- **Python files reorganised** - `enigmak.py` and `layout_bias_check.py` moved
  to `python/` subfolder for cleaner project structure.

- **Supply chain security note** added to README advising users to run
  `npm audit` before building the Electron wrapper.

### UX

- **Lowercase input warning** - the HTML machine now shows a visible amber
  warning when lowercase input is detected, noting that lowercase letters fold
  to uppercase and case-sensitive content (URLs, passwords) may not decrypt
  identically.

- **Non-ASCII note** added to README and SECURITY.md: characters outside the
  68-symbol ASCII alphabet pass through unencrypted. Do not use ENIGMAK to
  encrypt content containing non-ASCII characters.

### Known Limitations
- Non-ASCII characters (Cyrillic, accented Latin, emoji, etc.) pass through
  unencrypted, leaking content. Planned for v3.0.0.
- Word boundary leakage: spaces are not in the 68-symbol alphabet and appear
  in plaintext in ciphertext, revealing word lengths. Planned for v3.0.0.
- Lowercase letters fold to uppercase, breaking case-sensitive content such as
  URLs and passwords. Planned for v3.0.0.
- Not formally audited. Do not use for classified, medical, legal, or
  life-critical communications.

---

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

### Fixes
- **enigmak.js: keySum missing from computeKeyMaterial return** - caused undefined cascade in encrypted checksum pipeline, breaking checksum verification entirely in the JS module.

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
