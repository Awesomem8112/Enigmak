# ENIGMAK Technical Notes

This document describes the current `v3.0.0-rc.5` design at a high level. Its
active new-message format is `rc.4-hidden`. It complements
`SPECIFICATION.md`, not replaces it.

## Current Snapshot

The current release candidate now uses:

- a 95-symbol ASCII alphabet
- literal space as a first-class cipher symbol
- 1-13 rotors
- a `66/95` irregular step mask
- up to 47 stecker pairs
- keyed full-alphabet layout permutations
- keyed 95-position diffusion
- rotor-state feedback in position offsets
- position whitening
- a hidden-metadata ciphertext format with no visible `E3|` prefix
- 64-bit current-path seeded derivation
- random key generation with a 213.5-bit acceptance floor

## Why RC.4 Changed The Packaging

`rc.3` still exposed its version with a visible `E3|` header. `rc.4-hidden`
keeps the visible ciphertext looking plain while preserving:

- format versioning
- checksum verification
- keyed padding verification

It does that by splitting output into:

- a visible encrypted body
- a hidden encrypted metadata stream

The hidden stream is encoded as scattered zero-width carriers, so the message
still round-trips through normal text channels as long as those characters are
preserved exactly.

## Visible And Hidden Layers

The visible encrypted body corresponds to:

```text
[format_tag][len_field][plaintext][padding]
```

The hidden encrypted metadata corresponds to:

```text
[version][checksum]
```

Important implementation detail: the hidden metadata is encrypted by continuing
the same cipher state directly after the visible body. It is not a separate
fresh stream.

## Zero-Width Carrier Design

The carrier alphabet is fixed:

```text
U+200B  U+200C  U+200D  U+2060
```

Each hidden metadata character is converted into four base-4 digits, then
mapped through a keyed permutation of those four symbols. The resulting 44
carrier symbols are scattered across the ciphertext using a keyed 64-bit PRNG.

Practical consequence:

- if those carriers are removed, the visible body may still decrypt into a
  plausible plaintext candidate, but verification must fail explicitly

## 64-Bit Current Path

The active `rc.4` emit path moved the remaining seeded derivation logic to
64-bit state:

- rotor-state hash
- key sum
- diffusion seeding
- step-mask seeding
- per-layout permutation seeding
- whitening stream
- hidden carrier scatter seeds

This does not remove the legacy 32-bit path entirely. Old `rc.3` and `rc.2`
ciphertext still decrypt through compatibility code that preserves their
original behavior.

## RC.5 Hardening

`v3.0.0-rc.5` keeps the `rc.4-hidden` wire format unchanged. The hidden
metadata version character remains `4`.

The release hardens the interfaces around that format:

- Python decrypt and IoC can read ciphertext directly from the clipboard.
- Bare `python enigmak.py` starts an interactive prompt.
- Python interactive encryption copies exact ciphertext to the system clipboard,
  avoiding terminal-selection loss of zero-width metadata.
- Failed decrypts return the generic error `Decryption failed.` with blank
  plaintext.
- Failure paths overwrite partial decrypted buffers before returning with a
  fixed exactly 4096-character corruption buffer, independent of message
  length.
- Browser and Electron decrypt mode clear the output before decrypting and only
  write plaintext after explicit verification success, preventing stale
  plaintext after tampering or thrown exceptions.
- Static keyboard-layout definitions now include all printable keyboard rows
  for future tooling, while active cipher layout permutations remain keyed and
  full-alphabet.

## Keygen Fix

Earlier generators could repeatedly produce the same profile shape, which made
the displayed key-family size look suspiciously fixed. Current keygen now:

1. samples profile dimensions randomly from the allowed ranges
2. samples concrete layouts, rotors, stecker pairs, rounds, and nonce values
   inside that profile
3. rejects candidates below 213.5 family bits

That keeps generated keys varied without accepting low-strength families.

## Browser UI Notes

The root HTML, docs HTML, and Electron HTML now share the same UI state model:

- default key `0 000 0 001`
- `QWERTY` enabled by default
- one rotor at `00`
- no steck pairs
- no nonce
- collapsible Layouts / Rotors / Steckerbrett / Key panels
- diagnostics that mention hidden carrier counts and stripped metadata
- vertically resizable input and output text boxes
- fail-closed decrypt output behavior for corrupt visible text and missing
  hidden metadata

The browser UI now delegates actual encryption, decryption, key parsing,
keygen, key strength, and ciphertext diagnostics to the shared `enigmak.js`
runtime to reduce implementation drift.

## Compatibility

Decryption order is:

1. headed `rc.3`
2. hidden `rc.4`
3. legacy `rc.2`

That keeps old ciphertext readable while allowing new messages to use the
hidden format.

## Remaining Limits

- Non-ASCII / Unicode is still passthrough.
- The checksum is not authenticated encryption.
- ENIGMAK still needs formal review.
