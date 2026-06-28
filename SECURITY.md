# Security Policy

## Scope

This document covers the ENIGMAK cipher implementations and the Electron
desktop wrapper in this repository.

## Reporting a Vulnerability

If you discover a cryptographic weakness, implementation flaw, or security
issue, open a public GitHub issue tagged `security` and include:

- a clear description of the issue
- reproduction steps or a proof of concept
- your assessment of severity and exploitability

Do not privately disclose cryptographic weaknesses. ENIGMAK benefits from open
public scrutiny.

## Current Known Limitations

- **Not formally audited.** ENIGMAK has not undergone professional
  cryptanalytic review.
- **162-symbol alphabet with passthrough.** The active cipher operates on a
  162-symbol `ALPHA` (legacy printable ASCII, European extended characters, and
  newline). Characters outside `ALPHA` pass through unchanged on encrypt and do
  not advance rotor state. On the `rc.6-stream` decrypt path, any visible
  non-carrier stream character outside `ALPHA` causes verification failure.
- **Extended characters and layouts.** European extended characters and newline
  participate in stecker, diffusion, whitening, and keyed layout permutations.
  RC7 includes static layout definitions for all 16 layout labels.
- **Key reuse.** Reusing a key across messages creates correlated ciphertext
  and is strongly discouraged.
- **Checksum is not AEAD.** The `rc.6-stream` format protects version,
  checksum, and keyed padding, but it is not a substitute for researched
  authenticated encryption.
- **Zero-width metadata transport.** New `rc.6-stream` ciphertext depends on
  44 invisible metadata carriers. Use exact copy/export paths; terminal
  highlighting can omit those characters. Python interactive encryption copies
  exact output to the system clipboard to avoid this failure mode.
- **Materialized metadata transport.** The optional materialized mode emits the
  same 44 carrier events as visible `ALPHA` characters for carrier-hostile
  databases and APIs. Sender and receiver must use the same setting; mismatches
  fail closed.
- **Stream schedule integrity.** `rc.6-stream` interleaves payload symbols,
  scattered checksum symbols, and zero-width carriers in a keyed order.
  Removing or reordering checksum or carrier symbols must fail verification.
  There is no fixed visible checksum prefix in new ciphertext.
- **Phantom carrier advancement.** Zero-width carrier positions advance cipher
  state through key-derived wildcard alphabet characters. Tampering with
  carriers desynchronizes decryption.
- **Meet-in-the-middle.** A theoretical MITM attack may still be possible if
  the diffusion and scramble layers are not strong enough in aggregate.
- **Browser environment.** Running in a browser is less secure than dedicated
  hardware or a hardened native environment. Extensions, malicious pages, and
  memory access remain potential vectors.

## Historical Issues Fixed In Earlier Releases

- Keyboard layout bias was addressed by moving to key-derived full-alphabet
  layout permutations.
- The monocharacter oracle was addressed by mixing live rotor-state feedback
  into per-position offsets.
- The position-mod-N periodicity leak was addressed by the position whitening
  layer.
- Word-boundary leakage from plaintext spaces was addressed in `v3.0.0-rc.2`
  by adding space to the cipher alphabet.
- Exact plaintext-length leakage from a visible fixed checksum block was
  reduced in `v3.0.0-rc.3` by moving length, checksum, and padding inside the
  encrypted `E3|` payload.
- Visible format leakage was further reduced in `v3.0.0-rc.4` by moving
  version + checksum data into hidden zero-width carrier metadata.
- Decryption oracle detail was reduced in `v3.0.0-rc.5` by returning a generic
  failure message and blank plaintext on verification failure.
- Browser/Electron stale-output exposure was fixed in `v3.0.0-rc.5` by clearing
  decrypt outputs before attempting decrypt work and by hard-gating final output
  writes on successful verification.
- Failure-path corruption was fixed at exactly 4096 characters in `v3.0.0-rc.5`
  so the amount of local overwrite work is independent of message length.
- `v3.0.0-rc.6` introduced `rc.6-stream` with scattered encrypted checksum
  characters, phantom advancement at carrier positions, a 161-symbol alphabet,
  `K6:` base36 key encoding, and a `ROUND_MINIMUM` floor of 10 derived rounds.
- `v3.0.0-rc.7` expanded `ALPHA` to 162 symbols by adding newline, switched
  keyed shuffles to rejection sampling, added materialized metadata transport,
  filled all 16 static layout definitions, and added original `v2.0.0-legacy`
  decrypt support.

## Recommended Usage

- Generate a fresh key for every session.
- Use the nonce for every message.
- Never transmit keys through the same channel as ciphertext.
- Verify the key fingerprint verbally before use.
- Prefer `rc.6-stream` for all new messages.
- Preserve zero-width metadata when copying or exporting ciphertext.
- Use materialized metadata only when the transport cannot preserve zero-width
  carriers, and tell the receiver to use the same setting.
- Prefer clipboard or interactive mode for Python CLI decryption of real
  ciphertext, and rely on the interactive encryption clipboard copy rather than
  manually highlighting terminal output.
- Treat the current checksum as an integrity hint, not as authenticated
  encryption.
- Restrict plaintext to `ALPHA` when using `rc.6-stream` if you require
  reliable round-trip through the current decrypt path.
- Do not use ENIGMAK for classified, medical, legal, or life-critical
  communications.
