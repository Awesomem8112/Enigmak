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
- **Non-ASCII passthrough.** Characters outside the 95-symbol built-in ASCII
  alphabet still pass through unchanged in `v3.0.0-rc.3`.
- **Key reuse.** Reusing a key across messages creates correlated ciphertext
  and is strongly discouraged.
- **Checksum is not AEAD.** The current rc.3 package encrypts a 64-bit keyed
  checksum and deterministic padding, which is better than the old visible
  checksum block, but it is still not a substitute for researched
  authenticated encryption.
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

## Recommended Usage

- Generate a fresh key for every session.
- Use the nonce for every message.
- Never transmit keys through the same channel as ciphertext.
- Verify the key fingerprint verbally before use.
- Prefer the `E3|` rc.3 format for all new messages.
- Treat the current checksum as an integrity hint, not as authenticated
  encryption.
- Do not use ENIGMAK for classified, medical, legal, or life-critical
  communications.
