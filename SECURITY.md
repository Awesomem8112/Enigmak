# Security Policy

## Scope

This document covers the ENIGMAK cipher implementation and desktop wrapper.

## Reporting a Vulnerability

If you discover a cryptographic weakness, implementation flaw, or security vulnerability in ENIGMAK, please open a GitHub Issue tagged `security`. Include:

- A clear description of the vulnerability
- Steps to reproduce or a proof of concept
- Your assessment of severity and exploitability

Do not privately disclose cryptographic weaknesses. Remember, ENIGMAK benefits from **all** open public scrutiny.

## Known Limitations

- **Not formally audited.** ENIGMAK has not undergone professional cryptanalytic review.
- **Keyboard layout bias (FIXED in v2.0.0-rc.2).** The layouts used as rotor wirings were designed for ergonomic typing, not cryptographic uniformity. Theoretical bias may exist.
- **Monocharacter oracle.** Encrypting a single repeated character under chosen-plaintext reveals rotor cycle structure.
- **Key reuse.** Reusing a key across messages creates correlated ciphertext that may leak plaintext structure.
- **Meet-in-the-middle.** A theoretical MITM attack may be possible if diffusion/scramble layers are insufficiently non-linear.
- **Browser environment.** Running in a browser is less secure than dedicated hardware. Extensions, malicious pages, and memory access are potential vectors.

## Recommended Usage

- Generate a fresh key for every session
- Use the nonce for every message
- Never transmit keys through the same channel as ciphertext
- Verify the key fingerprint verbally before use
- Do not use for classified, medical, legal, or life-critical communications
