# Security Policy

## Scope

This document covers the ENIGMAK cipher implementation and desktop wrapper.

## Reporting a Vulnerability

If you discover a cryptographic weakness, implementation flaw, or security vulnerability in ENIGMAK, please open a GitHub Issue tagged `security`. Include:

- A clear description of the vulnerability
- Steps to reproduce or a proof of concept
- Your assessment of severity and exploitability

Do not privately disclose cryptographic weaknesses - ENIGMAK benefits from open public scrutiny.

## Known Limitations

- **Not formally audited.** ENIGMAK has not undergone professional cryptanalytic review.

- **Chosen-plaintext periodicity leak (confirmed).** Encrypting repeated plaintext reveals position-mod-68 periodic structure in the ciphertext. Bucketing ciphertext characters by position mod 68 and comparing distributions yields a measurable L1 distance (~0.025) between buckets, demonstrating that different rotor positions produce detectably different output distributions. This is a structural weakness in the stepping construction, not a usage edge case. Chosen-plaintext attacks are a standard adversarial model and the design does not hold under them.

- **Step mask leakage under chosen-plaintext.** Using the same bucket analysis, the deviation of each bucket from the global distribution correlates with the internal step mask at approximately 67% accuracy on a single run. The key-derived step mask is therefore partially recoverable under chosen-plaintext conditions. Credit: r/cryptography user (March 2026).

- **Keyboard layout bias.** The layouts used as rotor wirings were designed for ergonomic typing, not cryptographic uniformity. Theoretical bias may exist at scale.

- **Monocharacter oracle.** Encrypting a single repeated character under chosen-plaintext is the clearest instance of the periodicity leak described above.

- **Key reuse.** Reusing a key across messages creates correlated ciphertext that may leak plaintext structure.

- **Meet-in-the-middle.** A theoretical MITM attack may be possible if diffusion/scramble layers are insufficiently non-linear.

- **Browser environment.** Running in a browser is less secure than dedicated hardware. Extensions, malicious pages, and memory access are potential vectors.

## Recommended Usage

- Generate a fresh key for every session
- Use the nonce for every message
- Never transmit keys through the same channel as ciphertext
- Verify the key fingerprint verbally before use
- Do not use for classified, medical, legal, or life-critical communications
