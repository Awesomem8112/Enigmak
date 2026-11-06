# ENIGMAK rc.9 Correctness Audit

This is a bounded implementation audit, not a proof of correctness, a security
certification, or an independent cryptographic review. The audited target is
`v3.0.0-rc.9` in this repository.

## Finding ledger

| ID | Finding and impact | Resolution | Regression evidence |
|---|---|---|---|
| C-01 | The JavaScript parity runner used the wrong module/test path, and Python `unittest` discovered zero tests. Regressions could pass unnoticed. | Corrected paths, made the Python suite discoverable, pinned fixtures in `tests/fixtures.json`, and added `python scripts/verify.py`. | Repository verification harness. |
| C-02 | Variable-metadata, nonce-5, materialized, and Option A decoy fixtures were regenerated during test import. That did not detect output drift. | Replaced generated values with literal fixtures. Added reconstructed and cross-runtime-verified rc.4-hidden and v2.0.0 fixtures. | Python and JavaScript fixture suites. |
| C-03 | Python and JavaScript key parsing differed for trailing decimal junk, Unicode decimal digits, duplicate layouts, self-pairs, and reused Stecker characters. Malformed keys could be interpreted differently. | Added strict ASCII-decimal parsing and identical structural checks. | Malformed-key parity tests. |
| C-04 | JavaScript counted UTF-16 code units in ciphertext diagnostics and carrier extraction. Astral contamination produced different lengths and positions from Python. | Iteration now uses Unicode code points. | Unicode diagnostics parity tests. |
| C-05 | JavaScript key-family combinatorics used lossy `Number` arithmetic. Large profiles could overflow or round, including near policy comparisons. | Counts now use `BigInt`; logarithms use the high 53 bits; the 256-bit key-generation floor compares the exact count with `2^256`. Python also uses the exact integer for the floor. | Full generated-profile-grid parity test. |
| C-06 | Metadata length used `% 161`, introducing a small modulo bias. | New encryption uses deterministic 64-bit rejection sampling. Decryption also accepts the prior modulo-derived count and the historical fixed 44-carrier count. | Metadata-bound and compatibility fixtures. |
| C-07 | JavaScript negative remainder semantics could diverge from Python modulo after long state evolution. | Live rotor/whitening subtraction uses canonical mathematical modulo. | Long-message and modulo-boundary parity tests. |
| C-08 | ChaCha20 stream counters were not explicitly constrained at increment boundaries. | Counters are masked to the RFC 8439 32-bit width in both runtimes. | Import-time RFC 8439 block vector and boundary tests. |
| C-09 | JavaScript BLAKE3 split arithmetic used 32-bit shift behavior in places where safe integer arithmetic was required; primitive tests covered only tiny inputs. | Split arithmetic is safe for supported input bounds. Import-time checks now include official 0-, 1-, 1024-, and 2048-byte hash vectors plus `abc`. | Python, Node, browser, and Electron runtime load checks. |
| C-10 | v2.0.0 printable-text plausibility differed for non-ASCII code points. | JavaScript now mirrors Python `str.isprintable()` category behavior while preserving frozen v2 transforms. | v2 fixture and Unicode rejection parity tests. |
| C-11 | If the browser runtime was unavailable, the UI silently used an older local recompute path and could emit different ciphertext. | The browser clears output, reports the unavailable runtime, and emits nothing. | Browser missing-runtime smoke test. |
| C-12 | Browser randomness could rely on renderer `require`, which is unavailable in sandboxed Electron. | Random acquisition uses Web Crypto when available, a guarded Node Web Crypto path only in Node, and otherwise fails closed. | Browser/Electron runtime smoke checks. |
| C-13 | Package, About, alphabet, and release strings disagreed between rc.6/rc.8/rc.9 and 161/162 symbols. | Current package, lockfile, CLI, About dialog, Electron documentation, and user documentation are synchronized to rc.9 and 162 symbols. | Version/document consistency checks. |
| C-14 | Failure handling implied overwrite behavior that immutable Python/JavaScript strings cannot provide, and performed two nominal 4096-character passes in common paths. | Failure work is one fixed 4096-code-point pass. Mutable random arrays are cleared best-effort; documentation explicitly disclaims guaranteed erasure in garbage-collected runtimes. | Fixed-work regression and security documentation. |
| C-15 | The dual-slot filler was not checked after unwrap. Filler-only corruption could be accepted because the inner message still verified. | Decryption recomputes and compares all filler bytes before inner parsing. | Filler-bit-flip negatives in both runtimes. |
| C-16 | A chance rc.4 structural parse could return early and shadow a valid prefix-free dual envelope. Base64 decoding also allocated before applying the slot cap. | Failed rc.4 candidates continue to the bounded dual probe; encoded length is capped before decode/allocation. | Shadow-path and oversized-input tests. |
| C-17 | Option A terminology suggested the old two-ciphertext decoy bundle implemented same-blob dual decryption. | Option A remains API-compatible but is marked deprecated. The UI and primary CLI expose the one-ciphertext/two-key workflow. | API, CLI privacy, browser, and Electron tests. |
| C-18 | `pack_rc4_payload` / `packRc4Payload` used live BLAKE3/ChaCha helpers and was never called. It could not reconstruct historical rc.4 ciphertext. | Removed as proven-unreachable. Frozen rc.4 decrypt helpers and reconstructed fixtures remain. | Dead-code review plus pinned rc.4 fixture. |
| C-19 | Several documents still listed a 80-pair Stecker maximum from the 161-symbol alphabet. `N // 2` is 81 at 162 symbols, matching the UI and key-strength grid. | Documentation now uses 81 pairs. | Key-strength grid includes the `(16, 18, 81)` profile. |

## Compatibility decisions

- Existing `rc.6-stream`, materialized stream, `rc.4-hidden`, `rc.3`,
  `rc.2-legacy`, and `v2.0.0-legacy` decrypt paths remain supported.
- New single-message encryption still emits the version-5 `rc.6-stream`
  format. The new outer format reports `rc.9-dual-v1`.
- The old `encrypt_decoy_bundle` / `encryptDecoyBundle` and `encrypt-decoy`
  surfaces remain available as deprecated Option A behavior (two ciphertexts).
- Legacy fixed-44 and pre-audit modulo-derived metadata counts remain
  decrypt-only compatibility candidates.

## Residual risks and design limitations

- ENIGMAK is a custom construction and has not received external cryptographic
  review. Passing this repository suite establishes consistency with the
  specified vectors and properties only.
- The dual envelope has no public marker, header, or delimiter, but its size and
  base64url-like statistics can distinguish it from ordinary ENIGMAK output.
  This is not a formal plausible-deniability guarantee.
- Slot wrapping is a framing/privacy layer. Acceptance depends on exact filler
  recovery plus complete inner `rc.6-stream` checksum, metadata, and padding
  verification. The wrapper has no independent keyed BLAKE3 tag; this is a
  documented design limitation, not AEAD.
- Historical rc.4-hidden and v2.0.0 fixtures were reconstructed from frozen
  decrypt-only helpers because no original vectors were present in this tree.
  They are independently verified in Python and JavaScript, but they are not
  recovered from a historical git tag.
- Electron packaging (`electron` / `electron-builder`) currently reports
  transitive npm advisories. Cipher files have no npm dependencies; those
  advisories apply to the desktop packaging toolchain, not the cipher
  implementations.
- Python and JavaScript strings are immutable and garbage collected. Mutable
  temporary arrays are cleared best-effort, but keys and plaintext cannot be
  guaranteed overwritten in memory.
- Legacy decrypt algorithms intentionally retain historical FNV/LCG behavior.
  They are compatibility code, not recommendations for new encryption.
- Timing and cache behavior are not constant-time. Both dual slots are probed
  with bounded work where practical, but the implementation does not claim
  side-channel resistance.
- The 1 MiB per-slot bound is checked arithmetically and with malformed boundary
  tests. A literal multi-megabyte maximum-size fixture is not stored because it
  would add disproportionate repository and CI cost; this is classified as an
  impractical fixture-size edge, not an unbounded parser path.
