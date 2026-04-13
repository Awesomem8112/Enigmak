# ENIGMAK Technical Notes

This document describes the current `v3.0.0-rc.3` design at a high level. It
complements `SPECIFICATION.md`, not replaces it.

## Current RC.3 Snapshot

The active branch currently uses:

- a 95-symbol ASCII alphabet
- space as a first-class cipher symbol
- 1-13 rotors
- a `66/95` irregular step mask
- up to 47 stecker pairs
- keyed full-alphabet layout permutations
- keyed 95-position diffusion
- rotor-state feedback in position offsets
- position whitening
- an `E3|` ciphertext header
- an encrypted 64-bit checksum inside the payload
- deterministic keyed padding that hides exact plaintext length within a 16-character window
- full-random default key generation

Lowercase letters landed in `rc.1`. Space encryption and the 64-bit checksum
landed in `rc.2`. Versioned ciphertext, encrypted packaging, length-hiding
padding, and full-random keygen land in `rc.3`.

## The 95-Symbol Alphabet

The live alphabet is:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./!@#$%^&*()_+{}|:"<>?`~abcdefghijklmnopqrstuvwxyz[space]
```

This gives ENIGMAK a theoretical random IoC floor of `1/95 ~= 0.01053`.

Two practical consequences:

- mixed-case strings survive encryption intact
- spaces no longer leak plaintext word boundaries

Non-ASCII characters are still outside the cipher alphabet and pass through
unchanged in `rc.3`.

## Key Material

The core derived values remain:

```text
rounds = ((S + R + L + U) mod 999) + 1
keySum = (S*31 + R*17 + L*13) mod 2^32
```

Where:

- `S` is the normalized stecker-pair sum
- `R` is the rotor position sum
- `L` is the enabled-layout index sum
- `U` is the user-supplied base round count

From `keySum`, ENIGMAK derives:

- the `66/95` step mask
- the 95-position diffusion permutation
- the per-layout permutation seeds
- the position whitening seed

## Encryption Pipeline

Per in-alphabet character, the current code performs:

```text
1. Steckerbrett in
2. Plugboard forward using unused keyed layouts
3. N rotor rounds
4. Diffusion through a keyed 95-position permutation
5. Scramble through unused keyed layouts with shifts
6. Plugboard forward again
7. Steckerbrett out
8. Position whitening
```

Decryption reverses those operations in reverse order.

Two implementation details matter:

- characters outside the built-in alphabet pass through unchanged and do not
  advance the rotor register
- because ciphertext is punctuation-heavy, dropping or normalizing even one
  in-alphabet character during transfer can desync the rest of decryption; the
  shipped UI and CLI now warn on suspicious clipboard-normalized punctuation
  and non-ASCII paste damage

## RC.3 Ciphertext Packaging

New ciphertexts begin with:

```text
E3|
```

The encrypted rc.3 body carries:

```text
[len_field:4][plaintext][checksum:10][padding:0..15]
```

Notes:

- `len_field` is a fixed-width base-95 encoding of plaintext length
- `checksum` is a 64-bit value rendered as 10 base-95 characters
- `padding` length is deterministic and keyed:
  `pad_len = hash64(keyStr + "|" + plaintext + "|padlen") mod 16`
- padding characters are generated from a keyed 64-bit PRNG seeded with
  `hash64(keyStr + "|" + plaintext + "|padfill")`

Because the length field and checksum are encrypted with the rest of the body,
an observer no longer learns exact plaintext length from a fixed visible
checksum block. They only learn the ciphertext length bucket, which narrows
plaintext length to a 16-character window.

## Legacy Fallback

Decryptors still accept unheaded `rc.2` ciphertext by:

- locating the visible 10-character checksum at the old key-derived position
- stripping it before decryption
- recomputing the old checksum from recovered plaintext

Encryption no longer emits the legacy format.

## Keygen And Key Strength

Default keygen is now full-random across the valid key format:

- enabled layouts: uniform from `1..10`
- rotors: uniform from `1..13`
- steck pairs: uniform from `0..47`
- user rounds: uniform from `1..999`
- nonce presence: uniform on/off, with a 3-character nonce when present

Built-in strength reporting now separates:

- **key family strength**: theoretical brute-force size for keys of that shape
- **current key profile**: the specific enabled-layout count, rotor count,
  steck count, rounds, and nonce state of the live key

This prevents the old fixed-shape `keygen()` behavior from repeatedly showing
the same `151.5`-bit family metric and looking like a bug.

## Keyspace

At maximum configuration, ENIGMAK's current keyspace is still approximately:

```text
4.528 x 10^128
```

That is about `427` bits.

## Historical Weaknesses And Fixes

The following issues were identified by community review and addressed before
or during the current branch:

- fixed-layout substitution bias was removed by keyed layout permutations
- position-mod-N leakage was reduced by the whitening layer
- the monocharacter oracle was addressed by rotor-state feedback in the
  position offsets
- word-boundary leakage from plaintext spaces was removed in `rc.2`
- the exact-length leak from a visible fixed checksum block was reduced in `rc.3`

## Known Remaining Limits

- Non-ASCII / Unicode is still passthrough in `rc.3`.
- ENIGMAK has not undergone a formal audit.
- Key reuse remains a bad idea.
- Browser execution is less trustworthy than dedicated native or hardware
  environments.
- The checksum is still not authenticated encryption.

## Implementations

The repository currently ships:

- `enigmak.html` - primary browser machine
- `docs/index.html` - mirrored browser copy for publishing
- `enigmak.js` - JavaScript module
- `python/enigmak.py` - Python CLI
- `electron/` - Electron desktop wrapper around the same machine UI

The JS module, Python CLI, and browser implementation are intended to produce
compatible ciphertext for the same key and message.
