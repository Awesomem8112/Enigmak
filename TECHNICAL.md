# ENIGMAK Technical Notes

This document describes the current `v3.0.0-rc.2` design at a high level. It
is meant to complement `SPECIFICATION.md`, not replace it.

## Current RC.2 Snapshot

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
- a 64-bit checksum encoded as 10 base-95 characters

Lowercase letters were added in `rc.1`. Space encryption and the larger
checksum landed in `rc.2`.

## The 95-Symbol Alphabet

The live alphabet is:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./!@#$%^&*()_+{}|:"<>?`~abcdefghijklmnopqrstuvwxyz[space]
```

This gives ENIGMAK a theoretical random IoC floor of `1/95 ~= 0.01053`.

Two consequences matter in practice:

- Mixed-case strings survive encryption intact because lowercase letters are no
  longer folded into uppercase.
- Spaces no longer leak plaintext word boundaries because space is now
  encrypted like any other symbol.

Non-ASCII characters are still outside the cipher alphabet and pass through
unchanged in `rc.2`.

## Keyed Layout Permutations

The ten layout names remain:

```text
QWERTY, Colemak, Colemak-DH, Dvorak, Workman,
Norman, Asset, Halmak, AZERTY, QWERTZ
```

In the current design they are not used as raw ergonomic substitution tables.
Instead, each layout name seeds an independent key-derived permutation of the
full 95-symbol alphabet. This keeps the layout labels stable while removing the
 earlier bias from fixed keyboard-shaped mappings.

## Key Material

The core derived values are:

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

## Rotor Mechanics

The rotor model keeps the Enigma-style idea that state evolves per character,
but most of the mechanics are custom:

- rotor positions are base-95 instead of base-26
- stepping is gated by a key-derived boolean mask
- the combined shift is derived from the entire rotor register
- the current rotor state is hashed back into the next character's offsets

The rotor-state feedback is important. Without it, repeated plaintext under
chosen-plaintext conditions can reveal exploitable cycle structure.

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

Two implementation details are easy to miss:

- characters outside the built-in alphabet pass through unchanged and do not
  advance the rotor register
- the browser UI and module API expect ciphertext to include the embedded
  checksum, so decryption strips the checksum first and verifies it afterward

## Position Whitening

Position whitening was added to break the old periodicity leak caused by the
step mask repeating modulo the alphabet length.

The whitening stream uses a key-derived 32-bit LCG:

```text
state_0 = keySum XOR 0xC0FFEE42
state_n+1 = (state_n * 1664525 + 1013904223) mod 2^32
```

For encryption, `state mod 95` is added to the final symbol index. Decryption
subtracts the same offset first.

This gives every processed position a unique offset and breaks the old
modulo-period correlation.

## The RC.2 Checksum

`rc.2` uses a 64-bit checksum rendered as 10 base-95 characters.

At a high level:

1. Hash `plaintext + "|" + keyStr + "|chk64"` with 64-bit FNV-1a over UTF-8
   bytes.
2. Advance a 64-bit LCG ten times, xoring the loop index into the state before
   each step.
3. Emit one alphabet character per step via `state mod 95`.
4. Insert those 10 characters at a key-derived position inside the ciphertext.

The checksum position is still derived from a 32-bit FNV-1a hash of
`keyStr + "chkpos"`.

This is stronger than the old 4-character checksum, but it is still not the
same thing as researched authenticated encryption.

## Statistical Profile

The live IoC floor is:

```text
1 / 95 ~= 0.01053
```

Very short ciphertexts can legitimately show `0.000000` IoC if no in-alphabet
character repeats. That is expected behavior, not automatically a bug.

On longer messages, ciphertext should sit near the random floor rather than
near natural-language plaintext.

## Keyspace

At maximum configuration, ENIGMAK's current keyspace is approximately:

```text
4.528 x 10^128
```

That is about `427` bits.

This figure includes:

- ordered enabled-layout selection
- rotor layout / position choices
- up to 47 stecker pairs
- the `1-999` user-round input
- the optional built-in 3-character nonce space

## Historical Weaknesses And Fixes

The following issues were identified by community review and addressed before
or during the current branch:

- fixed-layout substitution bias was removed by keyed layout permutations
- position-mod-N leakage was reduced by the whitening layer
- the monocharacter oracle was addressed by rotor-state feedback in the
  position offsets
- word-boundary leakage from plaintext spaces was removed in `rc.2`

## Known Remaining Limits

- Non-ASCII / Unicode is still passthrough in `rc.2`.
- ENIGMAK has not undergone a formal audit.
- Key reuse remains a bad idea.
- Browser execution is less trustworthy than dedicated native or hardware
  environments.
- Authenticated encryption and stronger protocol framing are still future work.

## Implementations

The repository currently ships:

- `enigmak.html` - primary browser machine
- `docs/index.html` - mirrored browser copy for publishing
- `enigmak.js` - JavaScript module
- `python/enigmak.py` - Python CLI
- `electron/` - Electron desktop wrapper around the same machine UI

The JS module, Python CLI, and browser implementation are intended to produce
compatible ciphertext for the same key and message.
