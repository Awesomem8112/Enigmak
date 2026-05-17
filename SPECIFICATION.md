# ENIGMAK v3.0.0-rc.5 Formal Specification

## 1. Overview

ENIGMAK is a symmetric, stateful, character-by-character
substitution-permutation rotor cipher operating over a 95-symbol ASCII
alphabet. Release candidate `v3.0.0-rc.5` emits new ciphertext in the
`rc.4-hidden` format, which combines:

- a steckerbrett
- keyed layout permutations
- multi-round shifted substitution
- keyed diffusion
- rotor-state feedback
- position whitening
- a visible encrypted payload body
- hidden encrypted metadata carrying version + checksum

## 2. Alphabet

The alphabet `Sigma` is:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./!@#$%^&*()_+{}|:"<>?`~abcdefghijklmnopqrstuvwxyz[space]
```

`N = 95`

Characters not in `Sigma` pass through unchanged and do not advance the rotor
state.

## 3. Layout Labels

The implementation uses ten stable layout labels:

```text
0 QWERTY
1 Colemak
2 Colemak-DH
3 Dvorak
4 Workman
5 Norman
6 Asset
7 Halmak
8 AZERTY
9 QWERTZ
```

In the current core, each label seeds an independent key-derived permutation of
the full alphabet rather than acting as a fixed ergonomic substitution table.
The reserved static layout definitions cover all printable keyboard rows for
future tooling, but they do not alter the active keyed permutation path.

## 4. Key Format

A key has four required sections and one optional nonce section:

```text
[enabled] [rotors] [steck] [U] [nonce?]
```

- `enabled`: ordered sequence of distinct layout digits from `0..9`
- `rotors`: groups of `[layoutDigit][position:2 digits]`
- `steck`: `0` or sorted groups of `[charA:2 digits][charB:2 digits]`
- `U`: base rounds `001..999`
- `nonce`: optional three-character nonce encoded as 2-digit alphabet indices

Example default HTML key:

```text
0 000 0 001
```

## 5. Derived Quantities

Let:

- `S` = normalized stecker sum
- `R` = rotor position sum
- `L` = enabled-layout index sum
- `U` = user rounds

The live round count is:

```text
rounds = ((S + R + L + U) mod 999) + 1
```

The current-path key sum is:

```text
keySum = (S*31 + R*17 + L*13) mod 2^64
```

Current `rc.4-hidden` derivation uses 64-bit state for:

- rotor-state hashing
- step-mask seeding
- diffusion permutation seeding
- per-layout permutation seeding
- whitening stream seeding
- hidden metadata scatter / carrier mapping seeds

Legacy `rc.3` and `rc.2` decrypt compatibility retains their historical
32-bit derivation path only for decoding old ciphertext.

## 6. Encryption Pipeline

For each in-alphabet character, the current core applies:

```text
1. Steckerbrett in
2. Plugboard forward through unused keyed layouts
3. rounds keyed rotor/layout substitutions
4. Keyed 95-position diffusion permutation
5. Scramble through unused keyed layouts
6. Plugboard forward again
7. Steckerbrett out
8. Position whitening offset
9. Rotor advancement (controlled by the irregular step mask)
```

## 7. RC.4 Packaging

### 7.1 Visible payload

Before visible encryption, new messages are packed as:

```text
[format_tag:1][len_field:4][plaintext][padding:1..16]
```

- `format_tag` is the internal visible tag for the hidden format
- `len_field` is a 4-character base-95 plaintext length field
- `padding` is deterministic keyed padding

Padding length depends on:

```text
plaintext + keyStr + checksum + version
```

New messages always emit at least one visible padding character.

### 7.2 Hidden payload

Hidden metadata is packed as:

```text
[version:1][checksum:10]
```

- `version` is the current format version character
- `checksum` is a 64-bit keyed checksum rendered as 10 base-95 characters

The hidden payload is encrypted by continuing the same cipher state directly
after the visible payload.

### 7.3 Zero-width carrier encoding

Each encrypted hidden metadata character is encoded into four base-4 digits,
then mapped through a keyed permutation of:

```text
U+200B  U+200C  U+200D  U+2060
```

Because there are 11 hidden metadata characters, every new ciphertext carries:

```text
11 * 4 = 44
```

zero-width carrier symbols.

Those carriers are scattered across the visible ciphertext using a keyed
64-bit PRNG.

## 8. Decryption Order

Decryptors must attempt formats in this order:

1. headed `rc.3` (`E3|...`)
2. hidden `rc.4`
3. legacy `rc.2`

### 8.1 RC.3 path

If visible ciphertext begins with `E3|`, decryptors must:

- remove the header
- decrypt the body with the legacy `rc.3` path
- parse `[len_field][plaintext][checksum][padding]`
- verify checksum and padding

### 8.2 RC.4-hidden path

Otherwise, decryptors must:

1. strip zero-width carriers from visible ciphertext
2. decrypt the visible body with the current 64-bit path
3. parse `[format_tag][len_field][plaintext][padding]`
4. if the visible payload parses as current hidden format:
   - require exactly 44 hidden carriers
   - decode hidden carriers back into 11 encrypted metadata characters
   - continue cipher-state decryption of hidden metadata
   - verify version, checksum, and padding

If the visible body parses as current hidden format but hidden carriers are
missing, implementations record the internal reason, corrupt and clear any
partial plaintext, and return the generic public error:

```text
Decryption failed.
```

### 8.3 RC.2 legacy fallback

If neither `rc.3` nor `rc.4-hidden` apply, decryptors fall back to the legacy
visible-checksum `rc.2` path:

- locate the old checksum insertion position
- remove 10 visible checksum characters
- decrypt the stripped body with the legacy path
- recompute and compare the legacy checksum

## 9. Key Generation

Default key generation must avoid fixed-shape output while rejecting weak
families.

The generator therefore repeatedly:

1. samples `enabledCount`, `rotorCount`, `steckCount`, and `noncePresent`
   randomly from their allowed ranges, or from caller-supplied constraints
2. samples concrete layouts, rotors, stecker pairs, rounds, and nonce values
   uniformly inside that profile
3. computes the resulting key-family strength
4. accepts the key only if it has at least `213.5` family bits

If caller-supplied constraints make that floor impossible, key generation must
fail rather than return a weak key.

## 10. Diagnostics

Implementations should report:

- hidden carrier count
- suspicious clipboard-normalized punctuation
- control-character presence in ciphertext
- generic decryption failure without exposing verification details
- exact hidden carrier count for current ciphertext

## 11. Failure Hygiene

On failed verification, implementations must not return or display partial
plaintext. They should:

- return the public error `Decryption failed.`
- blank public plaintext fields
- corrupt an internal fixed-length buffer of exactly 4096 characters
- corrupt accessible key material and cipher state before returning
- clear browser/Electron decrypt output fields before attempting decrypt work,
  and write plaintext back only after explicit verification success

This is a local failure-handling rule. It does not make the checksum equivalent
to AEAD.

## 12. Python CLI Input Modes

The Python CLI preserves positional arguments and also supports shell-safe
ciphertext input:

- `decrypt --from-clipboard KEY`
- `ioc --from-clipboard`
- `interactive`
- bare `python enigmak.py`, which starts interactive mode

Interactive encryption must copy the exact ciphertext to the system clipboard
when possible. This is required because manual terminal highlighting can omit
zero-width metadata.

## 13. Limits

- Non-ASCII / Unicode characters remain passthrough.
- The checksum is an integrity signal, not authenticated encryption.
- ENIGMAK is not formally audited.
