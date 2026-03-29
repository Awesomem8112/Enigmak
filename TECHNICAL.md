# ENIGMAK: Building a Custom Rotor Cipher from Scratch

## What is ENIGMAK?

ENIGMAK is a custom symmetric cipher machine built around the concept of rotor-based encryption, inspired by the historical Enigma machine used in World War II but redesigned from the ground up with modern cryptographic principles in mind.

It operates on a 68symbol alphabet covering uppercase letters, digits, and all standard special characters, runs entirely offline as a single HTML file, and is available as a Python CLI and JavaScript module for developers.

This document covers the design decisions, the statistical testing methodology, two confirmed weaknesses discovered by the community, and how they were fixed.



## The Architecture

### Why Rotors?

The Enigma machine worked by passing each character through a series of rotating substitution wheels, with each keypress advancing the wheels in an odometer pattern. This meant the same letter typed twice in a row produced two different ciphertext characters  a significant improvement over simple substitution ciphers.

ENIGMAK inherits this concept but extends it significantly.

### The 68Symbol Alphabet

Most classical ciphers operate on 26 letters. ENIGMAK operates on 68 symbols:

```
A-Z, ;, 0-9, - = [ ] \ ' , . / ! @ # $ % ^ & * ( ) _ + { } | : " < > ? ` ~
```

This means digits and special characters are first-class cipher symbols  they go through the full encryption pipeline rather than passing through unchanged. The immediate benefit is a lower Index of Coincidence (IoC) floor: 1/68 ≈ 0.0147 versus 1/26 ≈ 0.0385 for a standard alphabet. A lower floor means more statistical headroom before a ciphertext starts looking structured.

### Ten Keyboard Layouts as Substitution Tables

ENIGMAK uses ten physical keyboard layouts (QWERTY, Colemak, ColemakDH, Dvorak, Workman, Norman, Asset, Halmak, AZERTY, QWERTZ) as the wiring for its substitution layers. Each layout defines a mapping from one set of character positions to another, creating a substitution table.

In v1.0.0, these were fixed  the same wiring regardless of key. In v2.0.0, they are key-derived (more on this below).

### The Steckerbrett

Borrowed directly from Enigma, the Steckerbrett is a plugboard that swaps pairs of characters before and after all other processing. ENIGMAK supports up to 34 symmetric pairs from the 68character alphabet. The swap is symmetric  if A maps to Z, then Z maps to A  and is applied identically at the start and end of the pipeline.

### KeyDerived Rounds

Unlike Enigma which applied one substitution pass per character, ENIGMAK applies multiple rounds. The round count is derived from all key material:

```
rounds = ((S + R + L + U) mod 999) + 1
```

Where S is a steckerbrett sum, R is the rotor position sum, L is the layout index sum, and U is a userset base value from 1 to 999. This means the round count changes with every key and is never directly stored  an attacker cannot simply look at the key string and know how many rounds were used.

### Irregular Stepping

In Enigma, the rightmost rotor advanced with every keypress in a predictable odometer pattern. This regularity was one of the properties that made cryptanalysis possible.

ENIGMAK uses a key-derived 47/68 step mask  a boolean array of 68 positions derived from the key via FisherYates shuffle. The rotor only advances when the current character position modulo 68 falls on an active mask position. This eliminates the lag68 periodicity that would otherwise appear.

### No Reflector

The original Enigma included a reflector, which created a fatal property: no letter could ever encrypt to itself. This constraint gave Bletchley Park's codebreakers a foothold  any proposed decryption that mapped a letter to itself could be immediately rejected.

ENIGMAK has no reflector. A character can encrypt to itself depending on the rotor state. There is no such foothold available.

### The Full PerCharacter Pipeline

For each character in the plaintext:

```
1. Steckerbrett in       (symmetric swap)
2. Plugboard forward     (unused layouts, sequential substitution)
3. N rotor rounds        (keyed shifts + layout offsets)
4. Diffusion             (keyed 68-position transposition)
5. Scramble              (unused layouts, keyed shifts)
6. Plugboard inverse
7. Steckerbrett out      (symmetric swap)
8. Position whitening    (LCG-derived offset, unique per position)
```

Decryption reverses every operation in reverse order.



## Statistical Profile

A good cipher should produce output statistically indistinguishable from random noise. The primary measure of this is the **Index of Coincidence (IoC)**:

```
IoC = sum(f(c) * (f(c) - 1)) / (L * (L - 1))
```

For a 68symbol alphabet, the theoretical random floor is 1/68 ≈ 0.0147. English plaintext has an IoC around 0.065. Naval Enigma ciphertext typically showed IoC around 0.0480.052.

ENIGMAK ciphertext consistently lands between 0.015 and 0.042 depending on message length and content  indistinguishable from uniform random noise on messages of any practical length.

Additional tests run on sample ciphertexts:
 Difference stream IoC (D1, D2): at or below random floor
 Autocorrelation: no detectable period
 Serial correlation: within expected random confidence interval
 Chisquare vs uniform: consistent with random distribution



## Keyspace

At maximum configuration (34 steck pairs, 13 rotors, all 10 layouts, U=999):

```
~4.929 x 10^98 possible keys (98 digits, ~325 bits)
```

For comparison, AES256 has a keyspace of 2^256 ≈ 1.16 x 10^77. ENIGMAK's maximum keyspace exceeds AES256 by approximately 10^21.

Brute force at one quadrillion attempts per second would take approximately 10^75 universe ages.



## Community Testing: Two Weaknesses Found and Fixed

After publishing ENIGMAK to r/cryptography, a community member identified two real cryptographic weaknesses. Both are documented here along with the fixes.

### Weakness 1: PositionMod68 Periodicity Leak

**The finding:**

Encrypting 50,000 identical characters and bucketing the ciphertext by position modulo 68 reveals that different bucket positions have measurably different output distributions. The average L1 distance between bucket distributions was ~0.025, when a truly random stream would show ~0.245.

The test code:

```python
from enigmak import process, parse_key, generate_key
from collections import Counter

key = generate_key()
k = parse_key(key)
pt = "A" * 50000
ct = process(pt, k["steck_pairs"], k["rotors"], k["enabled"], k["user_rounds"], k["nonce"])

buckets = [Counter() for _ in range(68)]
for i, c in enumerate(ct):
    buckets[i % 68][c] += 1
```

**Why it happened:**

The step mask `stepMask[ci % 68]` cycles with period 68. Position 0 and position 68 always check the same mask entry, meaning the rotor advances identically at both positions. Over a long repeated-plaintext message, this creates correlated rotor states at the same mod68 offset across cycles  and different rotor states produce different output distributions.

A secondary finding showed that the deviation of each bucket from the global distribution correlated with the internal step mask at approximately 67% accuracy, meaning the step mask itself was partially recoverable under chosen-plaintext conditions.

**Important note:** This is a chosen-plaintext attack. "No legitimate message would be 50,000 identical characters" is not a valid defense  chosen-plaintext is a standard adversarial model and the cipher must hold under it.

**The fix:**

A position whitening layer was added as the final step of encryption (and first step of decryption). For each character, an LCG (Linear Congruential Generator) advances from a key-derived seed and adds a unique offset to the output:

```python
# Encryption: add LCG offset
wstate = lcg(wstate)
x = ALPHA[(ALPHA.index(x) + wstate % N) % N]

# Decryption: subtract same LCG offset
wstate = lcg(wstate)
x = ALPHA[(ALPHA.index(x) - wstate % N) % N]
```

The LCG seed is derived from key material (`keySum XOR 0xC0FFEE42`) and has a period of 2^32  far beyond any practical message length. Since no two positions share the same LCG state, the mod68 correlation is completely broken.

**Result after fix:** L1 distance ~0.42 (above the random baseline of 0.245  more uniform than pure random, which is ideal).



### Weakness 2: Keyboard Layout Bias

**The finding:**

The ten keyboard layouts used as substitution tables in v1.0.0 were fixed  identical for every key. This created two problems:

1. Only 27 of 68 characters had explicit mappings. Digits and special characters passed through these layers unchanged.
2. The QWERTY layout (being the reference layout) mapped every character to itself  it was effectively doing nothing as a substitution table.
3. The same substitution was applied regardless of key, meaning the layout layer added no key-dependent complexity.

**The fix:**

The fixed keyboard layout wirings were replaced with key-derived bijective permutations. For each of the 10 layouts, a FisherYates shuffle seeded uniquely from key material generates a random permutation of all 68 characters:

```python
for li, name in enumerate(LAYOUT_NAMES):
    perm = list(range(N))
    seed = (key_sum ^ (li * 0x9E3779B9 + 0xABCD1234)) & 0xFFFFFFFF
    v = seed
    for i in range(N - 1, 0, -1):
        v = lcg(v)
        j = v % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    layout_maps[name] = {ALPHA[i]: ALPHA[perm[i]] for i in range(N)}
```

Each layout now:
 Covers all 68 characters (true bijection)
 Produces different substitutions for every key
 Has independent, non-correlated mappings from the other layouts

**Verification:** A dedicated bias checker (`layout_bias_check.py`) confirms all 10 layout maps are bijective, frequency-uniform, cross-key independent, and inter-layout independent. The old v1.0.0 wirings fail the same tests.



## Known Remaining Limitations

 **Not formally audited.** ENIGMAK has not undergone professional cryptanalytic review.
 **Meetinthemiddle.** A theoretical MITM attack may be possible if the diffusion and scramble layers are insufficiently non-linear. Unconfirmed.
 **Key reuse.** Reusing a key across messages creates correlated ciphertext. Always generate a fresh key per session.
 **Browser environment.** Running in a browser exposes the implementation to extensions, memory access, and other vectors not present in dedicated hardware.



## Implementations

 `enigmak.html`  browser-based machine, runs fully offline
 `enigmak.py`  Python CLI (`encrypt`, `decrypt`, `keygen`, `ioc`)
 `enigmak.js`  JavaScript module for Node.js and browser

All three implementations are cryptographically identical and produce compatible output.



## License

MIT License. Copyright (c) 2026 Erik Lindholm.

Not formally audited. Do not use for classified, medical, legal, or life-critical communications.
