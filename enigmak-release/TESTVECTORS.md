# Test Vectors

These known plaintext/ciphertext pairs allow implementers to verify correctness.

All vectors use the 68-character alphabet:
`ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./'!@#$%^&*()_+{}|:"<>?`~`

---

## Vector 1

**Key:** `1234 102031 0026081501040715 013`
**Plaintext:** `HELLOWORLD`
**Note:** No nonce, no steck pairs beyond the key defaults

---

## Vector 2 — Special characters

**Key:** `123 100200 0 050`
**Plaintext:** `TEST1TEST2TEST3`
**Note:** Tests digit and letter mixing

---

## Vector 3 — Full alphabet stress

**Key:** `5197 532907956112537115750740926542 0032016302350359042305310664071708410915105511141237135016391866194820542136224424422543264927452829303433573856406246534767516152586065 041 535917`
**Plaintext:** `TEST1TEST2TEST3TEST4TEST5TEST6TEST7TEST8TEST9TEST10`
**Expected ciphertext:** `QEV/;]V0+OK&` *(plus 4-char checksum at key-derived position)*
**Note:** 34 steck pairs, 10 rotors, nonce active

---

## Generating Vectors

Load `enigmak.html` in a browser, configure the key, encrypt the plaintext, and record the output. The checksum position is key-derived and will vary per key.

## Verification

A correct implementation of ENIGMAK must:
1. Produce identical ciphertext for identical plaintext + key + nonce
2. Decrypt its own output back to the original plaintext
3. Produce IoC ≈ 0.0147 on sufficiently long ciphertexts
