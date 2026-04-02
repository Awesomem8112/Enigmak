# Test Vectors

These known plaintext/ciphertext pairs allow implementers to verify correctness
against the v2.0.0 cipher implementation.

All vectors use the 68-character alphabet:
`ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./'!@#$%^&*()_+{}|:"<>?`~`

The ciphertext values below include the 4-character checksum embedded at the
key-derived position. Strip the checksum before decrypting.

---

## Vector 1

**Key:** `01 002103 0 013`
**Plaintext:** `HELLOWORLD`
**Ciphertext (with checksum):** `ON>}O!41"U},?I`
**Checksum position:** 0
**Note:** QWERTY and Colemak enabled. 2 rotors. No steck pairs. No nonce.

---

## Vector 2 - Special characters

**Key:** `123 100200 0 050`
**Plaintext:** `TEST1TEST2TEST3`
**Ciphertext (with checksum):** `&E1R2=ZG*QPS6I~<(B5`
**Checksum position:** 8
**Note:** Tests digit and letter mixing. Colemak, Colemak-DH, Dvorak enabled.

---

## Vector 3 - Full alphabet stress

**Key:** `5197 532907956112537115750740926542 0032016302350359042305310664071708410915105511141237135016391866194820542136224424422543264927452829303433573856406246534767516152586065 041 535917`
**Plaintext:** `TEST1TEST2TEST3TEST4TEST5TEST6TEST7TEST8TEST9TEST10`
**Ciphertext (with checksum):** `` `>?R:TMJS7FK6|)O2ZV>&U;IL2(.8O?N8(M7$G9~+N}G]9=Q4M;<{>, ``
**Checksum position:** 12
**Note:** 34 steck pairs, 10 rotors, nonce active. Maximum configuration stress test.

---

## Generating Vectors

Run from the `python/` folder:

```bash
python enigmak.py encrypt "PLAINTEXT" "KEY STRING"
```

Or load `enigmak.html` in a browser, configure the key, encrypt the plaintext,
and record the full output including checksum.

## Verification

A correct v2.0.0 implementation of ENIGMAK must:

1. Produce identical ciphertext for identical plaintext + key + nonce
2. Decrypt its own output back to the original plaintext
3. Strip exactly 4 checksum characters from the key-derived position before decrypting
4. Produce IoC close to 0.0147 (the 1/68 floor) on sufficiently long ciphertexts
5. Pass all five tests in `python/layout_bias_check.py`
