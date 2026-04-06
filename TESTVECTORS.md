# Test Vectors

These plaintext / ciphertext pairs target the current `v3.0.0-rc.2`
implementation.

All vectors below use the live 95-symbol alphabet:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./!@#$%^&*()_+{}|:"<>?`~abcdefghijklmnopqrstuvwxyz[space]
```

The ciphertext values below already include the embedded checksum. In `rc.2`
that checksum is:

- 64-bit
- encoded as 10 base-95 characters
- inserted at a key-derived position

## Vector 1

**Key:** `01 002103 0 013`  
**Plaintext:** `HELLOWORLD`  
**Ciphertext (with checksum):** `igmI{^8|?vR0W,lWpGzx`  
**Checksum position:** `0`  
**Notes:** Minimal uppercase-only regression vector. No steck pairs. No nonce.

## Vector 2

**Key:** `123 100200 0 050`  
**Plaintext:** `Hello World`  
**Ciphertext (with checksum):** `b$\.:j53ZHekRX~u.I#%)`  
**Checksum position:** `9`  
**Notes:** Exercises lowercase preservation and encrypted space handling.

## Vector 3

**Key:** `0538 556031042 2571315441866775 013 412715`  
**Plaintext:** `Hello there General Kenobi`  
**Ciphertext (with checksum):** ``oP1[(&v}3J'l=:!}g/e[vuNr'y%g`G+"bNdT``  
**Checksum position:** `19`  
**Notes:** Exercises lowercase, multiple spaces, steck pairs, and nonce use.

## Vector 4

**Key:** `1234056789 100201302403004505606707808909110211312 00800181028203830484058506860787088809891090119112921393149415751676177718781979206021612262236324642565266627672868296930703171327233733474355536563757385839594054415342524351445045494648 326 934460`  
**Plaintext:** `Hello World`  
**Ciphertext (with checksum):** ``{/lyID`=zrW,jH0i7L'x\``  
**Checksum position:** `5`  
**Notes:** Large-key regression vector used during `rc.2` validation.

## Generating Vectors

Python:

```bash
python python/enigmak.py encrypt "PLAINTEXT" "KEY STRING"
```

JavaScript:

```bash
node -e "const m=require('./enigmak.js'); console.log(m.encrypt('PLAINTEXT','KEY STRING'))"
```

Browser:

1. Open `enigmak.html`.
2. Import or construct the key.
3. Encrypt the plaintext.
4. Record the full ciphertext including the embedded checksum.

## Verification Checklist

A correct `v3.0.0-rc.2` implementation must:

1. Produce the exact ciphertext above for the same plaintext and key.
2. Remove exactly 10 checksum characters from the key-derived position before
   decryption.
3. Recover the original plaintext and report checksum verification success.
4. Preserve lowercase and spaces in recovered plaintext.
5. Produce ciphertext IoC near the `1/95 ~= 0.01053` floor on sufficiently long
   random-looking outputs.

Short ciphertexts may legitimately show `0.000000` IoC if no in-alphabet
character repeats.
