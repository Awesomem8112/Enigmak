# Test Vectors

These plaintext / ciphertext pairs target the current `v3.0.0-rc.3`
implementation.

All vectors below use the live 95-symbol alphabet:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./!@#$%^&*()_+{}|:"<>?`~abcdefghijklmnopqrstuvwxyz[space]
```

New ciphertexts begin with `E3|`. In `rc.3` the encrypted body contains:

- a 4-character base-95 plaintext length field
- the plaintext
- a 10-character 64-bit checksum
- 0 to 15 deterministic keyed padding characters

Those fields are encrypted together. There is no visible checksum position in
the new format.

## RC.3 Vector 1

**Key:** `01 002103 0 013`  
**Plaintext:** `HELLOWORLD`  
**Ciphertext:** `E3|@Q="`sGeh,VJlPIG*Y-I|+V_O\^Vxxlo^n`  
**Notes:** Minimal uppercase-only regression vector. No steck pairs. No nonce.

## RC.3 Vector 2

**Key:** `123 100200 0 050`  
**Plaintext:** `Hello World`  
**Ciphertext:** `E3|1]Qfw?Q{GF-#+nKPJlPm$w6H*R-'6^gk,[kLm+`  
**Notes:** Exercises lowercase preservation and encrypted space handling.

## RC.3 Vector 3

**Key:** `0538 556031042 2571315441866775 013 412715`  
**Plaintext:** `Hello there General Kenobi`  
**Ciphertext:** `E3|P!T`0zq%^+!>/e_'C!p0I[ Bq?<{3,8#%]RJF\/Kq6?enT1`  
**Notes:** Exercises lowercase, multiple spaces, steck pairs, and nonce use.

## RC.3 Vector 4

**Key:** `1234056789 100201302403004505606707808909110211312 00800181028203830484058506860787088809891090119112921393149415751676177718781979206021612262236324642565266627672868296930703171327233733474355536563757385839594054415342524351445045494648 326 934460`  
**Plaintext:** `Hello World`  
**Ciphertext:** `E3|w<4_dTt@7sc_i_7%7s@6K{AyOm@mdk0w)|V`  
**Notes:** Large-key regression vector used during `rc.3` validation.

## Legacy RC.2 Compatibility Check

Decryptors must still accept old unheaded ciphertext.

**Key:** `123 100200 0 050`  
**Legacy ciphertext:** `b$\.:j53ZHekRX~u.I#%)`  
**Expected plaintext:** `Hello World`  
**Expected format detection:** `rc.2-legacy`

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
4. Record the full `E3|...` ciphertext exactly as shown.

## Verification Checklist

A correct `v3.0.0-rc.3` implementation must:

1. Produce the exact ciphertext above for the same plaintext and key.
2. Prefix new ciphertext with `E3|`.
3. Decrypt the rc.3 body into length field, plaintext, checksum, and padding.
4. Verify checksum and padding successfully for valid rc.3 messages.
5. Still decrypt the legacy rc.2 sample correctly when no `E3|` header is present.
6. Produce ciphertext IoC near the `1/95 ~= 0.01053` floor on sufficiently long
   random-looking outputs.

Short ciphertexts may legitimately show `0.000000` IoC if no in-alphabet
character repeats.
