# Test Vectors

These vectors target release candidate `v3.0.0-rc.8`. They are rc.8 ciphertext
outputs even though the runtime API format label remains **`rc.6-stream`** with
hidden metadata version character **`5`**. rc.8 derives all live seeds with the
embedded BLAKE3 hash, so these ciphertexts differ from the rc.7 vectors for the
same key and plaintext even though the wire format is unchanged.

The live alphabet has **162** symbols: 95 legacy printable ASCII characters, 66
European extended characters, plus newline. See `ALPHA` in
`python/enigmak.py` for the exact string.

New `rc.6-stream` ciphertext:

- interleaves encrypted payload, **10** scattered encrypted checksum characters,
  and **44** zero-width carriers in a keyed schedule
- advances cipher state at carrier positions with key-derived phantom wildcards
- has no fixed visible checksum prefix
- does **not** begin with `E3|`

Optional materialized metadata mode keeps the same stream schedule and version
character but emits the 44 carrier events as visible `ALPHA` characters.

Record ciphertext using escaped JSON-style notation or another lossless
representation. Each escaped ciphertext below is a JSON string: decode it before
comparing, and do not include the outer quote characters. Copy paths that strip
zero-width markers break verification. Python interactive encryption copies
exact ciphertext to the system clipboard because manual terminal highlighting
can omit hidden metadata.

The current Python and JavaScript runtimes produce identical ciphertext for
these vectors.

The checksum is computed over the **packed visible payload** (the `H` tag,
length field, plaintext, and padding **before** stream scheduling) using
`deriveMacSubkey(keyStr)`, not over the raw plaintext alone.

## RC8 Stream Vector 1

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"HELLOWORLD"`  
**Plaintext literal:**

```text
HELLOWORLD
```

**Ciphertext (escaped):**

```text
"9\u00ed\u00e9\u00e4\u200c\u200b\u00f6\u200c\u200c\u200c\u2060}\u200b\u00d4\u200b;\u200cH\u200c\u200c\u200b\u00e3_\u200b\u200d\u200c\u2060\u200d\u200c\u200d\u200d\u200c\u200d\u200c\u200b\u200d\u2060]\u00eb\u00f6\u200b\u00c9YJ\u00c0\u200c\u200c\u00fe\u200b&\u00d3\u200b\u2060\u200c\u200d\u200b\u2060S\u200dn\u200cU\u200c\u200b\u200d\u00ee\u200d\u2060\u200b\u00cb\u00d4"
```

**Visible body (escaped):** `"9\u00ed\u00e9\u00e4\u00f6}\u00d4;H\u00e3_]\u00eb\u00f6\u00c9YJ\u00c0\u00fe&\u00d3SnU\u00ee\u00cb\u00d4"`  
**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

**Materialized ciphertext (escaped):**

```text
"9\u00ed\u00e9\u00e4\u00c9\u00e8\u00f6\u00d9\u00c5=o}D\u00d4\u00fa;?H\u00f9$\u00e2\u00e3_|@MEgX7\u00e8N+;-\"\u00c9]\u00eb\u00f6\u00fe\u00c9YJ\u00c0z\u00d3\u00fez&\u00d3,\u00a1H\\\u00c8YS\u00e2n\u00e0U\u00daxm\u00ee\u00d9~P\u00cb\u00d4"
```

**Expected runtime format label:** `rc.6-stream (materialized)`

## RC8 Stream Vector 2

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:**

```json
"UPPER lower [] {} `~ with spaces and words"
```

**Plaintext literal:**

```text
UPPER lower [] {} `~ with spaces and words
```

**Ciphertext (escaped):**

```text
"\u200c\u200bD\u200c\u200c\u200c\u00f6\u2060\u200b$o\u200b\u00ec\u00d1\u200dw{'\u200c\u00ce\u00d2\u200b\u200c\u200b:\u200c\u2060r\u00e2Y'\u200d\u200b^\u200d\u200d\u00cc\u2060\u00a1\n\u200dM\u00c2\u00da\u00dca\u200bx\u00d0s\u200cW-\u200b\u00da\u00d5\u00e0\u200c\u200c23U\u200c\u200b\u200d,t\u200b\u200d\u00f8\u00bf\u200d]\u200d\u2060J\u00d0q\u200d\u200d\u00cb\u200cD\u2060\u00d1;\u00c9\u20606+7\u00f5[\u200bDz\u200c\u00db\u00cc\u01539\u200d\u200c\u200c\u00c1R=\u00d63"
```

**Visible body (escaped):** `"D\u00f6$o\u00ec\u00d1w{'\u00ce\u00d2:r\u00e2Y'^\u00cc\u00a1\nM\u00c2\u00da\u00dcax\u00d0sW-\u00da\u00d5\u00e023U,t\u00f8\u00bf]J\u00d0q\u00cbD\u00d1;\u00c96+7\u00f5[Dz\u00db\u00cc\u01539\u00c1R=\u00d63"`  
**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

## RC8 Stream Vector 3

**Key:** `K6:1 102103 0 050`  
**Plaintext JSON:** `"Hello World"`  
**Plaintext literal:**

```text
Hello World
```

**Ciphertext (escaped):**

```text
"J\u200b\u20609\u00fb\u200b\u200b\u00d9\u200b2 \u200c\u00ee\u00c2\u200d\u200d\u00c5.\u200c\u200d\u200d\u200d\u2060\u200c\u00d4\u200b\u00df{\u2060\u200b\u2060$\u200d\u00d5\u2060\u200b\u00ca\u2060\u200b\u200c\u2060\u200b\u200dV\u200c\u2060%t\u200b\u00eb\u2060]\u00c5\u2060\u200cb\u200b\u00cd\u200c\u200bKv\u2060\u00ec\u200c\u200c\u200d\u200b\u200cs\u200d\u200d"
```

**Visible body (escaped):** `"J9\u00fb\u00d92 \u00ee\u00c2\u00c5.\u00d4\u00df{$\u00d5\u00caV%t\u00eb]\u00c5b\u00cdKv\u00ecs"`  
**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

## RC8 Stream Vector 4

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"Line one\nLine two"`  
**Plaintext literal:**

```text
Line one
Line two
```

**Ciphertext (escaped):**

```text
"\u00d4\u00dd\u00fc\u200c\u200bH*\u200c\"\u00fd\u200c\u200cv\u200c\u200b2\u200b\u200d\u2060\u2060Z\u00dd\u200b\u200d\u200c\u200c\u00dc\u2060\u00e8\u200c\u200c\u200c\u2060\u200c\u00ce\u200d\u200d:\u200b\u00d0\u00fb\u200c\u2060\u00cb\u200c\u200c\u200bp\u200d\u2060{\u200d\u00fc\u200c?\u00e5\u00f6\u200b?\u00d3\u200c\u00f9 \u00ca\u2060\u200cw\u200c\u200d\u00e1\u00d2\u200b\u200d\u200b\u200c\u200c"
```

**Visible body (escaped):** `"\u00d4\u00dd\u00fcH*\"\u00fdv2Z\u00dd\u00dc\u00e8\u00ce:\u00d0\u00fb\u00cbp{\u00fc?\u00e5\u00f6?\u00d3\u00f9 \u00caw\u00e1\u00d2"`  
**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

## Legacy RC.3 Compatibility Check

Decryptors must still accept headed `rc.3` ciphertext.

**Key:** `123 100200 0 050`  
**Ciphertext:** `E3|1]Qfw?Q{GF-#+nKPJlPm$w6H*R-'6^gk,[kLm+`  
**Expected plaintext:** `Hello World`  
**Expected format detection:** `rc.3`

## Legacy RC.2 Compatibility Check

Decryptors must still accept old unheaded ciphertext.

**Key:** `123 100200 0 050`  
**Legacy ciphertext:** `b$\.:j53ZHekRX~u.I#%)`  
**Expected plaintext:** `Hello World`  
**Expected format detection:** `rc.2-legacy`

## Legacy RC.4-Hidden Note

`rc.4-hidden` vectors from earlier release candidates remain valid regression
tests for decrypt-only compatibility. New interoperability vectors in this file
target **`rc.6-stream`** emit paths only.

## Legacy v2.0.0 Compatibility Note

Original v2.0.0 Python and JavaScript ciphertext should decrypt through the
dedicated `v2.0.0-legacy` path. That path is additive and must not change current
stream-format detection.

## Verification Checklist

A correct `v3.0.0-rc.8` implementation must:

1. Produce the exact `rc.6-stream` ciphertext above for the same plaintext and key.
2. Emit new ciphertext without a visible `E3|` header.
3. Preserve exactly `44` hidden carrier symbols on new messages.
4. Scatter exactly `10` encrypted checksum characters in the stream schedule.
5. Fail verification with the generic public error `Decryption failed.` when
   carriers, checksum symbols, or visible payload symbols are removed or reordered.
6. Confirm the first three visible ciphertext characters are not a fixed checksum
   prefix and differ for different plaintexts under the same key.
7. Confirm the first three visible ciphertext characters differ for the same
   plaintext under different keys.
8. Decrypt freshly encrypted zero-width and materialized ciphertext exactly.
9. Continue decrypting the rc.4-hidden path, the rc.3 sample, the rc.2 sample,
   and original v2.0.0 legacy fixtures correctly.
10. Preserve zero-width markers during copy, file export, and cross-runtime
    transport, or use materialized metadata with the same receiver setting.
11. Compute the current checksum from the packed visible payload using
   `deriveMacSubkey(keyStr)` and version `5`.
12. Interoperate both ways between Python and JavaScript for `rc.6-stream`.
13. Keep failure-path corruption buffers fixed at exactly 4096 characters.
14. Generate default random keys with at least `256` family bits.
15. Advance cipher state with key-derived phantom characters at all `44`
    zero-width carrier positions.
16. Derive all live seeds with the embedded BLAKE3 hash. Validate the BLAKE3
    `hash` mode against the official BLAKE3 `test_vectors.json` (empty, short,
    and multi-chunk inputs) in each implementation, and confirm `hash_str64` /
    `hash_str32` return the first 8 and 4 digest bytes as big-endian unsigned
    integers identically across Python, JavaScript, browser, and Electron.
17. Fail closed (generic `Decryption failed.`) when given rc.7-produced
    `rc.6-stream` ciphertext under the same key, since seed derivation changed.
