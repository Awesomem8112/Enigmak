# Test Vectors

These vectors target release candidate `v3.0.0-rc.7`. They are RC7 ciphertext
outputs even though the runtime API format label remains **`rc.6-stream`** with
hidden metadata version character **`5`**.

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

## RC7 Stream Vector 1

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"HELLOWORLD"`  
**Plaintext literal:**

```text
HELLOWORLD
```

**Ciphertext (escaped):**

```text
"\u200d\u00f3\u200c\u200d\u200d\u200c\u200b\u2060\u2060Q\u200d?\u00c9H\u2060\u200cQ\u2060\u00ee\u200b\u200d\u200b:b5\u200c\u200b\u200b\u00cf\u200d\u200c\u200b\u200b\u200dn\u2060\u200c\u200d\u00f2f\"\u00e5\u00e70\u200d\u2060\u00f1qm\u200d\u2060\u00cf\u200d\u200cC\u200d\u200c\u00f0\u200b\u200c\u00d5\u00f0\u200d\u00c6\u200dX\u200b\u200b\u200d\u200b\u200d\u200b"
```

**Visible body (escaped):** `"\u00f3Q?\u00c9HQ\u00ee:b5\u00cfn\u00f2f\"\u00e5\u00e70\u00f1qm\u00cfC\u00f0\u00d5\u00f0\u00c6X"`  
**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

**Materialized ciphertext (escaped):**

```text
"B\u00f3*\u00f8xFHA\u00c1Q\u00e2?\u00c9Hh\u0153Q@\u00eeW@a:b5\u00d6<@\u00cf\n8\u00fd\u00c7#n*\u00f1&\u00f2f\"\u00e5\u00e70v\u00c1\u00f1qm[\u00ff\u00cfZ^C!\u00cd\u00f01E\u00d5\u00f0\"\u00c6oX\u00d3r;\u00dbu\u00ff"
```

**Expected runtime format label:** `rc.6-stream (materialized)`

## RC7 Stream Vector 2

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
"\u00e8\u200dA\u200c\u00e1eV%\u200d\u200dY\u200b\u200d\u00cfV\u200d\u00ee\u00ecR\u00dba\u00f5\u200d\u00f1\u00f5\u200d\u00d95\u200b\u200c\u00d2\u00fb\u200c\u00db\u200d\u00fb\u00ed\u200d\u200d\u2060%6\u200be\u200b.(;\u200dmj\u200by\u00c2B8\u00ed\u00c6\u200b\u200c\u200b\u200d\u200d&\u200do\u200d\u200c\u00f0[\u00ff\u200c\u200cza\u200d\u200b_\u200c\u200c\u200dO\u200b\u200b\u00d2\u200c\u00fb\u00f9\u200b2\u00c8\u200cs\u200d3F\u00eb\u00ec\u2060\u2060\u200d"
```

**Visible body (escaped):** `"\u00e8A\u00e1eV%Y\u00cfV\u00ee\u00ecR\u00dba\u00f5\u00f1\u00f5\u00d95\u00d2\u00fb\u00db\u00fb\u00ed%6e.(;mjy\u00c2B8\u00ed\u00c6&o\u00f0[\u00ffza_O\u00d2\u00fb\u00f92\u00c8s3F\u00eb\u00ec"`  
**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

## RC7 Stream Vector 3

**Key:** `K6:1 102103 0 050`  
**Plaintext JSON:** `"Hello World"`  
**Plaintext literal:**

```text
Hello World
```

**Ciphertext (escaped):**

```text
"\u2060\u00f0#X\u200b\u2060\u2060+\u20607\u00f4\u00e9#^\u200d\u200b\u200c\u200c\u00cf\u200b\u2060\u200d\u200b\u00ea\u2060\u200c\u2060\u2060\u2060\u200d\u2060\u200b\u00cf\u200ch\u00c0;\u200c\u00dc\u200d\u00e2!\u200c\u200b\u2060\u00da\u200d\u206082\u200c\u00a1\u200c\u200b\u200c\u200c\u00bf\u00e4\u2060\u2060\u2060\u00e2\u00ffp\u2060k\u200d\u00e6\u200c\u2060\u200b\u2060\u200c\\"
```

**Visible body (escaped):** `"\u00f0#X+7\u00f4\u00e9#^\u00cf\u00ea\u00cfh\u00c0;\u00dc\u00e2!\u00da82\u00a1\u00bf\u00e4\u00e2\u00ffpk\u00e6\\"`  
**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

## RC7 Stream Vector 4

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"Line one\nLine two"`  
**Plaintext literal:**

```text
Line one
Line two
```

**Ciphertext (escaped):**

```text
"\u00e8&AU\u200dS\u200c \u200d\u00d9\u00de\u200d\u200b%T\u2060]\\'\u200c\u200c\u00f5\u200d\u200d\u00f5\u200c\u200c\u200bV\u200b\u200c\u2060\u00ea\u200cr\u00e7K\u200d\u200c([\u200b\u200c\u200b\u200c\u200c\u200d\u00fc\u200c\u200d\u200c\u00e7L\u200b\u200c*\u00c4\\8=\u200cD\u200bCl\u200d>n\u200bC\u200c\u00f0\u0152m\u2060\u200d\u00f5t\u200d\u200d\u200d\u00ee$z\u200b\u200d\u200cY\u200d\u00e0"
```

**Visible body (escaped):** `"\u00e8&AUS \u00d9\u00de%T]\\'\u00f5\u00f5V\u00ear\u00e7K([\u00fc\u00e7L*\u00c4\\8=DCl>nC\u00f0\u0152m\u00f5t\u00ee$zY\u00e0"`  
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

A correct `v3.0.0-rc.7` implementation must:

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
