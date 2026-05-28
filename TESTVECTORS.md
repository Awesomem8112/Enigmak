# Test Vectors

These vectors target release candidate `v3.0.0-rc.6`. New messages emit
**`rc.6-stream`** with hidden metadata version character **`5`**.

The live alphabet has **161** symbols: 95 legacy printable ASCII characters plus
66 European extended characters. See `ALPHA` in `python/enigmak.py` for the exact
string.

New `rc.6-stream` ciphertext:

- interleaves encrypted payload, **10** scattered encrypted checksum characters,
  and **44** zero-width carriers in a keyed schedule
- advances cipher state at carrier positions with key-derived phantom wildcards
- does **not** begin with `E3|`

Record ciphertext using escaped JSON-style notation or another lossless
representation. Copy paths that strip zero-width markers break verification.
Python interactive encryption copies exact ciphertext to the system clipboard
because manual terminal highlighting can omit hidden metadata.

The checksum is computed over the **packed visible payload** (the `H` tag,
length field, plaintext, and padding **before** stream scheduling) using
`deriveMacSubkey(keyStr)`, not over the raw plaintext alone.

## RC.6 Stream Vector 1

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"HELLOWORLD"`  
**Plaintext literal:**

```text
HELLOWORLD
```

**Ciphertext (escaped):**

```text
")\u200d\u200c\u00cd\u200d\u00ee\u200d\u200b\u200d\u200c\u00cd\"\u00fdN\u200b-\u200b30\u200d\u200ds\u200b\u00e8\u200d\u200b\u200b\u200c\u200bq\u2060\u00f1IA8P\u200c\u200d\u00cc\u200d\u200dF\u200c\u200c\u200cd\u00c5\u00c4\u00f8\u200d\u200ciVsX\u200c5fI\u200bo\u2060\u200c\u00eb:\u200d\u200c\u200ds\u00c8\u200c\u200b\u00c4\u200d<\u200c\u200d\u2060\u200b\u200bb\u200d\u200b"
```

**Visible body:** `)ÍîÍ"ýN-30sèqñIA8PÌFdÅÄøiVsX5fIoë:sÈÄ<b`  
**Hidden carrier count:** `44`  
**Expected format:** `rc.6-stream`

## RC.6 Stream Vector 2

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"UPPER lower [] {} \`~ with spaces and words"`  
**Plaintext literal:**

```text
UPPER lower [] {} `~ with spaces and words
```

**Ciphertext (escaped):**

```text
")\u200dC\u200c\u200d\u00cc_\u200d.]\u200d\u00c3\u200cE\u0153r\u200dA\u2060\u200c^\u00cao?\u00f0\u200d\u200d\u00d6\u200b\u00ce@\u00f2z!$\u200b\u00da\u200d\u200dGh\u200d{\u200b\u2060\u00cbX@\u00df\u200b\u00d1\u200c\u200d\u200b\u00e9c\u00cd\u200b#\u2060\u200bN|\u200d\u00c5\u200dv\u2060Q\u00ff\u00d4\u200d\u200c\u200b}p\u00d3\u00d5\u2060\u200b\u2060a\u200d>h\u00c0m\u200d\u200b\u00e8\u00ce4f6\u00e7m\u200b\u200d\u00ed,\u00d6!\u200b\u00f6\u200b\u200b\u2060\u200c:\u00c4"
```

**Visible body:** `)CÌ_.]ÃEœrA^Êo?ðÖÎ@òz!$ÚGh{ËX@ßÑécÍ#N|ÅvQÿÔ}pÓÕa>hÀmèÎ4f6çmí,Ö!ö:Ä`  
**Hidden carrier count:** `44`  
**Expected format:** `rc.6-stream`

## RC.6 Stream Vector 3

**Key:** `K6:1 102103 0 050`  
**Plaintext JSON:** `"Hello World"`  
**Plaintext literal:**

```text
Hello World
```

**Ciphertext (escaped):**

```text
"\u2060]\u200b\u00da\u00fe\u2060\u2060\u200b\u200c\u200b\u2060['\"\u2060d\u200da\u200b!\u200c\u200cO\u200d\u2060\u00e9`(\u2060\u2060\u200b\u00c40\u2060\u200c\u200c\u2060\u00bfK\u2060t\u200br|\u2060\u200bQ\u00fc\u200c\u200d\u2060\u200b\u200b\u2060\u200c\u200c\u00ec\u200b\u20609>\u200bv2ht\u200c>\u2060\u200c\u200c\u200buk\u2060,\u200d"
```

**Visible body:** `]Úþ['"da!Oé`(Ä0¿Ktr|Qüì9>v2ht>uk,`  
**Hidden carrier count:** `44`  
**Expected format:** `rc.6-stream`

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

## Verification Checklist

A correct `v3.0.0-rc.6` implementation must:

1. Produce the exact `rc.6-stream` ciphertext above for the same plaintext and key.
2. Emit new ciphertext without a visible `E3|` header.
3. Preserve exactly `44` hidden carrier symbols on new messages.
4. Scatter exactly `10` encrypted checksum characters in the stream schedule.
5. Fail verification with the generic public error `Decryption failed.` when
   carriers or checksum symbols are removed or reordered.
6. Continue decrypting the rc.3 and rc.2 legacy samples correctly.
7. Preserve zero-width markers during copy, file export, and cross-runtime transport.
8. Compute the rc.6 checksum from the packed visible payload using
   `deriveMacSubkey(keyStr)` and version `5`.
9. Interoperate both ways between Python and JavaScript for `rc.6-stream`.
10. Keep failure-path corruption buffers fixed at exactly 4096 characters.
11. Generate default random keys with at least `256` family bits.
12. Advance cipher state with key-derived phantom characters at all `44`
    carrier positions.
