# Test Vectors

These vectors target release candidate `v3.0.0-rc.9`. They are rc.9 ciphertext
outputs even though the runtime API format label remains **`rc.6-stream`** with
hidden metadata version character **`5`**. rc.9 derives all live pseudorandom
output from ChaCha20 keystream with BLAKE3-derived stream keys, so these
ciphertexts differ from the rc.8 vectors for the same key and plaintext even
though the wire format is unchanged.

The live alphabet has **162** symbols: 95 legacy printable ASCII characters, 66
European extended characters, plus newline. See `ALPHA` in
`python/enigmak.py` for the exact string.

New `rc.6-stream` ciphertext:

- interleaves encrypted payload, **10** scattered encrypted checksum characters,
  and **key-derived** zero-width metadata carriers in a keyed schedule
- carrier count = `derive_metadata_logical_len(key) * 4` (uniform over `4 .. (N-1)*4`
  at `N = 162`); legacy ciphertext with exactly **44** carriers still decrypts
- advances cipher state at carrier positions with key-derived phantom wildcards
- has no fixed visible checksum prefix
- does **not** begin with `E3|`

Optional materialized metadata mode keeps the same stream schedule and version
character but emits metadata carrier events as visible `ALPHA` characters (count
matches the key-derived carrier count).

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

## RC9 Stream Vector 1

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"HELLOWORLD"`  
**Plaintext literal:**

```text
HELLOWORLD
```

**Ciphertext (escaped):**

```text
"\u200d\u00d6\u200c\u200d'\u200d\u2060\u200b\u2060\u200d\u2060cl\u200bGK9\u2060\u200b\u200d\u2060\u00e0j\u00dd\u2060\u200cJY\u200d\u200b\u200b\u00c1\u200b\u2060S\u00cd\u2060W\u2060\u200c\u200d:\u00ec\u200d\u200b\u2060\u200cR/\u200d\u00d8\u200c\u200b\u200c\u200d\u00e6\u2060.\u200c\u200dD\u200b\u200c\u2060\u2060\u200c\u200dD\u200c\u00e0"
```

**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

**Materialized ciphertext (escaped):**

```text
"\u00dd\u00d6\no'\u00cb@s~[\u00c9cl`GK9{q\u00e8\u00c9\u00e0j\u00dd\u00e5kJY\u00c6p\u00c1\u00c1\u00c4\u00bfS\u00cd0W!9M:\u00ecBqbcR/m\u00d8'\u00ce>K\u00e6}.A]D6Ws\u00f2\u00c3zDd\u00e0"
```

**Expected runtime format label:** `rc.6-stream (materialized)`

## RC9 Stream Vector 2

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
"\u200d\u00d6\n\u200cWB\u200d\u200d\u200d\u00eb\u200bc\u00c3\u00ce\u2060\u200d\u00e9\u00cf\u2060\u00cd\u2060G}{O\u00f2\u200d\u2060\u00e1?h\u00cab\u00ce\u200c\u0152\u200d\u200b\u200b3\u200d\u00cco\u00df\u00d8\u200b;\u2060\u200d\u200d\u200d\u200c\u200c\u00f8v\u2060B\u2060\u2060\u200c\u00df\u2060\u00e5\u00d0\u200c\u2060uc8\u200c\u00ec\u00f4k`\u2060ccT\u200c\u00e2\u00cdSJ\u00d9\u2060C\u2060\u00d4X\u200d0\u200d\u200d\u2060 \u2060\u2060\u200d/\u00d3\u00d4\u2060\u00de\u00c4"
```

**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

## RC9 Stream Vector 3

**Key:** `K6:1 102103 0 050`  
**Plaintext JSON:** `"Hello World"`  
**Plaintext literal:**

```text
Hello World
```

**Ciphertext (escaped):**

```text
"\u2060\u200d\u2060\u00d2\u00ca\u2060\u200d*\u00f8\u200c\u200c\u200d\u2060\u2060\u2060q9\u00ff4wt\u00e9\u00dc\u200c\u200c\u200b\u200c\u200bY\u2060\u200d\u00c0I\u00ed(\u00a1\u2060\u200b\u200c\u200d\u00c4\u200cs\u00cci,\u2060\u200c\u200d\u2060yU\u200d/X\u00c8\n\u2060\u200d\u200cD\u200b\u00c0\u00c4e\u2060\u200b\u200c\u00ea\u00d1\u200d\\\u2060\u00cc|\u200b\u200c\u200b)E\u200c\u200d\u200c\u00a1\u200c"
```

**Hidden carrier count:** `44`  
**Expected runtime format label:** `rc.6-stream`

## RC9 Stream Vector 4

**Key:** `K6:0 000 0 013`  
**Plaintext JSON:** `"Line one\nLine two"`  
**Plaintext literal:**

```text
Line one
Line two
```

**Ciphertext (escaped):**

```text
"\u00dd\u200d\u200c\u00c4\u200d\u200d\u200d\u200dN\u200d\u200b\u200d\u2060Q\u2060\u200c\u200d\u2060{\u2060\u200c\u00e6\u200d\u200b\u2060\u200c\u200d#\u00ec\u200c\u0152 \u200b\u2060\u2060\u200b\u00e4;y\u00ff\u200c\u200c\u00f82\u2060\u00d0\u200d\u200c\u00c2\u200c\u00dc\u00fe\u2060^\u2060\u200c\u200d\u200d\u2060u\u200bYi\u2060\u200d\u00e7Nco\u200d\u200bb%b\u2060$\n9\u00f2"
```

**Hidden carrier count:** `44` (legacy fixed count)  
**Expected runtime format label:** `rc.6-stream`

## Variable Metadata Vector (logical length 1)

**Key:** `K6:B6AE E01B37E20B1QA17E2QB41E35B46E0U62264A 012V020X042I06350833090D0A0N0F3M0H260J220O2M0P410Q120S3H0T0V0Y28104B172G1F2L1G3K1I291J3U1L3C1M3S1P2J1S2S1V2D1W2W1Z232H392K3G2Q3Z2R4F2T4G303I313F36493A3L3Q42474H 841`  
**Plaintext:** `META_TEST`  
**Derived logical length:** `1`  
**Hidden carrier count:** `4`

**Ciphertext (escaped):**

```text
"\u00a1\u2060^\u00c4W\u00fe\u00e2\u200d9f\u00cb\u2060%\u00d5.\u00caL\u00f0\u2060R}op\u00d0p\u00ca\u00c3iO\u00bfRJ\u00c2\u00e3\u00f4\u00d0T{>"
```

## Variable Metadata Vector (logical length 30)

**Key:** `K6:F F0XF2JF1SF0HF26F2HF1RF1HF0KF1YF0QF22F1GF2T 002203290439063C073J09480A3X0B1S0D2J0G3G0H440I0W0J1F0K210N2A0O240P1D0Q1I0R2I0S3P0X3V0Y450Z1L103B113H1242131Q1435153S171V183F191O1A1J1B3Z1C1W1E3T1G1N1H2Y1M1Y1R261T301U2S1X2O1Z3R202G282Z2B4B2C322F2U2K4A2L3N2M432N2Q2P2W2R4C2T342V46334G363K373I383E3M473Q493W3Y414D 989`  
**Plaintext:** `META_TEST`  
**Derived logical length:** `30`  
**Hidden carrier count:** `120`

**Ciphertext (escaped):**

```text
"\u200b\u2060\u200b\u200b\u200c\u200b\"\u2060\u2060\u2060\u200b\u200d\u2060\u200cn\u2060\u200b\u200b\u200b\u200b\u200b\u200d\u00dd\u200c\u200dr`\u200b\u200bA\u200b\u00f3\u200b\u200d\u200b\u200c\u200b\u2060\u2060\u200c\u200d\u2060\u200b\u200b\u2060\u200c\u200b\u200b\u200c\u2060\u2060\u200c\u200c\u200d\u00fa\u2060\u200b\u200dV\u200c\u200b\u200b\u200bD\u2060\u200d\u200c\u200by\u200b\u2060\u200c\u200d\u200d\u200c\u200c\u200d\u200b\u200df\u200c\u00e6\u00f6\u2060\u200cZj\u00c8U\u200b\u200b\u200b\u2060\u2060\u200c\u200cv\u200c\u2060\u200b\u2060\u200c'\u200d\u200b\u200c\u200b\u200b\u2060\u200c\u200c\u200cY\u200c\u200c\u2060\u200c\u2060\u200bE\u2060\u2060\u2060\u200c\u2060\u2060\u200b\u200c\u2060\u200b\u200c\u200d\u2060\u200b\u2060\u200b\u200d\u00c3\u00bf@\u2060\u200c\u200c\u200c\u200c\u00e0"
```

## Variable Metadata Vector (logical length 50)

**Key:** `K6:F1260C5 C0T63412R52W62I62M24253IF0W60664E 012Y0228031Z050H073O08460A0V0B4G0D0P0E3F0I1G0K4H0L3Z0M2A0O3B0Q3X0S2R0T3D0W2J0Y44111S1232131N1448152516231C1E1D3H1J3M1M3G1O1Q1P211T3Y1U301V2D1W3L202F242O2629273Q2B372C2G2E2P2H402L352N2U2S4C2X2Z3149384E39473A3V3J4F3K3T 243`  
**Plaintext:** `META_TEST`  
**Derived logical length:** `50`  
**Hidden carrier count:** `200`

**Ciphertext (escaped):**

```text
"\u200b\u200d\u200b\u200b\u200c\u200c\u2060\u00c3\u200b\u200b\u200b\u200d\u200b\u200d\u200b\u200d\u200c\u200b\u200b\u200b\u200d\u200b\u2060\u200d\u200d\u200b\u00f2\u200c\u200c\u200c\u200b\u200b\u200c\u200c\u200c\u200c\u00cd\u20601\u200c\u200c\u2060\u2060\u200d\u00d9\u200b\u00e1\u200b\u200d\u200d\u200bD\u2060\u2060\u2060\u200c\u2060\u200b\u200c\u200d\u200b}\u200b\u200b\u200b\u2060\u200d\u2060\u200c\u200d\u2060\u200d\u200d\u200d/\u200b+\u00c3\u200c\u200d48\u200c\u2060\u00e2\u200d\u200b\u200d\u2060\u200d{\u200d\u200b\u200b\u2060\u200d\u200b\u2060\u2060\u200cE\u200b\u200c\u2060\u200bl\u2060\u200b\u200b\u200b\u200d\u200b\u200b\u200b\u2060\u2060\u200d\u200d\u200c\u2060\u200c&\u200b\u200c\u200d\u2060\u200dC\u200c\u200b\u200b\u200d\u200b$\u200c\u2060\u200c\u200b\u200d\u200c\u200c\u200b\u200d\u200b\u200b\u200b\u200b\u00c3\u200c\u200c\u200b\u200b\u200c\u200b\u200d\u200b\u2060\u200d\u00ca\u200c\u2060\u200d\u00f9y\u200b\u200c\u200d\u200b\u200b\u2060\u200c\u2060\u200d\u200c\u2060\u200b\u200ce\u200b\u200c\u200c\u200d\u200d\u200b\u200c\u200b4\u2060\u200d\u200d\u200c\u200d\u200c\u200b\u200c\u200c\u2060.\u200b\u200c\u200d\u200d\u200d\u200c\u200b\u2060\u200c\u200d\u200b\u200b\u2060\u200b\u200b\u200b\u00c6\u200b\u200b\u2060\u200b\u2060\u200b\u200d\u2060\u200c\u200d\u200c\u00c7*\u200c\u2060\u00fb#]"
```

## Five-Symbol Nonce Key Vector

**Key:** `K6:F17495D3 50Q41G72T70Z40Q90A 001N012N0218030J041O0609071S082V0A2R0B260C3Z0D300E2L0F4E0G3O0H1H0I4D0K1V0L280M1R0N1Q0O360P1Y0Q2M0T1W0U1J0V1G0W270X170Y4H0Z2I101B113L123N1346142S162A192H1C3Y1D2B1E2T1F2C1I291K2X1L3M1T201U3P1X43213C2333244525382D3I2E2Y2G492J402P342Q412U4B2W3G313R324837423A443B473D4C3F3K3H4F3Q4A 224 1O4D3W3L2D`  
**Nonce length:** `5`  
**Plaintext:** `NONCE5_TEST`

**Ciphertext (escaped):**

```text
"\u200b\u200d\u200b\u200b\u200c0\u200c^\u00d5\u200c\u00f6\u200b\u200b\u200c\u200b\u200c\u00de\u200b\u200b\u200b7\u2060\u200d\u200c\u200b\u200d\u200d\u200b\u2060\u200b\u200b\u2060\u200d\u200c\u200c\u200d\u200b\u200b\u200c\u200d\u200d\u200b\u200b\u2060\u200b\u200cs\u200d-\u200c\u200b\u200c\u200c\u200d\u200c\u200bx\u200d\u200c\u200b\u200b\u200b\u200b\u200d\u200d'\u200c\u200bp\u200b\u2060\u200c\u200b=\u200c\u200c\u200b\u2060\u200c\u200c\u200b\u200d\u200b\u200d\u200d\u200c\u200c\u2060\u200b>\u200d\u200d\u200d\u200d\u200b\u200d\u2060\u200c\u200c\u2060\u2060\u200b\u200c\u200b\u200d\u200b\u200d\u200c\u200d\u200c\u200d\u2060&\u200b\u200b\u200c\u200d\u2060\u200c\u200c\u200d\u200b\u200b\u200b\u2060f\u200c\u200b\u200d\u2060\u2060\u200b\u2060\u200d\u200d\u200b\u200d\u2060\u2060\u200b\u200c\u2060S\u200d\u200d\u200b\u200d\u200c\u200b\u2060\u200d\u200d\u200b\u200d\u200c\u200b\u200d\u200c\u2060\u2060\u200c\u200b\u200d\u2060\u200b\u2060\u200b\u200c\u200b\u2060\u200d\u200c\u200b]\u200b\u200b\u2060\u200c\u200c\u200d\u200c\u200b\u200c'\u200d\u200d\u200d\u200c\u2060\u200b\u200b\u2060\u200c\u200c\u200d\u200dZ\u200b\u200b\u200c'\u00f6\u200bD\u200c\u2060\u200d\u200cX\u200d\u2060\u200b\u200c\u200d\u200b\u200d\u200b\u200d\u2060\u200d\u00ce\u200c\u200c\u2060\u200b\u200c\u200b\u2060\u00fa\u200b\u200c\u2060\u200b\u200c\u200d\u200d\u200b\u200c\u200c\u2060\u00ff\u2060\u200d\u200c<\u2060\u2060\u200b\u200d}\u2060\u200d\u200b\u200c\u200d\u200d\u200c\u2060\u200d\u200b\u200c\u200c\u200d\u200d\u200b\u2060\u2060\u200c\u200b\u200b\u200d\u200c\u200b\u200b\u200b\u00da\u200b\u200b\u200c\u2060\u200b\u200b\u200c\u200d\u2060\u200b\u00f4\u200d\u200d\u200di\u200c\u200d\u200d\u2060$\u200b\u2060\u200c\u200d"
```

## Pinned Decoy Fixture

Cross-install regression for decoy bundles (`real_key = K6:0 000 0 013` at encrypt time).

**Decoy key:** `K6:0B415F82 40B007B3383M53N515F35115237524440B3J53C527838 0E2X0G0V0K230X2N0Z3K102A1Y24224F2Z34 138`  
**Cover plaintext:** `Meeting moved to Tuesday`  
**Expected:** `verified: true`, `success: true`

**Decoy ciphertext (escaped):**

```text
"s\u2060\u200b\u2060\u2060\u2060\u00db\u200c\u2060\u2060\u00d6\u200b\u200d\u200d\u2060|\u200d\u200b\u00df\u200c\u00ca\u200c\u2060C\u2060\u2060?\u00cb\u200b\u00e8\u2060}\u2060\u2060\u00da\u200b\u200dM\u2060\u200d\u200b\u2060\u00f8\u00d4\u2060\u200b\u00ca\u200b\u200d\u2060\u200c\u200b\u2060\u00a1\u2060\u200d\u200d\u200bo\u2060a\u200c\u2060\u2060\u200d\u200d\u200b\u200b\u2060\u200c\u200d=\u2060\u00c8\u00d2\u200c\u200d\u200c\u200b\u200b\u2060\u2060\u200d\u200d\u200c\u200b\u2060S\u200b\u200b\u200c\u2060\u200c\u20603\u200bb\u200d\u200d\u200b\u200b\u2060G\u200d\u00c45\u200b\u200b\u200d\u200b\u200d\u200d\u2060G\u200d\u00c4\u200c\u00c9\u200b\u200b\u200d9\u200c\u200b\u2060\u2060\u200b\u200b\u2060\u200c\u200b\u200c\u2060\u200cr\u200b\u200d\u2060\u2060\u2060\u2060\u2060\u0152\u200c\u200b\u200b\u2060^\u200b\u200b\u200c\u2060\u200d\u2060\u200b\u200b\u200d\u200d\u2060\u200d\u00de\u2060\u2060\u200c\u2060\u00bf\u00ce\u2060\u2060\u2060\u00fa\u2060\u200b\u200b\u200cP?\u200d0\u200c\u200c\u200d\u200d\u00c8\u200cr\u00e5\u2060\u2060\u200d\u200b\u2060\u2060\u200b\u20600\u200b\u200d\u2060w\u2060\u200d\u2060\u200b\u00e8\u200dZ\u200c\u200b\u200b\u00c2\u200d\u2060\u200b\u200b>\u200d\u200b\u200d\u2060\u2060\u200dh+:\u200d\u200d\u200c\u200c\u200c\u200d\u200c\u200d\u200b"
```

Negative pairing: decoy key + real ciphertext → `verified: false`; real key + decoy ciphertext → `verified: false`.

## Dual-Message Vectors (`rc.9-dual-v1`)

Pinned one-ciphertext/two-key fixtures live in `tests/dual_vectors.json`. Each
vector records intended and faux plaintexts, independently generated keys, a
fixed 16-byte envelope nonce, and the unpadded base64url ciphertext. Recreating
the envelope with those inputs must match the literal ciphertext exactly.

| Vector | Intended plaintext | Faux plaintext | Materialized |
|---|---|---|---|
| `equal_lengths` | `SECRET PLAN` | `PUBLIC NOTE` | no |
| `different_lengths` | `Rendezvous at the north gate` | `Routine maintenance` | no |
| `empty_intended` | empty | `Nothing to report` | no |
| `empty_faux` | `The intended text` | empty | no |
| `extended_newline` | `ÀßŒœ` plus newline plus `INTENDED` | `Cover` plus newline plus `àÿ¿` | no |
| `materialized` | `VISIBLE INNER` | `FAUX VISIBLE` | yes |

Both keys must decrypt the same ciphertext to their own fully verified
plaintexts with format `rc.9-dual-v1`. A third unrelated key, truncated or
padded ciphertext, filler/control/flag/length/inner mutations, duplicate valid
slots, and recursive dual inners must fail closed with `Decryption failed.`
and blank plaintext. The ciphertext literal has no public magic prefix; the
first four characters differ across the pinned vectors.

## Legacy RC.3 Compatibility Check

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

`rc.4-hidden` and `v2.0.0-legacy` vectors are pinned in `tests/fixtures.json`
(`rc4_hidden`, `v200`). They were reconstructed from frozen decrypt-only helpers
because no historical git-tagged originals were present in this tree; Python and
JavaScript independently verify them. New interoperability vectors in this file
target **`rc.6-stream`** emit paths and **`rc.9-dual-v1`** envelopes.

## Legacy v2.0.0 Compatibility Note

Original v2.0.0 Python and JavaScript ciphertext should decrypt through the
dedicated `v2.0.0-legacy` path. That path is additive and must not change current
stream-format detection.

## Verification Checklist

A correct `v3.0.0-rc.9` implementation must:

1. Produce the exact `rc.6-stream` ciphertext above for the same plaintext and key.
2. Emit new ciphertext without a visible `E3|` header.
3. Use key-derived hidden carrier count on new encrypt (`logical_len * 4`); legacy
   44-carrier ciphertext still decrypts.
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
14. Generate default random keys with at least `256` family bits and five-symbol
    nonces when a nonce is included.
15. Advance cipher state with key-derived phantom characters at every metadata
    carrier position (count key-derived or legacy 44).
16. Derive all live seeds with the embedded BLAKE3 hash. Validate the BLAKE3
    `hash` mode against the official BLAKE3 `test_vectors.json` (empty, short,
    and multi-chunk inputs) in each implementation, and confirm `hash_str64` /
    `hash_str32` return the first 8 and 4 digest bytes as big-endian unsigned
    integers identically across Python, JavaScript, browser, and Electron.
17. Fail closed (generic `Decryption failed.`) when given rc.7-produced
    `rc.6-stream` ciphertext under the same key, since seed derivation changed.
18. Decrypt variable-metadata vectors (logical lengths 1, 30, 50) and the pinned
    decoy fixture with full verification.
19. Parse legacy three-symbol nonce keys; default keygen uses five-symbol nonces.
20. Recreate every `tests/dual_vectors.json` envelope exactly, decrypt both
    keys independently, and keep dual ciphertext prefix-free.
21. Interoperate both ways between Python and JavaScript for `rc.9-dual-v1`.
22. Keep Electron Security menu copy-key items and dual renderer round-trips.
