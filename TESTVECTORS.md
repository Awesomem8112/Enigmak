# Test Vectors

These vectors target release candidate `v3.0.0-rc.4`. Its current new-message
format is `rc.4-hidden`.

All vectors below use the live 95-symbol alphabet:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\',./!@#$%^&*()_+{}|:"<>?`~abcdefghijklmnopqrstuvwxyz[space]
```

New ciphertext no longer begins with `E3|`. Instead, `rc.4-hidden` emits:

- a visible encrypted body: `[format_tag:1][len_field:4][plaintext][padding:1..16]`
- hidden encrypted metadata: `[version:1][checksum:10]`
- 44 invisible zero-width carrier symbols (`\u200B`, `\u200C`, `\u200D`, `\u2060`)

The checksum is computed over the **visible ciphertext** using a MAC subkey
derived from the cipher key (`deriveMacSubkey(keyStr)`), not over the plaintext.
This removes the known-plaintext foothold present in earlier rc.4 builds.

Record `rc.4-hidden` ciphertext using escaped JSON-style notation or another
lossless representation. Copy paths that strip zero-width markers will break
verification.

## RC.4 Hidden Vector 1

**Key:** `01 002103 0 013`  
**Plaintext:** `HELLOWORLD`  
**Ciphertext (escaped):**

```text
"T>\u200d\u200d\u200c\u2060z\u200c\u200b\u200d\u200b\u200c\u2060%+;\u200b\u200c\u200c\u2060\u200d\u2060\u200c*\u2060\u200c\u200dDb\"\u200d\u200d\u200c>\u200b\u200d\u200d\u200c~+}\u200d\u200c\u200c\u2060N\u200d\u200c\u20602c/\u2060\u200b\u200c\u200d \u2060\u200b\u200c\u200d\u200c\u200d"
```

**Visible body:** `T>z%+;*Db">~+}N2c/ `  
**Hidden carrier count:** `44`

## RC.4 Hidden Vector 2

**Key:** `01 002103 0 013`  
**Plaintext:** `UPPER lower [] {} \`~ with spaces\nand newline`  
**Ciphertext (escaped):**

```text
"T>\u200d\u200dz%!\u200dq\u2060k\u200dM3\u200dF\u200d\u2060 7\u200d#\u200ciSuT\u200cd\u200b\u200c\u200bC\u200d\u200d-\u200c\u200dg\u200c\u200b{\u200dV\u200d\u200b47}\u200bM\u200d\u200c%k\u200d\u2060!\u200c@M\u200c\u200dPqQ\u200d\u200c\u200b!l\u200b\n\u200c\u200d<<>GD\u200cb\u200d\u2060\u200cs8\u200ciSQ\u200cIV\u2060="
```

**Visible body:**

```text
T>z%!qkM3F 7#iSuTdC-g{V47}M%k!@MPqQ!l
<<>GDbs8iSQIV=
```

**Hidden carrier count:** `44`

## RC.4 Hidden Vector 3

**Key:** `123 100200 0 050`  
**Plaintext:** `Hello World`  
**Ciphertext (escaped):**

```text
"%\u2060\u200b\u200c\u2060<\u200bG\u2060\u200cjX\u200c\u200bL\u200b[\u2060\u200b\u200b\u2060\u200do\u200b\u2060\u200b[\u200c\u200c\u2060\u200bp\u2060\u200b\u200b\u2060o\u20604\u200b\u2060\u2060\u200cF\u200dE\u2060!\u2060%\u200dP\u200c\u2060\u2060\u200b\u2060\u200b\u2060W\u200b\u2060"
```

**Visible body:** `%<GjXL[o[po4FE!%PW`  
**Hidden carrier count:** `44`

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

## Verification Checklist

A correct `v3.0.0-rc.4` implementation must:

1. Produce the exact ciphertext above for the same plaintext and key.
2. Emit new ciphertext without a visible `E3|` header.
3. Preserve exactly `44` hidden carrier symbols on new messages.
4. Fail new-message verification with `Hidden metadata missing or stripped from ciphertext` when those carriers are removed.
5. Continue decrypting the rc.3 and rc.2 legacy samples correctly.
6. Preserve zero-width markers during copy, file export, and cross-runtime transport.
7. Compute the rc.4 checksum over the visible ciphertext using `deriveMacSubkey(keyStr)`, not over the plaintext.
