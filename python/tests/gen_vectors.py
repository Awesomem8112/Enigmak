#!/usr/bin/env python3
"""Generate test vectors for rc.9 features (run once, not part of CI)."""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from enigmak import (
    decrypt_text, encrypt_text, encrypt_decoy_bundle, generate_key,
    derive_metadata_logical_len, derive_metadata_carrier_count, parse_key,
    LEGACY_HIDDEN_SYMBOL_COUNT,
)

VECTOR1_CT = json.loads(
    '"\u200d\u00d6\u200c\u200d\'\u200d\u2060\u200b\u2060\u200d\u2060cl\u200bGK9\u2060\u200b\u200d\u2060\u00e0j\u00dd\u2060\u200cJY\u200d\u200b\u200b\u00c1\u200b\u2060S\u00cd\u2060W\u2060\u200c\u200d:\u00ec\u200d\u200b\u2060\u200cR/\u200d\u00d8\u200c\u200b\u200c\u200d\u00e6\u2060.\u200c\u200dD\u200b\u200c\u2060\u2060\u200c\u200dD\u200c\u00e0"'
)
VECTOR1_KEY = 'K6:0 000 0 013'

def main():
    targets = {1: None, 30: None, 50: None}
    for _ in range(500000):
        k = generate_key()
        ll = derive_metadata_logical_len(k)
        if ll in targets and targets[ll] is None:
            targets[ll] = k
        if all(v for v in targets.values()):
            break

    print('=== Metadata length keys ===')
    for ll in sorted(targets):
        k = targets[ll]
        cc = derive_metadata_carrier_count(k)
        pt = 'META_TEST'
        ct = encrypt_text(pt, k)
        r = decrypt_text(ct, k)
        print(f'll={ll} carriers={cc} key={k} verified={r["verified"]} pt={r["plaintext"]}')
        print(f'  ct={json.dumps(ct)}')

    print('\n=== Decoy fixture ===')
    bundle = encrypt_decoy_bundle(
        'real secret', 'Meeting moved to Tuesday', real_key_str=VECTOR1_KEY
    )
    d = decrypt_text(bundle['decoy']['ciphertext'], bundle['decoy']['key'])
    print(f'key={bundle["decoy"]["key"]}')
    print(f'ct={json.dumps(bundle["decoy"]["ciphertext"])}')
    print(f'cover={bundle["decoy"]["plaintext"]} verified={d["verified"]}')

    print('\n=== 5-char nonce sample key ===')
    k5 = generate_key()
    print(f'key={k5} nonce_len={len(parse_key(k5)["nonce"])}')

    print('\n=== Legacy vector 1 ===')
    r = decrypt_text(VECTOR1_CT, VECTOR1_KEY)
    print(f'verified={r["verified"]} pt={r["plaintext"]}')

    # Legacy rc.3 and rc.2
    r3 = decrypt_text('E3|1]Qfw?Q{GF-#+nKPJlPm$w6H*R-\'6^gk,[kLm+`', '123 100200 0 050')
    print(f'rc3 verified={r3["verified"]} pt={r3["plaintext"]}')
    r2 = decrypt_text('b$\\.:j53ZHekRX~u.I#%)', '123 100200 0 050')
    print(f'rc2 verified={r2["verified"]} pt={r2["plaintext"]}')

if __name__ == '__main__':
    main()
