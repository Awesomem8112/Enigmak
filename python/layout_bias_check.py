"""
ENIGMAK rc.5 layout and safety bias checker.

This checks the current key-derived layout system, random key generator, fixed
corruption buffer, and tamper-fail behavior.
"""

from collections import Counter
import math
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from enigmak import (  # noqa: E402
    ALPHA,
    LAYOUT_NAMES,
    MAX_CORRUPT_LEN,
    MIN_GENERATED_KEY_BITS,
    N,
    ZERO_WIDTH_SET,
    _corrupt_buffer,
    calc_key_strength,
    compute_key_material,
    decrypt_text,
    encrypt_text,
    generate_key,
    parse_key,
)


def check(condition, message, failures):
    print(f"  {'PASS' if condition else 'FAIL'} - {message}")
    if not condition:
        failures.append(message)


def key_material_for(key):
    parsed = parse_key(key)
    return parsed, compute_key_material(
        parsed['steck_pairs'],
        parsed['rotors'],
        parsed['enabled'],
        parsed['user_rounds'],
    )


def summarize_profile(parsed):
    return (
        len(parsed['enabled']),
        len(parsed['rotors']),
        len(parsed['steck_pairs']),
        bool(parsed['nonce']),
    )


def main():
    failures = []
    print("=" * 72)
    print("ENIGMAK rc.5 Layout Bias / Safety Checker")
    print("=" * 72)

    print("\n[1] Key-derived layout maps are bijective and invertible")
    key = generate_key()
    parsed, km = key_material_for(key)
    for name in LAYOUT_NAMES:
        fwd = km['layout_maps'][name]
        inv = km['inv_layout_maps'][name]
        covers_input = set(fwd.keys()) == set(ALPHA)
        covers_output = set(fwd.values()) == set(ALPHA)
        roundtrip = all(inv[fwd[c]] == c for c in ALPHA)
        check(covers_input and covers_output and roundtrip, f"{name} is a full permutation", failures)

    print("\n[2] Uniform input remains uniform through every layout permutation")
    plain = ALPHA * 97
    for name in LAYOUT_NAMES:
        fwd = km['layout_maps'][name]
        freq = Counter(fwd[c] for c in plain)
        counts = set(freq.values())
        check(counts == {97}, f"{name} output frequency is exactly uniform", failures)

    print("\n[3] Layout maps are independent enough to avoid fixed keyboard-layout bias")
    pair_matches = []
    for i, left in enumerate(LAYOUT_NAMES):
        for right in LAYOUT_NAMES[i + 1:]:
            matches = sum(1 for c in ALPHA if km['layout_maps'][left][c] == km['layout_maps'][right][c])
            pair_matches.append(matches)
    average_matches = sum(pair_matches) / len(pair_matches)
    max_matches = max(pair_matches)
    print(f"  Average shared mappings per layout pair: {average_matches:.2f} (random expectation about 1)")
    print(f"  Maximum shared mappings in one pair: {max_matches}")
    check(average_matches < 3.0 and max_matches < 10, "inter-layout overlap stays near random", failures)

    print("\n[4] Across keys, the same layout/input does not settle into one mapping")
    samples = []
    profiles = []
    bit_values = []
    for _ in range(32):
        sample_key = generate_key()
        sample_parsed, sample_km = key_material_for(sample_key)
        samples.append(sample_km['layout_maps']['Colemak']['E'])
        profiles.append(summarize_profile(sample_parsed))
        bit_values.append(round(calc_key_strength(sample_parsed)['family_bits'], 1))
    unique_outputs = len(set(samples))
    unique_profiles = len(set(profiles))
    unique_bits = len(set(bit_values))
    print(f"  Colemak E mapped to {unique_outputs} unique outputs across 32 keys")
    print(f"  Generated {unique_profiles} unique key profiles and {unique_bits} unique strength values")
    check(unique_outputs >= 12, "cross-key mapping varies", failures)
    check(unique_profiles >= 6, "keygen is not locked to one theoretical profile", failures)
    check(unique_bits >= 6 and 151.5 not in set(bit_values), "keygen is not producing fixed 151.5-bit keys", failures)

    print("\n[5] Generated keys meet the rc.5 minimum accepted family strength")
    for index in range(20):
        sample_key = generate_key()
        sample_parsed = parse_key(sample_key)
        bits = calc_key_strength(sample_parsed)['family_bits']
        check(bits >= MIN_GENERATED_KEY_BITS, f"key {index + 1:02d} has {bits:.1f} bits", failures)

    print("\n[6] Corruption buffer is fixed length")
    check(MAX_CORRUPT_LEN == 4096, "MAX_CORRUPT_LEN is exactly 4096", failures)
    check(len(_corrupt_buffer()) == 4096, "_corrupt_buffer() emits exactly 4096 code points", failures)

    print("\n[7] Tampered rc.4-hidden ciphertext fails closed")
    test_key = generate_key()
    ciphertext = encrypt_text("metadata integrity check", test_key)
    visible_only = ''.join(c for c in ciphertext if c not in ZERO_WIDTH_SET)
    one_visible_deleted = ciphertext[:5] + ciphertext[6:]
    for label, damaged in (
        ("hidden metadata removed", visible_only),
        ("one visible character removed", one_visible_deleted),
    ):
        result = decrypt_text(damaged, test_key)
        check(
            not result.get('success') and not result.get('verified') and result.get('plaintext') == '',
            f"{label}: plaintext is not exposed",
            failures,
        )

    print("\n" + "=" * 72)
    if failures:
        print("FAILURES")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
