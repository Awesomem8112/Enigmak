"""
ENIGMAK Layout Bias Checker
Tests whether key-derived layout permutations have eliminated
ergonomic keyboard layout bias in substitution tables.

Tests run:
1. Frequency uniformity - does each output char appear equally often?
2. Cross-key consistency - do different keys produce different biases?
3. Chi-square vs uniform distribution
4. Substitution collision check - is each layout map truly bijective?
5. Inter-layout independence - are different layouts' maps correlated?
"""
import sys
sys.path.insert(0, '.')
from enigmak import (parse_key, generate_key, compute_key_material,
                     ALPHA, N, LAYOUT_NAMES)
from collections import Counter
import math

print("=" * 60)
print("ENIGMAK Layout Bias Checker")
print("=" * 60)

# ── Test 1: Bijectivity ────────────────────────────────────────────────────────
print("\n[1] Bijectivity - each layout map must be a true permutation")
key = generate_key()
k = parse_key(key)
km = compute_key_material(k['steck_pairs'], k['rotors'], k['enabled'], k['user_rounds'])

all_bijective = True
for name in LAYOUT_NAMES:
    lm = km['layout_maps'][name]
    ilm = km['inv_layout_maps'][name]
    # Forward map covers all N chars
    outputs = set(lm.values())
    # Inverse is consistent
    roundtrip = all(ilm[lm[c]] == c for c in ALPHA if c in lm)
    bijective = len(outputs) == N and roundtrip
    if not bijective:
        all_bijective = False
    print(f"  {name:12s}: {'✓ bijective' if bijective else '✗ NOT bijective'}")
print(f"  Result: {'PASS' if all_bijective else 'FAIL'}")

# ── Test 2: Frequency uniformity per layout ───────────────────────────────────
print("\n[2] Frequency uniformity - uniform plaintext should produce uniform output")
plain = ALPHA * 1000  # Each char appears 1000 times
results = []
for name in LAYOUT_NAMES:
    lm = km['layout_maps'][name]
    freq = Counter(lm.get(c, c) for c in plain)
    expected = len(plain) / N
    chi2 = sum((freq.get(c, 0) - expected) ** 2 / expected for c in ALPHA)
    # Chi2 with 67 dof: 95th percentile ~87, 99th ~100
    uniform = chi2 < 87
    results.append(chi2)
    print(f"  {name:12s}: chi2={chi2:6.2f} {'✓' if uniform else '✗'}")
print(f"  Avg chi2: {sum(results)/len(results):.2f} (expect ~67 for uniform)")
print(f"  Result: {'PASS' if all(r < 87 for r in results) else 'FAIL'}")

# ── Test 3: Cross-key bias ────────────────────────────────────────────────────
print("\n[3] Cross-key bias - different keys should produce different substitutions")
n_keys = 20
all_top1 = []
for _ in range(n_keys):
    k2 = parse_key(generate_key())
    km2 = compute_key_material(k2['steck_pairs'], k2['rotors'], k2['enabled'], k2['user_rounds'])
    # What does 'A' map to under Colemak in this key?
    all_top1.append(km2['layout_maps']['Colemak'].get('A', 'A'))

unique_mappings = len(set(all_top1))
print(f"  'A' under Colemak across {n_keys} keys: {unique_mappings} unique outputs")
print(f"  Mappings: {', '.join(sorted(set(all_top1)))}")
print(f"  Result: {'PASS' if unique_mappings > n_keys * 0.5 else 'FAIL'}")

# ── Test 4: Inter-layout independence ─────────────────────────────────────────
print("\n[4] Inter-layout independence - layouts should not share mappings")
shared = 0
total_checked = 0
for i, n1 in enumerate(LAYOUT_NAMES):
    for n2 in LAYOUT_NAMES[i+1:]:
        lm1 = km['layout_maps'][n1]
        lm2 = km['layout_maps'][n2]
        matches = sum(1 for c in ALPHA if lm1.get(c) == lm2.get(c))
        shared += matches
        total_checked += N
# Expected matches by chance: N/N = 1 per char pair
expected_shared = total_checked / N
print(f"  Shared mappings: {shared} (expected by chance: ~{expected_shared:.0f})")
independence = shared < expected_shared * 3
print(f"  Result: {'PASS' if independence else 'FAIL'}")

# ── Test 5: Old layout bias check (what v2.0.0 would show) ───────────────────
print("\n[5] Confirming v2.0.0 bias is gone - 'E' frequency under old QWERTY wiring")
# In old QWERTY, 'E' maps to 'E' (identity for most letter positions)
# Check if current key-derived map treats all chars equally
lm_qwerty = km['layout_maps']['QWERTY']
# Measure how many chars map to themselves (identity mappings)
identity_count = sum(1 for c in ALPHA if lm_qwerty.get(c) == c)
expected_identity = 1  # By chance, ~68/68^2 = ~1 identity expected
print(f"  Identity mappings in QWERTY permutation: {identity_count} (random expect ~1)")
print(f"  Result: {'PASS' if identity_count <= 5 else 'FAIL -- too many identity mappings'}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
