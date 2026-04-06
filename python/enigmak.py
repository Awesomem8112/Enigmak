#!/usr/bin/env python3
"""
ENIGMAK v3.0.0-rc.2 - Command-line cipher machine
95-symbol multi-round substitution-permutation rotor cipher

Usage:
    python enigmak.py encrypt "YOUR MESSAGE" "KEY STRING"
    python enigmak.py decrypt "CIPHERTEXT"  "KEY STRING"
    python enigmak.py keygen
    python enigmak.py ioc "CIPHERTEXT"

See README.md and SPECIFICATION.md for full details.
"""

import sys
import math
import hashlib
import secrets
import argparse

# ── Alphabet ──────────────────────────────────────────────────────────────────
ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\\\',./' + '!@#$%^&*()_+{}|:"<>?`~' + 'abcdefghijklmnopqrstuvwxyz '
N = len(ALPHA)  # 95
assert N == 95
STEP_MASK_ACTIVE = 66
CHECKSUM_LEN = 10
U64_MASK = (1 << 64) - 1

LAYOUT_NAMES = ['QWERTY','Colemak','Colemak-DH','Dvorak','Workman',
                'Norman','Asset','Halmak','AZERTY','QWERTZ']

LAYOUT_DEFS = {
    'QWERTY':    {'top':'QWERTYUIOP', 'home':'ASDFGHJKL;', 'bot':'ZXCVBNM'},
    'Colemak':   {'top':'QWFPGJLUY;', 'home':'ARSTDHNEIO', 'bot':'ZXCVBKM'},
    'Colemak-DH':{'top':'QWFPBJLUY;', 'home':'ARSTGMNEIO', 'bot':'ZXCDVKH'},
    'Dvorak':    {'top':"',.PYFGCRL", 'home':'AOEUIDHTNS', 'bot':';QJKXBM'},
    'Workman':   {'top':'QDRWBJFUP;', 'home':'ASHTGYNEOI', 'bot':'ZXMCVKL'},
    'Norman':    {'top':'QWDFKJURL;', 'home':'ASETGYNIOH', 'bot':'ZXCVBPM'},
    'Asset':     {'top':'QWJFGYPUL;', 'home':'ASETDHNIOR', 'bot':'ZXCVBKM'},
    'Halmak':    {'top':'WLRBJZFUO;', 'home':'SHNTMEDAIC', 'bot':'QGVXPKY'},
    'AZERTY':    {'top':'AZERTYUIOP', 'home':'QSDFGHJKL;', 'bot':'WXCVBNM'},
    'QWERTZ':    {'top':'QWERTZUIOP', 'home':'ASDFGHJKL;', 'bot':'YXCVBNM'},
}

QWERTY_TOP  = 'QWERTYUIOP'
QWERTY_HOME = 'ASDFGHJKL;'
QWERTY_BOT  = 'ZXCVBNM'

# ── Build substitution maps ───────────────────────────────────────────────────
def build_map(layout_name):
    d = LAYOUT_DEFS[layout_name]
    m = {}
    for q, c in zip(QWERTY_TOP,  d['top']):
        if c.upper() in ALPHA: m[q] = c.upper()
    for q, c in zip(QWERTY_HOME, d['home']):
        if c.upper() in ALPHA: m[q] = c.upper()
    for q, c in zip(QWERTY_BOT,  d['bot']):
        if c.upper() in ALPHA: m[q] = c.upper()
    return m

MAPS     = {n: build_map(n) for n in LAYOUT_NAMES}
INV_MAPS = {n: {v:k for k,v in MAPS[n].items()} for n in LAYOUT_NAMES}

# ── Hash primitive (FNV-1a inspired) ─────────────────────────────────────────
def hash_str(s):
    h = 2166136261
    for c in s:
        h ^= ord(c)
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def lcg(v):
    return (v * 1664525 + 1013904223) & 0xFFFFFFFF

def lcg64(v):
    return (v * 6364136223846793005 + 1442695040888963407) & U64_MASK

def hash_str64(s):
    h = 0xCBF29CE484222325
    for b in s.encode('utf-8'):
        h ^= b
        h = (h * 0x100000001B3) & U64_MASK
    return h

def rotor_state_hash(rotors):
    """Compute a digest of current rotor state for position offset feedback."""
    h = 2166136261
    for r in rotors:
        h ^= r['pos'] * 73
        h = (h * 16777619) & 0xFFFFFFFF
    return h

# ── Key material derivation ───────────────────────────────────────────────────
def compute_key_material(steck_pairs, rotors, enabled_layouts, user_rounds):
    S = sum(
        (min(ALPHA.index(a), ALPHA.index(b)) * N + max(ALPHA.index(a), ALPHA.index(b)))
        for a, b in steck_pairs
    )
    R = sum(r['pos'] for r in rotors)
    L = sum(LAYOUT_NAMES.index(n) for n in enabled_layouts)
    rounds = ((S + R + L + user_rounds) % 999) + 1
    key_sum = (S * 31 + R * 17 + L * 13) & 0xFFFFFFFF

    # Step mask (~69% of positions active)
    step_pos = list(range(N))
    v = (key_sum ^ 0x5A5A5A5A) & 0xFFFFFFFF
    for i in range(N - 1, 0, -1):
        v = lcg(v)
        j = v % (i + 1)
        step_pos[i], step_pos[j] = step_pos[j], step_pos[i]
    step_mask = [False] * N
    for p in step_pos[:STEP_MASK_ACTIVE]:
        step_mask[p] = True

    # Diffusion transposition
    trans_perm = list(range(N))
    v = (key_sum ^ 0xDEAD1234) & 0xFFFFFFFF
    for i in range(N - 1, 0, -1):
        v = lcg(v)
        j = v % (i + 1)
        trans_perm[i], trans_perm[j] = trans_perm[j], trans_perm[i]
    inv_trans_perm = [0] * N
    for i, x in enumerate(trans_perm):
        inv_trans_perm[x] = i

    layout_key_base = key_sum % N

    # Key-derived layout permutations -- replaces fixed keyboard layout wirings
    # Each layout gets a unique bijective permutation of ALPHA seeded from key material
    # This eliminates ergonomic typing bias from the substitution tables
    layout_maps = {}
    inv_layout_maps = {}
    for li, name in enumerate(LAYOUT_NAMES):
        perm = list(range(N))
        seed = (key_sum ^ (li * 0x9E3779B9 + 0xABCD1234)) & 0xFFFFFFFF
        v2 = seed
        for i in range(N - 1, 0, -1):
            v2 = lcg(v2)
            j = v2 % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        layout_maps[name] = {ALPHA[i]: ALPHA[perm[i]] for i in range(N)}
        inv_layout_maps[name] = {ALPHA[perm[i]]: ALPHA[i] for i in range(N)}

    # Whitening seed: separate LCG seed for position whitening layer
    whitening_seed = (key_sum ^ 0xC0FFEE42) & 0xFFFFFFFF
    return {
        'rounds': rounds, 'key_sum': key_sum,
        'step_mask': step_mask,
        'trans_perm': trans_perm, 'inv_trans_perm': inv_trans_perm,
        'layout_key_base': layout_key_base,
        'layout_maps': layout_maps, 'inv_layout_maps': inv_layout_maps,
        'whitening_seed': whitening_seed
    }

def keyed_layout_offset(layout_name, layout_key_base):
    return (LAYOUT_NAMES.index(layout_name) * 7 + layout_key_base) % N

# ── Rotor mechanics ───────────────────────────────────────────────────────────
def rotor_shift(rotors):
    val = 0
    for i, r in enumerate(rotors):
        val += r['pos'] * (N ** (len(rotors) - 1 - i))
    return int(val) % N

def advance_rotors(rotors, char_idx, step_mask):
    if not step_mask[char_idx % N]:
        return [dict(r) for r in rotors]
    rs = [dict(r) for r in rotors]
    rs[-1]['pos'] = (rs[-1]['pos'] + 1) % N
    for i in range(len(rs) - 1, 0, -1):
        if rs[i]['pos'] == 0:
            rs[i-1]['pos'] = (rs[i-1]['pos'] + 1) % N
    return rs

def apply_nonce(rotors, nonce):
    if not nonce:
        return rotors
    result = []
    for i, r in enumerate(rotors):
        off = ALPHA.index(nonce[i]) if i < len(nonce) else 0
        result.append({**r, 'pos': (r['pos'] + off) % N})
    return result

# ── Substitution layers ───────────────────────────────────────────────────────
def apply_layout(c, layout_name, shift, invert, layout_maps, inv_layout_maps):
    if not invert:
        x = layout_maps[layout_name].get(c, c)
        if x in ALPHA:
            x = ALPHA[(ALPHA.index(x) + shift) % N]
        return x
    else:
        x = c
        if x in ALPHA:
            x = ALPHA[(ALPHA.index(x) - shift) % N]
        x = inv_layout_maps[layout_name].get(x, x)
        return x

def plug_fwd(c, layouts, layout_maps):
    for n in layouts:
        c = layout_maps[n].get(c, c)
    return c

def plug_inv(c, layouts, inv_layout_maps):
    for n in reversed(layouts):
        c = inv_layout_maps[n].get(c, c)
    return c

# ── Core encryption/decryption ────────────────────────────────────────────────
def process(text, steck_pairs, rotors, enabled_layouts, user_rounds, nonce='', decrypt=False):
    km = compute_key_material(steck_pairs, rotors, enabled_layouts, user_rounds)
    rds = km['rounds']

    # Steck map
    steck_map = {c: c for c in ALPHA}
    for a, b in steck_pairs:
        steck_map[a] = b
        steck_map[b] = a

    rotor_set = {r['layout'] for r in rotors}
    el = list(enabled_layouts)
    unused = [n for n in el if n not in rotor_set]
    rs = apply_nonce([dict(r) for r in rotors], nonce)
    lm = km['layout_maps']
    ilm = km['inv_layout_maps']

    # Position whitening: LCG-derived offset per character, period 2^32
    wstate = km['whitening_seed']
    result = []
    ci = 0
    for c in text:
        if c not in ALPHA:
            result.append(c)
            continue

        ss = rotor_shift(rs)
        step_layouts = [el[r % len(el)] for r in range(rds)]
        # Position offset: rotor state feedback breaks monocharacter oracle
        # Same plaintext produces different rotor queries each encryption due to state dependency
        rs_hash = rotor_state_hash(rs)
        pos_offset = (km['key_sum'] * 37 + ci * 13 + rs_hash) % N
        # Mix absolute position (ci) into shifts - breaks mod-N periodicity
        step_shifts = [(ss + r + ci + pos_offset + keyed_layout_offset(step_layouts[r], km['layout_key_base'])) % N
                       for r in range(rds)]
        scramble_shifts = [(ss + rds + i + ci + pos_offset + keyed_layout_offset(unused[i], km['layout_key_base'])) % N
                           for i in range(len(unused))]

        x = c
        if not decrypt:
            x = steck_map[x]
            x = plug_fwd(x, unused, lm)
            for r in range(rds):
                x = apply_layout(x, step_layouts[r], step_shifts[r], False, lm, ilm)
            if x in ALPHA:
                x = ALPHA[km['trans_perm'][ALPHA.index(x)]]
            for i, n in enumerate(unused):
                x = apply_layout(x, n, scramble_shifts[i], False, lm, ilm)
            x = plug_fwd(x, unused, lm)
            x = steck_map[x]
            # Position whitening: add key+position LCG offset - breaks mod-N periodicity
            wstate = lcg(wstate)
            x = ALPHA[(ALPHA.index(x) + wstate % N) % N]
        else:
            # Remove position whitening first (subtract same LCG offset)
            wstate = lcg(wstate)
            x = ALPHA[(ALPHA.index(x) - wstate % N) % N]
            x = steck_map[x]
            x = plug_inv(x, unused, ilm)
            for i in range(len(unused) - 1, -1, -1):
                x = apply_layout(x, unused[i], scramble_shifts[i], True, lm, ilm)
            if x in ALPHA:
                x = ALPHA[km['inv_trans_perm'][ALPHA.index(x)]]
            for r in range(rds - 1, -1, -1):
                x = apply_layout(x, step_layouts[r], step_shifts[r], True, lm, ilm)
            x = plug_inv(x, unused, ilm)
            x = steck_map[x]

        result.append(x)
        rs = advance_rotors(rs, ci, km['step_mask'])
        ci += 1

    return ''.join(result)

# ── Checksum ──────────────────────────────────────────────────────────────────
def compute_checksum(plaintext, key_str):
    v = hash_str64(plaintext + '|' + key_str + '|chk64')
    out = ''
    for i in range(CHECKSUM_LEN):
        v = lcg64(v ^ i)
        out += ALPHA[v % N]
    return out

def checksum_pos(key_str, total_len):
    h = hash_str(key_str + 'chkpos')
    return h % max(1, total_len - CHECKSUM_LEN)

def embed_checksum(ciphertext, plaintext, key_str):
    chk = compute_checksum(plaintext, key_str)
    pos = checksum_pos(key_str, len(ciphertext) + CHECKSUM_LEN)
    return ciphertext[:pos] + chk + ciphertext[pos:]

def strip_checksum(ciphertext, key_str):
    pos = checksum_pos(key_str, len(ciphertext))
    chk = ciphertext[pos:pos + CHECKSUM_LEN]
    stripped = ciphertext[:pos] + ciphertext[pos + CHECKSUM_LEN:]
    return stripped, chk

def verify_checksum(plaintext, extracted_chk, key_str):
    expected = compute_checksum(plaintext, key_str)
    return extracted_chk == expected

# ── Key parsing ───────────────────────────────────────────────────────────────
def parse_key(key_str):
    parts = key_str.strip().split()
    if len(parts) not in (4, 5):
        raise ValueError(f'Expected 4 or 5 sections, got {len(parts)}')

    enabled_str, rotor_str, steck_str, u_str = parts[:4]
    nonce_str = parts[4] if len(parts) == 5 else ''

    enabled = [LAYOUT_NAMES[int(c)] for c in enabled_str]
    if not enabled:
        raise ValueError('No layouts enabled')

    rotors = []
    for i in range(0, len(rotor_str), 3):
        lidx = int(rotor_str[i])
        pos  = int(rotor_str[i+1:i+3])
        rotors.append({'layout': LAYOUT_NAMES[lidx], 'pos': pos})
    if not rotors:
        raise ValueError('No rotors specified')

    steck_pairs = []
    if steck_str != '0':
        for i in range(0, len(steck_str), 4):
            ai = int(steck_str[i:i+2])
            bi = int(steck_str[i+2:i+4])
            steck_pairs.append((ALPHA[ai], ALPHA[bi]))

    user_rounds = int(u_str)

    nonce = ''
    if nonce_str:
        for i in range(0, len(nonce_str), 2):
            nonce += ALPHA[int(nonce_str[i:i+2])]

    return {
        'enabled': enabled,
        'rotors': rotors,
        'steck_pairs': steck_pairs,
        'user_rounds': user_rounds,
        'nonce': nonce,
        'key_str': key_str.strip()
    }

def encode_key(enabled, rotors, steck_pairs, user_rounds, nonce=''):
    enabled_str = ''.join(str(LAYOUT_NAMES.index(n)) for n in enabled)
    rotor_str   = ''.join(f'{LAYOUT_NAMES.index(r["layout"])}{r["pos"]:02d}' for r in rotors)
    if steck_pairs:
        steck_str = ''.join(
            f'{min(ALPHA.index(a),ALPHA.index(b)):02d}{max(ALPHA.index(a),ALPHA.index(b)):02d}'
            for a, b in sorted(steck_pairs, key=lambda p: min(ALPHA.index(p[0]),ALPHA.index(p[1])))
        )
    else:
        steck_str = '0'
    u_str = f'{user_rounds:03d}'
    base = f'{enabled_str} {rotor_str} {steck_str} {u_str}'
    if nonce:
        nonce_str = ''.join(f'{ALPHA.index(c):02d}' for c in nonce)
        return f'{base} {nonce_str}'
    return base

# ── IoC ───────────────────────────────────────────────────────────────────────
def calc_ioc(text):
    freq = {}
    for c in ALPHA:
        freq[c] = 0
    for c in text:
        if c in freq:
            freq[c] += 1
    L = sum(freq.values())
    if L < 2:
        return 0.0
    num = sum(n * (n - 1) for n in freq.values())
    return num / (L * (L - 1))

def calc_key_strength(parsed_key):
    """
    Calculate theoretical key strength (bits) for a parsed key.
    Components:
      - Enabled layouts: C(10, k) where k = len(enabled)
      - Rotors: (10 * N)^n where n = len(rotors)
      - Stecker pairs: depends on number of pairs (each pair removes 2! permutations)
      - User rounds: 999 possibilities (1-999)
      - Nonce: optional N^3 possibilities
    Returns: (bits, keyspace_str)
    """
    import math
    
    # Layouts: P(10, k) ordered permutations -- layout order matters in ENIGMAK
    k = len(parsed_key['enabled'])
    layout_combos = math.factorial(10) // math.factorial(10 - k)
    
    # Rotors: each rotor can be any of 10 layouts at N positions
    num_rotors = len(parsed_key['rotors'])
    rotor_combos = (10 * N) ** num_rotors
    
    # Stecker: C(N, 2k) * k! for k pairs (symmetric, so divided by 2^k)
    # But we store as unordered pairs, so it's just ways to choose 2k chars from N
    # For k pairs: C(N, 2k) * (2k)! / (2^k * k!) = C(N, 2k) * (2k-1)!! 
    # Simpler: number of ways to partition 2k items into k unordered pairs
    num_pairs = len(parsed_key['steck_pairs'])
    if num_pairs == 0:
        steck_combos = 1
    else:
        # C(N, 2*num_pairs) * (2*num_pairs-1)!! / num_pairs!
        # But we implement: C(N, 2k) for choosing chars, then partition into pairs
        steck_combos = 1
        remaining = N
        for i in range(num_pairs):
            steck_combos *= math.comb(remaining, 2)
            remaining -= 2
        steck_combos //= math.factorial(num_pairs)  # unordered pairs
    
    # Rounds: 999 (1-999)
    round_combos = 999
    
    # Nonce: N^3 if present
    nonce_combos = (N ** 3) if parsed_key['nonce'] else 1
    
    total = layout_combos * rotor_combos * steck_combos * round_combos * nonce_combos
    bits = math.log2(total)
    
    return bits, total

# ── Key generation ────────────────────────────────────────────────────────────
def generate_key(num_rotors=3, num_steck_pairs=8, num_layouts=4):
    enabled_idxs = secrets.SystemRandom().sample(range(10), num_layouts)
    enabled = [LAYOUT_NAMES[i] for i in enabled_idxs]
    rotors = [
        {'layout': LAYOUT_NAMES[secrets.choice(enabled_idxs)], 'pos': secrets.randbelow(N)}
        for _ in range(num_rotors)
    ]
    chars = list(ALPHA)
    secrets.SystemRandom().shuffle(chars)
    steck_pairs = [(chars[i*2], chars[i*2+1]) for i in range(num_steck_pairs)]
    user_rounds = secrets.randbelow(999) + 1
    nonce_chars = [ALPHA[secrets.randbelow(N)] for _ in range(3)]
    nonce = ''.join(nonce_chars)
    return encode_key(enabled, rotors, steck_pairs, user_rounds, nonce)

# ── CLI ───────────────────────────────────────────────────────────────────────
def cmd_encrypt(plaintext, key_str):
    k = parse_key(key_str)
    cipher = process(plaintext, k['steck_pairs'], k['rotors'],
                     k['enabled'], k['user_rounds'], k['nonce'], decrypt=False)
    result = embed_checksum(cipher, plaintext, k['key_str'])
    print(result)

def cmd_decrypt(ciphertext, key_str):
    k = parse_key(key_str)
    stripped, chk = strip_checksum(ciphertext, k['key_str'])
    plain = process(stripped, k['steck_pairs'], k['rotors'],
                    k['enabled'], k['user_rounds'], k['nonce'], decrypt=True)
    verified = verify_checksum(plain, chk, k['key_str'])
    print(plain)
    if verified:
        print('[✓ Checksum verified]', file=sys.stderr)
    else:
        print('[✗ Checksum mismatch - wrong key or corrupted message]', file=sys.stderr)

def cmd_keygen():
    key = generate_key()
    print(key)

def cmd_ioc(ciphertext):
    ioc = calc_ioc(ciphertext)
    floor = 1 / N
    print(f'IoC:   {ioc:.6f}')
    print(f'Floor: {floor:.6f} (1/{N})')
    print(f'Delta: {ioc - floor:+.6f}')

def cmd_keystrength(key_str):
    k = parse_key(key_str)
    bits, keyspace = calc_key_strength(k)
    print(f'Key strength: {bits:.1f} bits (~2^{bits:.1f})')
    print(f'Keyspace: {keyspace:.3e}')

def main():
    parser = argparse.ArgumentParser(
        description='ENIGMAK v3.0.0-rc.2 - 95-symbol rotor cipher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = parser.add_subparsers(dest='command')

    enc = sub.add_parser('encrypt', help='Encrypt plaintext')
    enc.add_argument('plaintext')
    enc.add_argument('key')

    dec = sub.add_parser('decrypt', help='Decrypt ciphertext')
    dec.add_argument('ciphertext')
    dec.add_argument('key')

    sub.add_parser('keygen', help='Generate a random key')

    ioc_p = sub.add_parser('ioc', help='Calculate Index of Coincidence')
    ioc_p.add_argument('ciphertext')

    strength_p = sub.add_parser('keystrength', help='Calculate key strength in bits')
    strength_p.add_argument('key')

    args = parser.parse_args()

    if args.command == 'encrypt':
        cmd_encrypt(args.plaintext, args.key)
    elif args.command == 'decrypt':
        cmd_decrypt(args.ciphertext, args.key)
    elif args.command == 'keygen':
        cmd_keygen()
    elif args.command == 'ioc':
        cmd_ioc(args.ciphertext)
    elif args.command == 'keystrength':
        cmd_keystrength(args.key)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
