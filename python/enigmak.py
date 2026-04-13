#!/usr/bin/env python3
"""
ENIGMAK v3.0.0-rc.3 - Command-line cipher machine
95-symbol multi-round substitution-permutation rotor cipher

Usage:
    python enigmak.py encrypt "YOUR MESSAGE" "KEY STRING"
    python enigmak.py decrypt "CIPHERTEXT"  "KEY STRING"
    python enigmak.py keygen
    python enigmak.py ioc "CIPHERTEXT"
    python enigmak.py keystrength "KEY STRING"

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
CIPHERTEXT_HEADER = 'E3|'
LEN_FIELD_LEN = 4
MAX_PAD_LEN = 16
U64_MASK = (1 << 64) - 1
CLIPBOARD_NORMALIZATION_MAP = {
    '\u2018': "'",
    '\u2019': "'",
    '\u201C': '"',
    '\u201D': '"',
    '\u2013': '-',
    '\u2014': '-',
    '\u2212': '-',
    '\u00A0': ' ',
    '\u2007': ' ',
    '\u202F': ' ',
    '\u2026': '...'
}

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
def encode_base95_int(value, width):
    if value < 0:
        raise ValueError('Base-95 encoding requires a non-negative integer')
    chars = ['0'] * width
    for i in range(width - 1, -1, -1):
        chars[i] = ALPHA[value % N]
        value //= N
    if value:
        raise ValueError(f'Value exceeds {width} base-95 characters')
    return ''.join(chars)

def decode_base95_int(text):
    value = 0
    for ch in text:
        idx = ALPHA.find(ch)
        if idx < 0:
            raise ValueError(f'Non-alphabet character in base-95 field: {repr(ch)}')
        value = value * N + idx
    return value

def encode_length_field(length):
    return encode_base95_int(length, LEN_FIELD_LEN)

def decode_length_field(field):
    if len(field) != LEN_FIELD_LEN:
        raise ValueError(f'Length field must be {LEN_FIELD_LEN} characters')
    return decode_base95_int(field)

def compute_checksum(plaintext, key_str, len_field=None):
    if len_field is None:
        len_field = encode_length_field(len(plaintext))
    v = hash_str64(len_field + '|' + plaintext + '|' + key_str + '|chk64')
    out = ''
    for i in range(CHECKSUM_LEN):
        v = lcg64(v ^ i)
        out += ALPHA[v % N]
    return out

def legacy_compute_checksum(plaintext, key_str):
    v = hash_str64(plaintext + '|' + key_str + '|chk64')
    out = ''
    for i in range(CHECKSUM_LEN):
        v = lcg64(v ^ i)
        out += ALPHA[v % N]
    return out

def legacy_checksum_pos(key_str, total_len):
    h = hash_str(key_str + 'chkpos')
    return h % max(1, total_len - CHECKSUM_LEN)

def legacy_embed_checksum(ciphertext, plaintext, key_str):
    chk = legacy_compute_checksum(plaintext, key_str)
    pos = legacy_checksum_pos(key_str, len(ciphertext) + CHECKSUM_LEN)
    return ciphertext[:pos] + chk + ciphertext[pos:]

def legacy_strip_checksum(ciphertext, key_str):
    pos = legacy_checksum_pos(key_str, len(ciphertext))
    chk = ciphertext[pos:pos + CHECKSUM_LEN]
    stripped = ciphertext[:pos] + ciphertext[pos + CHECKSUM_LEN:]
    return stripped, chk

def legacy_verify_checksum(plaintext, extracted_chk, key_str):
    return extracted_chk == legacy_compute_checksum(plaintext, key_str)

def compute_pad_length(plaintext, key_str):
    return hash_str64(key_str + '|' + plaintext + '|padlen') % MAX_PAD_LEN

def generate_padding(plaintext, key_str, pad_len=None):
    if pad_len is None:
        pad_len = compute_pad_length(plaintext, key_str)
    if pad_len == 0:
        return ''
    out = ''
    v = hash_str64(key_str + '|' + plaintext + '|padfill')
    for i in range(pad_len):
        v = lcg64(v ^ i)
        out += ALPHA[v % N]
    return out

def pack_rc3_payload(plaintext, key_str):
    len_field = encode_length_field(len(plaintext))
    checksum = compute_checksum(plaintext, key_str, len_field)
    padding = generate_padding(plaintext, key_str)
    return len_field + plaintext + checksum + padding

def unpack_rc3_payload(payload, key_str):
    min_len = LEN_FIELD_LEN + CHECKSUM_LEN
    if len(payload) < min_len:
        return {
            'plaintext': '',
            'verified': False,
            'checksum_ok': False,
            'padding_ok': False,
            'structure_ok': False,
            'length_field': '',
            'padding': '',
            'error': f'Payload too short for rc.3 package ({len(payload)} chars)'
        }

    len_field = payload[:LEN_FIELD_LEN]
    try:
        plaintext_len = decode_length_field(len_field)
    except ValueError as exc:
        return {
            'plaintext': '',
            'verified': False,
            'checksum_ok': False,
            'padding_ok': False,
            'structure_ok': False,
            'length_field': len_field,
            'padding': '',
            'error': str(exc)
        }

    remaining = payload[LEN_FIELD_LEN:]
    if plaintext_len > len(remaining) - CHECKSUM_LEN:
        return {
            'plaintext': '',
            'verified': False,
            'checksum_ok': False,
            'padding_ok': False,
            'structure_ok': False,
            'length_field': len_field,
            'padding': '',
            'error': f'Length field decodes to {plaintext_len}, but payload only has {len(remaining)} chars after the header'
        }

    plaintext = remaining[:plaintext_len]
    checksum = remaining[plaintext_len:plaintext_len + CHECKSUM_LEN]
    padding = remaining[plaintext_len + CHECKSUM_LEN:]
    checksum_ok = checksum == compute_checksum(plaintext, key_str, len_field)
    expected_pad_len = compute_pad_length(plaintext, key_str)
    expected_padding = generate_padding(plaintext, key_str, expected_pad_len)
    padding_ok = len(padding) == expected_pad_len and padding == expected_padding
    verified = checksum_ok and padding_ok
    return {
        'plaintext': plaintext,
        'verified': verified,
        'checksum_ok': checksum_ok,
        'padding_ok': padding_ok,
        'structure_ok': True,
        'length_field': len_field,
        'padding': padding,
        'error': None if verified else 'Checksum or padding verification failed'
    }

def encrypt_text(plaintext, key_str):
    k = parse_key(key_str)
    payload = pack_rc3_payload(plaintext, k['key_str'])
    cipher = process(payload, k['steck_pairs'], k['rotors'],
                     k['enabled'], k['user_rounds'], k['nonce'], decrypt=False)
    return CIPHERTEXT_HEADER + cipher

def decrypt_text(ciphertext, key_str):
    diagnostics = analyze_ciphertext(ciphertext)
    k = parse_key(key_str)

    if ciphertext.startswith(CIPHERTEXT_HEADER):
        body = ciphertext[len(CIPHERTEXT_HEADER):]
        payload = process(body, k['steck_pairs'], k['rotors'],
                          k['enabled'], k['user_rounds'], k['nonce'], decrypt=True)
        unpacked = unpack_rc3_payload(payload, k['key_str'])
        unpacked.update({
            'format': 'rc.3',
            'diagnostics': diagnostics,
            'payload': payload
        })
        return unpacked

    stripped, chk = legacy_strip_checksum(ciphertext, k['key_str'])
    plaintext = process(stripped, k['steck_pairs'], k['rotors'],
                        k['enabled'], k['user_rounds'], k['nonce'], decrypt=True)
    verified = legacy_verify_checksum(plaintext, chk, k['key_str'])
    return {
        'plaintext': plaintext,
        'verified': verified,
        'checksum_ok': verified,
        'padding_ok': True,
        'structure_ok': True,
        'length_field': '',
        'padding': '',
        'error': None if verified else 'Checksum mismatch',
        'format': 'rc.2-legacy',
        'diagnostics': diagnostics,
        'payload': stripped
    }


def format_cipher_char(ch):
    if ch == ' ':
        return '[space]'
    if ch == '\n':
        return '\\n'
    if ch == '\r':
        return '\\r'
    if ch == '\t':
        return '\\t'
    return ch


def summarize_cipher_issues(entries):
    shown = []
    for pos, char, replacement in entries[:4]:
        base = f'{format_cipher_char(char)}@{pos}'
        shown.append(base if replacement is None else f'{base}->{format_cipher_char(replacement)}')
    if len(entries) > 4:
        shown.append(f'+{len(entries) - 4} more')
    return ', '.join(shown)


def analyze_ciphertext(text):
    non_ascii = []
    normalized = []
    controls = []
    outside_alpha_count = 0
    for pos, ch in enumerate(text, start=1):
        if ch in ALPHA:
            continue
        outside_alpha_count += 1
        replacement = CLIPBOARD_NORMALIZATION_MAP.get(ch)
        if replacement is not None:
            normalized.append((pos, ch, replacement))
        if ch in '\r\n\t':
            controls.append((pos, ch, None))
        if ord(ch) > 127:
            non_ascii.append((pos, ch, replacement))
    warnings = []
    if normalized:
        warnings.append(f'Suspicious clipboard-normalized punctuation: {summarize_cipher_issues(normalized)}')
    elif non_ascii:
        warnings.append(f'Non-ASCII ciphertext characters detected: {summarize_cipher_issues(non_ascii)}')
    if controls:
        warnings.append(f'Whitespace/control characters detected: {summarize_cipher_issues(controls)}')
    return {
        'length': len(text),
        'outside_alpha_count': outside_alpha_count,
        'non_ascii': non_ascii,
        'normalized': normalized,
        'controls': controls,
        'warnings': warnings,
    }

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

def _permutation_count(n, k):
    total = 1
    for i in range(k):
        total *= (n - i)
    return total

def _steck_pairing_count(alpha_size, num_pairs):
    if num_pairs == 0:
        return 1
    total = 1
    remaining = alpha_size
    for _ in range(num_pairs):
        total *= math.comb(remaining, 2)
        remaining -= 2
    return total // math.factorial(num_pairs)

def calc_key_strength(parsed_key):
    enabled_count = len(parsed_key['enabled'])
    rotor_count = len(parsed_key['rotors'])
    pair_count = len(parsed_key['steck_pairs'])
    layout_combos = _permutation_count(10, enabled_count)
    rotor_combos = (enabled_count * N) ** rotor_count
    steck_combos = _steck_pairing_count(N, pair_count)
    round_combos = 999
    nonce_combos = (N ** 3) if parsed_key['nonce'] else 1

    total = layout_combos * rotor_combos * steck_combos * round_combos * nonce_combos
    components = {
        'layouts': {'count': layout_combos, 'bits': math.log2(layout_combos)},
        'rotors': {'count': rotor_combos, 'bits': math.log2(rotor_combos) if rotor_combos > 1 else 0.0},
        'steck': {'count': steck_combos, 'bits': math.log2(steck_combos) if steck_combos > 1 else 0.0},
        'rounds': {'count': round_combos, 'bits': math.log2(round_combos)},
        'nonce': {'count': nonce_combos, 'bits': math.log2(nonce_combos) if nonce_combos > 1 else 0.0},
    }
    km = compute_key_material(parsed_key['steck_pairs'], parsed_key['rotors'],
                              parsed_key['enabled'], parsed_key['user_rounds'])
    profile = {
        'enabled_layouts': list(parsed_key['enabled']),
        'enabled_count': enabled_count,
        'rotor_count': rotor_count,
        'rotor_layouts': [r['layout'] for r in parsed_key['rotors']],
        'steck_pairs': pair_count,
        'base_rounds': parsed_key['user_rounds'],
        'final_rounds': km['rounds'],
        'nonce_present': bool(parsed_key['nonce']),
        'nonce': parsed_key['nonce'] or '-',
    }
    return {
        'family_bits': math.log2(total),
        'total': total,
        'components': components,
        'profile': profile,
    }

# ── Key generation ────────────────────────────────────────────────────────────
def generate_key(num_rotors=None, num_steck_pairs=None, num_layouts=None, user_rounds=None, include_nonce=None):
    rng = secrets.SystemRandom()
    if num_layouts is None:
        num_layouts = secrets.randbelow(len(LAYOUT_NAMES)) + 1
    if num_rotors is None:
        num_rotors = secrets.randbelow(13) + 1
    if num_steck_pairs is None:
        num_steck_pairs = secrets.randbelow((N // 2) + 1)
    if user_rounds is None:
        user_rounds = secrets.randbelow(999) + 1
    if include_nonce is None:
        include_nonce = bool(secrets.randbelow(2))

    if not 1 <= num_layouts <= len(LAYOUT_NAMES):
        raise ValueError(f'num_layouts must be between 1 and {len(LAYOUT_NAMES)}')
    if not 1 <= num_rotors <= 13:
        raise ValueError('num_rotors must be between 1 and 13')
    if not 0 <= num_steck_pairs <= N // 2:
        raise ValueError(f'num_steck_pairs must be between 0 and {N // 2}')
    if not 1 <= user_rounds <= 999:
        raise ValueError('user_rounds must be between 1 and 999')

    enabled_idxs = rng.sample(range(len(LAYOUT_NAMES)), num_layouts)
    enabled = [LAYOUT_NAMES[i] for i in enabled_idxs]
    rotors = [
        {'layout': LAYOUT_NAMES[rng.choice(enabled_idxs)], 'pos': secrets.randbelow(N)}
        for _ in range(num_rotors)
    ]
    chars = list(ALPHA)
    rng.shuffle(chars)
    steck_pairs = [(chars[i * 2], chars[i * 2 + 1]) for i in range(num_steck_pairs)]
    nonce = ''
    if include_nonce:
        nonce = ''.join(ALPHA[secrets.randbelow(N)] for _ in range(3))
    return encode_key(enabled, rotors, steck_pairs, user_rounds, nonce)

# ── CLI ───────────────────────────────────────────────────────────────────────
def cmd_encrypt(plaintext, key_str):
    print(encrypt_text(plaintext, key_str))

def cmd_decrypt(ciphertext, key_str):
    result = decrypt_text(ciphertext, key_str)
    diagnostics = result['diagnostics']
    for warning in diagnostics['warnings']:
        print(f'[!] {warning}', file=sys.stderr)
    print(result['plaintext'])
    print(f'[i] Format: {result["format"]}', file=sys.stderr)
    if result['verified']:
        print('[OK] Checksum and padding verified', file=sys.stderr)
    else:
        print('[X] Verification failed - wrong key or corrupted message', file=sys.stderr)
        if result['format'] == 'rc.3':
            if not result['structure_ok']:
                print(f'[!] rc.3 package parse failed: {result["error"]}', file=sys.stderr)
            else:
                if not result['checksum_ok']:
                    print('[!] rc.3 checksum mismatch', file=sys.stderr)
                if not result['padding_ok']:
                    print('[!] rc.3 padding mismatch', file=sys.stderr)
        if diagnostics['outside_alpha_count'] > 0:
            print('[!] Characters outside the ENIGMAK alphabet do not advance rotor state and can desync the rest of the message.', file=sys.stderr)
        print(f'[!] Ciphertext received: {diagnostics["length"]} chars. Compare length and watch for dropped punctuation such as backticks (`).', file=sys.stderr)

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
    strength = calc_key_strength(k)
    profile = strength['profile']
    print(f'Key family strength: {strength["family_bits"]:.1f} bits (~2^{strength["family_bits"]:.1f})')
    print(f'Keyspace: {strength["total"]:.3e}')
    print('Family-size breakdown:')
    print(f'  layouts: {strength["components"]["layouts"]["bits"]:.3f} bits')
    print(f'  rotors:  {strength["components"]["rotors"]["bits"]:.3f} bits')
    print(f'  steck:   {strength["components"]["steck"]["bits"]:.3f} bits')
    print(f'  rounds:  {strength["components"]["rounds"]["bits"]:.3f} bits')
    print(f'  nonce:   {strength["components"]["nonce"]["bits"]:.3f} bits')
    print('Current key profile:')
    print(f'  enabled layouts: {profile["enabled_count"]} ({",".join(profile["enabled_layouts"])})')
    print(f'  rotors: {profile["rotor_count"]} ({",".join(profile["rotor_layouts"])})')
    print(f'  steck pairs: {profile["steck_pairs"]}')
    print(f'  base rounds: {profile["base_rounds"]}')
    print(f'  final rounds: {profile["final_rounds"]}')
    print(f'  nonce: {profile["nonce"]}')

def main():
    parser = argparse.ArgumentParser(
        description='ENIGMAK v3.0.0-rc.3 - 95-symbol rotor cipher',
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
