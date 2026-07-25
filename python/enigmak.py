#!/usr/bin/env python3
"""
ENIGMAK v3.0.0-rc.8 - Command-line cipher machine
161-symbol multi-round substitution-permutation rotor cipher

Usage:
    python enigmak.py encrypt "YOUR MESSAGE" "KEY STRING"
    python enigmak.py encrypt --to-clipboard "YOUR MESSAGE" "KEY STRING"
    python enigmak.py encrypt --materialize "YOUR MESSAGE" "KEY STRING"
    python enigmak.py encrypt --to-clipboard --materialize "YOUR MESSAGE" "KEY STRING"
    python enigmak.py decrypt "CIPHERTEXT"  "KEY STRING"
    python enigmak.py decrypt --materialize "CIPHERTEXT" "KEY STRING"
    python enigmak.py decrypt --from-clipboard "KEY STRING"
    python enigmak.py decrypt --materialize --from-clipboard "KEY STRING"
    python enigmak.py keygen
    python enigmak.py ioc "CIPHERTEXT"
    python enigmak.py ioc --from-clipboard
    python enigmak.py keystrength "KEY STRING"
    python enigmak.py interactive

    --materialize (encrypt/decrypt only): emit metadata as 44 visible carrier
    characters instead of zero-width carriers. Use when terminals or copy/paste
    paths strip invisible metadata. Interactive mode prompts for this option.

See README.md and SPECIFICATION.md for full details.
"""

import sys
if hasattr(sys.stdin, 'reconfigure'):
    sys.stdin.reconfigure(encoding='utf-8')
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

import argparse
import math
import secrets

LEGACY_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\\\',./' + \
    '!@#$%^&*()_+{}|:"<>?`~' + 'abcdefghijklmnopqrstuvwxyz '
EXTENDED_ALPHA = 'ÀàÁáÂâÃãÄäÅåÆæÇçÈèÉéÊêËëÌìÍíÎîÏïÐðÑñÒòÓóÔôÕõÖöØøÙùÚúÛûÜüÝýÞþßÿ¡¿Œœ'
ALPHA = LEGACY_ALPHA + EXTENDED_ALPHA + '\n'
# NOTE: Newline (\n) at index 161 is permanently layout-unassigned (no physical
# QWERTY key produces it directly) but participates fully in all keyed
# permutations and cipher operations, so multi-line plaintext round-trips
# without special handling. Characters above index 94 (U+00C0 and beyond) are
# European extended characters that are assigned by the national language
# layouts added in rc.7 and participate in all cipher operations.
LEGACY_N = len(LEGACY_ALPHA)
N = len(ALPHA)
assert LEGACY_N == 95
assert N == 162
STEP_MASK_ACTIVE = 66
ROUND_MINIMUM = 10
CHECKSUM_LEN = 10
LEN_FIELD_LEN = 4
MAX_PAD_LEN = 16
LEGACY_RC3_HEADER = 'E3|'
RC4_FORMAT_TAG = 'H'
RC4_VERSION_CHAR = '4'
RC6_VERSION_CHAR = '5'
HIDDEN_METADATA_LEN = 1 + CHECKSUM_LEN
HIDDEN_CHUNK_LEN = 4
HIDDEN_SYMBOL_COUNT = HIDDEN_METADATA_LEN * HIDDEN_CHUNK_LEN
GENERIC_DECRYPT_ERROR = 'Decryption failed.'
MAX_CORRUPT_LEN = 4096
MIN_GENERATED_KEY_BITS = 256
KEY_V6_PREFIX = 'K6:'
K6_ENCRYPT_REQUIRED_ERROR = 'Encryption requires a K6: key. Legacy keys remain decrypt-only.'
BASE36_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
CARRIER_WILDCARD_DOMAIN = '|carrier-wildcards|'
STREAM_SCHEDULE_DOMAIN = '|stream-schedule|'
U64_MASK = (1 << 64) - 1
FNV64_OFFSET = 0xCBF29CE484222325
FNV64_PRIME = 0x100000001B3
STEP_MASK_SEED_CONST = 0x5A5A5A5AA55AA55A
TRANS_SEED_CONST = 0xDEAD1234CAFEBABE
LAYOUT_SEED_MIX = 0x9E3779B97F4A7C15
LAYOUT_SEED_CONST = 0xABCD1234BADC0FFE
WHITENING_SEED_CONST = 0xC0FFEE42D15EA5E5
ZERO_WIDTH_SYMBOLS = ['\u200B', '\u200C', '\u200D', '\u2060']
ZERO_WIDTH_SET = set(ZERO_WIDTH_SYMBOLS)
ZERO_WIDTH_LABELS = {
    '\u200B': 'ZWSP',
    '\u200C': 'ZWNJ',
    '\u200D': 'ZWJ',
    '\u2060': 'WJ',
}
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

LAYOUT_NAMES = ['QWERTY', 'Colemak', 'Colemak-DH', 'Dvorak', 'Workman',
                'Norman', 'Asset', 'Halmak', 'AZERTY', 'QWERTZ',
                # National language layouts sourced from Microsoft Windows DLLs.
                'Spanish', 'Swedish', 'Norwegian', 'Danish', 'Icelandic', 'Belgian']
LEGACY_LAYOUT_NAMES = LAYOUT_NAMES[:10]

LAYOUT_DEFS = {
    'QWERTY': {
        'top_top': '`1234567890-=~!@#$%^&*()_+',
        'top': 'qwertyuiop[]\\QWERTYUIOP{}|',
        'home': "asdfghjkl;'ASDFGHJKL:\"",
        'bot': 'zxcvbnm,./ZXCVBNM<>?',
    },
    'Colemak': {
        'top_top': '`1234567890-=~!@#$%^&*()_+',
        'top': 'qwfpgjluy;[]\\QWFPGJLUY:{}|',
        'home': "arstdhneio'ARSTDHNEIO\"",
        'bot': 'zxcvbkm,./ZXCVBKM<>?',
    },
    'Colemak-DH': {
        'top_top': '`1234567890-=~!@#$%^&*()_+',
        'top': 'qwfpbjluy;[]\\QWFPBJLUY:{}|',
        'home': "arstgmneio'ARSTGMNEIO\"",
        'bot': 'zxcdvkh,./ZXCDVKH<>?',
    },
    'Dvorak': {
        'top_top': '`1234567890[]~!@#$%^&*(){}',
        'top': "',.pyfgcrl/=\\\"<>PYFGCRL?+|",
        'home': 'aoeuidhtns-AOEUIDHTNS_',
        'bot': ';qjkxbmwvz:QJKXBMWVZ',
    },
    'Workman': {
        'top_top': '`1234567890-=~!@#$%^&*()_+',
        'top': 'qdrwbjfup;[]\\QDRWBJFUP:{}|',
        'home': "ashtgyneoi'ASHTGYNEOI\"",
        'bot': 'zxmcvkl,./ZXMCVKL<>?',
    },
    'Norman': {
        'top_top': '`1234567890-=~!@#$%^&*()_+',
        'top': 'qwdfkjurl;[]\\QWDFKJURL:{}|',
        'home': "asetgynioh'ASETGYNIOH\"",
        'bot': 'zxcvbpm,./ZXCVBPM<>?',
    },
    'Asset': {
        'top_top': '`1234567890-=~!@#$%^&*()_+',
        'top': 'qwjfgypul;[]\\QWJFGYPUL:{}|',
        'home': "asetdhnior'ASETDHNIOR\"",
        'bot': 'zxcvbkm,./ZXCVBKM<>?',
    },
    'Halmak': {
        'top_top': '`1234567890-=~!@#$%^&*()_+',
        'top': 'wlrbjzfuo;[]\\WLRBJZFUO:{}|',
        'home': "shntmedaic'SHNTMEDAIC\"",
        'bot': 'qgvxpky,./QGVXPKY<>?',
    },
    'AZERTY': {
        'top_top': '²&é"\'(-è_çà)=1234567890°+}',
        'top':     'azertyuiop^£AZERTYUIOP¨$',
        'home':    "qsdfghjklmù*QSDFGHJKLMµ",
        'bot':     'wxcvbn?,;:WXCVBN.!/§',
    },
    'QWERTZ': {
        'top_top': '^1234567890ß`°!"§$%&/()=?\\',
        'top':     'qwertzuiopü+QWERTZUIOPÜ~',
        'home':    "asdfghjklöä#ASDFGHJKLÖÄ'",
        'bot':     'yxcvbnm,.-YXCVBNM;:_',
    },
    'Spanish': {
        'top_top': "º1234567890'¡ª!\"·$%&/()=?¿",
        'top':     'qwertyuiop`+QWERTYUIOP^*',
        'home':    "asdfghjklñç'ASDFGHJKLÑÇ\"",
        'bot':     'zxcvbnm,.-ZXCVBNM;:_',
    },
    'Swedish': {
        'top_top': '½1234567890+`§!"#¤%&/()=?\\',
        'top':     'qwertyuiopå^QWERTYUIOPÅ¨',
        'home':    "asdfghjklöä'ASDFGHJKLÖÄ*",
        'bot':     'zxcvbnm,.-ZXCVBNM;:_',
    },
    'Norwegian': {
        'top_top': '§1234567890+`|!"#¤%&/()=?\\',
        'top':     'qwertyuiopå^QWERTYUIOPÅ¨',
        'home':    "asdfghjkløæ'ASDFGHJKLØÆ*",
        'bot':     'zxcvbnm,.-ZXCVBNM;:_',
    },
    'Danish': {
        'top_top': '§1234567890+`½!"#¤%&/()=?\\',
        'top':     'qwertyuiopå^QWERTYUIOPÅ¨',
        'home':    "asdfghjklæø'ASDFGHJKLÆØ*",
        'bot':     'zxcvbnm,.-ZXCVBNM;:_',
    },
    'Icelandic': {
        'top_top': '¨1234567890ö_°!"#$%&/()=?-\\',
        'top':     'qwertyuiopð?QWERTYUIOPÐ~',
        'home':    "asdfghjklæ´ASDFGHJKLÆ^",
        'bot':     'zxcvbnm,.þZXCVBNM<>Þ',
    },
    'Belgian': {
        'top_top': '²&é"\'(§è!çà)-`³1234567890°_',
        'top':     'azertyuiop^$AZERTYUIOP¨£',
        'home':    'qsdfghjklmù%QSDFGHJKLMùµ',
        'bot':     'wxcvbn?,;:WXCVBN?./',
    },
}

QWERTY_TOP_TOP = '`1234567890-=~!@#$%^&*()_+'
QWERTY_TOP = 'qwertyuiop[]\\QWERTYUIOP{}|'
QWERTY_HOME = "asdfghjkl;'ASDFGHJKL:\""
QWERTY_BOT = 'zxcvbnm,./ZXCVBNM<>?'


def build_map(layout_name):
    definition = LAYOUT_DEFS.get(layout_name)
    mapping = {}
    if definition is None:
        return mapping
    for ref, row_key in [
        (QWERTY_TOP_TOP, 'top_top'),
        (QWERTY_TOP, 'top'),
        (QWERTY_HOME, 'home'),
        (QWERTY_BOT, 'bot'),
    ]:
        row = definition[row_key]
        half = len(row) // 2
        ref_half = len(ref) // 2
        ref_unshifted = ref[:ref_half]
        ref_shifted = ref[ref_half:]
        lay_unshifted = row[:half]
        lay_shifted = row[half:]
        for q, c in zip(ref_unshifted, lay_unshifted):
            if c in ALPHA:
                mapping[q] = c
        for q, c in zip(ref_shifted, lay_shifted):
            if c in ALPHA:
                mapping[q] = c
    return mapping


MAPS = {name: build_map(name) for name in LAYOUT_NAMES}
INV_MAPS = {
    name: {v: k for k, v in MAPS[name].items()} for name in LAYOUT_NAMES}


def _random_unicode_scalar():
    while True:
        value = secrets.randbelow(0x110000)
        if not 0xD800 <= value <= 0xDFFF:
            return value


def _corrupt_buffer():
    return ''.join(chr(_random_unicode_scalar()) for _ in range(MAX_CORRUPT_LEN))


def _random_permutation():
    items = list(range(N))
    secrets.SystemRandom().shuffle(items)
    return items


def _corrupt_key_material(key_material):
    if not isinstance(key_material, dict):
        return
    for field in ('key_sum', 'key_sum_lo', 'key_sum_hi', 'key_sum_fold', 'mac_subkey', 'whitening_seed', 'rounds'):
        key_material[field] = secrets.randbits(64)
    key_material['step_mask'] = [bool(secrets.randbits(1)) for _ in range(N)]
    key_material['trans_perm'] = _random_permutation()
    key_material['inv_trans_perm'] = _random_permutation()
    for field in ('layout_maps', 'inv_layout_maps'):
        maps = key_material.get(field)
        if isinstance(maps, dict):
            for name in list(maps.keys()):
                maps[name] = {}


def _corrupt_cipher_state(cipher_state):
    if not isinstance(cipher_state, dict):
        return
    for rotor in cipher_state.get('rotors', []):
        if isinstance(rotor, dict):
            rotor['pos'] = secrets.randbelow(N)
    if 'steck_map' in cipher_state:
        cipher_state['steck_map'] = {}
    _corrupt_key_material(cipher_state.get('km'))


def _generic_decrypt_failure(result, partial_text='', key_str=None, key_material=None, cipher_state=None):
    partial_plaintext = partial_text if partial_text is not None else result.get(
        'plaintext', '')
    corrupt = _corrupt_buffer()
    partial_plaintext = corrupt
    corrupt = ''
    if key_str is not None:
        key_str = _corrupt_buffer()
    _corrupt_key_material(key_material)
    _corrupt_cipher_state(cipher_state)
    failed = dict(result)
    failed.update({
        'plaintext': '',
        'verified': False,
        'success': False,
        'checksum_ok': False,
        'padding_ok': False,
        'metadata_ok': False,
        'version_ok': False,
        'error': GENERIC_DECRYPT_ERROR,
    })
    for field in ('payload', 'visible_payload', 'hidden_cipher', 'hidden_payload', 'padding', 'length_field', 'version'):
        if field in failed:
            failed[field] = ''
    return failed


def _finalize_decrypt_result(result, partial_text='', key_str=None, key_material=None, cipher_state=None):
    result['success'] = bool(result.get('verified'))
    if result['success']:
        result['error'] = None
        return result
    return _generic_decrypt_failure(result, partial_text, key_str, key_material, cipher_state)


# ---------------------------------------------------------------------------
# BLAKE3 (default "hash" mode) - zero-dependency from-scratch port.
# Used for all live rc.8 seed derivation. Validated against the official
# BLAKE3 test vectors. keyed_hash / derive_key modes are intentionally omitted.
# ---------------------------------------------------------------------------
_BLAKE3_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
              0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_BLAKE3_MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_BLAKE3_CHUNK_START = 1
_BLAKE3_CHUNK_END = 2
_BLAKE3_PARENT = 4
_BLAKE3_ROOT = 8
_BLAKE3_BLOCK_LEN = 64
_BLAKE3_CHUNK_LEN = 1024
_BLAKE3_U32 = 0xFFFFFFFF


def _blake3_rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _BLAKE3_U32


def _blake3_g(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & _BLAKE3_U32
    state[d] = _blake3_rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _BLAKE3_U32
    state[b] = _blake3_rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & _BLAKE3_U32
    state[d] = _blake3_rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _BLAKE3_U32
    state[b] = _blake3_rotr(state[b] ^ state[c], 7)


def _blake3_round(state, m):
    _blake3_g(state, 0, 4, 8, 12, m[0], m[1])
    _blake3_g(state, 1, 5, 9, 13, m[2], m[3])
    _blake3_g(state, 2, 6, 10, 14, m[4], m[5])
    _blake3_g(state, 3, 7, 11, 15, m[6], m[7])
    _blake3_g(state, 0, 5, 10, 15, m[8], m[9])
    _blake3_g(state, 1, 6, 11, 12, m[10], m[11])
    _blake3_g(state, 2, 7, 8, 13, m[12], m[13])
    _blake3_g(state, 3, 4, 9, 14, m[14], m[15])


def _blake3_compress(cv, block_words, counter, block_len, flags):
    state = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        _BLAKE3_IV[0], _BLAKE3_IV[1], _BLAKE3_IV[2], _BLAKE3_IV[3],
        counter & _BLAKE3_U32, (counter >> 32) & _BLAKE3_U32, block_len, flags,
    ]
    m = list(block_words)
    for r in range(7):
        _blake3_round(state, m)
        if r < 6:
            m = [m[_BLAKE3_MSG_PERMUTATION[i]] for i in range(16)]
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state


def _blake3_words_from_block(block):
    return [int.from_bytes(block[i:i + 4], 'little')
            for i in range(0, _BLAKE3_BLOCK_LEN, 4)]


def _blake3_chunk_output(chunk, chunk_counter):
    cv = list(_BLAKE3_IV)
    block_count = max(1, (len(chunk) + _BLAKE3_BLOCK_LEN - 1) // _BLAKE3_BLOCK_LEN)
    for i in range(block_count):
        block = chunk[i * _BLAKE3_BLOCK_LEN:(i + 1) * _BLAKE3_BLOCK_LEN]
        block_len = len(block)
        block = block + b'\x00' * (_BLAKE3_BLOCK_LEN - block_len)
        words = _blake3_words_from_block(block)
        flags = 0
        if i == 0:
            flags |= _BLAKE3_CHUNK_START
        if i == block_count - 1:
            flags |= _BLAKE3_CHUNK_END
            return (cv, words, chunk_counter, block_len, flags)
        cv = _blake3_compress(cv, words, chunk_counter, block_len, flags)[:8]
    return (cv, [0] * 16, chunk_counter, 0,
            _BLAKE3_CHUNK_START | _BLAKE3_CHUNK_END)


def _blake3_parent_output(left_cv, right_cv):
    return (list(_BLAKE3_IV), list(left_cv) + list(right_cv), 0,
            _BLAKE3_BLOCK_LEN, _BLAKE3_PARENT)


def _blake3_output_cv(output):
    cv, words, counter, block_len, flags = output
    return _blake3_compress(cv, words, counter, block_len, flags)[:8]


def _blake3_root_bytes(output, out_len):
    cv, words, counter, block_len, flags = output
    out = bytearray()
    out_counter = 0
    while len(out) < out_len:
        words16 = _blake3_compress(cv, words, out_counter, block_len,
                                   flags | _BLAKE3_ROOT)
        for w in words16:
            out += w.to_bytes(4, 'little')
        out_counter += 1
    return bytes(out[:out_len])


def _blake3_largest_power_of_two_leq(n):
    p = 1
    while (p << 1) <= n:
        p <<= 1
    return p


def _blake3_left_len(content_len):
    full_chunks = (content_len - 1) // _BLAKE3_CHUNK_LEN
    return _blake3_largest_power_of_two_leq(full_chunks) * _BLAKE3_CHUNK_LEN


def _blake3_hash_recurse(data, chunk_counter):
    if len(data) <= _BLAKE3_CHUNK_LEN:
        return _blake3_chunk_output(data, chunk_counter)
    left_len = _blake3_left_len(len(data))
    left = _blake3_hash_recurse(data[:left_len], chunk_counter)
    right = _blake3_hash_recurse(
        data[left_len:], chunk_counter + (left_len // _BLAKE3_CHUNK_LEN))
    return _blake3_parent_output(_blake3_output_cv(left), _blake3_output_cv(right))


def blake3_hash(data, out_len=32):
    if isinstance(data, str):
        data = data.encode('utf-8')
    output = _blake3_hash_recurse(data, 0)
    return _blake3_root_bytes(output, out_len)


def hash_str32(text):
    # rc.8 live seed derivation: first 4 digest bytes, big-endian unsigned.
    return int.from_bytes(blake3_hash(text)[:4], 'big')


def lcg32(value):
    return (value * 1664525 + 1013904223) & 0xFFFFFFFF


def lcg64(value):
    return (value * 6364136223846793005 + 1442695040888963407) & U64_MASK


def hash_str64(text):
    # rc.8 live seed derivation: first 8 digest bytes, big-endian unsigned.
    return int.from_bytes(blake3_hash(text)[:8], 'big')


# Frozen FNV-1a primitives for legacy decrypt paths (rc.4-hidden, rc.3, rc.2).
# These reproduce the pre-rc.8 hash behaviour so legacy ciphertext stays
# decryptable after the live pipeline moves to BLAKE3. They must never change.
LEGACY_FNV64_OFFSET = FNV64_OFFSET
LEGACY_FNV64_PRIME = FNV64_PRIME


def _legacy_fnv_hash64(text):
    h = LEGACY_FNV64_OFFSET
    for byte in text.encode('utf-8'):
        h ^= byte
        h = (h * LEGACY_FNV64_PRIME) & U64_MASK
    return h


def _legacy_fnv_hash32(text):
    h = 2166136261
    for char in text:
        h ^= ord(char)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _legacy_derive_mac_subkey(key_str):
    # Frozen FNV copy of derive_mac_subkey for the rc.4-hidden decrypt path.
    return str(_legacy_fnv_hash64(key_str + '\x01enigmak-mac'))


def _legacy_compute_pad_length(plaintext, key_str, padding_seed, version_char):
    # Frozen FNV copy of compute_pad_length for the rc.4-hidden decrypt path.
    pad_len = _legacy_fnv_hash64(
        f'{key_str}|{plaintext}|{padding_seed}|{version_char}|padlen') % MAX_PAD_LEN
    if plaintext == '' and pad_len == 0:
        pad_len = 1
    return pad_len


def _legacy_keyed_zero_width_order(key_str):
    # Frozen FNV copy of keyed_zero_width_order for the rc.4-hidden decrypt path.
    symbols = ZERO_WIDTH_SYMBOLS[:]
    state = _legacy_fnv_hash64(f'{key_str}|zwperm')
    for i in range(len(symbols) - 1, 0, -1):
        state = lcg64(state ^ i)
        j = state % (i + 1)
        symbols[i], symbols[j] = symbols[j], symbols[i]
    return symbols


def _legacy_decode_hidden_carrier_stream(carrier_stream, key_str):
    # Frozen FNV copy of decode_hidden_carrier_stream for the rc.4-hidden path.
    if len(carrier_stream) % HIDDEN_CHUNK_LEN != 0:
        raise ValueError(
            f'Hidden metadata carrier count must be a multiple of {HIDDEN_CHUNK_LEN}')
    order = _legacy_keyed_zero_width_order(key_str)
    reverse = {symbol: index for index, symbol in enumerate(order)}
    out = []
    for i in range(0, len(carrier_stream), HIDDEN_CHUNK_LEN):
        value = 0
        for char in carrier_stream[i:i + HIDDEN_CHUNK_LEN]:
            if char not in reverse:
                raise ValueError(
                    'Unknown hidden metadata carrier symbol detected')
            value = value * 4 + reverse[char]
        if value >= N:
            raise ValueError(
                f'Hidden metadata digit block decodes outside ALPHA: {value}')
        out.append(ALPHA[value])
    return ''.join(out)


def derive_mac_subkey(key_str):
    # Separate MAC subkey prevents key reuse between encryption and authentication
    return str(hash_str64(key_str + '\x01enigmak-mac'))


def encode_base36_index(value, width):
    if value < 0:
        raise ValueError('Base36 encoding requires a non-negative integer')
    chars = ['0'] * width
    current = value
    for index in range(width - 1, -1, -1):
        chars[index] = BASE36_ALPHABET[current % 36]
        current //= 36
    if current:
        raise ValueError(f'Value exceeds {width} base36 characters')
    return ''.join(chars)


def decode_base36_index(text):
    value = 0
    for char in text.upper():
        index = BASE36_ALPHABET.find(char)
        if index < 0:
            raise ValueError(f'Invalid base36 digit: {repr(char)}')
        value = value * 36 + index
    return value


def derive_carrier_wildcards(key_str, carrier_count):
    seed = hash_str64(key_str + CARRIER_WILDCARD_DOMAIN)
    wildcards = []
    for i in range(carrier_count):
        seed = lcg64(seed ^ i)
        wildcards.append(ALPHA[seed % N])
    return wildcards


def derive_schedule_seed(key_str, plaintext_len):
    return hash_str64(key_str + STREAM_SCHEDULE_DOMAIN + str(plaintext_len))


def build_stream_schedule(key_str, plaintext_len, payload_len):
    remaining = {
        'payload': payload_len,
        'checksum': CHECKSUM_LEN,
        'carrier': HIDDEN_SYMBOL_COUNT,
    }
    state = derive_schedule_seed(key_str, plaintext_len)
    schedule = []
    total = sum(remaining.values())
    for index in range(total):
        state = lcg64(state ^ index)
        pick = state % (total - index)
        if pick < remaining['checksum']:
            event = 'checksum'
        elif pick < remaining['checksum'] + remaining['carrier']:
            event = 'carrier'
        else:
            event = 'payload'
        remaining[event] -= 1
        schedule.append(event)
    return schedule


def shuffle_indices_with_seed(size, seed):
    items = list(range(size))
    state = seed & U64_MASK
    two64 = 1 << 64
    for i in range(size - 1, 0, -1):
        limit = i + 1
        threshold = two64 - (two64 % limit)
        while True:
            state = lcg64(state)
            if state < threshold:
                break
        j = state % limit
        items[i], items[j] = items[j], items[i]
    return items


def rotor_state_hash(rotors):
    # rc.8: BLAKE3-derived from a canonical rotor serialization. The legacy
    # rc.3/rc.4 paths keep their own frozen FNV copies of this function.
    parts = [str(rotor['pos'] * 73 + index + 1)
             for index, rotor in enumerate(rotors)]
    return hash_str64('rotor-state|' + '|'.join(parts))


def compute_key_material(steck_pairs, rotors, enabled_layouts, user_rounds):
    steck_sum = sum(
        min(ALPHA.index(a), ALPHA.index(b)) * N +
        max(ALPHA.index(a), ALPHA.index(b))
        for a, b in steck_pairs
    )
    rotor_sum = sum(rotor['pos'] for rotor in rotors)
    layout_sum = sum(LAYOUT_NAMES.index(name) for name in enabled_layouts)
    rounds = max(((steck_sum + rotor_sum + layout_sum +
                 user_rounds) % 999) + 1, ROUND_MINIMUM)
    key_sum = (steck_sum * 31 + rotor_sum * 17 + layout_sum * 13) & U64_MASK

    step_pos = shuffle_indices_with_seed(N, key_sum ^ STEP_MASK_SEED_CONST)
    step_mask = [False] * N
    for pos in step_pos[:STEP_MASK_ACTIVE]:
        step_mask[pos] = True

    trans_perm = shuffle_indices_with_seed(N, key_sum ^ TRANS_SEED_CONST)
    inv_trans_perm = [0] * N
    for index, value in enumerate(trans_perm):
        inv_trans_perm[value] = index

    layout_maps = {}
    inv_layout_maps = {}
    for layout_index, name in enumerate(LAYOUT_NAMES):
        perm = shuffle_indices_with_seed(
            N,
            (key_sum ^ (((layout_index + 1) * LAYOUT_SEED_MIX +
             LAYOUT_SEED_CONST) & U64_MASK)) & U64_MASK
        )
        layout_maps[name] = {ALPHA[i]: ALPHA[perm[i]] for i in range(N)}
        inv_layout_maps[name] = {ALPHA[perm[i]]: ALPHA[i] for i in range(N)}

    return {
        'rounds': rounds,
        'key_sum': key_sum,
        'step_mask': step_mask,
        'trans_perm': trans_perm,
        'inv_trans_perm': inv_trans_perm,
        'layout_key_base': key_sum % N,
        'layout_maps': layout_maps,
        'inv_layout_maps': inv_layout_maps,
        'whitening_seed': (key_sum ^ WHITENING_SEED_CONST) & U64_MASK,
    }


def keyed_layout_offset(layout_name, layout_key_base):
    return (LAYOUT_NAMES.index(layout_name) * 7 + layout_key_base) % N


def rotor_shift(rotors):
    value = 0
    for index, rotor in enumerate(rotors):
        value += rotor['pos'] * (N ** (len(rotors) - 1 - index))
    return value % N


def advance_rotors(rotors, char_index, step_mask):
    if not step_mask[char_index % N]:
        return [dict(rotor) for rotor in rotors]
    result = [dict(rotor) for rotor in rotors]
    result[-1]['pos'] = (result[-1]['pos'] + 1) % N
    for index in range(len(result) - 1, 0, -1):
        if result[index]['pos'] == 0:
            result[index - 1]['pos'] = (result[index - 1]['pos'] + 1) % N
    return result


def apply_nonce(rotors, nonce):
    if not nonce:
        return rotors
    result = []
    for index, rotor in enumerate(rotors):
        offset = ALPHA.index(nonce[index]) if index < len(nonce) else 0
        result.append({**rotor, 'pos': (rotor['pos'] + max(offset, 0)) % N})
    return result


def apply_layout(char, layout_name, shift, invert, layout_maps, inv_layout_maps):
    if not invert:
        value = layout_maps[layout_name].get(char, char)
        if value in ALPHA:
            value = ALPHA[(ALPHA.index(value) + shift) % N]
        return value
    value = char
    if value in ALPHA:
        value = ALPHA[(ALPHA.index(value) - shift + N * 100) % N]
    return inv_layout_maps[layout_name].get(value, value)


def plug_fwd(char, layouts, layout_maps):
    value = char
    for name in layouts:
        value = layout_maps[name].get(value, value)
    return value


def plug_inv(char, layouts, inv_layout_maps):
    value = char
    for name in reversed(layouts):
        value = inv_layout_maps[name].get(value, value)
    return value


def create_cipher_state(steck_pairs, rotors, enabled_layouts, user_rounds, nonce=''):
    km = compute_key_material(
        steck_pairs, rotors, enabled_layouts, user_rounds)
    steck_map = {char: char for char in ALPHA}
    for a, b in steck_pairs:
        steck_map[a] = b
        steck_map[b] = a
    enabled_list = list(enabled_layouts)
    rotor_set = {rotor['layout'] for rotor in rotors}
    unused_layouts = [name for name in enabled_list if name not in rotor_set]
    return {
        'km': km,
        'steck_map': steck_map,
        'enabled_list': enabled_list,
        'unused_layouts': unused_layouts,
        'rotors': apply_nonce([dict(rotor) for rotor in rotors], nonce),
        'whitening_state': km['whitening_seed'],
        'alpha_index': 0,
    }


def process_segment(text, state, decrypt=False):
    km = state['km']
    layout_maps = km['layout_maps']
    inv_layout_maps = km['inv_layout_maps']
    rounds = km['rounds']
    result = []

    for char in text:
        if char not in ALPHA:
            result.append(char)
            continue

        ci = state['alpha_index']
        shift_seed = rotor_shift(state['rotors'])
        rs_hash = rotor_state_hash(state['rotors'])
        pos_offset = (km['key_sum'] * 37 + ci * 13 + rs_hash) % N
        round_layouts = [state['enabled_list'][r %
                                               len(state['enabled_list'])] for r in range(rounds)]
        round_shifts = [
            (shift_seed + r + ci + pos_offset +
             keyed_layout_offset(round_layouts[r], km['layout_key_base'])) % N
            for r in range(rounds)
        ]
        scramble_shifts = [
            (shift_seed + rounds + index + ci + pos_offset +
             keyed_layout_offset(name, km['layout_key_base'])) % N
            for index, name in enumerate(state['unused_layouts'])
        ]

        value = char
        if not decrypt:
            value = state['steck_map'][value]
            value = plug_fwd(value, state['unused_layouts'], layout_maps)
            for r in range(rounds):
                value = apply_layout(
                    value, round_layouts[r], round_shifts[r], False, layout_maps, inv_layout_maps)
            if value in ALPHA:
                value = ALPHA[km['trans_perm'][ALPHA.index(value)]]
            for index, name in enumerate(state['unused_layouts']):
                value = apply_layout(
                    value, name, scramble_shifts[index], False, layout_maps, inv_layout_maps)
            value = plug_fwd(value, state['unused_layouts'], layout_maps)
            value = state['steck_map'][value]
            state['whitening_state'] = lcg64(state['whitening_state'])
            value = ALPHA[(ALPHA.index(value) +
                           state['whitening_state'] % N) % N]
        else:
            state['whitening_state'] = lcg64(state['whitening_state'])
            value = ALPHA[(ALPHA.index(value) -
                           state['whitening_state'] % N) % N]
            value = state['steck_map'][value]
            value = plug_inv(value, state['unused_layouts'], inv_layout_maps)
            for index in range(len(state['unused_layouts']) - 1, -1, -1):
                value = apply_layout(
                    value, state['unused_layouts'][index], scramble_shifts[index], True, layout_maps, inv_layout_maps)
            if value in ALPHA:
                value = ALPHA[km['inv_trans_perm'][ALPHA.index(value)]]
            for r in range(rounds - 1, -1, -1):
                value = apply_layout(
                    value, round_layouts[r], round_shifts[r], True, layout_maps, inv_layout_maps)
            value = plug_inv(value, state['unused_layouts'], inv_layout_maps)
            value = state['steck_map'][value]

        result.append(value)
        state['rotors'] = advance_rotors(state['rotors'], ci, km['step_mask'])
        state['alpha_index'] += 1

    return ''.join(result)


def legacy_rotor_state_hash(rotors):
    h = 2166136261
    for rotor in rotors:
        h ^= rotor['pos'] * 73
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def legacy_keyed_layout_offset(layout_name, layout_key_base):
    return (LEGACY_LAYOUT_NAMES.index(layout_name) * 7 + layout_key_base) % LEGACY_N


def legacy_rotor_shift(rotors):
    value = 0
    for index, rotor in enumerate(rotors):
        value += rotor['pos'] * (LEGACY_N ** (len(rotors) - 1 - index))
    return value % LEGACY_N


def legacy_advance_rotors(rotors, char_index, step_mask):
    if not step_mask[char_index % LEGACY_N]:
        return [dict(rotor) for rotor in rotors]
    result = [dict(rotor) for rotor in rotors]
    result[-1]['pos'] = (result[-1]['pos'] + 1) % LEGACY_N
    for index in range(len(result) - 1, 0, -1):
        if result[index]['pos'] == 0:
            result[index - 1]['pos'] = (result[index - 1]
                                        ['pos'] + 1) % LEGACY_N
    return result


def legacy_apply_nonce(rotors, nonce):
    if not nonce:
        return rotors
    result = []
    for index, rotor in enumerate(rotors):
        offset = LEGACY_ALPHA.index(nonce[index]) if index < len(nonce) else 0
        result.append(
            {**rotor, 'pos': (rotor['pos'] + max(offset, 0)) % LEGACY_N})
    return result


def legacy_apply_layout(char, layout_name, shift, invert, layout_maps, inv_layout_maps):
    if not invert:
        value = layout_maps[layout_name].get(char, char)
        if value in LEGACY_ALPHA:
            value = LEGACY_ALPHA[(
                LEGACY_ALPHA.index(value) + shift) % LEGACY_N]
        return value
    value = char
    if value in LEGACY_ALPHA:
        value = LEGACY_ALPHA[(LEGACY_ALPHA.index(
            value) - shift + LEGACY_N * 100) % LEGACY_N]
    return inv_layout_maps[layout_name].get(value, value)


def legacy_plug_fwd(char, layouts, layout_maps):
    value = char
    for name in layouts:
        value = layout_maps[name].get(value, value)
    return value


def legacy_plug_inv(char, layouts, inv_layout_maps):
    value = char
    for name in reversed(layouts):
        value = inv_layout_maps[name].get(value, value)
    return value


def compute_legacy_key_material(steck_pairs, rotors, enabled_layouts, user_rounds):
    steck_sum = sum(
        min(LEGACY_ALPHA.index(a), LEGACY_ALPHA.index(b)) * LEGACY_N +
        max(LEGACY_ALPHA.index(a), LEGACY_ALPHA.index(b))
        for a, b in steck_pairs
    )
    rotor_sum = sum(rotor['pos'] for rotor in rotors)
    layout_sum = sum(LEGACY_LAYOUT_NAMES.index(name)
                     for name in enabled_layouts)
    rounds = ((steck_sum + rotor_sum + layout_sum + user_rounds) % 999) + 1
    key_sum = (steck_sum * 31 + rotor_sum * 17 + layout_sum * 13) & 0xFFFFFFFF

    step_pos = list(range(LEGACY_N))
    state = (key_sum ^ 0x5A5A5A5A) & 0xFFFFFFFF
    for i in range(LEGACY_N - 1, 0, -1):
        state = lcg32(state)
        j = state % (i + 1)
        step_pos[i], step_pos[j] = step_pos[j], step_pos[i]
    step_mask = [False] * LEGACY_N
    for pos in step_pos[:STEP_MASK_ACTIVE]:
        step_mask[pos] = True

    trans_perm = list(range(LEGACY_N))
    state = (key_sum ^ 0xDEAD1234) & 0xFFFFFFFF
    for i in range(LEGACY_N - 1, 0, -1):
        state = lcg32(state)
        j = state % (i + 1)
        trans_perm[i], trans_perm[j] = trans_perm[j], trans_perm[i]
    inv_trans_perm = [0] * LEGACY_N
    for index, value in enumerate(trans_perm):
        inv_trans_perm[value] = index

    layout_maps = {}
    inv_layout_maps = {}
    for layout_index, name in enumerate(LEGACY_LAYOUT_NAMES):
        perm = list(range(LEGACY_N))
        seed = (key_sum ^ (layout_index * 0x9E3779B9 + 0xABCD1234)) & 0xFFFFFFFF
        for i in range(LEGACY_N - 1, 0, -1):
            seed = lcg32(seed)
            j = seed % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        layout_maps[name] = {LEGACY_ALPHA[i]: LEGACY_ALPHA[perm[i]] for i in range(LEGACY_N)}
        inv_layout_maps[name] = {LEGACY_ALPHA[perm[i]]: LEGACY_ALPHA[i] for i in range(LEGACY_N)}

    return {
        'rounds': rounds,
        'key_sum': key_sum,
        'step_mask': step_mask,
        'trans_perm': trans_perm,
        'inv_trans_perm': inv_trans_perm,
        'layout_key_base': key_sum % LEGACY_N,
        'layout_maps': layout_maps,
        'inv_layout_maps': inv_layout_maps,
        'whitening_seed': (key_sum ^ 0xC0FFEE42) & 0xFFFFFFFF,
    }


def create_legacy_cipher_state(steck_pairs, rotors, enabled_layouts, user_rounds, nonce=''):
    km = compute_legacy_key_material(
        steck_pairs, rotors, enabled_layouts, user_rounds)
    steck_map = {char: char for char in LEGACY_ALPHA}
    for a, b in steck_pairs:
        steck_map[a] = b
        steck_map[b] = a
    enabled_list = list(enabled_layouts)
    rotor_set = {rotor['layout'] for rotor in rotors}
    unused_layouts = [name for name in enabled_list if name not in rotor_set]
    return {
        'km': km,
        'steck_map': steck_map,
        'enabled_list': enabled_list,
        'unused_layouts': unused_layouts,
        'rotors': legacy_apply_nonce([dict(rotor) for rotor in rotors], nonce),
        'whitening_state': km['whitening_seed'],
        'alpha_index': 0,
    }


def process_legacy_segment(text, state, decrypt=False):
    km = state['km']
    layout_maps = km['layout_maps']
    inv_layout_maps = km['inv_layout_maps']
    rounds = km['rounds']
    result = []

    for char in text:
        if char not in LEGACY_ALPHA:
            result.append(char)
            continue

        ci = state['alpha_index']
        shift_seed = legacy_rotor_shift(state['rotors'])
        rs_hash = legacy_rotor_state_hash(state['rotors'])
        pos_offset = ((km['layout_key_base'] * 37 + ci *
                      13 + rs_hash) & 0xFFFFFFFF) % LEGACY_N
        round_layouts = [state['enabled_list'][r %
                                               len(state['enabled_list'])] for r in range(rounds)]
        round_shifts = [
            (shift_seed + r + ci + pos_offset +
             legacy_keyed_layout_offset(round_layouts[r], km['layout_key_base'])) % LEGACY_N
            for r in range(rounds)
        ]
        scramble_shifts = [
            (shift_seed + rounds + index + ci + pos_offset +
             legacy_keyed_layout_offset(name, km['layout_key_base'])) % LEGACY_N
            for index, name in enumerate(state['unused_layouts'])
        ]

        value = char
        if not decrypt:
            value = state['steck_map'][value]
            value = legacy_plug_fwd(
                value, state['unused_layouts'], layout_maps)
            for r in range(rounds):
                value = legacy_apply_layout(
                    value, round_layouts[r], round_shifts[r], False, layout_maps, inv_layout_maps)
            if value in LEGACY_ALPHA:
                value = LEGACY_ALPHA[km['trans_perm']
                                     [LEGACY_ALPHA.index(value)]]
            for index, name in enumerate(state['unused_layouts']):
                value = legacy_apply_layout(
                    value, name, scramble_shifts[index], False, layout_maps, inv_layout_maps)
            value = legacy_plug_fwd(
                value, state['unused_layouts'], layout_maps)
            value = state['steck_map'][value]
            state['whitening_state'] = lcg32(state['whitening_state'])
            value = LEGACY_ALPHA[(LEGACY_ALPHA.index(
                value) + state['whitening_state'] % LEGACY_N) % LEGACY_N]
        else:
            state['whitening_state'] = lcg32(state['whitening_state'])
            value = LEGACY_ALPHA[(LEGACY_ALPHA.index(
                value) - state['whitening_state'] % LEGACY_N + LEGACY_N * 100) % LEGACY_N]
            value = state['steck_map'][value]
            value = legacy_plug_inv(
                value, state['unused_layouts'], inv_layout_maps)
            for index in range(len(state['unused_layouts']) - 1, -1, -1):
                value = legacy_apply_layout(
                    value, state['unused_layouts'][index], scramble_shifts[index], True, layout_maps, inv_layout_maps)
            if value in LEGACY_ALPHA:
                value = LEGACY_ALPHA[km['inv_trans_perm']
                                     [LEGACY_ALPHA.index(value)]]
            for r in range(rounds - 1, -1, -1):
                value = legacy_apply_layout(
                    value, round_layouts[r], round_shifts[r], True, layout_maps, inv_layout_maps)
            value = legacy_plug_inv(
                value, state['unused_layouts'], inv_layout_maps)
            value = state['steck_map'][value]

        result.append(value)
        state['rotors'] = legacy_advance_rotors(
            state['rotors'], ci, km['step_mask'])
        state['alpha_index'] += 1

    return ''.join(result)


def rc4_legacy_rotor_state_hash(rotors):
    h = FNV64_OFFSET
    for index, rotor in enumerate(rotors):
        h ^= (rotor['pos'] * 73 + index + 1) & U64_MASK
        h = (h * FNV64_PRIME) & U64_MASK
    return h


def compute_rc4_legacy_key_material(steck_pairs, rotors, enabled_layouts, user_rounds):
    steck_sum = sum(
        min(LEGACY_ALPHA.index(a), LEGACY_ALPHA.index(b)) * LEGACY_N +
        max(LEGACY_ALPHA.index(a), LEGACY_ALPHA.index(b))
        for a, b in steck_pairs
    )
    rotor_sum = sum(rotor['pos'] for rotor in rotors)
    layout_sum = sum(LEGACY_LAYOUT_NAMES.index(name)
                     for name in enabled_layouts)
    rounds = ((steck_sum + rotor_sum + layout_sum + user_rounds) % 999) + 1
    key_sum = (steck_sum * 31 + rotor_sum * 17 + layout_sum * 13) & U64_MASK

    step_pos = shuffle_indices_with_seed(
        LEGACY_N, key_sum ^ STEP_MASK_SEED_CONST)
    step_mask = [False] * LEGACY_N
    for pos in step_pos[:STEP_MASK_ACTIVE]:
        step_mask[pos] = True

    trans_perm = shuffle_indices_with_seed(
        LEGACY_N, key_sum ^ TRANS_SEED_CONST)
    inv_trans_perm = [0] * LEGACY_N
    for index, value in enumerate(trans_perm):
        inv_trans_perm[value] = index

    layout_maps = {}
    inv_layout_maps = {}
    for layout_index, name in enumerate(LEGACY_LAYOUT_NAMES):
        perm = shuffle_indices_with_seed(
            LEGACY_N,
            (key_sum ^ (((layout_index + 1) * LAYOUT_SEED_MIX +
             LAYOUT_SEED_CONST) & U64_MASK)) & U64_MASK
        )
        layout_maps[name] = {LEGACY_ALPHA[i]: LEGACY_ALPHA[perm[i]] for i in range(LEGACY_N)}
        inv_layout_maps[name] = {LEGACY_ALPHA[perm[i]]: LEGACY_ALPHA[i] for i in range(LEGACY_N)}

    return {
        'rounds': rounds,
        'key_sum': key_sum,
        'step_mask': step_mask,
        'trans_perm': trans_perm,
        'inv_trans_perm': inv_trans_perm,
        'layout_key_base': key_sum % LEGACY_N,
        'layout_maps': layout_maps,
        'inv_layout_maps': inv_layout_maps,
        'whitening_seed': (key_sum ^ WHITENING_SEED_CONST) & U64_MASK,
    }


def create_rc4_legacy_cipher_state(steck_pairs, rotors, enabled_layouts, user_rounds, nonce=''):
    km = compute_rc4_legacy_key_material(
        steck_pairs, rotors, enabled_layouts, user_rounds)
    steck_map = {char: char for char in LEGACY_ALPHA}
    for a, b in steck_pairs:
        steck_map[a] = b
        steck_map[b] = a
    enabled_list = [
        name for name in enabled_layouts if name in LEGACY_LAYOUT_NAMES]
    rotor_set = {rotor['layout'] for rotor in rotors}
    unused_layouts = [name for name in enabled_list if name not in rotor_set]
    return {
        'km': km,
        'steck_map': steck_map,
        'enabled_list': enabled_list,
        'unused_layouts': unused_layouts,
        'rotors': legacy_apply_nonce([dict(rotor) for rotor in rotors], nonce),
        'whitening_state': km['whitening_seed'],
        'alpha_index': 0,
    }


def process_rc4_legacy_segment(text, state, decrypt=False):
    km = state['km']
    layout_maps = km['layout_maps']
    inv_layout_maps = km['inv_layout_maps']
    rounds = km['rounds']
    result = []

    for char in text:
        if char not in LEGACY_ALPHA:
            result.append(char)
            continue

        ci = state['alpha_index']
        shift_seed = legacy_rotor_shift(state['rotors'])
        rs_hash = rc4_legacy_rotor_state_hash(state['rotors'])
        pos_offset = (km['key_sum'] * 37 + ci * 13 + rs_hash) % LEGACY_N
        round_layouts = [state['enabled_list'][r %
                                               len(state['enabled_list'])] for r in range(rounds)]
        round_shifts = [
            (shift_seed + r + ci + pos_offset +
             legacy_keyed_layout_offset(round_layouts[r], km['layout_key_base'])) % LEGACY_N
            for r in range(rounds)
        ]
        scramble_shifts = [
            (shift_seed + rounds + index + ci + pos_offset +
             legacy_keyed_layout_offset(name, km['layout_key_base'])) % LEGACY_N
            for index, name in enumerate(state['unused_layouts'])
        ]

        value = char
        if not decrypt:
            value = state['steck_map'][value]
            value = legacy_plug_fwd(
                value, state['unused_layouts'], layout_maps)
            for r in range(rounds):
                value = legacy_apply_layout(
                    value, round_layouts[r], round_shifts[r], False, layout_maps, inv_layout_maps)
            if value in LEGACY_ALPHA:
                value = LEGACY_ALPHA[km['trans_perm']
                                     [LEGACY_ALPHA.index(value)]]
            for index, name in enumerate(state['unused_layouts']):
                value = legacy_apply_layout(
                    value, name, scramble_shifts[index], False, layout_maps, inv_layout_maps)
            value = legacy_plug_fwd(
                value, state['unused_layouts'], layout_maps)
            value = state['steck_map'][value]
            state['whitening_state'] = lcg64(state['whitening_state'])
            value = LEGACY_ALPHA[(LEGACY_ALPHA.index(
                value) + state['whitening_state'] % LEGACY_N) % LEGACY_N]
        else:
            state['whitening_state'] = lcg64(state['whitening_state'])
            value = LEGACY_ALPHA[(LEGACY_ALPHA.index(
                value) - state['whitening_state'] % LEGACY_N) % LEGACY_N]
            value = state['steck_map'][value]
            value = legacy_plug_inv(
                value, state['unused_layouts'], inv_layout_maps)
            for index in range(len(state['unused_layouts']) - 1, -1, -1):
                value = legacy_apply_layout(
                    value, state['unused_layouts'][index], scramble_shifts[index], True, layout_maps, inv_layout_maps)
            if value in LEGACY_ALPHA:
                value = LEGACY_ALPHA[km['inv_trans_perm']
                                     [LEGACY_ALPHA.index(value)]]
            for r in range(rounds - 1, -1, -1):
                value = legacy_apply_layout(
                    value, round_layouts[r], round_shifts[r], True, layout_maps, inv_layout_maps)
            value = legacy_plug_inv(
                value, state['unused_layouts'], inv_layout_maps)
            value = state['steck_map'][value]

        result.append(value)
        state['rotors'] = legacy_advance_rotors(
            state['rotors'], ci, km['step_mask'])
        state['alpha_index'] += 1

    return ''.join(result)


def encode_base95_int(value, width):
    if value < 0:
        raise ValueError('Base-95 encoding requires a non-negative integer')
    chars = ['0'] * width
    current = value
    for index in range(width - 1, -1, -1):
        chars[index] = ALPHA[current % N]
        current //= N
    if current:
        raise ValueError(f'Value exceeds {width} base-95 characters')
    return ''.join(chars)


def decode_base95_int(text):
    value = 0
    for char in text:
        index = ALPHA.find(char)
        if index < 0:
            raise ValueError(
                f'Non-alphabet character in base-95 field: {repr(char)}')
        value = value * N + index
    return value


def encode_length_field(length):
    return encode_base95_int(length, LEN_FIELD_LEN)


def decode_length_field(field):
    if len(field) != LEN_FIELD_LEN:
        raise ValueError(f'Length field must be {LEN_FIELD_LEN} characters')
    return decode_base95_int(field)


def encode_legacy_base95_int(value, width):
    if value < 0:
        raise ValueError('Base-95 encoding requires a non-negative integer')
    chars = ['0'] * width
    current = value
    for index in range(width - 1, -1, -1):
        chars[index] = LEGACY_ALPHA[current % LEGACY_N]
        current //= LEGACY_N
    if current:
        raise ValueError(f'Value exceeds {width} base-95 characters')
    return ''.join(chars)


def decode_legacy_base95_int(text):
    value = 0
    for char in text:
        index = LEGACY_ALPHA.find(char)
        if index < 0:
            raise ValueError(
                f'Non-alphabet character in legacy base-95 field: {repr(char)}')
        value = value * LEGACY_N + index
    return value


def encode_legacy_length_field(length):
    return encode_legacy_base95_int(length, LEN_FIELD_LEN)


def decode_legacy_length_field(field):
    if len(field) != LEN_FIELD_LEN:
        raise ValueError(f'Length field must be {LEN_FIELD_LEN} characters')
    return decode_legacy_base95_int(field)


def compute_legacy_alphabet_checksum(checksum_input, key_str, version_char=RC4_VERSION_CHAR):
    state = _legacy_fnv_hash64(f'{checksum_input}|{key_str}|{version_char}|chk64')
    out = []
    for index in range(CHECKSUM_LEN):
        state = lcg64(state ^ index)
        out.append(LEGACY_ALPHA[state % LEGACY_N])
    return ''.join(out)


def compute_checksum(checksum_input, key_str, version_char=RC4_VERSION_CHAR):
    state = hash_str64(f'{checksum_input}|{key_str}|{version_char}|chk64')
    out = []
    for index in range(CHECKSUM_LEN):
        state = lcg64(state ^ index)
        out.append(ALPHA[state % N])
    return ''.join(out)


def compute_padding_seed(plaintext, key_str, length_field=None, version_char=RC4_VERSION_CHAR):
    field = length_field if length_field is not None else encode_length_field(
        len(plaintext))
    return compute_checksum(f'{field}|{plaintext}', key_str, version_char)


def compute_rc3_checksum(plaintext, key_str, length_field=None):
    field = length_field if length_field is not None else encode_legacy_length_field(
        len(plaintext))
    state = _legacy_fnv_hash64(f'{field}|{plaintext}|{key_str}|chk64')
    out = []
    for index in range(CHECKSUM_LEN):
        state = lcg64(state ^ index)
        out.append(LEGACY_ALPHA[state % LEGACY_N])
    return ''.join(out)


def legacy_compute_checksum(plaintext, key_str):
    state = _legacy_fnv_hash64(f'{plaintext}|{key_str}|chk64')
    out = []
    for index in range(CHECKSUM_LEN):
        state = lcg64(state ^ index)
        out.append(LEGACY_ALPHA[state % LEGACY_N])
    return ''.join(out)


def legacy_checksum_pos(key_str, total_len):
    return _legacy_fnv_hash32(f'{key_str}chkpos') % max(1, total_len - CHECKSUM_LEN)


def compute_pad_length(plaintext, key_str, padding_seed, version_char):
    pad_len = hash_str64(
        f'{key_str}|{plaintext}|{padding_seed}|{version_char}|padlen') % MAX_PAD_LEN
    if plaintext == '' and pad_len == 0:
        pad_len = 1
    return pad_len


def generate_padding(plaintext, key_str, padding_seed, version_char, pad_len=None):
    target_len = compute_pad_length(
        plaintext, key_str, padding_seed, version_char) if pad_len is None else pad_len
    if target_len == 0:
        return ''
    out = []
    state = hash_str64(
        f'{key_str}|{plaintext}|{padding_seed}|{version_char}|padfill')
    for index in range(target_len):
        state = lcg64(state ^ index)
        out.append(ALPHA[state % N])
    return ''.join(out)


def compute_legacy_padding_seed(plaintext, key_str, length_field=None, version_char=RC4_VERSION_CHAR):
    field = length_field if length_field is not None else encode_legacy_length_field(
        len(plaintext))
    return compute_legacy_alphabet_checksum(f'{field}|{plaintext}', key_str, version_char)


def generate_legacy_padding(plaintext, key_str, padding_seed, version_char, pad_len=None):
    target_len = _legacy_compute_pad_length(
        plaintext, key_str, padding_seed, version_char) if pad_len is None else pad_len
    if target_len == 0:
        return ''
    out = []
    state = _legacy_fnv_hash64(
        f'{key_str}|{plaintext}|{padding_seed}|{version_char}|padfill')
    for index in range(target_len):
        state = lcg64(state ^ index)
        out.append(LEGACY_ALPHA[state % LEGACY_N])
    return ''.join(out)


def compute_rc3_pad_length(plaintext, key_str):
    return _legacy_fnv_hash64(f'{key_str}|{plaintext}|padlen') % MAX_PAD_LEN


def generate_rc3_padding(plaintext, key_str, pad_len=None):
    target_len = compute_rc3_pad_length(
        plaintext, key_str) if pad_len is None else pad_len
    if target_len == 0:
        return ''
    out = []
    state = _legacy_fnv_hash64(f'{key_str}|{plaintext}|padfill')
    for index in range(target_len):
        state = lcg64(state ^ index)
        out.append(LEGACY_ALPHA[state % LEGACY_N])
    return ''.join(out)


def pack_rc4_payload(plaintext, key_str):
    version = RC4_VERSION_CHAR
    length_field = encode_length_field(len(plaintext))
    padding_seed = compute_padding_seed(
        plaintext, key_str, length_field, version)
    padding = generate_padding(plaintext, key_str, padding_seed, version)
    return {
        'visible_payload': RC4_FORMAT_TAG + length_field + plaintext + padding,
        'version': version,
        'length_field': length_field,
        'padding': padding,
        'padding_seed': padding_seed,
    }


def pack_rc6_payload(plaintext, key_str):
    version = RC6_VERSION_CHAR
    length_field = encode_length_field(len(plaintext))
    padding_seed = compute_padding_seed(
        plaintext, key_str, length_field, version)
    padding = generate_padding(plaintext, key_str, padding_seed, version)
    return {
        'visible_payload': RC4_FORMAT_TAG + length_field + plaintext + padding,
        'version': version,
        'length_field': length_field,
        'padding': padding,
        'padding_seed': padding_seed,
    }


def pack_rc3_payload(plaintext, key_str):
    length_field = encode_legacy_length_field(len(plaintext))
    checksum = compute_rc3_checksum(plaintext, key_str, length_field)
    padding = generate_rc3_padding(plaintext, key_str)
    return length_field + plaintext + checksum + padding


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

    length_field = payload[:LEN_FIELD_LEN]
    try:
        plaintext_len = decode_legacy_length_field(length_field)
    except ValueError as exc:
        return {
            'plaintext': '',
            'verified': False,
            'checksum_ok': False,
            'padding_ok': False,
            'structure_ok': False,
            'length_field': length_field,
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
            'length_field': length_field,
            'padding': '',
            'error': f'Length field decodes to {plaintext_len}, but payload only has {len(remaining)} chars after the header'
        }

    plaintext = remaining[:plaintext_len]
    checksum = remaining[plaintext_len:plaintext_len + CHECKSUM_LEN]
    padding = remaining[plaintext_len + CHECKSUM_LEN:]
    checksum_ok = checksum == compute_rc3_checksum(
        plaintext, key_str, length_field)
    expected_pad_len = compute_rc3_pad_length(plaintext, key_str)
    expected_padding = generate_rc3_padding(
        plaintext, key_str, expected_pad_len)
    padding_ok = len(
        padding) == expected_pad_len and padding == expected_padding
    return {
        'plaintext': plaintext,
        'verified': checksum_ok and padding_ok,
        'checksum_ok': checksum_ok,
        'padding_ok': padding_ok,
        'structure_ok': True,
        'length_field': length_field,
        'padding': padding,
        'error': None if checksum_ok and padding_ok else GENERIC_DECRYPT_ERROR
    }


def unpack_rc4_visible_payload(payload):
    min_len = 1 + LEN_FIELD_LEN
    if len(payload) < min_len:
        return {
            'format_tag': '',
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': '',
            'padding': '',
            'error': f'Payload too short for rc.4-hidden visible package ({len(payload)} chars)',
        }

    format_tag = payload[0]
    if format_tag != RC4_FORMAT_TAG:
        return {
            'format_tag': format_tag,
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': '',
            'padding': '',
            'error': 'Visible payload tag does not match rc.4-hidden'
        }

    length_field = payload[1:1 + LEN_FIELD_LEN]
    try:
        plaintext_len = decode_length_field(length_field)
    except ValueError as exc:
        return {
            'format_tag': format_tag,
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': length_field,
            'padding': '',
            'error': str(exc)
        }

    remaining = payload[1 + LEN_FIELD_LEN:]
    if plaintext_len > len(remaining):
        return {
            'format_tag': format_tag,
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': length_field,
            'padding': '',
            'error': f'Length field decodes to {plaintext_len}, but visible payload only has {len(remaining)} chars after the header'
        }

    return {
        'format_tag': format_tag,
        'plaintext': remaining[:plaintext_len],
        'padding': remaining[plaintext_len:],
        'length_field': length_field,
        'structure_ok': True,
        'verified': False,
        'checksum_ok': False,
        'padding_ok': False,
        'metadata_ok': False,
        'version_ok': False,
        'error': None,
    }


def unpack_rc4_legacy_visible_payload(payload):
    min_len = 1 + LEN_FIELD_LEN
    if len(payload) < min_len:
        return {
            'format_tag': '',
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': '',
            'padding': '',
            'error': f'Payload too short for rc.4-hidden visible package ({len(payload)} chars)',
        }

    format_tag = payload[0]
    if format_tag != RC4_FORMAT_TAG:
        return {
            'format_tag': format_tag,
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': '',
            'padding': '',
            'error': 'Visible payload tag does not match rc.4-hidden'
        }

    length_field = payload[1:1 + LEN_FIELD_LEN]
    try:
        plaintext_len = decode_legacy_length_field(length_field)
    except ValueError as exc:
        return {
            'format_tag': format_tag,
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': length_field,
            'padding': '',
            'error': str(exc)
        }

    remaining = payload[1 + LEN_FIELD_LEN:]
    if plaintext_len > len(remaining):
        return {
            'format_tag': format_tag,
            'plaintext': '',
            'verified': False,
            'structure_ok': False,
            'checksum_ok': False,
            'padding_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'length_field': length_field,
            'padding': '',
            'error': f'Length field decodes to {plaintext_len}, but visible payload only has {len(remaining)} chars after the header'
        }

    return {
        'format_tag': format_tag,
        'plaintext': remaining[:plaintext_len],
        'padding': remaining[plaintext_len:],
        'length_field': length_field,
        'structure_ok': True,
        'verified': False,
        'checksum_ok': False,
        'padding_ok': False,
        'metadata_ok': False,
        'version_ok': False,
        'error': None,
    }


def keyed_zero_width_order(key_str):
    symbols = ZERO_WIDTH_SYMBOLS[:]
    state = hash_str64(f'{key_str}|zwperm')
    for i in range(len(symbols) - 1, 0, -1):
        state = lcg64(state ^ i)
        j = state % (i + 1)
        symbols[i], symbols[j] = symbols[j], symbols[i]
    return symbols


def keyed_visible_carrier_alphabet(key_str):
    # Visible carrier alphabet for materialized metadata: keyed order of A,B,C,D.
    # Same Fisher-Yates-with-seed structure as keyed_zero_width_order, so the
    # 4 carrier digit symbols rotate per key just like the zero-width digits do.
    symbols = [ALPHA[0], ALPHA[1], ALPHA[2], ALPHA[3]]
    state = hash_str64(f'{key_str}|matperm')
    for i in range(len(symbols) - 1, 0, -1):
        state = lcg64(state ^ i)
        j = state % (i + 1)
        symbols[i], symbols[j] = symbols[j], symbols[i]
    return symbols


def encode_hidden_carrier_chars(hidden_cipher, key_str):
    order = keyed_zero_width_order(key_str)
    out = []
    for char in hidden_cipher:
        index = ALPHA.index(char)
        digits = [0, 0, 0, 0]
        value = index
        for digit_index in range(len(digits) - 1, -1, -1):
            digits[digit_index] = value % 4
            value //= 4
        out.extend(order[digit] for digit in digits)
    return ''.join(out)


def encode_visible_carrier_chars(metadata, key_str):
    order = keyed_visible_carrier_alphabet(key_str)
    out = []
    for char in metadata:
        index = ALPHA.index(char)
        digits = [0, 0, 0, 0]
        value = index
        for digit_index in range(len(digits) - 1, -1, -1):
            digits[digit_index] = value % 4
            value //= 4
        out.extend(order[digit] for digit in digits)
    return ''.join(out)


def decode_visible_carrier_stream(stream, key_str):
    if len(stream) % HIDDEN_CHUNK_LEN != 0:
        raise ValueError(
            f'Materialized metadata carrier count must be a multiple of {HIDDEN_CHUNK_LEN}')
    order = keyed_visible_carrier_alphabet(key_str)
    reverse = {symbol: index for index, symbol in enumerate(order)}
    out = []
    for i in range(0, len(stream), HIDDEN_CHUNK_LEN):
        value = 0
        for char in stream[i:i + HIDDEN_CHUNK_LEN]:
            if char not in reverse:
                raise ValueError(
                    'Unknown materialized metadata carrier symbol detected')
            value = value * 4 + reverse[char]
        if value >= N:
            raise ValueError(
                f'Materialized metadata digit block decodes outside ALPHA: {value}')
        out.append(ALPHA[value])
    return ''.join(out)


def inject_hidden_carriers(visible_cipher, carrier_stream, key_str):
    gap_count = len(visible_cipher) + 1
    counts = [0] * gap_count
    state = hash_str64(f'{key_str}|{len(visible_cipher)}|zwscatter')
    for index in range(len(carrier_stream)):
        state = lcg64(state ^ index)
        counts[state % gap_count] += 1

    cursor = 0
    out = []
    for gap in range(gap_count):
        if counts[gap]:
            out.append(carrier_stream[cursor:cursor + counts[gap]])
            cursor += counts[gap]
        if gap < len(visible_cipher):
            out.append(visible_cipher[gap])
    return ''.join(out)


def extract_carrier_info(text):
    visible_chars = []
    carrier_chars = []
    positions = []
    for pos, char in enumerate(text, start=1):
        if char in ZERO_WIDTH_SET:
            carrier_chars.append(char)
            positions.append((pos, char))
        else:
            visible_chars.append(char)
    return {
        'visible_text': ''.join(visible_chars),
        'carrier_stream': ''.join(carrier_chars),
        'hidden_carrier_count': len(carrier_chars),
        'hidden_carrier_positions': positions,
    }


def decode_hidden_carrier_stream(carrier_stream, key_str):
    if len(carrier_stream) % HIDDEN_CHUNK_LEN != 0:
        raise ValueError(
            f'Hidden metadata carrier count must be a multiple of {HIDDEN_CHUNK_LEN}')
    order = keyed_zero_width_order(key_str)
    reverse = {symbol: index for index, symbol in enumerate(order)}
    out = []
    for i in range(0, len(carrier_stream), HIDDEN_CHUNK_LEN):
        value = 0
        for char in carrier_stream[i:i + HIDDEN_CHUNK_LEN]:
            if char not in reverse:
                raise ValueError(
                    'Unknown hidden metadata carrier symbol detected')
            value = value * 4 + reverse[char]
        if value >= N:
            raise ValueError(
                f'Hidden metadata digit block decodes outside ALPHA: {value}')
        out.append(ALPHA[value])
    return ''.join(out)


def _try_decode_rc6_metadata(carrier_stream, key_str):
    if len(carrier_stream) != HIDDEN_SYMBOL_COUNT:
        return None
    try:
        metadata = decode_hidden_carrier_stream(carrier_stream, key_str)
    except ValueError:
        return None
    if len(metadata) != HIDDEN_METADATA_LEN or metadata[0] != RC6_VERSION_CHAR:
        return None
    return metadata


def encrypt_rc6_stream(plaintext, key, materialize=False):
    payload = pack_rc6_payload(plaintext, key['key_str'])
    checksum = compute_checksum(payload['visible_payload'], derive_mac_subkey(
        key['key_str']), payload['version'])
    if materialize:
        carrier_stream = encode_visible_carrier_chars(
            payload['version'] + checksum, key['key_str'])
        wildcards = None
    else:
        carrier_stream = encode_hidden_carrier_chars(
            payload['version'] + checksum, key['key_str'])
        wildcards = derive_carrier_wildcards(
            key['key_str'], HIDDEN_SYMBOL_COUNT)
    schedule = build_stream_schedule(key['key_str'], len(
        plaintext), len(payload['visible_payload']))
    state = create_cipher_state(
        key['steck_pairs'], key['rotors'], key['enabled'], key['user_rounds'], key['nonce'])

    payload_index = 0
    checksum_index = 0
    carrier_index = 0
    out = []
    for event in schedule:
        if event == 'payload':
            out.append(process_segment(
                payload['visible_payload'][payload_index], state, decrypt=False))
            payload_index += 1
        elif event == 'checksum':
            out.append(process_segment(
                checksum[checksum_index], state, decrypt=False))
            checksum_index += 1
        else:
            if materialize:
                out.append(process_segment(
                    carrier_stream[carrier_index], state, decrypt=False))
            else:
                process_segment(wildcards[carrier_index], state, decrypt=False)
                out.append(carrier_stream[carrier_index])
            carrier_index += 1

    return ''.join(out)


def _attempt_decrypt_rc6_stream(ciphertext, key, diagnostics, plaintext_len, materialize=False):
    if materialize:
        visible_len = len(ciphertext)
        payload_len = visible_len - CHECKSUM_LEN - HIDDEN_SYMBOL_COUNT
    else:
        visible_len = sum(
            1 for char in ciphertext if char not in ZERO_WIDTH_SET)
        payload_len = visible_len - CHECKSUM_LEN
    if payload_len < 1 + LEN_FIELD_LEN:
        return None
    schedule = build_stream_schedule(
        key['key_str'], plaintext_len, payload_len)
    if len(schedule) != len(ciphertext):
        return None

    wildcards = None if materialize else derive_carrier_wildcards(
        key['key_str'], HIDDEN_SYMBOL_COUNT)
    state = create_cipher_state(
        key['steck_pairs'], key['rotors'], key['enabled'], key['user_rounds'], key['nonce'])
    payload = []
    checksum_chars = []
    carrier_chars = []
    visible_carrier_chars = []
    carrier_index = 0

    for index, event in enumerate(schedule):
        char = ciphertext[index]
        if event == 'carrier':
            if carrier_index >= HIDDEN_SYMBOL_COUNT:
                return None
            if materialize:
                if char not in ALPHA:
                    return None
                value = process_segment(char, state, decrypt=True)
                visible_carrier_chars.append(value)
            else:
                if char not in ZERO_WIDTH_SET:
                    return None
                process_segment(wildcards[carrier_index], state, decrypt=True)
                carrier_chars.append(char)
            carrier_index += 1
            continue

        if char in ZERO_WIDTH_SET or char not in ALPHA:
            return None
        value = process_segment(char, state, decrypt=True)
        if event == 'checksum':
            checksum_chars.append(value)
        else:
            payload.append(value)

    if carrier_index != HIDDEN_SYMBOL_COUNT:
        return None

    if materialize:
        try:
            metadata = decode_visible_carrier_stream(
                ''.join(visible_carrier_chars), key['key_str'])
        except ValueError:
            return None
    else:
        carrier_stream = ''.join(carrier_chars)
        metadata = _try_decode_rc6_metadata(carrier_stream, key['key_str'])
        if metadata is None:
            return None

    payload_text = ''.join(payload)
    checksum = ''.join(checksum_chars)
    visible_fields = unpack_rc4_visible_payload(payload_text)
    if not visible_fields['structure_ok'] or visible_fields['format_tag'] != RC4_FORMAT_TAG:
        return None
    if len(visible_fields['plaintext']) != plaintext_len:
        return None

    version = metadata[0]
    metadata_checksum = metadata[1:]
    expected_checksum = compute_checksum(
        payload_text, derive_mac_subkey(key['key_str']), version)
    padding_seed = compute_padding_seed(
        visible_fields['plaintext'], key['key_str'], visible_fields['length_field'], version)
    expected_pad_len = compute_pad_length(
        visible_fields['plaintext'], key['key_str'], padding_seed, version)
    expected_padding = generate_padding(
        visible_fields['plaintext'], key['key_str'], padding_seed, version, expected_pad_len)
    version_ok = version == RC6_VERSION_CHAR
    checksum_ok = version_ok and checksum == expected_checksum and metadata_checksum == checksum
    padding_ok = version_ok and len(
        visible_fields['padding']) == expected_pad_len and visible_fields['padding'] == expected_padding
    verified = version_ok and checksum_ok and padding_ok
    if not verified:
        return None

    result = {
        'plaintext': visible_fields['plaintext'],
        'verified': True,
        'checksum_ok': checksum_ok,
        'padding_ok': padding_ok,
        'structure_ok': True,
        'metadata_ok': True,
        'version_ok': version_ok,
        'diagnostics': diagnostics,
        'payload': payload_text,
        'visible_payload': payload_text,
        'format': 'rc.6-stream',
        'materialize': materialize,
        'length_field': visible_fields['length_field'],
        'padding': visible_fields['padding'],
        'hidden_payload': metadata,
        'version': version,
        'error': None,
    }
    return _finalize_decrypt_result(result, visible_fields['plaintext'], key['key_str'], state['km'], state)


def decrypt_rc6_stream(ciphertext, key, diagnostics, extracted, materialize=False):
    if materialize:
        if extracted['hidden_carrier_count'] != 0:
            return None
        if any(char not in ALPHA for char in ciphertext):
            return None
        visible_len = len(ciphertext)
        payload_len = visible_len - CHECKSUM_LEN - HIDDEN_SYMBOL_COUNT
    else:
        if extracted['hidden_carrier_count'] != HIDDEN_SYMBOL_COUNT:
            return None
        if _try_decode_rc6_metadata(extracted['carrier_stream'], key['key_str']) is None:
            return None
        visible_len = len(extracted['visible_text'])
        payload_len = visible_len - CHECKSUM_LEN
    if payload_len < 1 + LEN_FIELD_LEN:
        return None

    for pad_len in range(MAX_PAD_LEN):
        plaintext_len = payload_len - (1 + LEN_FIELD_LEN) - pad_len
        if plaintext_len < 0:
            continue
        result = _attempt_decrypt_rc6_stream(
            ciphertext, key, diagnostics, plaintext_len, materialize=materialize)
        if result and result.get('success'):
            return result
    return None


def format_cipher_char(char):
    if char in ZERO_WIDTH_LABELS:
        return ZERO_WIDTH_LABELS[char]
    if char == ' ':
        return '[space]'
    if char == '\n':
        return '\\n'
    if char == '\r':
        return '\\r'
    if char == '\t':
        return '\\t'
    return char


def summarize_cipher_issues(entries):
    shown = []
    for pos, char, replacement in entries[:4]:
        base = f'{format_cipher_char(char)}@{pos}'
        shown.append(
            base if replacement is None else f'{base}->{format_cipher_char(replacement)}')
    if len(entries) > 4:
        shown.append(f'+{len(entries) - 4} more')
    return ', '.join(shown)


def analyze_ciphertext(text):
    non_ascii = []
    normalized = []
    controls = []
    hidden_carriers = []
    outside_alpha_count = 0
    for pos, char in enumerate(text, start=1):
        if char in ALPHA:
            continue
        if char in ZERO_WIDTH_SET:
            hidden_carriers.append((pos, char, None))
            continue
        outside_alpha_count += 1
        replacement = CLIPBOARD_NORMALIZATION_MAP.get(char)
        if replacement is not None:
            normalized.append((pos, char, replacement))
        if char in '\r\n\t':
            controls.append((pos, char, None))
        if ord(char) > 127:
            non_ascii.append((pos, char, replacement))
    warnings = []
    if normalized:
        warnings.append(
            f'Suspicious clipboard-normalized punctuation: {summarize_cipher_issues(normalized)}')
    elif non_ascii:
        warnings.append(
            f'Non-ASCII ciphertext characters detected: {summarize_cipher_issues(non_ascii)}')
    if controls:
        warnings.append(
            f'Whitespace/control characters detected: {summarize_cipher_issues(controls)}')
    if hidden_carriers and len(hidden_carriers) % HIDDEN_CHUNK_LEN != 0:
        warnings.append(
            f'Hidden metadata carrier count looks damaged: {len(hidden_carriers)} markers')
    return {
        'length': len(text),
        'visible_length': len(text) - len(hidden_carriers),
        'outside_alpha_count': outside_alpha_count,
        'non_ascii': non_ascii,
        'normalized': normalized,
        'controls': controls,
        'hidden_carriers': hidden_carriers,
        'hidden_carrier_count': len(hidden_carriers),
        'warnings': warnings,
    }


def parse_key(key_str):
    parts = key_str.strip().split()
    if len(parts) not in (4, 5):
        raise ValueError(f'Expected 4 or 5 sections, got {len(parts)}')

    enabled_str, rotor_str, steck_str, rounds_str = parts[:4]
    nonce_str = parts[4] if len(parts) == 5 else ''
    wide_key = enabled_str.startswith(KEY_V6_PREFIX)
    if wide_key:
        enabled_token = enabled_str[len(KEY_V6_PREFIX):]
        enabled = []
        for char in enabled_token:
            layout_index = decode_base36_index(char)
            if layout_index >= len(LAYOUT_NAMES):
                raise ValueError(f'Invalid enabled layout digit: {repr(char)}')
            enabled.append(LAYOUT_NAMES[layout_index])
    else:
        enabled = [LAYOUT_NAMES[int(char)] for char in enabled_str]
    rotors = []
    if not rotor_str or len(rotor_str) % 3 != 0:
        raise ValueError('Rotor section must be groups of 3 digits')
    for i in range(0, len(rotor_str), 3):
        if wide_key:
            layout_index = decode_base36_index(rotor_str[i])
            pos = decode_base36_index(rotor_str[i + 1:i + 3])
        else:
            layout_index = int(rotor_str[i])
            pos = int(rotor_str[i + 1:i + 3])
        if layout_index >= len(LAYOUT_NAMES):
            raise ValueError(f'Invalid rotor layout index at {i}')
        if pos >= N:
            raise ValueError(f'Invalid rotor position at {i + 1}')
        rotors.append({'layout': LAYOUT_NAMES[layout_index], 'pos': pos})
    steck_pairs = []
    if steck_str != '0':
        if len(steck_str) % 4 != 0:
            raise ValueError('Steck section must be groups of 4 digits')
        for i in range(0, len(steck_str), 4):
            if wide_key:
                ai = decode_base36_index(steck_str[i:i + 2])
                bi = decode_base36_index(steck_str[i + 2:i + 4])
            else:
                ai = int(steck_str[i:i + 2])
                bi = int(steck_str[i + 2:i + 4])
            if ai >= N or bi >= N:
                raise ValueError(
                    'Steck section contains an out-of-range alphabet index')
            steck_pairs.append((ALPHA[ai], ALPHA[bi]))
    user_rounds = int(rounds_str)
    if not 1 <= user_rounds <= 999:
        raise ValueError('Rounds section must be 001-999')
    nonce = ''
    if nonce_str:
        if len(nonce_str) % 2 != 0:
            raise ValueError('Nonce section must be groups of 2 digits')
        for i in range(0, len(nonce_str), 2):
            index = decode_base36_index(
                nonce_str[i:i + 2]) if wide_key else int(nonce_str[i:i + 2])
            if index >= N:
                raise ValueError(
                    'Nonce section contains an out-of-range alphabet index')
            nonce += ALPHA[index]
    return {
        'enabled': enabled,
        'rotors': rotors,
        'steck_pairs': steck_pairs,
        'user_rounds': user_rounds,
        'nonce': nonce,
        'key_str': key_str.strip(),
    }


def encode_key(enabled, rotors, steck_pairs, user_rounds, nonce=''):
    enabled_str = KEY_V6_PREFIX + \
        ''.join(encode_base36_index(LAYOUT_NAMES.index(name), 1)
                for name in enabled)
    rotor_str = ''.join(
        f'{encode_base36_index(LAYOUT_NAMES.index(rotor["layout"]), 1)}{encode_base36_index(rotor["pos"], 2)}'
        for rotor in rotors
    )
    if steck_pairs:
        steck_str = ''.join(
            f'{encode_base36_index(min(ALPHA.index(a), ALPHA.index(b)), 2)}{encode_base36_index(max(ALPHA.index(a), ALPHA.index(b)), 2)}'
            for a, b in sorted(steck_pairs, key=lambda pair: (min(ALPHA.index(pair[0]), ALPHA.index(pair[1])), max(ALPHA.index(pair[0]), ALPHA.index(pair[1]))))
        )
    else:
        steck_str = '0'
    rounds_str = f'{user_rounds:03d}'
    base = f'{enabled_str} {rotor_str} {steck_str} {rounds_str}'
    if not nonce:
        return base
    nonce_str = ''.join(encode_base36_index(ALPHA.index(char), 2)
                        for char in nonce)
    return f'{base} {nonce_str}'


# -- v2.0.0 legacy decryption (self-contained, decrypt-only) ------------------
# A complete reimplementation of the v2.0.0 cipher pipeline so rc.7 can recover
# ciphertexts produced by v2.0.0. None of these symbols are reused by rc.6+; they
# share only the variable-name patterns of the v2.0.0 source.

V200_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ;0123456789-=[]\\\',./' + \
    '!@#$%^&*()_+{}|:"<>?`~'
V200_N = 68
assert len(V200_ALPHA) == V200_N
V200_CHECKSUM_LEN = 4
V200_FNV_OFFSET = 2166136261
V200_FNV_PRIME = 16777619
V200_LCG_MULT = 1664525
V200_LCG_INC = 1013904223
V200_LCG_MASK = 0xFFFFFFFF
V200_STEP_MASK_ACTIVE = 47
V200_LAYOUT_NAMES = ['QWERTY', 'Colemak', 'Colemak-DH', 'Dvorak', 'Workman',
                     'Norman', 'Asset', 'Halmak', 'AZERTY', 'QWERTZ']
V200_LAYOUT_DEFS = {
    'QWERTY':    {'top': 'QWERTYUIOP', 'home': 'ASDFGHJKL;', 'bot': 'ZXCVBNM'},
    'Colemak':   {'top': 'QWFPGJLUY;', 'home': 'ARSTDHNEIO', 'bot': 'ZXCVBKM'},
    'Colemak-DH': {'top': 'QWFPBJLUY;', 'home': 'ARSTGMNEIO', 'bot': 'ZXCDVKH'},
    'Dvorak':    {'top': "',.PYFGCRL", 'home': 'AOEUIDHTNS', 'bot': ';QJKXBM'},
    'Workman':   {'top': 'QDRWBJFUP;', 'home': 'ASHTGYNEOI', 'bot': 'ZXMCVKL'},
    'Norman':    {'top': 'QWDFKJURL;', 'home': 'ASETGYNIOH', 'bot': 'ZXCVBPM'},
    'Asset':     {'top': 'QWJFGYPUL;', 'home': 'ASETDHNIOR', 'bot': 'ZXCVBKM'},
    'Halmak':    {'top': 'WLRBJZFUO;', 'home': 'SHNTMEDAIC', 'bot': 'QGVXPKY'},
    'AZERTY':    {'top': 'AZERTYUIOP', 'home': 'QSDFGHJKL;', 'bot': 'WXCVBNM'},
    'QWERTZ':    {'top': 'QWERTZUIOP', 'home': 'ASDFGHJKL;', 'bot': 'YXCVBNM'},
}
V200_QWERTY_TOP = 'QWERTYUIOP'
V200_QWERTY_HOME = 'ASDFGHJKL;'
V200_QWERTY_BOT = 'ZXCVBNM'


def v200_hash_str(s):
    h = V200_FNV_OFFSET
    for ch in s:
        h ^= ord(ch)
        h = (h * V200_FNV_PRIME) & V200_LCG_MASK
    return h


def v200_lcg(v):
    return (v * V200_LCG_MULT + V200_LCG_INC) & V200_LCG_MASK


def v200_rotor_state_hash(rotors):
    h = V200_FNV_OFFSET
    for r in rotors:
        h ^= r['pos'] * 73
        h = (h * V200_FNV_PRIME) & V200_LCG_MASK
    return h


def v200_build_map(name):
    d = V200_LAYOUT_DEFS[name]
    m = {}
    for q, c in zip(V200_QWERTY_TOP, d['top']):
        if c.upper() in V200_ALPHA:
            m[q] = c.upper()
    for q, c in zip(V200_QWERTY_HOME, d['home']):
        if c.upper() in V200_ALPHA:
            m[q] = c.upper()
    for q, c in zip(V200_QWERTY_BOT, d['bot']):
        if c.upper() in V200_ALPHA:
            m[q] = c.upper()
    return m


def v200_compute_key_material(steck_pairs, rotors, enabled_layouts, user_rounds):
    S = sum(
        (min(V200_ALPHA.index(a), V200_ALPHA.index(b)) *
         V200_N + max(V200_ALPHA.index(a), V200_ALPHA.index(b)))
        for a, b in steck_pairs
    )
    R = sum(r['pos'] for r in rotors)
    L = sum(V200_LAYOUT_NAMES.index(n) for n in enabled_layouts)
    rounds = ((S + R + L + user_rounds) % 999) + 1
    key_sum = (S * 31 + R * 17 + L * 13) & V200_LCG_MASK

    step_pos = list(range(V200_N))
    v = (key_sum ^ 0x5A5A5A5A) & V200_LCG_MASK
    for i in range(V200_N - 1, 0, -1):
        v = v200_lcg(v)
        j = v % (i + 1)
        step_pos[i], step_pos[j] = step_pos[j], step_pos[i]
    step_mask = [False] * V200_N
    for p in step_pos[:V200_STEP_MASK_ACTIVE]:
        step_mask[p] = True

    trans_perm = list(range(V200_N))
    v = (key_sum ^ 0xDEAD1234) & V200_LCG_MASK
    for i in range(V200_N - 1, 0, -1):
        v = v200_lcg(v)
        j = v % (i + 1)
        trans_perm[i], trans_perm[j] = trans_perm[j], trans_perm[i]
    inv_trans_perm = [0] * V200_N
    for i, x in enumerate(trans_perm):
        inv_trans_perm[x] = i

    layout_key_base = key_sum % V200_N

    layout_maps = {}
    inv_layout_maps = {}
    for li, name in enumerate(V200_LAYOUT_NAMES):
        perm = list(range(V200_N))
        seed = (key_sum ^ (li * 0x9E3779B9 + 0xABCD1234)) & V200_LCG_MASK
        v2 = seed
        for i in range(V200_N - 1, 0, -1):
            v2 = v200_lcg(v2)
            j = v2 % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        layout_maps[name] = {V200_ALPHA[i]: V200_ALPHA[perm[i]] for i in range(V200_N)}
        inv_layout_maps[name] = {V200_ALPHA[perm[i]]: V200_ALPHA[i] for i in range(V200_N)}

    whitening_seed = (key_sum ^ 0xC0FFEE42) & V200_LCG_MASK
    return {
        'rounds': rounds,
        'key_sum': key_sum,
        'step_mask': step_mask,
        'trans_perm': trans_perm,
        'inv_trans_perm': inv_trans_perm,
        'layout_key_base': layout_key_base,
        'layout_maps': layout_maps,
        'inv_layout_maps': inv_layout_maps,
        'whitening_seed': whitening_seed,
    }


def v200_keyed_layout_offset(layout_name, layout_key_base):
    return (V200_LAYOUT_NAMES.index(layout_name) * 7 + layout_key_base) % V200_N


def v200_rotor_shift(rotors):
    val = 0
    n = len(rotors)
    for i, r in enumerate(rotors):
        val += r['pos'] * (V200_N ** (n - 1 - i))
    return int(val) % V200_N


def v200_advance_rotors(rotors, char_idx, step_mask):
    if not step_mask[char_idx % V200_N]:
        return [dict(r) for r in rotors]
    rs = [dict(r) for r in rotors]
    rs[-1]['pos'] = (rs[-1]['pos'] + 1) % V200_N
    for i in range(len(rs) - 1, 0, -1):
        if rs[i]['pos'] == 0:
            rs[i - 1]['pos'] = (rs[i - 1]['pos'] + 1) % V200_N
    return rs


def v200_apply_nonce(rotors, nonce):
    if not nonce:
        return [dict(r) for r in rotors]
    result = []
    for i, r in enumerate(rotors):
        off = V200_ALPHA.index(nonce[i]) if i < len(nonce) else 0
        result.append({**r, 'pos': (r['pos'] + off) % V200_N})
    return result


def v200_apply_layout(c, layout_name, shift, invert, layout_maps, inv_layout_maps):
    if not invert:
        x = layout_maps[layout_name].get(c, c)
        if x in V200_ALPHA:
            x = V200_ALPHA[(V200_ALPHA.index(x) + shift) % V200_N]
        return x
    x = c
    if x in V200_ALPHA:
        x = V200_ALPHA[(V200_ALPHA.index(x) - shift) % V200_N]
    return inv_layout_maps[layout_name].get(x, x)


def v200_plug_fwd(c, layouts, layout_maps):
    for n in layouts:
        c = layout_maps[n].get(c, c)
    return c


def v200_plug_inv(c, layouts, inv_layout_maps):
    for n in reversed(layouts):
        c = inv_layout_maps[n].get(c, c)
    return c


def v200_process(text, key, decrypt=True, variant='py'):
    km = v200_compute_key_material(
        key['steck_pairs'], key['rotors'], key['enabled'], key['user_rounds'])
    rds = km['rounds']
    steck_map = {ch: ch for ch in V200_ALPHA}
    for a, b in key['steck_pairs']:
        steck_map[a] = b
        steck_map[b] = a
    rotor_set = {r['layout'] for r in key['rotors']}
    el = list(key['enabled'])
    unused = [n for n in el if n not in rotor_set]
    rs = v200_apply_nonce(key['rotors'], key['nonce'])
    lm = km['layout_maps']
    ilm = km['inv_layout_maps']
    wstate = km['whitening_seed']
    result = []
    ci = 0
    for c in text:
        ch = c.upper() if 'a' <= c <= 'z' else c
        if ch not in V200_ALPHA:
            result.append(c)
            continue
        ss = v200_rotor_shift(rs)
        step_layouts = [el[r % len(el)] for r in range(rds)]
        rs_hash = v200_rotor_state_hash(rs)
        if variant == 'py':
            pos_offset = (km['key_sum'] * 37 + ci * 13 + rs_hash) % V200_N
        else:
            pos_offset = ((km['layout_key_base'] * 37 + ci *
                          13 + rs_hash) & V200_LCG_MASK) % V200_N
        step_shifts = [
            (ss + r + ci + pos_offset +
             v200_keyed_layout_offset(step_layouts[r], km['layout_key_base'])) % V200_N
            for r in range(rds)
        ]
        scramble_shifts = [
            (ss + rds + i + ci + pos_offset +
             v200_keyed_layout_offset(unused[i], km['layout_key_base'])) % V200_N
            for i in range(len(unused))
        ]
        x = ch
        if not decrypt:
            x = steck_map[x]
            x = v200_plug_fwd(x, unused, lm)
            for r in range(rds):
                x = v200_apply_layout(
                    x, step_layouts[r], step_shifts[r], False, lm, ilm)
            if x in V200_ALPHA:
                x = V200_ALPHA[km['trans_perm'][V200_ALPHA.index(x)]]
            for i, n in enumerate(unused):
                x = v200_apply_layout(x, n, scramble_shifts[i], False, lm, ilm)
            x = v200_plug_fwd(x, unused, lm)
            x = steck_map[x]
            wstate = v200_lcg(wstate)
            x = V200_ALPHA[(V200_ALPHA.index(x) + wstate % V200_N) % V200_N]
        else:
            wstate = v200_lcg(wstate)
            x = V200_ALPHA[(V200_ALPHA.index(x) - wstate % V200_N) % V200_N]
            x = steck_map[x]
            x = v200_plug_inv(x, unused, ilm)
            for i in range(len(unused) - 1, -1, -1):
                x = v200_apply_layout(
                    x, unused[i], scramble_shifts[i], True, lm, ilm)
            if x in V200_ALPHA:
                x = V200_ALPHA[km['inv_trans_perm'][V200_ALPHA.index(x)]]
            for r in range(rds - 1, -1, -1):
                x = v200_apply_layout(
                    x, step_layouts[r], step_shifts[r], True, lm, ilm)
            x = v200_plug_inv(x, unused, ilm)
            x = steck_map[x]
        result.append(x)
        rs = v200_advance_rotors(rs, ci, km['step_mask'])
        ci += 1
    return ''.join(result)


def v200_compute_checksum(plaintext, key_str):
    h1 = v200_hash_str(plaintext + '|' + key_str + '|chk1')
    h2 = v200_hash_str(plaintext + '|' + key_str + '|chk2')
    v = (h1 ^ (h2 << 16)) & V200_LCG_MASK
    out = ''
    for _ in range(V200_CHECKSUM_LEN):
        v = v200_lcg(v)
        out += V200_ALPHA[v % V200_N]
    return out


def v200_checksum_pos(key_str, total_len):
    h = v200_hash_str(key_str + 'chkpos')
    return h % max(1, total_len - V200_CHECKSUM_LEN)


def v200_strip_checksum(ciphertext, key_str):
    pos = v200_checksum_pos(key_str, len(ciphertext))
    chk = ciphertext[pos:pos + V200_CHECKSUM_LEN]
    stripped = ciphertext[:pos] + ciphertext[pos + V200_CHECKSUM_LEN:]
    return stripped, chk


def v200_sentence_case_for_checksum(text):
    lower = text.lower()
    if not lower:
        return lower
    return lower[0].upper() + lower[1:]


def v200_verify_checksum(chk, stripped, plaintext, key_str):
    if chk == v200_compute_checksum(stripped, key_str):
        return 'stripped'
    if chk == v200_compute_checksum(plaintext, key_str):
        return 'plain'
    folded = v200_sentence_case_for_checksum(plaintext)
    if chk == v200_compute_checksum(folded, key_str):
        return 'sentence'
    return None


def v200_parse_key(key_str):
    if key_str.strip().split()[0].startswith(KEY_V6_PREFIX):
        return None
    parts = key_str.strip().split()
    if len(parts) not in (4, 5):
        return None
    enabled_str, rotor_str, steck_str, u_str = parts[:4]
    nonce_str = parts[4] if len(parts) == 5 else ''
    try:
        enabled_indices = [int(c) for c in enabled_str]
        if not enabled_indices or any(idx >= len(V200_LAYOUT_NAMES) for idx in enabled_indices):
            return None
        enabled = [V200_LAYOUT_NAMES[idx] for idx in enabled_indices]
        if len(rotor_str) % 3 != 0 or not rotor_str:
            return None
        rotors = []
        for i in range(0, len(rotor_str), 3):
            lidx = int(rotor_str[i])
            pos = int(rotor_str[i + 1:i + 3])
            if lidx >= len(V200_LAYOUT_NAMES) or pos >= V200_N:
                return None
            rotors.append({'layout': V200_LAYOUT_NAMES[lidx], 'pos': pos})
        steck_pairs = []
        if steck_str != '0':
            if len(steck_str) % 4 != 0:
                return None
            for i in range(0, len(steck_str), 4):
                ai = int(steck_str[i:i + 2])
                bi = int(steck_str[i + 2:i + 4])
                if ai >= V200_N or bi >= V200_N:
                    return None
                steck_pairs.append((V200_ALPHA[ai], V200_ALPHA[bi]))
        user_rounds = int(u_str)
        nonce = ''
        if nonce_str:
            if len(nonce_str) % 2 != 0:
                return None
            for i in range(0, len(nonce_str), 2):
                idx = int(nonce_str[i:i + 2])
                if idx >= V200_N:
                    return None
                nonce += V200_ALPHA[idx]
        return {
            'enabled': enabled,
            'rotors': rotors,
            'steck_pairs': steck_pairs,
            'user_rounds': user_rounds,
            'nonce': nonce,
            'key_str': key_str.strip(),
        }
    except (ValueError, IndexError):
        return None


def v200_try_decrypt(ciphertext, key_str):
    if any(ch not in V200_ALPHA for ch in ciphertext if ch.isprintable() and ch != ' '):
        return None
    key = v200_parse_key(key_str)
    if key is None:
        return None
    if len(ciphertext) <= V200_CHECKSUM_LEN:
        return None
    for variant in ('py', 'js'):
        try:
            stripped, chk = v200_strip_checksum(ciphertext, key['key_str'])
            plaintext = v200_process(
                stripped, key, decrypt=True, variant=variant)
            verify_mode = v200_verify_checksum(
                chk, stripped, plaintext, key['key_str'])
            if verify_mode is not None:
                return {
                    'plaintext': plaintext,
                    'variant': variant,
                    'verify_mode': verify_mode,
                }
        except (ValueError, IndexError, KeyError):
            continue
    return None


def encode_v200_key_string(parsed):
    enabled_list = list(parsed['enabled'])
    if not enabled_list:
        return None
    enabled_parts = []
    for name in enabled_list:
        idx = V200_LAYOUT_NAMES.index(name) if name in V200_LAYOUT_NAMES else -1
        if idx < 0:
            return None
        enabled_parts.append(str(idx))
    enabled_str = ''.join(enabled_parts)

    rotor_str = ''
    for rotor in parsed['rotors']:
        lidx = V200_LAYOUT_NAMES.index(rotor['layout']) if rotor['layout'] in V200_LAYOUT_NAMES else -1
        if lidx < 0 or rotor['pos'] >= V200_N or rotor['layout'] not in enabled_list:
            return None
        rotor_str += f'{lidx}{rotor["pos"]:02d}'
    if not rotor_str:
        return None

    if parsed['steck_pairs']:
        steck_str = ''.join(
            f'{V200_ALPHA.index(a):02d}{V200_ALPHA.index(b):02d}'
            for a, b in parsed['steck_pairs']
            if V200_ALPHA.index(a) >= 0 and V200_ALPHA.index(b) >= 0
        )
        if len(steck_str) != len(parsed['steck_pairs']) * 4:
            return None
    else:
        steck_str = '0'

    rounds_str = f'{parsed["user_rounds"]:03d}'
    key = f'{enabled_str} {rotor_str} {steck_str} {rounds_str}'
    if parsed['nonce']:
        nonce_str = ''
        for ch in parsed['nonce']:
            idx = V200_ALPHA.index(ch) if ch in V200_ALPHA else -1
            if idx < 0:
                return None
            nonce_str += f'{idx:02d}'
        key += f' {nonce_str}'
    return key


def collect_v200_key_candidates(key_str, extra_candidates=()):
    candidates = []
    seen = set()

    def add(value):
        trimmed = (value or '').strip()
        if not trimmed or trimmed in seen:
            return
        seen.add(trimmed)
        candidates.append(trimmed)

    add(key_str)
    for value in extra_candidates:
        add(value)
    if v200_parse_key(key_str):
        add(key_str)
    try:
        add(encode_v200_key_string(parse_key(key_str)))
    except (ValueError, IndexError, KeyError):
        pass
    return candidates


def v200_try_decrypt_with_candidates(ciphertext, key_str, extra_candidates=()):
    for candidate in collect_v200_key_candidates(key_str, extra_candidates):
        result = v200_try_decrypt(ciphertext, candidate)
        if result is not None:
            result['key_str'] = candidate
            return result
    return None


def _finalize_v200_decrypt_result(v200_result, diagnostics, visible_text):
    result = {
        'plaintext': v200_result['plaintext'],
        'verified': True,
        'checksum_ok': True,
        'padding_ok': True,
        'structure_ok': True,
        'metadata_ok': True,
        'version_ok': True,
        'length_field': '',
        'padding': '',
        'error': None,
        'format': 'v2.0.0-legacy',
        'variant': v200_result['variant'],
        'diagnostics': diagnostics,
        'payload': visible_text,
    }
    return _finalize_decrypt_result(
        result, v200_result['plaintext'], v200_result['key_str'], {}, {'km': {}, 'rotors': []})


def encrypt_text(plaintext, key_str, materialize=False):
    if not key_str.strip().split()[0].startswith(KEY_V6_PREFIX):
        raise ValueError(K6_ENCRYPT_REQUIRED_ERROR)
    key = parse_key(key_str)
    return encrypt_rc6_stream(plaintext, key, materialize=materialize)


def decrypt_text(ciphertext, key_str, materialize=False, key_candidates=()):
    diagnostics = analyze_ciphertext(ciphertext)
    extracted = extract_carrier_info(ciphertext)
    visible_text = extracted['visible_text']

    v200_result = v200_try_decrypt_with_candidates(
        visible_text, key_str, key_candidates)
    if v200_result is not None:
        return _finalize_v200_decrypt_result(v200_result, diagnostics, visible_text)

    key = parse_key(key_str)

    if materialize:
        rc6_result = decrypt_rc6_stream(
            ciphertext, key, diagnostics, extracted, materialize=True)
        if rc6_result is not None:
            return rc6_result
        return _generic_decrypt_failure({
            'plaintext': '',
            'verified': False,
            'checksum_ok': False,
            'padding_ok': False,
            'structure_ok': False,
            'metadata_ok': False,
            'version_ok': False,
            'diagnostics': diagnostics,
            'payload': '',
            'visible_payload': '',
            'format': 'rc.6-stream',
            'materialize': True,
            'error': GENERIC_DECRYPT_ERROR,
        }, '', key['key_str'])

    rc6_result = decrypt_rc6_stream(ciphertext, key, diagnostics, extracted)
    if rc6_result is not None:
        return rc6_result
    if _try_decode_rc6_metadata(extracted['carrier_stream'], key['key_str']) is not None:
        return _generic_decrypt_failure({
            'plaintext': '',
            'verified': False,
            'checksum_ok': False,
            'padding_ok': False,
            'structure_ok': False,
            'metadata_ok': True,
            'version_ok': True,
            'diagnostics': diagnostics,
            'payload': '',
            'visible_payload': '',
            'format': 'rc.6-stream',
            'error': GENERIC_DECRYPT_ERROR,
        }, '', key['key_str'])

    if visible_text.startswith(LEGACY_RC3_HEADER):
        body = visible_text[len(LEGACY_RC3_HEADER):]
        state = create_legacy_cipher_state(
            key['steck_pairs'], key['rotors'], key['enabled'], key['user_rounds'], key['nonce'])
        payload = process_legacy_segment(body, state, decrypt=True)
        unpacked = unpack_rc3_payload(payload, key['key_str'])
        unpacked.update({
            'format': 'rc.3',
            'diagnostics': diagnostics,
            'payload': payload,
        })
        return _finalize_decrypt_result(unpacked, unpacked.get('plaintext', payload), key['key_str'], state['km'], state)

    try:
        rc4_state = create_rc4_legacy_cipher_state(
            key['steck_pairs'], key['rotors'], key['enabled'], key['user_rounds'], key['nonce'])
        visible_payload = process_rc4_legacy_segment(
            visible_text, rc4_state, decrypt=True)
        visible_fields = unpack_rc4_legacy_visible_payload(visible_payload)
    except (ValueError, IndexError, KeyError):
        rc4_state = None
        visible_payload = ''
        visible_fields = {'structure_ok': False}
    if visible_fields['structure_ok'] and visible_fields['format_tag'] == RC4_FORMAT_TAG:
        base_result = {
            'plaintext': visible_fields['plaintext'],
            'verified': False,
            'checksum_ok': False,
            'padding_ok': False,
            'structure_ok': True,
            'metadata_ok': False,
            'version_ok': False,
            'diagnostics': diagnostics,
            'payload': visible_payload,
            'visible_payload': visible_payload,
            'format': 'rc.4-hidden',
            'length_field': visible_fields['length_field'],
            'padding': visible_fields['padding'],
        }

        if extracted['hidden_carrier_count'] == 0:
            return _generic_decrypt_failure({
                **base_result,
            }, visible_fields['plaintext'], key['key_str'], rc4_state['km'], rc4_state)

        if extracted['hidden_carrier_count'] != HIDDEN_SYMBOL_COUNT:
            return _generic_decrypt_failure({
                **base_result,
            }, visible_fields['plaintext'], key['key_str'], rc4_state['km'], rc4_state)

        try:
            hidden_cipher = _legacy_decode_hidden_carrier_stream(
                extracted['carrier_stream'], key['key_str'])
        except ValueError:
            return _generic_decrypt_failure({
                **base_result,
            }, visible_fields['plaintext'], key['key_str'], rc4_state['km'], rc4_state)

        hidden_payload = process_rc4_legacy_segment(
            hidden_cipher, rc4_state, decrypt=True)
        if len(hidden_payload) != HIDDEN_METADATA_LEN:
            return _generic_decrypt_failure({
                **base_result,
                'hidden_cipher': hidden_cipher,
                'hidden_payload': hidden_payload,
            }, visible_fields['plaintext'], key['key_str'], rc4_state['km'], rc4_state)

        version = hidden_payload[0]
        checksum = hidden_payload[1:]
        version_ok = version == RC4_VERSION_CHAR
        checksum_ok = version_ok and checksum == compute_legacy_alphabet_checksum(
            visible_text, _legacy_derive_mac_subkey(key['key_str']), version)
        padding_seed = compute_legacy_padding_seed(
            visible_fields['plaintext'], key['key_str'], visible_fields['length_field'], version) if version_ok else ''
        expected_pad_len = _legacy_compute_pad_length(
            visible_fields['plaintext'], key['key_str'], padding_seed, version) if version_ok else 0
        expected_padding = generate_legacy_padding(
            visible_fields['plaintext'], key['key_str'], padding_seed, version, expected_pad_len) if version_ok else ''
        padding_ok = version_ok and len(
            visible_fields['padding']) == expected_pad_len and visible_fields['padding'] == expected_padding
        verified = version_ok and checksum_ok and padding_ok
        result = {
            **base_result,
            'verified': verified,
            'checksum_ok': checksum_ok,
            'padding_ok': padding_ok,
            'metadata_ok': True,
            'version_ok': version_ok,
            'hidden_cipher': hidden_cipher,
            'hidden_payload': hidden_payload,
            'version': version,
            'error': None if verified else GENERIC_DECRYPT_ERROR,
        }
        return _finalize_decrypt_result(result, visible_fields['plaintext'], key['key_str'], rc4_state['km'], rc4_state)

    pos = legacy_checksum_pos(key['key_str'], len(visible_text))
    checksum = visible_text[pos:pos + CHECKSUM_LEN]
    stripped = visible_text[:pos] + visible_text[pos + CHECKSUM_LEN:]
    try:
        state = create_legacy_cipher_state(
            key['steck_pairs'], key['rotors'], key['enabled'], key['user_rounds'], key['nonce'])
        plaintext = process_legacy_segment(stripped, state, decrypt=True)
        verified = checksum == legacy_compute_checksum(
            plaintext, key['key_str'])
    except (ValueError, IndexError, KeyError):
        state = {'km': {}, 'rotors': []}
        plaintext = ''
        verified = False
    result = {
        'plaintext': plaintext,
        'verified': verified,
        'checksum_ok': verified,
        'padding_ok': True,
        'structure_ok': True,
        'metadata_ok': False,
        'version_ok': False,
        'length_field': '',
        'padding': '',
        'error': None if verified else GENERIC_DECRYPT_ERROR,
        'format': 'rc.2-legacy',
        'diagnostics': diagnostics,
        'payload': stripped,
    }
    return _finalize_decrypt_result(result, plaintext, key['key_str'], state['km'], state)


def calc_ioc(text):
    freq = {char: 0 for char in ALPHA}
    for char in text:
        if char in freq:
            freq[char] += 1
    length = sum(freq.values())
    if length < 2:
        return 0.0
    numerator = sum(count * (count - 1) for count in freq.values())
    return numerator / (length * (length - 1))


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
    layout_combos = _permutation_count(len(LAYOUT_NAMES), enabled_count)
    rotor_combos = (enabled_count * N) ** rotor_count
    steck_combos = _steck_pairing_count(N, pair_count)
    round_combos = 999
    nonce_combos = (N ** 3) if parsed_key['nonce'] else 1

    total = layout_combos * rotor_combos * \
        steck_combos * round_combos * nonce_combos
    km = compute_key_material(
        parsed_key['steck_pairs'], parsed_key['rotors'], parsed_key['enabled'], parsed_key['user_rounds'])
    return {
        'family_bits': math.log2(total),
        'total': total,
        'components': {
            'layouts': {'count': layout_combos, 'bits': math.log2(layout_combos)},
            'rotors': {'count': rotor_combos, 'bits': math.log2(rotor_combos) if rotor_combos > 1 else 0.0},
            'steck': {'count': steck_combos, 'bits': math.log2(steck_combos) if steck_combos > 1 else 0.0},
            'rounds': {'count': round_combos, 'bits': math.log2(round_combos)},
            'nonce': {'count': nonce_combos, 'bits': math.log2(nonce_combos) if nonce_combos > 1 else 0.0},
        },
        'profile': {
            'enabled_layouts': list(parsed_key['enabled']),
            'enabled_count': enabled_count,
            'rotor_count': rotor_count,
            'rotor_layouts': [rotor['layout'] for rotor in parsed_key['rotors']],
            'steck_pairs': pair_count,
            'base_rounds': parsed_key['user_rounds'],
            'final_rounds': km['rounds'],
            'nonce_present': bool(parsed_key['nonce']),
            'nonce': parsed_key['nonce'] or '-',
        }
    }


def _random_choice(values):
    values = list(values)
    return values[secrets.randbelow(len(values))]


def _choose_random_profile(num_layouts, num_rotors, num_steck_pairs, include_nonce):
    layout_choices = range(1, len(LAYOUT_NAMES) + 1) if num_layouts is None else [num_layouts]
    rotor_choices = range(1, 19) if num_rotors is None else [num_rotors]
    steck_choices = range(0, (N // 2) + 1) if num_steck_pairs is None else [num_steck_pairs]
    nonce_choices = [False, True] if include_nonce is None else [bool(include_nonce)]
    return (
        _random_choice(layout_choices),
        _random_choice(rotor_choices),
        _random_choice(steck_choices),
        _random_choice(nonce_choices),
    )


def generate_key(num_rotors=None, num_steck_pairs=None, num_layouts=None, user_rounds=None, include_nonce=None):
    rng = secrets.SystemRandom()
    if num_layouts is not None and not 1 <= num_layouts <= len(LAYOUT_NAMES):
        raise ValueError(f'num_layouts must be between 1 and {len(LAYOUT_NAMES)}')
    if num_rotors is not None and not 1 <= num_rotors <= 18:
        raise ValueError('num_rotors must be between 1 and 18')
    if num_steck_pairs is not None and not 0 <= num_steck_pairs <= N // 2:
        raise ValueError(f'num_steck_pairs must be between 0 and {N // 2}')
    if user_rounds is not None and not 1 <= user_rounds <= 999:
        raise ValueError('user_rounds must be between 1 and 999')

    for _ in range(10000):
        layout_count, rotor_count, steck_count, nonce_flag = _choose_random_profile(
            num_layouts, num_rotors, num_steck_pairs, include_nonce
        )
        enabled_indexes = rng.sample(range(len(LAYOUT_NAMES)), layout_count)
        enabled = [LAYOUT_NAMES[index] for index in enabled_indexes]
        rotors = [
            {'layout': LAYOUT_NAMES[rng.choice(
                enabled_indexes)], 'pos': secrets.randbelow(N)}
            for _ in range(rotor_count)
        ]
        chars = list(ALPHA)
        rng.shuffle(chars)
        steck_pairs = [(chars[index * 2], chars[index * 2 + 1])
                       for index in range(steck_count)]
        final_rounds = user_rounds if user_rounds is not None else secrets.randbelow(999) + 1
        nonce = ''.join(ALPHA[secrets.randbelow(N)]
                        for _ in range(3)) if nonce_flag else ''
        key = encode_key(enabled, rotors, steck_pairs, final_rounds, nonce)
        if calc_key_strength(parse_key(key))['family_bits'] >= MIN_GENERATED_KEY_BITS:
            return key
    raise ValueError(f'Unable to generate a key with at least {MIN_GENERATED_KEY_BITS:.1f} bits using the requested constraints')


def cmd_encrypt(plaintext, key_str, materialize=False, to_clipboard=False):
    ciphertext = encrypt_text(plaintext, key_str, materialize=materialize)
    sys.stdout.write(ciphertext)
    sys.stdout.write('\n')
    if to_clipboard:
        _report_encrypt_clipboard(ciphertext, materialize)
    return ciphertext


def cmd_decrypt(ciphertext, key_str, materialize=False):
    result = decrypt_text(ciphertext, key_str, materialize=materialize)
    diagnostics = result['diagnostics']
    for warning in diagnostics['warnings']:
        print(f'[!] {warning}', file=sys.stderr)
    if diagnostics['hidden_carrier_count'] > 0:
        print(
            f'[i] Hidden metadata carriers detected: {diagnostics["hidden_carrier_count"]}', file=sys.stderr)
    print(result['plaintext'])
    format_label = result['format']
    if format_label == 'rc.6-stream' and result.get('materialize'):
        format_label = 'rc.6-stream (materialized)'
    print(f'[i] Format: {format_label}', file=sys.stderr)
    if result['verified']:
        if result['format'] == 'rc.6-stream':
            if result.get('materialize'):
                print(
                    '[OK] Scattered checksum, materialized metadata, and padding verified', file=sys.stderr)
            else:
                print(
                    '[OK] Scattered checksum, hidden metadata, and padding verified', file=sys.stderr)
        elif result['format'] == 'rc.4-hidden':
            print('[OK] Hidden metadata, checksum, and padding verified',
                  file=sys.stderr)
        else:
            print('[OK] Checksum and padding verified', file=sys.stderr)
    else:
        print(f'[X] {GENERIC_DECRYPT_ERROR}', file=sys.stderr)
        if diagnostics['outside_alpha_count'] > 0:
            print('[!] Characters outside the ENIGMAK alphabet do not advance rotor state and can desync the rest of the message.', file=sys.stderr)
        print(
            f'[!] Ciphertext received: {diagnostics["length"]} chars. Compare length and preserve zero-width markers when copying.', file=sys.stderr)


def cmd_keygen():
    print(generate_key())


def cmd_ioc(ciphertext):
    ioc = calc_ioc(ciphertext)
    floor = 1 / N
    print(f'IoC:   {ioc:.6f}')
    print(f'Floor: {floor:.6f} (1/{N})')
    print(f'Delta: {ioc - floor:+.6f}')


def cmd_keystrength(key_str):
    key = parse_key(key_str)
    strength = calc_key_strength(key)
    profile = strength['profile']
    print(
        f'Key family strength: {strength["family_bits"]:.1f} bits (~2^{strength["family_bits"]:.1f})')
    print(f'Keyspace: {strength["total"]:.3e}')
    print('Family-size breakdown:')
    print(f'  layouts: {strength["components"]["layouts"]["bits"]:.3f} bits')
    print(f'  rotors:  {strength["components"]["rotors"]["bits"]:.3f} bits')
    print(f'  steck:   {strength["components"]["steck"]["bits"]:.3f} bits')
    print(f'  rounds:  {strength["components"]["rounds"]["bits"]:.3f} bits')
    print(f'  nonce:   {strength["components"]["nonce"]["bits"]:.3f} bits')
    print('Current key profile:')
    print(
        f'  enabled layouts: {profile["enabled_count"]} ({",".join(profile["enabled_layouts"])})')
    print(
        f'  rotors: {profile["rotor_count"]} ({",".join(profile["rotor_layouts"])})')
    print(f'  steck pairs: {profile["steck_pairs"]}')
    print(f'  base rounds: {profile["base_rounds"]}')
    print(f'  final rounds: {profile["final_rounds"]}')
    print(f'  nonce: {profile["nonce"]}')


class FriendlyArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(f'[!] {message}', file=sys.stderr)
        print('Tip: Run python enigmak.py with no arguments for interactive mode.', file=sys.stderr)
        self.exit(2)


def _clipboard_text_or_exit():
    try:
        import tkinter as tk
    except ImportError:
        print(
            '[!] tkinter is not available in this Python installation.\n'
            '    Run python enigmak.py with no arguments to use interactive mode instead.',
            file=sys.stderr
        )
        sys.exit(1)

    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        return root.clipboard_get()
    except tk.TclError:
        print('[!] Clipboard is empty or contains non-text data.', file=sys.stderr)
        sys.exit(1)
    finally:
        if root is not None:
            root.destroy()


def _copy_text_to_windows_clipboard(text):
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return False

    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    data = text.encode('utf-16-le') + b'\x00\x00'
    handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
    if not handle:
        return False

    locked = kernel32.GlobalLock(handle)
    if not locked:
        kernel32.GlobalFree(handle)
        return False
    ctypes.memmove(locked, data, len(data))
    kernel32.GlobalUnlock(handle)

    if not user32.OpenClipboard(None):
        kernel32.GlobalFree(handle)
        return False
    try:
        if not user32.EmptyClipboard():
            kernel32.GlobalFree(handle)
            return False
        if not user32.SetClipboardData(CF_UNICODETEXT, handle):
            kernel32.GlobalFree(handle)
            return False
        handle = None
        return True
    finally:
        user32.CloseClipboard()


def _copy_text_to_tk_clipboard(text):
    try:
        import tkinter as tk
    except ImportError:
        return False

    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        return True
    except tk.TclError:
        return False
    finally:
        if root is not None:
            root.destroy()


def _copy_text_to_clipboard(text):
    if sys.platform.startswith('win') and _copy_text_to_windows_clipboard(text):
        return True
    return _copy_text_to_tk_clipboard(text)


def _report_encrypt_clipboard(ciphertext, materialize):
    if _copy_text_to_clipboard(ciphertext):
        if materialize:
            print('[i] Materialized ciphertext copied to clipboard.',
                  file=sys.stderr)
        else:
            print(
                '[i] Exact ciphertext copied to clipboard for zero-width metadata preservation.', file=sys.stderr)
    elif materialize:
        print('[!] Could not copy to clipboard.', file=sys.stderr)
    else:
        print('[!] Could not copy to clipboard. Terminal highlighting may omit zero-width metadata.', file=sys.stderr)


def _usage_error(message):
    print(f'[!] {message}', file=sys.stderr)
    print('Tip: Run python enigmak.py with no arguments for interactive mode.', file=sys.stderr)
    sys.exit(2)


def _resolve_decrypt_args(args):
    values = getattr(args, 'values', [])
    if getattr(args, 'from_clipboard', False):
        if len(values) not in (1, 2):
            _usage_error('Provide a key when using --from-clipboard.')
        return _clipboard_text_or_exit(), values[-1]
    if len(values) != 2:
        _usage_error(
            'Provide ciphertext as an argument or use --from-clipboard.')
    return values[0], values[1]


def _resolve_ioc_ciphertext_arg(args):
    if getattr(args, 'from_clipboard', False):
        return _clipboard_text_or_exit()
    values = getattr(args, 'values', [])
    if len(values) != 1:
        _usage_error(
            'Provide ciphertext as an argument or use --from-clipboard.')
    return values[0]


PASTE_TERMINATOR = '---END---'


def _interactive_input(prompt):
    """Read a line; Ctrl+C cancels the current prompt without exiting."""
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print()
        return None


def read_multiline_input(label):
    print(f'Paste your {label} below.')
    print(f'When done, type {PASTE_TERMINATOR} on a new line and press Enter:')
    lines = []
    try:
        while True:
            line = sys.stdin.readline()
            if line == '':
                break
            if line.rstrip('\n') == PASTE_TERMINATOR:
                break
            lines.append(line)
    except KeyboardInterrupt:
        print()
        return None
    return ''.join(lines).rstrip('\n')


def _prompt_materialize():
    answer = _interactive_input('Materialize metadata? (y/N): ')
    if answer is None:
        return None
    return answer.strip().lower() in ('y', 'yes')


def cmd_interactive():
    print('ENIGMAK v3.0.0-rc.8 Interactive Mode')
    print('======================================')
    print('Commands: encrypt, decrypt, keygen, ioc, keystrength, quit')
    print()
    while True:
        try:
            raw = _interactive_input('> ')
        except EOFError:
            print()
            break
        if raw is None:
            continue
        command = raw.strip().lower()
        if command == '':
            continue
        if command in ('quit', 'exit'):
            break
        try:
            if command == 'encrypt':
                plaintext = read_multiline_input('plaintext')
                if plaintext is None:
                    continue
                key = _interactive_input('Enter key: ')
                if key is None:
                    continue
                materialize = _prompt_materialize()
                if materialize is None:
                    continue
                cmd_encrypt(plaintext, key, materialize=materialize,
                            to_clipboard=True)
            elif command == 'decrypt':
                ciphertext = read_multiline_input('ciphertext')
                if ciphertext is None:
                    continue
                key = _interactive_input('Enter key: ')
                if key is None:
                    continue
                materialize = _prompt_materialize()
                if materialize is None:
                    continue
                cmd_decrypt(ciphertext, key, materialize=materialize)
            elif command == 'keygen':
                cmd_keygen()
            elif command == 'ioc':
                ciphertext = read_multiline_input('ciphertext')
                if ciphertext is None:
                    continue
                cmd_ioc(ciphertext)
            elif command == 'keystrength':
                key = _interactive_input('Enter key: ')
                if key is None:
                    continue
                cmd_keystrength(key)
            else:
                print('[!] Unknown command.', file=sys.stderr)
                print(
                    'Commands: encrypt, decrypt, keygen, ioc, keystrength, quit', file=sys.stderr)
        except EOFError:
            print()
            break
        except Exception as exc:
            print(f'[!] {exc}', file=sys.stderr)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        cmd_interactive()
        return

    parser = FriendlyArgumentParser(
        description='ENIGMAK v3.0.0-rc.8 - 162-symbol rotor cipher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = parser.add_subparsers(
        dest='command', parser_class=FriendlyArgumentParser)

    enc = sub.add_parser('encrypt', help='Encrypt plaintext')
    enc.add_argument('plaintext')
    enc.add_argument('key')
    enc.add_argument('--materialize', action='store_true',
                     help='Emit visible carrier metadata (44 ALPHA chars) instead of zero-width carriers')
    enc.add_argument('--to-clipboard', action='store_true',
                     help='Copy exact ciphertext to the system clipboard after encryption')

    dec = sub.add_parser('decrypt', help='Decrypt ciphertext')
    dec.add_argument('values', nargs='*')
    dec.add_argument('--from-clipboard', action='store_true',
                     help='Read ciphertext from clipboard instead of argument')
    dec.add_argument('--materialize', action='store_true',
                     help='Decode visible carrier metadata (must match the encrypt-side setting)')

    sub.add_parser('keygen', help='Generate a random key')

    ioc_parser = sub.add_parser('ioc', help='Calculate Index of Coincidence')
    ioc_parser.add_argument('values', nargs='*')
    ioc_parser.add_argument('--from-clipboard', action='store_true',
                            help='Read ciphertext from clipboard instead of argument')

    strength_parser = sub.add_parser(
        'keystrength', help='Calculate key strength in bits')
    strength_parser.add_argument('key')

    sub.add_parser('interactive', help='Start interactive mode')

    args, unknown = parser.parse_known_args(argv)
    if unknown:
        if args.command in ('decrypt', 'ioc'):
            args.values.extend(unknown)
        else:
            parser.error(f'unrecognized arguments: {" ".join(unknown)}')
    try:
        if args.command == 'encrypt':
            cmd_encrypt(args.plaintext, args.key, materialize=args.materialize,
                        to_clipboard=args.to_clipboard)
        elif args.command == 'decrypt':
            ciphertext, key = _resolve_decrypt_args(args)
            cmd_decrypt(ciphertext, key, materialize=args.materialize)
        elif args.command == 'keygen':
            cmd_keygen()
        elif args.command == 'ioc':
            cmd_ioc(_resolve_ioc_ciphertext_arg(args))
        elif args.command == 'keystrength':
            cmd_keystrength(args.key)
        elif args.command == 'interactive':
            cmd_interactive()
        else:
            parser.error('unrecognized command')
    except ValueError as exc:
        _usage_error(str(exc))


if __name__ == '__main__':
    main()
