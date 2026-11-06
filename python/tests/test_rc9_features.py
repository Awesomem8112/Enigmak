#!/usr/bin/env python3
"""Full regression tests for rc.9 features and TESTVECTORS."""
import json
import subprocess
import sys
import os
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from enigmak import (
    decrypt_text, encrypt_text, encrypt_decoy_bundle, generate_key,
    derive_metadata_logical_len, derive_metadata_carrier_count, parse_key,
    NONCE_LEN, LEGACY_HIDDEN_SYMBOL_COUNT,
)

FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / 'tests' / 'fixtures.json').read_text(
        encoding='utf-8'))

VECTOR1_CT = json.loads(
    '"\u200d\u00d6\u200c\u200d\'\u200d\u2060\u200b\u2060\u200d\u2060cl\u200bGK9\u2060\u200b\u200d\u2060\u00e0j\u00dd\u2060\u200cJY\u200d\u200b\u200b\u00c1\u200b\u2060S\u00cd\u2060W\u2060\u200c\u200d:\u00ec\u200d\u200b\u2060\u200cR/\u200d\u00d8\u200c\u200b\u200c\u200d\u00e6\u2060.\u200c\u200dD\u200b\u200c\u2060\u2060\u200c\u200dD\u200c\u00e0"'
)
VECTOR1_KEY = 'K6:0 000 0 013'

VECTOR2_CT = (
    '\u200d\u00d6\n\u200cWB\u200d\u200d\u200d\u00eb\u200bc\u00c3\u00ce\u2060\u200d\u00e9\u00cf\u2060\u00cd\u2060G}{O\u00f2\u200d\u2060\u00e1?h\u00cab\u00ce\u200c\u0152\u200d\u200b\u200b3\u200d\u00cco\u00df\u00d8\u200b;\u2060\u200d\u200d\u200d\u200c\u200c\u00f8v\u2060B\u2060\u2060\u200c\u00df\u2060\u00e5\u00d0\u200c\u2060uc8\u200c\u00ec\u00f4k`\u2060ccT\u200c\u00e2\u00cdSJ\u00d9\u2060C\u2060\u00d4X\u200d0\u200d\u200d\u2060 \u2060\u2060\u200d/\u00d3\u00d4\u2060\u00de\u00c4'
)

VECTOR3_CT = (
    '\u2060\u200d\u2060\u00d2\u00ca\u2060\u200d*\u00f8\u200c\u200c\u200d\u2060\u2060\u2060q9\u00ff4wt\u00e9\u00dc\u200c\u200c\u200b\u200c\u200bY\u2060\u200d\u00c0I\u00ed(\u00a1\u2060\u200b\u200c\u200d\u00c4\u200cs\u00cci,\u2060\u200c\u200d\u2060yU\u200d/X\u00c8\n\u2060\u200d\u200cD\u200b\u00c0\u00c4e\u2060\u200b\u200c\u00ea\u00d1\u200d\\\u2060\u00cc|\u200b\u200c\u200b)E\u200c\u200d\u200c\u00a1\u200c'
)
VECTOR3_KEY = 'K6:1 102103 0 050'

VECTOR4_CT = (
    '\u00dd\u200d\u200c\u00c4\u200d\u200d\u200d\u200dN\u200d\u200b\u200d\u2060Q\u2060\u200c\u200d\u2060{\u2060\u200c\u00e6\u200d\u200b\u2060\u200c\u200d#\u00ec\u200c\u0152 \u200b\u2060\u2060\u200b\u00e4;y\u00ff\u200c\u200c\u00f82\u2060\u00d0\u200d\u200c\u00c2\u200c\u00dc\u00fe\u2060^\u2060\u200c\u200d\u200d\u2060u\u200bYi\u2060\u200d\u00e7Nco\u200d\u200bb%b\u2060$\n9\u00f2'
)

RC3_CT = 'E3|1]Qfw?Q{GF-#+nKPJlPm$w6H*R-\'6^gk,[kLm+'
RC3_KEY = '123 100200 0 050'
RC2_CT = 'b$\\.:j53ZHekRX~u.I#%)'

# Pinned keys for variable metadata lengths (from gen_vectors.py)
META_KEY_LL1 = 'K6:B6AE E01B37E20B1QA17E2QB41E35B46E0U62264A 012V020X042I06350833090D0A0N0F3M0H260J220O2M0P410Q120S3H0T0V0Y28104B172G1F2L1G3K1I291J3U1L3C1M3S1P2J1S2S1V2D1W2W1Z232H392K3G2Q3Z2R4F2T4G303I313F36493A3L3Q42474H 841'
META_KEY_LL30 = 'K6:F F0XF2JF1SF0HF26F2HF1RF1HF0KF1YF0QF22F1GF2T 002203290439063C073J09480A3X0B1S0D2J0G3G0H440I0W0J1F0K210N2A0O240P1D0Q1I0R2I0S3P0X3V0Y450Z1L103B113H1242131Q1435153S171V183F191O1A1J1B3Z1C1W1E3T1G1N1H2Y1M1Y1R261T301U2S1X2O1Z3R202G282Z2B4B2C322F2U2K4A2L3N2M432N2Q2P2W2R4C2T342V46334G363K373I383E3M473Q493W3Y414D 989'
META_KEY_LL50 = 'K6:F1260C5 C0T63412R52W62I62M24253IF0W60664E 012Y0228031Z050H073O08460A0V0B4G0D0P0E3F0I1G0K4H0L3Z0M2A0O3B0Q3X0S2R0T3D0W2J0Y44111S1232131N1448152516231C1E1D3H1J3M1M3G1O1Q1P211T3Y1U301V2D1W3L202F242O2629273Q2B372C2G2E2P2H402L352N2U2S4C2X2Z3149384E39473A3V3J4F3K3T 243'
META_PT = 'META_TEST'
META_CT_LL1 = FIXTURES['rc6_variable_1']['ciphertext']
META_CT_LL30 = FIXTURES['rc6_variable_30']['ciphertext']
META_CT_LL50 = FIXTURES['rc6_variable_50']['ciphertext']

DECOY_COVER = 'Meeting moved to Tuesday'
DECOY_KEY = 'K6:0B415F82 40B007B3383M53N515F35115237524440B3J53C527838 0E2X0G0V0K230X2N0Z3K102A1Y24224F2Z34 138'
DECOY_CT = FIXTURES['option_a_decoy']['ciphertext']

NONCE5_KEY = 'K6:F17495D3 50Q41G72T70Z40Q90A 001N012N0218030J041O0609071S082V0A2R0B260C3Z0D300E2L0F4E0G3O0H1H0I4D0K1V0L280M1R0N1Q0O360P1Y0Q2M0T1W0U1J0V1G0W270X170Y4H0Z2I101B113L123N1346142S162A192H1C3Y1D2B1E2T1F2C1I291K2X1L3M1T201U3P1X43213C2333244525382D3I2E2Y2G492J402P342Q412U4B2W3G313R324837423A443B473D4C3F3K3H4F3Q4A 224 1O4D3W3L2D'
NONCE5_CT = FIXTURES['rc6_nonce5']['ciphertext']


def test_legacy_vectors():
    r1 = decrypt_text(VECTOR1_CT, VECTOR1_KEY)
    assert r1['verified'] and r1['plaintext'] == 'HELLOWORLD', r1
    r2 = decrypt_text(VECTOR2_CT, VECTOR1_KEY)
    assert r2['verified'], r2
    r3 = decrypt_text(VECTOR3_CT, VECTOR3_KEY)
    assert r3['verified'] and r3['plaintext'] == 'Hello World', r3
    r4 = decrypt_text(VECTOR4_CT, VECTOR1_KEY)
    assert r4['verified'], r4
    rc3 = decrypt_text(RC3_CT, RC3_KEY)
    assert rc3['verified'] and rc3['plaintext'] == 'Hello World', rc3
    rc2 = decrypt_text(RC2_CT, RC3_KEY)
    assert rc2['verified'] and rc2['plaintext'] == 'Hello World', rc2
    for fixture_name in ('rc4_hidden', 'v200', 'rc6_materialized_current'):
        fixture = FIXTURES[fixture_name]
        result = decrypt_text(
            fixture['ciphertext'], fixture['key'],
            materialize=fixture_name == 'rc6_materialized_current')
        assert result['verified'], (fixture_name, result)
        assert result['plaintext'] == fixture['plaintext'], (fixture_name, result)
        assert result['format'] == fixture['format'], (fixture_name, result)


def test_variable_metadata():
    assert derive_metadata_logical_len(META_KEY_LL1) == 1
    assert derive_metadata_carrier_count(META_KEY_LL1) == 4
    r1 = decrypt_text(META_CT_LL1, META_KEY_LL1)
    assert r1['verified'] and r1['plaintext'] == 'META_TEST', r1
    assert derive_metadata_logical_len(META_KEY_LL30) == 30
    r30 = decrypt_text(META_CT_LL30, META_KEY_LL30)
    assert r30['verified'] and r30['plaintext'] == 'META_TEST', r30
    assert derive_metadata_logical_len(META_KEY_LL50) == 50
    r50 = decrypt_text(META_CT_LL50, META_KEY_LL50)
    assert r50['verified'] and r50['plaintext'] == 'META_TEST', r50


def test_nonce_five():
    pk = parse_key(NONCE5_KEY)
    assert len(pk['nonce']) == NONCE_LEN, pk
    r = decrypt_text(NONCE5_CT, NONCE5_KEY)
    assert r['verified'] and r['plaintext'] == 'NONCE5_TEST', r
    k = generate_key(include_nonce=True)
    assert len(parse_key(k)['nonce']) == NONCE_LEN


def test_decoy_bundle():
    bundle = encrypt_decoy_bundle('secret', DECOY_COVER, real_key_str=VECTOR1_KEY)
    decoy_r = decrypt_text(bundle['decoy']['ciphertext'], bundle['decoy']['key'])
    assert decoy_r['verified'] and decoy_r['plaintext'] == DECOY_COVER
    pinned = decrypt_text(DECOY_CT, DECOY_KEY)
    assert pinned['verified'] and pinned['plaintext'] == DECOY_COVER, pinned
    wrong = decrypt_text(bundle['real']['ciphertext'], bundle['decoy']['key'])
    assert not wrong['verified']
    wrong2 = decrypt_text(bundle['decoy']['ciphertext'], VECTOR1_KEY)
    assert not wrong2['verified']


def test_decoy_subprocess():
    proc = subprocess.run(
        [sys.executable, 'enigmak.py', 'decrypt', DECOY_CT, DECOY_KEY],
        capture_output=True, text=True, encoding='utf-8', cwd=os.path.dirname(__file__),
    )
    assert proc.returncode == 0, proc.stderr
    assert DECOY_COVER in proc.stdout
    assert '[OK]' in proc.stderr


def main():
    test_legacy_vectors()
    test_variable_metadata()
    test_nonce_five()
    test_decoy_bundle()
    test_decoy_subprocess()
    print('All tests passed')


class TestRC9Features(unittest.TestCase):
    def test_legacy_vectors(self):
        test_legacy_vectors()

    def test_variable_metadata(self):
        test_variable_metadata()

    def test_nonce_five(self):
        test_nonce_five()

    def test_decoy_bundle(self):
        test_decoy_bundle()

    def test_decoy_subprocess(self):
        test_decoy_subprocess()


if __name__ == '__main__':
    main()
