#!/usr/bin/env python3
"""Cross-language parser, arithmetic, Unicode, and profile-grid checks."""

import hashlib
import json
import math
import subprocess
import unittest
from pathlib import Path

import enigmak as e


ROOT = Path(__file__).resolve().parents[1]
DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def node_json(script):
    completed = subprocess.run(
        ["node", "-e", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def profile_key(layouts, rotors, pairs, nonce_present):
    enabled = DIGITS[:layouts]
    rotor_text = "000" * rotors
    steck = "".join(
        e.encode_base36_index(index * 2, 2)
        + e.encode_base36_index(index * 2 + 1, 2)
        for index in range(pairs)
    ) or "0"
    nonce = " 0000000000" if nonce_present else ""
    return f"K6:{enabled} {rotor_text} {steck} 001{nonce}"


class TestCorrectnessAudit(unittest.TestCase):
    def test_malformed_key_rejection_matches_javascript(self):
        keys = [
            "K6:0 000 0 013",
            "0 000 0 013 000102",
            "K6:00 000 0 013",
            "00 000 0 013",
            "K6:! 000 0 013",
            "K6:0 00! 0 013",
            "K6:0 000 0000 013",
            "K6:0 000 00010002 013",
            "K6:0 000 0 013x",
            "0 000 0 +13",
            "0 000 0 ٠١٣",
            "0 000 0 013 00010x",
        ]

        def accepts(key):
            try:
                e.parse_key(key)
                return True
            except (ValueError, IndexError):
                return False

        python_results = [accepts(key) for key in keys]
        script = (
            "const e=require('./javascript/enigmak.js');"
            f"const keys={json.dumps(keys, ensure_ascii=False)};"
            "process.stdout.write(JSON.stringify(keys.map(k=>{"
            "try{e.parseKey(k);return true;}catch(_){return false;}})));"
        )
        self.assertEqual(node_json(script), python_results)
        self.assertEqual(python_results[:2], [True, True])
        self.assertTrue(all(not value for value in python_results[2:]))

    def test_unicode_diagnostics_use_code_point_positions(self):
        value = "A😀B\u200bC\r"
        python = e.analyze_ciphertext(value)
        script = (
            "const e=require('./javascript/enigmak.js');"
            f"process.stdout.write(JSON.stringify(e.analyzeCiphertext({json.dumps(value)})));"
        )
        javascript = node_json(script)
        self.assertEqual(javascript["length"], python["length"])
        self.assertEqual(
            javascript["hiddenCarrierCount"], python["hidden_carrier_count"]
        )
        self.assertEqual(
            [entry["pos"] for entry in javascript["hiddenCarriers"]],
            [entry[0] for entry in python["hidden_carriers"]],
        )
        self.assertEqual(javascript["outsideAlphabetCount"], 2)
        self.assertEqual(javascript["length"], 6)

    def test_metadata_rejection_draw_and_schedule_bounds(self):
        for rounds in range(1, 200):
            key = f"K6:0 000 0 {rounds:03d}"
            logical = e.derive_metadata_logical_len(key)
            legacy = e.derive_metadata_logical_len_legacy(key)
            self.assertGreaterEqual(logical, 1)
            self.assertLess(logical, e.N)
            for count in {
                e.LEGACY_HIDDEN_SYMBOL_COUNT,
                logical * e.HIDDEN_CHUNK_LEN,
                legacy * e.HIDDEN_CHUNK_LEN,
            }:
                self.assertEqual(
                    e.effective_metadata_carrier_count(key, count), count
                )

            payload_len = 9 + rounds % 31
            carrier_count = logical * e.HIDDEN_CHUNK_LEN
            schedule = e.build_stream_schedule(
                key, rounds % 23, payload_len, carrier_count
            )
            self.assertEqual(schedule.count("payload"), payload_len)
            self.assertEqual(schedule.count("checksum"), e.CHECKSUM_LEN)
            self.assertEqual(schedule.count("carrier"), carrier_count)

    def test_long_message_python_javascript_byte_parity(self):
        key = "K6:01 000101 00010203 997 0001020304"
        plaintext = "".join(
            e.ALPHA[(index * 73 + 161) % e.N] for index in range(e.N * 4 + 7)
        )
        python_ciphertext = e.encrypt_text(plaintext, key)
        script = (
            "const e=require('./javascript/enigmak.js');"
            f"const p={json.dumps(plaintext, ensure_ascii=False)};"
            f"const k={json.dumps(key)};"
            "const c=e.encrypt(p,k);const r=e.decrypt(c,k);"
            "process.stdout.write(JSON.stringify({c,ok:r.verified,p:r.plaintext}));"
        )
        javascript = node_json(script)
        self.assertEqual(javascript["c"], python_ciphertext)
        self.assertTrue(javascript["ok"])
        self.assertEqual(javascript["p"], plaintext)
        self.assertEqual(
            e.decrypt_text(javascript["c"], key)["plaintext"], plaintext
        )

    def test_every_generated_key_strength_profile_matches_javascript(self):
        digest = hashlib.sha256()
        count = 0
        samples = []
        for layouts in range(1, 17):
            for rotors in range(1, 19):
                for pairs in range(82):
                    for nonce_present in (False, True):
                        strength = e.calc_key_strength(
                            e.parse_key(
                                profile_key(
                                    layouts, rotors, pairs, nonce_present
                                )
                            )
                        )
                        digest.update(
                            (
                                f"{layouts},{rotors},{pairs},"
                                f"{int(nonce_present)}:{strength['total']}\n"
                            ).encode("ascii")
                        )
                        count += 1
                        if (
                            (layouts, rotors, pairs)
                            in ((1, 1, 0), (16, 18, 81))
                        ):
                            samples.append(strength)

        completed = subprocess.run(
            ["node", "javascript/test_key_strength_grid.js"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        javascript = json.loads(completed.stdout)
        self.assertEqual(javascript["count"], count)
        self.assertEqual(javascript["digest"], digest.hexdigest())
        self.assertEqual(len(javascript["samples"]), len(samples))
        for js_sample, py_sample in zip(javascript["samples"], samples):
            self.assertEqual(int(js_sample["total"]), py_sample["total"])
            self.assertTrue(
                math.isclose(
                    js_sample["bits"],
                    py_sample["family_bits"],
                    rel_tol=0,
                    abs_tol=1e-12,
                )
            )

    def test_failure_work_is_fixed_size(self):
        self.assertEqual(len(e._corrupt_buffer()), e.MAX_CORRUPT_LEN)
        self.assertEqual(e.MAX_CORRUPT_LEN, 4096)


if __name__ == "__main__":
    unittest.main()
