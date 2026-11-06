#!/usr/bin/env python3
"""Dual-envelope vectors, malformed inputs, and property checks."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import enigmak as e


ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(
    (ROOT / "tests" / "dual_vectors.json").read_text(encoding="utf-8")
)
WRONG_KEY = "K6:2 204205 0 060"


def assert_generic_failure(testcase, result):
    testcase.assertFalse(result["success"])
    testcase.assertFalse(result["verified"])
    testcase.assertEqual(result["plaintext"], "")
    testcase.assertEqual(result["error"], e.GENERIC_DECRYPT_ERROR)


def decoded_parts(vector):
    raw = bytearray(e._dual_b64url_decode(vector["ciphertext"]))
    slot_len = (len(raw) - e.DUAL_NONCE_LEN) // 2
    return raw, bytes(raw[:e.DUAL_NONCE_LEN]), slot_len


def matching_slot(vector, key):
    raw, nonce, slot_len = decoded_parts(vector)
    for slot_index in range(2):
        start = e.DUAL_NONCE_LEN + slot_index * slot_len
        wrapped = bytes(raw[start:start + slot_len])
        mask = e._dual_stream_bytes(
            key, nonce, slot_index, e.DUAL_WRAP_DOMAIN, slot_len
        )
        frame = e._dual_xor(wrapped, mask)
        if frame.startswith(e.DUAL_INTERNAL_MAGIC):
            return raw, nonce, slot_len, slot_index, bytearray(frame)
    raise AssertionError("Fixture key did not unwrap either slot")


class TestDualVectors(unittest.TestCase):
    def test_pinned_vectors_and_both_keys(self):
        prefixes = set()
        for name, vector in VECTORS.items():
            recreated = e.encrypt_dual_message(
                vector["real_plaintext"],
                vector["faux_plaintext"],
                vector["real_key"],
                vector["faux_key"],
                vector["materialize"],
                _envelope_nonce=bytes.fromhex(vector["nonce_hex"]),
            )
            self.assertEqual(recreated["ciphertext"], vector["ciphertext"], name)
            real = e.decrypt_text(vector["ciphertext"], vector["real_key"])
            faux = e.decrypt_text(vector["ciphertext"], vector["faux_key"])
            self.assertTrue(real["success"] and real["verified"], name)
            self.assertTrue(faux["success"] and faux["verified"], name)
            self.assertEqual(real["plaintext"], vector["real_plaintext"], name)
            self.assertEqual(faux["plaintext"], vector["faux_plaintext"], name)
            self.assertEqual(real["format"], e.DUAL_FORMAT_LABEL)
            self.assertEqual(faux["format"], e.DUAL_FORMAT_LABEL)
            prefixes.add(vector["ciphertext"][:4])

            raw = e._dual_b64url_decode(vector["ciphertext"])
            self.assertNotIn(e.DUAL_INTERNAL_MAGIC, raw, name)
            assert_generic_failure(
                self, e.decrypt_text(vector["ciphertext"], WRONG_KEY)
            )
        self.assertGreater(len(prefixes), 1)

    def test_slot_corruption_and_malformed_envelopes(self):
        vector = VECTORS["equal_lengths"]
        raw, nonce, slot_len, slot_index, frame = matching_slot(
            vector, vector["real_key"]
        )
        slot_start = e.DUAL_NONCE_LEN + slot_index * slot_len
        length_offset = len(e.DUAL_INTERNAL_MAGIC) + 1
        inner_len = int.from_bytes(
            frame[length_offset:length_offset + 4], "big"
        )
        inner_start = e.DUAL_CONTROL_LEN
        filler_start = inner_start + inner_len

        mutations = {
            "control": slot_start,
            "flags": slot_start + len(e.DUAL_INTERNAL_MAGIC),
            "inner": slot_start + inner_start,
            "filler": slot_start + filler_start,
        }
        for name, position in mutations.items():
            altered = bytearray(raw)
            altered[position] ^= 0x80
            result = e.decrypt_text(
                e._dual_b64url_encode(altered), vector["real_key"]
            )
            assert_generic_failure(self, result)

        forged = bytearray(raw)
        for offset in range(4):
            position = slot_start + length_offset + offset
            forged[position] ^= frame[length_offset + offset] ^ 0xFF
        assert_generic_failure(
            self,
            e.decrypt_text(
                e._dual_b64url_encode(forged), vector["real_key"]
            ),
        )

        invalid_utf8 = bytearray(raw)
        invalid_utf8[slot_start + inner_start] ^= frame[inner_start] ^ 0xFF
        assert_generic_failure(
            self,
            e.decrypt_text(
                e._dual_b64url_encode(invalid_utf8), vector["real_key"]
            ),
        )

        for malformed in (
            "AAAA" + vector["ciphertext"],
            vector["ciphertext"][:-1],
            vector["ciphertext"] + "!",
            vector["ciphertext"][1:],
            "",
        ):
            assert_generic_failure(
                self, e.decrypt_text(malformed, vector["real_key"])
            )

    def test_duplicate_valid_slots_are_ambiguous(self):
        vector = VECTORS["equal_lengths"]
        raw, nonce, slot_len, slot_index, frame = matching_slot(
            vector, vector["real_key"]
        )
        length_offset = len(e.DUAL_INTERNAL_MAGIC) + 1
        inner_len = int.from_bytes(
            frame[length_offset:length_offset + 4], "big"
        )
        inner = bytes(
            frame[e.DUAL_CONTROL_LEN:e.DUAL_CONTROL_LEN + inner_len]
        ).decode("utf-8")
        other_index = 1 - slot_index
        duplicate = e._dual_build_slot(
            inner,
            vector["real_key"],
            nonce,
            other_index,
            slot_len,
            frame[len(e.DUAL_INTERNAL_MAGIC)],
        )
        start = e.DUAL_NONCE_LEN + other_index * slot_len
        raw[start:start + slot_len] = duplicate
        assert_generic_failure(
            self,
            e.decrypt_text(
                e._dual_b64url_encode(raw), vector["real_key"]
            ),
        )

    def test_recursive_dual_inner_is_rejected(self):
        vector = VECTORS["equal_lengths"]
        nonce = bytes.fromhex("100102030405060708090a0b0c0d0e0f")
        recursive_inner = vector["ciphertext"]
        slot_len = (
            e.DUAL_CONTROL_LEN
            + len(recursive_inner.encode("utf-8"))
            + e.DUAL_MIN_FILLER_LEN
        )
        first = e._dual_build_slot(
            recursive_inner, vector["real_key"], nonce, 0, slot_len, 0
        )
        second = bytes(slot_len)
        ciphertext = e._dual_b64url_encode(nonce + first + second)
        assert_generic_failure(
            self, e.decrypt_text(ciphertext, vector["real_key"])
        )

    def test_size_cap_precedes_base64_allocation(self):
        too_long = "A" * (e.DUAL_MAX_ENCODED_CHARS + 1)
        with self.assertRaises(ValueError):
            e._dual_b64url_decode(too_long)

    def test_deterministic_round_trip_properties(self):
        alphabet = e.ALPHA
        for index in range(8):
            real = "".join(
                alphabet[(index * 19 + offset * 31) % e.N]
                for offset in range(index * 3)
            )
            faux = "".join(
                alphabet[(index * 23 + offset * 17) % e.N]
                for offset in range(25 - index)
            )
            nonce = bytes([index * 2 + 16]) + bytes(range(1, 16))
            bundle = e.encrypt_dual_message(
                real,
                faux,
                VECTORS["equal_lengths"]["real_key"],
                VECTORS["equal_lengths"]["faux_key"],
                materialize=bool(index % 2),
                _envelope_nonce=nonce,
            )
            self.assertEqual(
                e.decrypt_text(
                    bundle["ciphertext"], bundle["real"]["key"]
                )["plaintext"],
                real,
            )
            self.assertEqual(
                e.decrypt_text(
                    bundle["ciphertext"], bundle["faux"]["key"]
                )["plaintext"],
                faux,
            )

    def test_javascript_encrypts_and_python_decrypts_same_bytes(self):
        vector = VECTORS["different_lengths"]
        python_bundle = e.encrypt_dual_message(
            vector["real_plaintext"],
            vector["faux_plaintext"],
            f"  {vector['real_key']}  ",
            f"  {vector['faux_key']}  ",
            vector["materialize"],
            _envelope_nonce=bytes.fromhex(vector["nonce_hex"]),
        )
        self.assertEqual(python_bundle["ciphertext"], vector["ciphertext"])
        self.assertEqual(python_bundle["real"]["key"], vector["real_key"])
        script = (
            "const e=require('./javascript/enigmak.js');"
            f"const v={json.dumps(vector)};"
            "const b=e.encryptDualMessage(v.real_plaintext,v.faux_plaintext,{"
            "realKeyStr:`  ${v.real_key}  `,fauxKeyStr:`  ${v.faux_key}  `,"
            "materialize:v.materialize,"
            "envelopeNonce:Buffer.from(v.nonce_hex,'hex')});"
            "const p=e.decrypt(v.ciphertext,v.real_key);"
            "process.stdout.write(JSON.stringify({b,p}));"
        )
        completed = subprocess.run(
            ["node", "-e", script],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        javascript = json.loads(completed.stdout)
        self.assertEqual(javascript["b"]["ciphertext"], vector["ciphertext"])
        self.assertEqual(javascript["b"]["real"]["key"], vector["real_key"])
        self.assertTrue(javascript["p"]["verified"])
        self.assertEqual(
            javascript["p"]["plaintext"], vector["real_plaintext"]
        )
        python = e.decrypt_text(
            javascript["b"]["ciphertext"], vector["faux_key"]
        )
        self.assertTrue(python["verified"])
        self.assertEqual(python["plaintext"], vector["faux_plaintext"])

    def test_cli_json_and_faux_only_privacy(self):
        vector = VECTORS["equal_lengths"]
        base = [
            sys.executable,
            str(ROOT / "python" / "enigmak.py"),
            "encrypt-dual",
            vector["real_plaintext"],
            "--faux-plaintext",
            vector["faux_plaintext"],
            "--real-key",
            vector["real_key"],
            "--faux-key",
            vector["faux_key"],
            "--json",
        ]
        full = subprocess.run(
            base, cwd=ROOT, check=True, capture_output=True, text=True,
            encoding="utf-8"
        )
        parsed = json.loads(full.stdout)
        self.assertEqual(parsed["real"]["key"], vector["real_key"])
        self.assertEqual(parsed["faux"]["key"], vector["faux_key"])

        private = subprocess.run(
            base + ["--faux-only"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        faux_only = json.loads(private.stdout)
        self.assertNotIn("real", faux_only)
        self.assertNotIn(vector["real_key"], private.stdout + private.stderr)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "faux.json"
            exported = subprocess.run(
                base[:-1] + ["--faux-out", str(path)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertNotIn(vector["real_key"], exported.stderr)
            self.assertNotIn("real", json.loads(path.read_text("utf-8")))


class TestBrowserHtmlSurfaces(unittest.TestCase):
    def test_html_dual_controls_fail_closed_runtime_and_no_dead_packer(self):
        html = (ROOT / "enigmak.html").read_text(encoding="utf-8")
        for needle in (
            'id="faux-input"',
            'id="dual-intended-key-val"',
            'id="dual-faux-key-val"',
            "onclick=\"generateDualMessage()\"",
            "Cipher runtime unavailable; no ciphertext was emitted.",
            "max 81 pairs",
            "mode === 'enc' && hasFaux",
        ):
            self.assertIn(needle, html)
        self.assertNotIn("function packRc4Payload", html)
        self.assertNotIn("function pack_rc4_payload", html)

    def test_html_mirrors_match_source(self):
        source = (ROOT / "enigmak.html").read_bytes()
        for relative in ("docs/index.html", "electron/src/index.html"):
            self.assertEqual(
                (ROOT / relative).read_bytes(), source, relative
            )


if __name__ == "__main__":
    unittest.main()
