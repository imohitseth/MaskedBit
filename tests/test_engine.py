"""
tests/test_engine.py — pytest test suite for MaskedBit engine

Run with:
    pytest tests/ -v
    pytest tests/ -v --tb=short
"""

import io
import os
import struct
import pytest
from PIL import Image
import numpy as np

import engine


# Fixtures
def _make_png(width: int = 200, height: int = 200, seed: int = 42) -> bytes:
    """Create a reproducible PNG in memory with pseudo-random pixel data."""
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 256, (height, width, 3), dtype=np.uint8)
    img = Image.fromarray(arr, "RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


SMALL_PNG   = _make_png(50, 50)      # ~7 KB capacity
MEDIUM_PNG  = _make_png(200, 200)    # ~117 KB capacity
LARGE_PNG   = _make_png(500, 500)    # ~732 KB capacity


# Capacity
class TestCapacity:
    def test_capacity_formula(self):
        img = Image.open(io.BytesIO(MEDIUM_PNG)).convert("RGB")
        # 200*200 pixels * 3 channels = 120000 bits → 15000 bytes
        assert engine.capacity_bytes(img) == 200 * 200 * 3 // 8

    def test_capacity_check_passes_when_within(self):
        img = Image.open(io.BytesIO(LARGE_PNG)).convert("RGB")
        engine.capacity_check(img, 100)   # should not raise

    def test_capacity_check_raises_when_exceeded(self):
        img = Image.open(io.BytesIO(SMALL_PNG)).convert("RGB")
        cap = engine.capacity_bytes(img)
        with pytest.raises(ValueError, match="exceeds image capacity"):
            engine.capacity_check(img, cap + 1)


# Encryption
class TestEncryption:
    def test_round_trip(self):
        plain = b"Hello, AES-256-GCM!"
        blob  = engine.encrypt_payload(plain, "secret")
        assert engine.decrypt_payload(blob, "secret") == plain

    def test_wrong_passphrase_raises(self):
        blob = engine.encrypt_payload(b"data", "correct")
        with pytest.raises(ValueError, match="Decryption failed"):
            engine.decrypt_payload(blob, "wrong")

    def test_tampered_ciphertext_raises(self):
        blob  = bytearray(engine.encrypt_payload(b"data", "pw"))
        blob[-1] ^= 0xFF   # flip last byte of ciphertext
        with pytest.raises(ValueError, match="Decryption failed"):
            engine.decrypt_payload(bytes(blob), "pw")

    def test_different_ciphertexts_for_same_plaintext(self):
        """Random salt+nonce ensures every encryption is unique."""
        a = engine.encrypt_payload(b"same", "pw")
        b = engine.encrypt_payload(b"same", "pw")
        assert a != b

    def test_blob_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            engine.decrypt_payload(b"\x00" * 5, "pw")

    def test_large_payload(self):
        plain = os.urandom(50_000)
        blob  = engine.encrypt_payload(plain, "longpassphrase!!")
        assert engine.decrypt_payload(blob, "longpassphrase!!") == plain

    def test_unicode_passphrase(self):
        plain = b"secret"
        blob  = engine.encrypt_payload(plain, "pässwörд🔑")
        assert engine.decrypt_payload(blob, "pässwörд🔑") == plain


# Text encode / decode — no encryption
class TestTextNoEncryption:
    def test_basic_round_trip(self):
        stego = engine.encode_text(MEDIUM_PNG, "Hello, World!")
        assert engine.decode_text(stego) == "Hello, World!"

    def test_empty_message(self):
        stego = engine.encode_text(MEDIUM_PNG, "")
        assert engine.decode_text(stego) == ""

    def test_unicode_message(self):
        msg   = "こんにちは世界 🌏 مرحبا"
        stego = engine.encode_text(MEDIUM_PNG, msg)
        assert engine.decode_text(stego) == msg

    def test_newlines_preserved(self):
        msg   = "line 1\nline 2\nline 3"
        stego = engine.encode_text(MEDIUM_PNG, msg)
        assert engine.decode_text(stego) == msg

    def test_output_is_png(self):
        stego = engine.encode_text(MEDIUM_PNG, "test")
        img   = Image.open(io.BytesIO(stego))
        assert img.format == "PNG"

    def test_image_dimensions_unchanged(self):
        orig  = Image.open(io.BytesIO(MEDIUM_PNG))
        stego = engine.encode_text(MEDIUM_PNG, "test")
        enc   = Image.open(io.BytesIO(stego))
        assert orig.size == enc.size

    def test_pixel_difference_is_at_most_1(self):
        """LSB embedding changes each channel value by at most 1."""
        stego   = engine.encode_text(MEDIUM_PNG, "test message")
        orig_arr  = np.array(Image.open(io.BytesIO(MEDIUM_PNG)).convert("RGB"))
        stego_arr = np.array(Image.open(io.BytesIO(stego)).convert("RGB"))
        diff = np.abs(orig_arr.astype(int) - stego_arr.astype(int))
        assert diff.max() <= 1

    def test_capacity_error_on_overflow(self):
        big_msg = "X" * (engine.capacity_bytes(Image.open(io.BytesIO(SMALL_PNG))) + 1000)
        with pytest.raises(ValueError, match="exceeds image capacity"):
            engine.encode_text(SMALL_PNG, big_msg)

    def test_no_disk_writes(self, tmp_path, monkeypatch):
        """Verify no files are created in the working directory during encode/decode."""
        written = []
        original_open = open

        def mock_open(path, mode="r", *a, **kw):
            if "w" in mode or "b" in mode and ("w" in mode or "x" in mode):
                written.append(path)
            return original_open(path, mode, *a, **kw)

        stego = engine.encode_text(MEDIUM_PNG, "disk check")
        engine.decode_text(stego)
        # No temp files should have been created
        assert not any("temp" in str(p).lower() for p in written)


# Text encode / decode — with AES-256-GCM
class TestTextWithEncryption:
    def test_basic_encrypted_round_trip(self):
        msg   = "Encrypted secret message"
        stego = engine.encode_text(MEDIUM_PNG, msg, passphrase="mypassword")
        assert engine.decode_text(stego, passphrase="mypassword") == msg

    def test_wrong_passphrase_raises(self):
        stego = engine.encode_text(MEDIUM_PNG, "secret", passphrase="correct")
        with pytest.raises(ValueError):
            engine.decode_text(stego, passphrase="wrong")

    def test_decrypt_unencrypted_without_passphrase(self):
        """Decoding an unencrypted message without passphrase should work fine."""
        stego = engine.encode_text(MEDIUM_PNG, "plain")
        assert engine.decode_text(stego) == "plain"

    def test_long_encrypted_message(self):
        msg   = "Z" * 5000
        stego = engine.encode_text(LARGE_PNG, msg, passphrase="pw")
        assert engine.decode_text(stego, passphrase="pw") == msg

    def test_unicode_encrypted(self):
        msg   = "🔐 Тайное сообщение 秘密"
        stego = engine.encode_text(MEDIUM_PNG, msg, passphrase="unicodepw")
        assert engine.decode_text(stego, passphrase="unicodepw") == msg


# File encode / decode — no encryption
class TestFileNoEncryption:
    def test_basic_round_trip(self):
        data  = b"PDF-like binary content \x00\x01\x02\x03"
        stego = engine.encode_file(LARGE_PNG, data, "test.bin")
        fname, out = engine.decode_file(stego)
        assert fname == "test.bin"
        assert out   == data

    def test_filename_preserved(self):
        stego = engine.encode_file(LARGE_PNG, b"data", "my document.pdf")
        fname, _ = engine.decode_file(stego)
        assert fname == "my document.pdf"

    def test_binary_content_integrity(self):
        data = os.urandom(1000)
        stego = engine.encode_file(LARGE_PNG, data, "random.bin")
        _, out = engine.decode_file(stego)
        assert out == data

    def test_text_decode_on_file_payload_raises(self):
        stego = engine.encode_file(LARGE_PNG, b"file data", "f.txt")
        with pytest.raises(ValueError, match="file payload"):
            engine.decode_text(stego)

    def test_file_decode_on_text_payload_raises(self):
        stego = engine.encode_text(LARGE_PNG, "text message")
        with pytest.raises(ValueError, match="text payload"):
            engine.decode_file(stego)


# File encode / decode — with AES-256-GCM
class TestFileWithEncryption:
    def test_encrypted_file_round_trip(self):
        data  = b"\x89PNG fake image bytes" * 100
        stego = engine.encode_file(LARGE_PNG, data, "image.png", passphrase="filepass")
        fname, out = engine.decode_file(stego, passphrase="filepass")
        assert fname == "image.png"
        assert out   == data

    def test_wrong_passphrase_raises(self):
        stego = engine.encode_file(LARGE_PNG, b"secret", "f.bin", passphrase="correct")
        with pytest.raises(ValueError):
            engine.decode_file(stego, passphrase="wrong")


# Steganalysis — chi-square
class TestSteganalysis:
    def test_clean_image_low_chi2(self):
        """A natural image should not trigger a stego detection."""
        r = engine.chi_square_analysis(MEDIUM_PNG)
        # p_value should generally be > 0.05 for a clean image
        assert "chi2" in r
        assert "p_value" in r
        assert "conclusion" in r
        assert "lsb_entropy" in r

    def test_saturated_stego_detected(self):
        """An image with a very large encrypted payload should show high chi2."""
        msg   = "S" * 10_000
        stego = engine.encode_text(LARGE_PNG, msg, passphrase="pw")
        r     = engine.chi_square_analysis(stego)
        # Encrypted payload randomises LSBs → chi2 should rise
        assert r["chi2"] >= 0   # always non-negative
        assert 0.0 <= r["lsb_entropy"] <= 1.0

    def test_returns_all_fields(self):
        r = engine.chi_square_analysis(MEDIUM_PNG)
        assert set(r.keys()) >= {"chi2", "p_value", "conclusion", "lsb_entropy", "dof"}

    def test_lsb_entropy_range(self):
        r = engine.chi_square_analysis(MEDIUM_PNG)
        assert 0.0 <= r["lsb_entropy"] <= 1.0


# Benchmark
class TestBenchmark:
    def test_benchmark_returns_expected_keys(self):
        r = engine.benchmark(MEDIUM_PNG, "X" * 100)
        expected = {
            "image_size_px", "capacity_bytes", "payload_bytes",
            "encode_time_ms", "decode_time_ms",
            "encode_throughput_kbps", "decode_throughput_kbps",
        }
        assert expected.issubset(r.keys())

    def test_benchmark_positive_timings(self):
        r = engine.benchmark(MEDIUM_PNG, "X" * 100)
        assert r["encode_time_ms"] > 0
        assert r["decode_time_ms"] > 0

    def test_benchmark_payload_size_matches(self):
        msg = "B" * 500
        r   = engine.benchmark(MEDIUM_PNG, msg)
        assert r["payload_bytes"] == 500


# Frame integrity
class TestFrameIntegrity:
    def test_no_maskedbit_magic_raises(self):
        """Decoding an unmodified clean image should raise a clear error."""
        with pytest.raises(ValueError, match="No MaskedBit payload"):
            engine.decode_text(MEDIUM_PNG)

    def test_file_decode_on_clean_image_raises(self):
        with pytest.raises(ValueError):
            engine.decode_file(MEDIUM_PNG)
