"""
engine.py — MaskedBit core steganography and cryptography engine.

Provides:
  - AES-256-GCM encryption/decryption (PyCryptodome)
  - LSB steganography for text and arbitrary file payloads
  - Steganalysis via chi-square test on pixel LSB distribution
  - Capacity validation before encoding
  - Throughput benchmarking
  - Zero disk I/O: all operations work on in-memory bytes/BytesIO
"""

from __future__ import annotations

import io
import os
import struct
import time
import math
from typing import Optional, Tuple

import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# Constants
KDF_ITERATIONS   = 200_000          # PBKDF2-HMAC-SHA256 rounds
KEY_LEN          = 32               # AES-256
NONCE_LEN        = 12               # GCM standard nonce
TAG_LEN          = 16               # GCM authentication tag
SALT_LEN         = 16               # random per-message salt
HEADER_MAGIC     = b"MBIT"          # 4-byte magic to detect MaskedBit payloads
VERSION          = 1                # protocol version byte
TEXT_FLAG        = 0x01             # payload-type flag: text message
FILE_FLAG        = 0x02             # payload-type flag: arbitrary file


# Key Derivation
def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256."""
    return PBKDF2(
        passphrase.encode("utf-8"),
        salt,
        dkLen=KEY_LEN,
        count=KDF_ITERATIONS,
        prf=lambda p, s: __import__("hmac").new(p, s, "sha256").digest(),
    )


# Encryption / Decryption
def encrypt_payload(plaintext: bytes, passphrase: str) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Wire format:
        [salt: 16B][nonce: 12B][tag: 16B][ciphertext: NB]

    Returns raw bytes ready to be embedded via LSB.
    """
    salt  = get_random_bytes(SALT_LEN)
    key   = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_LEN))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return salt + cipher.nonce + tag + ciphertext


def decrypt_payload(blob: bytes, passphrase: str) -> bytes:
    """
    Decrypt a blob produced by encrypt_payload.
    Raises ValueError on authentication failure (wrong passphrase or tampered data).
    """
    if len(blob) < SALT_LEN + NONCE_LEN + TAG_LEN:
        raise ValueError("Payload is too short to be a valid encrypted blob.")

    salt       = blob[:SALT_LEN]
    nonce      = blob[SALT_LEN : SALT_LEN + NONCE_LEN]
    tag        = blob[SALT_LEN + NONCE_LEN : SALT_LEN + NONCE_LEN + TAG_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN + TAG_LEN:]

    key    = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError(
            "Decryption failed: wrong passphrase or the image has been modified."
        )


# Frame construction
def _build_frame(payload: bytes, flag: int, filename: str = "") -> bytes:
    """
    Wrap a (possibly encrypted) payload in a structured frame.

    Frame layout:
        [magic: 4B][version: 1B][flag: 1B][filename_len: 2B][filename: NB]
        [payload_len: 4B][payload: NB]
    """
    fname_bytes = filename.encode("utf-8")[:255]
    header = (
        HEADER_MAGIC
        + struct.pack("B", VERSION)
        + struct.pack("B", flag)
        + struct.pack(">H", len(fname_bytes))
        + fname_bytes
        + struct.pack(">I", len(payload))
    )
    return header + payload


def _parse_frame(raw: bytes) -> Tuple[int, str, bytes]:
    """
    Parse a frame produced by _build_frame.
    Returns (flag, filename, payload_bytes).
    Raises ValueError on malformed or unrecognized frames.
    """
    if raw[:4] != HEADER_MAGIC:
        raise ValueError(
            "No MaskedBit payload found. "
            "Make sure you are using an image encoded with MaskedBit."
        )
    idx = 4
    version    = struct.unpack("B", raw[idx:idx+1])[0]; idx += 1
    flag       = struct.unpack("B", raw[idx:idx+1])[0]; idx += 1
    fname_len  = struct.unpack(">H", raw[idx:idx+2])[0]; idx += 2
    filename   = raw[idx:idx+fname_len].decode("utf-8"); idx += fname_len
    payload_len = struct.unpack(">I", raw[idx:idx+4])[0]; idx += 4
    payload    = raw[idx:idx+payload_len]
    return flag, filename, payload


# Capacity
def capacity_bytes(image: Image.Image) -> int:
    """Return how many bytes can be hidden in this image (1 bit per channel)."""
    arr  = np.array(image.convert("RGB"))
    bits = arr.size          # total channel values = total available bits
    return bits // 8


def capacity_check(image: Image.Image, payload_bytes: int) -> None:
    """Raise ValueError if the image cannot hold payload_bytes bytes."""
    cap = capacity_bytes(image)
    if payload_bytes > cap:
        raise ValueError(
            f"Payload ({payload_bytes:,} B) exceeds image capacity "
            f"({cap:,} B) by {payload_bytes - cap:,} B. "
            f"Use a larger image or a shorter message."
        )


# LSB Encode / Decode
def _lsb_embed(arr: np.ndarray, data: bytes) -> np.ndarray:
    """Embed data bits into the LSB of every channel in arr (in-place copy)."""
    flat  = arr.flatten().astype(np.uint8)
    bits  = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    if len(bits) > len(flat):
        raise ValueError("Data exceeds pixel capacity (internal check failed).")
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    return flat.reshape(arr.shape)


def _lsb_extract(arr: np.ndarray, num_bytes: int) -> bytes:
    """Extract num_bytes worth of LSBs from arr."""
    flat = arr.flatten().astype(np.uint8)
    bits = flat[:num_bytes * 8] & 1
    return np.packbits(bits).tobytes()


# Public API: Text
def encode_text(
    image_bytes: bytes,
    message: str,
    passphrase: Optional[str] = None,
) -> bytes:
    """
    Hide a UTF-8 text message inside a PNG image.

    Args:
        image_bytes:  Raw bytes of the source PNG.
        message:      Plaintext to hide.
        passphrase:   If provided, the message is AES-256-GCM encrypted first.

    Returns:
        Raw bytes of the stego PNG (never written to disk).
    """
    img  = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr  = np.array(img)

    raw_payload = message.encode("utf-8")
    if passphrase:
        raw_payload = encrypt_payload(raw_payload, passphrase)

    frame = _build_frame(raw_payload, flag=TEXT_FLAG)

    # Prefix frame with its total length (4 bytes) so decode knows where to stop
    blob = struct.pack(">I", len(frame)) + frame

    capacity_check(img, len(blob))

    stego_arr = _lsb_embed(arr, blob)
    stego_img = Image.fromarray(stego_arr.astype(np.uint8), "RGB")

    buf = io.BytesIO()
    stego_img.save(buf, format="PNG")
    return buf.getvalue()


def decode_text(
    image_bytes: bytes,
    passphrase: Optional[str] = None,
) -> str:
    """
    Extract a hidden text message from a stego PNG.

    Args:
        image_bytes:  Raw bytes of the stego PNG.
        passphrase:   Required if the message was encrypted.

    Returns:
        The original plaintext message.
    """
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.array(img)

    # First extract 4 bytes to learn frame length
    length_blob = _lsb_extract(arr, 4)
    frame_len   = struct.unpack(">I", length_blob)[0]

    if frame_len > capacity_bytes(img):
        raise ValueError("Image does not appear to contain a MaskedBit payload.")

    raw = _lsb_extract(arr, 4 + frame_len)[4:]   # skip the 4-byte length prefix
    flag, _, payload = _parse_frame(raw)

    if flag != TEXT_FLAG:
        raise ValueError("This image contains a file payload, not a text message.")

    if passphrase:
        payload = decrypt_payload(payload, passphrase)

    return payload.decode("utf-8")


# Public API: File Embedding
def encode_file(
    image_bytes: bytes,
    file_data: bytes,
    filename: str,
    passphrase: Optional[str] = None,
) -> bytes:
    """
    Hide an arbitrary file inside a PNG image.

    Args:
        image_bytes:  Raw bytes of the source PNG.
        file_data:    Raw bytes of the file to hide.
        filename:     Original filename (stored in frame for recovery).
        passphrase:   If provided, encrypts the file data with AES-256-GCM.

    Returns:
        Raw bytes of the stego PNG.
    """
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.array(img)

    raw_payload = file_data
    if passphrase:
        raw_payload = encrypt_payload(raw_payload, passphrase)

    frame = _build_frame(raw_payload, flag=FILE_FLAG, filename=filename)
    blob  = struct.pack(">I", len(frame)) + frame

    capacity_check(img, len(blob))

    stego_arr = _lsb_embed(arr, blob)
    stego_img = Image.fromarray(stego_arr.astype(np.uint8), "RGB")

    buf = io.BytesIO()
    stego_img.save(buf, format="PNG")
    return buf.getvalue()


def decode_file(
    image_bytes: bytes,
    passphrase: Optional[str] = None,
) -> Tuple[str, bytes]:
    """
    Extract a hidden file from a stego PNG.

    Returns:
        (filename, file_data) tuple.
    """
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.array(img)

    length_blob = _lsb_extract(arr, 4)
    frame_len   = struct.unpack(">I", length_blob)[0]

    if frame_len > capacity_bytes(img):
        raise ValueError("Image does not appear to contain a MaskedBit payload.")

    raw = _lsb_extract(arr, 4 + frame_len)[4:]
    flag, filename, payload = _parse_frame(raw)

    if flag != FILE_FLAG:
        raise ValueError("This image contains a text payload, not a file.")

    if passphrase:
        payload = decrypt_payload(payload, passphrase)

    return filename, payload


# Steganalysis: Chi-Square Test
def chi_square_analysis(image_bytes: bytes) -> dict:
    """
    Perform a chi-square steganalysis test on an image.

    LSB steganography disturbs the natural relationship between pairs of
    pixel values (2k, 2k+1): in a clean image these pairs occur with similar
    frequency; in a stego image their frequencies converge.

    Returns a dict with:
        chi2       - chi-square statistic (higher → more likely stego)
        p_value    - estimated p-value
        conclusion - human-readable verdict
        lsb_entropy - Shannon entropy of the LSB plane (bits; max 1.0)
    """
    img  = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr  = np.array(img).flatten().astype(np.uint32)

    # Pair frequencies: how often does 2k appear vs 2k+1 for each k in 0..127
    even_vals = arr[arr % 2 == 0]
    odd_vals  = arr[arr % 2 == 1]

    chi2 = 0.0
    for k in range(128):
        observed_even = np.sum(arr == 2 * k)
        observed_odd  = np.sum(arr == 2 * k + 1)
        expected      = (observed_even + observed_odd) / 2
        if expected > 0:
            chi2 += ((observed_even - expected) ** 2 + (observed_odd - expected) ** 2) / expected

    # Degrees of freedom = 127 (pairs 0..127)
    dof = 127
    # Approximate p-value using normal approximation to chi2 distribution
    z = (chi2 - dof) / math.sqrt(2 * dof)
    # Survival function approximation: p ≈ 0.5 * erfc(z / sqrt(2))
    import math as _m
    p_value = 0.5 * math.erfc(z / math.sqrt(2))

    # LSB entropy
    lsbs = arr & 1
    p1   = np.mean(lsbs)
    p0   = 1 - p1
    eps  = 1e-12
    lsb_entropy = -(p0 * math.log2(p0 + eps) + p1 * math.log2(p1 + eps))

    if p_value < 0.05:
        conclusion = "⚠️  Likely contains hidden data (chi-square p < 0.05)"
    elif p_value < 0.20:
        conclusion = "🔶 Possibly contains hidden data (borderline chi-square)"
    else:
        conclusion = "✅ No statistically significant steganography detected"

    return {
        "chi2":        round(chi2, 2),
        "p_value":     round(p_value, 4),
        "conclusion":  conclusion,
        "lsb_entropy": round(lsb_entropy, 4),
        "dof":         dof,
    }


# Benchmarking
def benchmark(image_bytes: bytes, message: str = "A" * 1000) -> dict:
    """
    Measure encode + decode throughput on the given image.

    Returns timing and throughput stats as a dict.
    """
    payload_size = len(message.encode("utf-8"))

    t0    = time.perf_counter()
    stego = encode_text(image_bytes, message)
    t_enc = time.perf_counter() - t0

    t0    = time.perf_counter()
    _     = decode_text(stego)
    t_dec = time.perf_counter() - t0

    img   = Image.open(io.BytesIO(image_bytes))
    cap   = capacity_bytes(img)

    return {
        "image_size_px":    img.size,
        "capacity_bytes":   cap,
        "payload_bytes":    payload_size,
        "encode_time_ms":   round(t_enc * 1000, 2),
        "decode_time_ms":   round(t_dec * 1000, 2),
        "encode_throughput_kbps": round(payload_size / t_enc / 1024, 1),
        "decode_throughput_kbps": round(payload_size / t_dec / 1024, 1),
    }
