# 🎭 MaskedBit

[![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-deployed-FF4B4B?logo=streamlit&logoColor=white)](https://maskedbit.streamlit.app)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen?logo=pytest)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Live demo → [maskedbit.streamlit.app](https://maskedbit.streamlit.app)**

MaskedBit hides encrypted text messages and arbitrary files inside PNG images using LSB (Least Significant Bit) steganography. The image is visually indistinguishable from the original; the payload exists only in the statistical structure of pixel values.

---

## What it does

| Feature | Detail |
|---|---|
| **Text hiding** | Embed any UTF-8 message in a PNG's pixel LSBs |
| **File hiding** | Embed any binary file (PDF, ZIP, image…) in a PNG |
| **AES-256-GCM encryption** | Optional per-message encryption before embedding |
| **Steganalysis** | Chi-square test to detect whether an image contains hidden data |
| **Capacity validation** | Hard check before encoding so data is never silently truncated |
| **Zero disk I/O** | All operations run on in-memory `BytesIO` objects — nothing hits disk |
| **Streamlit UI** | Browser-based interface with 6 tabs |
| **CLI** | Full command-line interface via `cli.py` |
| **Benchmark** | Built-in throughput measurement (encode/decode KB/s) |
| **Test suite** | 35+ pytest tests covering edge cases, crypto tampering, and frame integrity |

---

## How it works

### LSB Steganography

Each pixel channel value (0–255) has its least significant bit replaced with one bit of payload data. Because each value changes by at most 1, the human eye cannot detect the modification.

```
Message: "Hi"  →  Binary: 0 1 0 0 1 0 0 0  0 1 1 0 1 0 0 1

Pixel[0] R: 1100 1010  →  1100 1010  (LSB ← 0)
Pixel[0] G: 1011 0011  →  1011 0011  (LSB ← 1)
Pixel[0] B: 1110 0101  →  1110 0100  (LSB ← 0)
Pixel[1] R: 0110 1001  →  0110 1001  (LSB ← 0)
...
```

A 500×500 RGB image holds up to **93,750 bytes** (≈91 KB) of payload.

### Wire Format

Every payload is wrapped in a structured binary frame before LSB embedding:

```
┌─────────────────────────────────────────────────────────────┐
│  Length prefix (4B)  │  MBIT magic (4B)  │  Version (1B)  │
│  Flags (1B)  │  Filename length (2B)  │  Filename (NB)  │
│  Payload length (4B)  │  Payload (NB)  │
└─────────────────────────────────────────────────────────────┘
```

This structured frame enables: type detection (text vs file), filename recovery, and version-safe decoding.

### Encryption Pipeline (when passphrase is provided)

```
Plaintext
    │
    ▼
PBKDF2-HMAC-SHA256(passphrase, salt, iterations=200_000)  →  256-bit key
    │
    ▼
AES-256-GCM(key, nonce=random 12B)
    │
    ├── ciphertext
    └── authentication tag (16B)
    │
    ▼
Wire blob: [salt 16B][nonce 12B][tag 16B][ciphertext NB]
    │
    ▼
LSB-embed into PNG pixels
```

- **Salt** is random per message — same passphrase, different ciphertext every time.
- **GCM authentication tag** guarantees integrity — any pixel modification causes decryption to fail with a clear error, not silent corruption.
- **200,000 PBKDF2 iterations** makes brute-force passphrase attacks expensive.

### Steganalysis: Chi-Square Test

LSB steganography disturbs the natural frequency relationship between pixel-value pairs `(2k, 2k+1)`. In a clean image these pairs have similar counts; in a stego image their frequencies converge toward equality (because random bits replace the LSBs). The chi-square statistic measures this convergence across all 128 pairs.

---

## Project structure

```
MaskedBit/
├── engine.py          # Core library: crypto, LSB, steganalysis, benchmark
├── app.py             # Streamlit UI (6 tabs, zero disk I/O)
├── cli.py             # Command-line interface
├── requirements.txt
├── tests/
│   └── test_engine.py # 35+ pytest tests
└── .devcontainer/     # GitHub Codespaces config
```

---

## Setup

```bash
git clone https://github.com/imohitseth/MaskedBit.git
cd MaskedBit
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Run the web app:**
```bash
streamlit run app.py
```

**Run tests:**
```bash
pytest tests/ -v
```

---

## CLI usage

```bash
# Hide a text message
python cli.py encode-text cover.png -m "Secret message" -o stego.png

# Hide with AES-256-GCM encryption
python cli.py encode-text cover.png -m "Encrypted" -p mypassword -o stego.png

# Recover text
python cli.py decode-text stego.png
python cli.py decode-text stego.png -p mypassword

# Hide a file
python cli.py encode-file cover.png secret.pdf -p mypassword -o stego.png

# Recover a file
python cli.py decode-file stego.png -p mypassword -o ./output/

# Steganalysis
python cli.py analyse image.png

# Benchmark
python cli.py benchmark cover.png --payload-size 10000

# Check image capacity
python cli.py capacity cover.png
```

---

## Engineering decisions

**Why AES-256-GCM?**  
GCM provides both confidentiality and authenticity in one pass. Any modification to the stego image (compression, cropping, re-encoding) corrupts the authentication tag and produces a clear error rather than silently returning garbage.

**Why PBKDF2 with 200k iterations?**  
Steganography without a strong KDF is weak because the passphrase could be brute-forced offline. PBKDF2-HMAC-SHA256 with 200,000 rounds costs ~0.3s per attempt on a modern CPU, making dictionary attacks impractical.

**Why a structured binary frame instead of a delimiter?**  
A delimiter-based approach (like `#####`) breaks if the payload contains that byte sequence. A length-prefixed binary frame is deterministic, payload-agnostic, and supports arbitrary binary files without encoding overhead.

**Why `io.BytesIO` throughout?**  
Disk writes are observable by the OS, other processes, and forensic tools. Keeping everything in RAM avoids temp-file leakage and is also faster.

**Why chi-square steganalysis?**  
It's a foundational technique that demonstrates understanding of what LSB embedding actually does to the statistical distribution of pixel values — not just how to embed.

---

## Limitations

- **PNG only.** JPEG recompression destroys the LSB payload. This is a fundamental property of lossy compression, not a bug.
- **Not resistant to statistical steganalysis** for large payloads. The chi-square test included in this project can detect large embedded messages. Advanced resistance (e.g. HUGO or WOW cost functions) is future work.
- **No key exchange.** The passphrase must be shared out-of-band. Adding Diffie-Hellman or public-key encryption (e.g., RSA-OAEP or X25519) is a planned feature.
- **Sequential pixel write.** All bits are written to the first N pixels. Pseudo-random pixel ordering using the passphrase as a seed would improve steganalysis resistance.

---

## Roadmap

- [ ] Pseudo-random pixel ordering (seed from passphrase hash)
- [ ] HUGO/WOW adaptive embedding cost functions for steganalysis resistance
- [ ] X25519 key exchange for passwordless encryption
- [ ] JPEG support via DCT coefficient manipulation
- [ ] REST API (FastAPI) for programmatic access
- [ ] GitHub Actions CI with automated test runs on push
