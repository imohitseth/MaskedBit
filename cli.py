#!/usr/bin/env python3
"""
cli.py — MaskedBit command-line interface

Usage examples:
  python cli.py encode-text cover.png -m "Secret" -o stego.png
  python cli.py encode-text cover.png -m "Secret" -p mypassword -o stego.png
  python cli.py decode-text stego.png
  python cli.py decode-text stego.png -p mypassword

  python cli.py encode-file cover.png secret.pdf -o stego.png -p mypassword
  python cli.py decode-file stego.png -p mypassword -o recovered/

  python cli.py analyse image.png
  python cli.py benchmark image.png --payload-size 10000
  python cli.py capacity image.png
"""

import argparse
import os
import sys
from pathlib import Path

import engine


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _write(path: str, data: bytes) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"Written → {path}  ({len(data):,} bytes)")


# encode-text
def cmd_encode_text(args: argparse.Namespace) -> int:
    img = _read(args.image)
    if args.message:
        message = args.message
    else:
        print("Enter message (end with Ctrl-D / Ctrl-Z):")
        message = sys.stdin.read()

    passphrase = args.passphrase or None

    try:
        stego = engine.encode_text(img, message, passphrase)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    output = args.output or args.image.replace(".png", "_stego.png")
    _write(output, stego)
    enc_note = " (AES-256-GCM encrypted)" if passphrase else ""
    print(f"✅ Text hidden{enc_note}: {len(message):,} chars → {output}")
    return 0


# decode-text
def cmd_decode_text(args: argparse.Namespace) -> int:
    img = _read(args.image)
    passphrase = args.passphrase or None

    try:
        msg = engine.decode_text(img, passphrase)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.output:
        _write(args.output, msg.encode("utf-8"))
    else:
        print("\n─── Decoded message ─────────────────────────")
        print(msg)
        print("─────────────────────────────────────────────")
    return 0


# encode-file
def cmd_encode_file(args: argparse.Namespace) -> int:
    img       = _read(args.image)
    file_data = _read(args.file)
    filename  = Path(args.file).name
    passphrase = args.passphrase or None

    try:
        stego = engine.encode_file(img, file_data, filename, passphrase)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    output = args.output or args.image.replace(".png", "_stego.png")
    _write(output, stego)
    enc_note = " (AES-256-GCM encrypted)" if passphrase else ""
    print(f"✅ File '{filename}' hidden{enc_note}: {len(file_data):,} bytes → {output}")
    return 0


# decode-file
def cmd_decode_file(args: argparse.Namespace) -> int:
    img = _read(args.image)
    passphrase = args.passphrase or None

    try:
        filename, data = engine.decode_file(img, passphrase)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    out_dir  = args.output or "."
    out_path = os.path.join(out_dir, filename)
    _write(out_path, data)
    print(f"✅ File recovered: '{filename}' ({len(data):,} bytes)")
    return 0


# analyse
def cmd_analyse(args: argparse.Namespace) -> int:
    img = _read(args.image)
    r   = engine.chi_square_analysis(img)

    print(f"\n{'─'*50}")
    print(f"  Steganalysis report: {args.image}")
    print(f"{'─'*50}")
    print(f"  χ² statistic : {r['chi2']}")
    print(f"  p-value      : {r['p_value']}")
    print(f"  LSB entropy  : {r['lsb_entropy']} bits (max 1.0)")
    print(f"  Conclusion   : {r['conclusion']}")
    print(f"{'─'*50}\n")
    return 0


# benchmark
def cmd_benchmark(args: argparse.Namespace) -> int:
    img = _read(args.image)
    r   = engine.benchmark(img, "A" * args.payload_size)

    print(f"\n{'─'*50}")
    print(f"  Benchmark: {args.image}")
    print(f"{'─'*50}")
    print(f"  Image size     : {r['image_size_px'][0]}×{r['image_size_px'][1]} px")
    print(f"  Capacity       : {r['capacity_bytes']:,} bytes")
    print(f"  Payload        : {r['payload_bytes']:,} bytes")
    print(f"  Encode time    : {r['encode_time_ms']} ms  ({r['encode_throughput_kbps']} KB/s)")
    print(f"  Decode time    : {r['decode_time_ms']} ms  ({r['decode_throughput_kbps']} KB/s)")
    print(f"{'─'*50}\n")
    return 0


# capacity
def cmd_capacity(args: argparse.Namespace) -> int:
    from PIL import Image
    import io
    img  = Image.open(io.BytesIO(_read(args.image))).convert("RGB")
    cap  = engine.capacity_bytes(img)
    print(f"\n  {args.image}: {img.size[0]}×{img.size[1]} px")
    print(f"  Max payload : {cap:,} bytes ({cap / 1024:.1f} KB)\n")
    return 0


# Main
def main() -> int:
    parser = argparse.ArgumentParser(
        prog="maskedbit",
        description="MaskedBit — LSB steganography with AES-256-GCM encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encode-text
    p = sub.add_parser("encode-text", help="Hide a text message in a PNG")
    p.add_argument("image",   help="Cover PNG path")
    p.add_argument("-m", "--message",    help="Message to hide (or pipe via stdin)")
    p.add_argument("-p", "--passphrase", help="AES-256-GCM passphrase (optional)")
    p.add_argument("-o", "--output",     help="Output PNG path (default: <image>_stego.png)")

    # decode-text
    p = sub.add_parser("decode-text", help="Recover a hidden text message")
    p.add_argument("image",   help="Stego PNG path")
    p.add_argument("-p", "--passphrase", help="Decryption passphrase (if encrypted)")
    p.add_argument("-o", "--output",     help="Save message to file instead of printing")

    # encode-file
    p = sub.add_parser("encode-file", help="Hide a file inside a PNG")
    p.add_argument("image",  help="Cover PNG path")
    p.add_argument("file",   help="File to hide")
    p.add_argument("-p", "--passphrase", help="AES-256-GCM passphrase (optional)")
    p.add_argument("-o", "--output",     help="Output PNG path")

    # decode-file
    p = sub.add_parser("decode-file", help="Recover a hidden file")
    p.add_argument("image",  help="Stego PNG path")
    p.add_argument("-p", "--passphrase", help="Decryption passphrase (if encrypted)")
    p.add_argument("-o", "--output",     help="Output directory (default: current dir)")

    # analyse
    p = sub.add_parser("analyse", help="Chi-square steganalysis on a PNG")
    p.add_argument("image", help="PNG path to analyse")

    # benchmark
    p = sub.add_parser("benchmark", help="Measure encode/decode throughput")
    p.add_argument("image", help="PNG path")
    p.add_argument("--payload-size", type=int, default=5000, help="Payload size in bytes (default: 5000)")

    # capacity
    p = sub.add_parser("capacity", help="Print the byte capacity of a PNG")
    p.add_argument("image", help="PNG path")

    args = parser.parse_args()

    dispatch = {
        "encode-text":  cmd_encode_text,
        "decode-text":  cmd_decode_text,
        "encode-file":  cmd_encode_file,
        "decode-file":  cmd_decode_file,
        "analyse":      cmd_analyse,
        "benchmark":    cmd_benchmark,
        "capacity":     cmd_capacity,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
