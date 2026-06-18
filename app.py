"""
app.py — MaskedBit Streamlit UI

Tabs:
  1. Encode Text   — hide an encrypted text message in a PNG
  2. Decode Text   — recover a hidden text message
  3. Encode File   — hide an arbitrary file inside a PNG
  4. Decode File   — recover a hidden file
  5. Steganalysis  — chi-square test to detect hidden data
  6. Benchmark     — measure encode/decode throughput

All I/O is in-memory (BytesIO). Nothing is written to disk.
"""

import io
import streamlit as st
from PIL import Image

import engine


st.set_page_config(
    page_title="MaskedBit",
    page_icon="🎭",
    layout="centered",
)

st.title("🎭 MaskedBit")
st.caption(
    "LSB steganography with optional AES-256-GCM encryption. "
    "Hide text or files inside PNG images — all processing is in-memory."
)

tabs = st.tabs([
    "🔒 Encode Text",
    "🔓 Decode Text",
    "📁 Encode File",
    "📂 Decode File",
    "🔬 Steganalysis",
    "⚡ Benchmark",
])



def _image_upload(key: str, label: str = "Upload a PNG image") -> bytes | None:
    f = st.file_uploader(label, type=["png"], key=key)
    if f:
        data = f.read()
        st.image(data, caption="Uploaded image", use_container_width=True)
        img = Image.open(io.BytesIO(data)).convert("RGB")
        cap = engine.capacity_bytes(img)
        st.caption(
            f"Image: {img.size[0]}×{img.size[1]} px · "
            f"Capacity: {cap:,} bytes ({cap / 1024:.1f} KB)"
        )
        return data
    return None


def _passphrase_input(key: str, label: str = "Passphrase (leave blank for no encryption)") -> str:
    return st.text_input(label, type="password", key=key)



# Tab 1 — Encode Text
with tabs[0]:
    st.subheader("Hide a text message inside a PNG")
    img_bytes = _image_upload("enc_text_img")
    message   = st.text_area("Message to hide", height=150, key="enc_text_msg",
                              placeholder="Enter your secret message here…")
    passphrase = _passphrase_input("enc_text_pass")

    if st.button("Encode", key="enc_text_btn", type="primary"):
        if not img_bytes:
            st.error("Please upload a cover image.")
        elif not message.strip():
            st.error("Message cannot be empty.")
        else:
            with st.spinner("Encoding…"):
                try:
                    stego = engine.encode_text(img_bytes, message, passphrase or None)
                    st.success(
                        f"✅ Done! Message hidden ({len(message):,} chars, "
                        f"{len(message.encode()):,} bytes)."
                        + (" Encrypted with AES-256-GCM." if passphrase else " No encryption.")
                    )
                    st.image(stego, caption="Stego image (visually identical)", use_container_width=True)
                    st.download_button(
                        "⬇️ Download stego PNG",
                        data=stego,
                        file_name="maskedbit_stego.png",
                        mime="image/png",
                        key="enc_text_dl",
                    )
                except ValueError as e:
                    st.error(str(e))



# Tab 2 — Decode Text
with tabs[1]:
    st.subheader("Recover a hidden text message")
    img_bytes  = _image_upload("dec_text_img")
    passphrase = _passphrase_input("dec_text_pass",
                                   "Passphrase (required if the message was encrypted)")

    if st.button("Decode", key="dec_text_btn", type="primary"):
        if not img_bytes:
            st.error("Please upload a stego image.")
        else:
            with st.spinner("Decoding…"):
                try:
                    msg = engine.decode_text(img_bytes, passphrase or None)
                    st.success("✅ Message recovered!")
                    st.text_area("Hidden message", value=msg, height=200, key="dec_text_out")
                    st.download_button(
                        "⬇️ Download as .txt",
                        data=msg.encode("utf-8"),
                        file_name="maskedbit_message.txt",
                        mime="text/plain",
                        key="dec_text_dl",
                    )
                except ValueError as e:
                    st.error(str(e))


# Tab 3 — Encode File
with tabs[2]:
    st.subheader("Hide any file inside a PNG")
    st.caption(
        "The file's bytes are embedded in the image's LSB plane. "
        "The original filename is stored in the frame header."
    )
    img_bytes  = _image_upload("enc_file_img")
    secret_f   = st.file_uploader("File to hide (any format)", key="enc_file_secret")
    passphrase = _passphrase_input("enc_file_pass")

    if st.button("Encode", key="enc_file_btn", type="primary"):
        if not img_bytes:
            st.error("Please upload a cover image.")
        elif not secret_f:
            st.error("Please select a file to hide.")
        else:
            file_data = secret_f.read()
            with st.spinner(f"Encoding {len(file_data):,} bytes…"):
                try:
                    stego = engine.encode_file(
                        img_bytes, file_data, secret_f.name, passphrase or None
                    )
                    st.success(
                        f"✅ '{secret_f.name}' ({len(file_data):,} bytes) hidden."
                        + (" Encrypted with AES-256-GCM." if passphrase else " No encryption.")
                    )
                    st.image(stego, caption="Stego image", use_container_width=True)
                    st.download_button(
                        "⬇️ Download stego PNG",
                        data=stego,
                        file_name="maskedbit_stego.png",
                        mime="image/png",
                        key="enc_file_dl",
                    )
                except ValueError as e:
                    st.error(str(e))


# Tab 4 — Decode File
with tabs[3]:
    st.subheader("Recover a hidden file")
    img_bytes  = _image_upload("dec_file_img")
    passphrase = _passphrase_input("dec_file_pass",
                                   "Passphrase (required if file was encrypted)")

    if st.button("Decode", key="dec_file_btn", type="primary"):
        if not img_bytes:
            st.error("Please upload a stego image.")
        else:
            with st.spinner("Extracting…"):
                try:
                    filename, data = engine.decode_file(img_bytes, passphrase or None)
                    st.success(f"✅ File recovered: '{filename}' ({len(data):,} bytes)")
                    st.download_button(
                        f"⬇️ Download '{filename}'",
                        data=data,
                        file_name=filename,
                        key="dec_file_dl",
                    )
                except ValueError as e:
                    st.error(str(e))


# Tab 5 — Steganalysis
with tabs[4]:
    st.subheader("Chi-square steganalysis")
    st.caption(
        "LSB steganography disturbs the natural frequency balance between pixel-value pairs "
        "(2k, 2k+1). This test measures that disturbance and estimates the probability that "
        "the image contains hidden data."
    )
    img_bytes = _image_upload("steg_img")

    if st.button("Analyse", key="steg_btn", type="primary"):
        if not img_bytes:
            st.error("Please upload an image.")
        else:
            with st.spinner("Running chi-square test…"):
                r = engine.chi_square_analysis(img_bytes)

            st.markdown(f"### {r['conclusion']}")

            col1, col2, col3 = st.columns(3)
            col1.metric("χ² statistic", r["chi2"])
            col2.metric("p-value", r["p_value"])
            col3.metric("LSB entropy (bits)", r["lsb_entropy"])

            with st.expander("Interpretation guide"):
                st.markdown(
                    """
| p-value | Interpretation |
|---|---|
| < 0.05 | Strong evidence of hidden data |
| 0.05 – 0.20 | Borderline — possible hidden data |
| > 0.20 | No significant evidence of hidden data |

**LSB entropy**: a clean image has LSBs close to 0.85–0.95 bits; a fully-saturated stego image
approaches 1.0 (perfectly random LSBs due to encrypted payload).

**Limitations**: chi-square is sensitive to large payloads in uncompressed images. It produces
false negatives on small or encrypted payloads and false positives on noisy photographs.
                    """
                )


# Tab 6 — Benchmark
with tabs[5]:
    st.subheader("Encode / decode throughput benchmark")
    st.caption("Measures real encode and decode time on your uploaded image.")
    img_bytes = _image_upload("bench_img")
    msg_size  = st.slider("Payload size (bytes)", 100, 50_000, 5_000, step=100, key="bench_size")

    if st.button("Run benchmark", key="bench_btn", type="primary"):
        if not img_bytes:
            st.error("Please upload an image.")
        else:
            with st.spinner("Benchmarking…"):
                try:
                    r = engine.benchmark(img_bytes, "A" * msg_size)
                    st.success("Benchmark complete.")

                    col1, col2 = st.columns(2)
                    col1.metric("Encode time", f"{r['encode_time_ms']} ms")
                    col2.metric("Decode time", f"{r['decode_time_ms']} ms")

                    col3, col4 = st.columns(2)
                    col3.metric("Encode throughput", f"{r['encode_throughput_kbps']} KB/s")
                    col4.metric("Decode throughput", f"{r['decode_throughput_kbps']} KB/s")

                    col5, col6 = st.columns(2)
                    col5.metric("Image size", f"{r['image_size_px'][0]}×{r['image_size_px'][1]} px")
                    col6.metric("Image capacity", f"{r['capacity_bytes']:,} bytes")

                except ValueError as e:
                    st.error(str(e))
