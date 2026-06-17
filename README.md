# MaskedBit

Link- https://maskedbit.streamlit.app/

**MaskedBit** is a production-grade, privacy-focused security tool that bridges the gap between cryptography and spatial steganography. Built with Python and Streamlit, the system implements an end-to-end processing pipeline that encrypts sensitive payloads (text data or nested asset files) using **AES-256-GCM (Galois/Counter Mode)** before safely embedding them into the Least Significant Bits (LSB) of lossless image pixel matrices.

The application executes entirely on the client side, meaning zero data persistence, minimal transmission overhead, and verifiable privacy boundaries.

---

## 🚀 Core Engineering Highlights

* **Authenticated Symmetric Cryptography:** Implements industrial-strength `AES-256-GCM`. Provides multi-layered defense—achieving both *confidentiality* via bit encryption and *integrity/authenticity* through cryptographic message tags, neutralizing payload bit-flipping attacks entirely.
* **Polymorphic Payload Encoding:** Supports dual-mode steganographic hiding. The core engine dynamically handles abstract bitstream serialization, allowing users to conceal raw text messages or encapsulate distinct file binaries (e.g., identity documents, certificates) inside a separate, benign cover image.
* **Predictive Capacity & Risk Analytics Engine:** Prioritizes carrier structural integrity. The application programmatically evaluates spatial boundaries before writing to memory, parsing dimensional byte limits ($W \times H \times \text{Channels}$) against total encrypted bit arrays (inclusive of nonces and signature metadata tags) to flag structural degradation or risk of steganalysis.
* **Zero-Trust Session State Handling:** Leverages Streamlit's virtual memory pipeline alongside stateless file object streaming (`io.BytesIO`) to process buffers dynamically in memory without triggering local server storage page faults or temporary disk leakage.

---

## 🛠️ System Architecture & Workflow

The architecture decouples the transformation pipeline into distinct data layers to enforce a clean separation of concerns:

```mermaid
graph TD
    A[Plaintext / File Binary] --> B[PBKDF2 Key Derivation]
    C[Raw Bitstream Object] --> D[AES-256-GCM Cipher]
    B --> D
    D --> E[Nonce + Tag + Ciphertext Bundle]
    F[PNG / BMP Lossless Image] --> G[LSB Spatial Embedding Engine]
    E --> G
    G --> H[Final Masked Image]



## 🎛️ Technology Stack & Dependencies

* **Language:** Python (v3.9+)
* **Interface Layer:** Streamlit (UI/UX deployment container, reactive input loops)
* **Image Processing Engine:** Pillow (PIL fork for low-level matrix channel slicing and image type assertions)
* **Cryptographic Provider:** PyCryptodome (C-extended primitives optimized for block-cipher performance)

---

```markdown
## ⚙️ Local Development Setup

To replicate, test, or modify the processing pipeline locally:

```bash
# 1. Clone the repository down into your environment
git clone [https://github.com/imohitseth/MaskedBit.git](https://github.com/imohitseth/MaskedBit.git)
cd MaskedBit

# 2. Establish a modular isolated virtual workspace
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# 3. Install required execution primitives
pip install -r requirements.txt

# 4. Boot up the application server interface instance
streamlit run app.py
