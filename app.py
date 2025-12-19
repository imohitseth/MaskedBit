import streamlit as st
from PIL import Image
import io
import engine
st.set_page_config(page_title="Wizard's Invisible Ink", page_icon="🪄")

st.title("🪄 Wizard's Invisible Ink")
st.markdown("Hide secret messages inside images using LSB Steganography.")

tab1, tab2 = st.tabs(["🔒 Hide Message", "🔓 Reveal Message"])

with tab1:
    st.header("Encode a Secret")
    uploaded_file = st.file_uploader("Choose a base image (PNG recommended)", type=["png", "jpg", "jpeg"])
    
    if uploaded_file is not None:
        secret_msg = st.text_area("Enter your secret message:")
        
        if st.button("Cast Hiding Spell ✨"):
            if not secret_msg:
                st.error("Please enter a message!")
            else:
                input_img = Image.open(uploaded_file)
                input_img.save("temp_input.png")
                
                engine.encode_lsb("temp_input.png", secret_msg, "secret_output.png")
                st.success("Message hidden successfully!")
                st.image("secret_output.png", caption="Your Stego-Image", width=300)
                
                with open("secret_output.png", "rb") as file:
                    st.download_button(
                        label="Download Stego-Image",
                        data=file,
                        file_name="secret_output.png",
                        mime="image/png"
                    )

with tab2:
    st.header("Reveal a Secret")
    stego_file = st.file_uploader("Upload a Stego-Image", type=["png"], key="decoder_upload")
    
    if stego_file is not None:
       
        st.image(stego_file, caption="Uploaded Stego-Image", width=250)
        
        if st.button("Reveal Message 📜"):
            with st.spinner("Decoding magic..."):
                try:
                    message = engine.decode_lsb(stego_file)
                    
                    if message:
                        st.success("Message Found!")
                        st.code(message, language=None)
                    else:
                        st.warning("No hidden message detected or delimiter missing.")
                except Exception as e:
                    st.error(f"An error occurred: {e}")