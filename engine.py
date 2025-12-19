import numpy as np
from PIL import Image

def msg_to_bin(msg):
    if isinstance(msg, str):
        return ''.join([format(ord(i), "08b") for i in msg])
    elif isinstance(msg, bytes) or isinstance(msg, np.ndarray):
        return [format(i, "08b") for i in msg]
    elif isinstance(msg, int) or isinstance(msg, np.uint8):
        return format(msg, "08b")

def encode_lsb(image_path, secret_msg, output_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = np.array(img)

    secret_msg += "#####" 
    binary_msg = msg_to_bin(secret_msg)
    data_len = len(binary_msg)
    
    idx = 0
    flat_pixels = pixels.flatten()

    for i in range(len(flat_pixels)):
        if idx < data_len:
            flat_pixels[i] = (flat_pixels[i] & 254) | int(binary_msg[idx])
            idx += 1
        else:
            break
            
    new_pixels = flat_pixels.reshape(pixels.shape)
    res_img = Image.fromarray(new_pixels.astype('uint8'), 'RGB')
    res_img.save(output_path)
    print(f"Success! Message hidden in {output_path}")

def decode_lsb(img_input):
    img = Image.open(img_input)
    img = img.convert('RGB')
    pixels = np.array(img).flatten()

    all_bits = (pixels & 1).astype(str)
    binary_str = "".join(all_bits)
    decoded_msg = ""
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) < 8: break
        
        char = chr(int(byte, 2))
        decoded_msg += char
    
        if decoded_msg.endswith("#####"):
            return decoded_msg[:-5]
            
    return "No message found."

if __name__ == "__main__":
    encode_lsb("input.png", "Secret Message", "secret_output.png")
    print("Hidden Message:", decode_lsb("secret_output.png"))
    pass