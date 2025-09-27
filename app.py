from flask import Flask, request, render_template, send_file
from io import BytesIO
import json
import os
from PIL import Image
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Encryption helper functions
def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key: bytes, iv_ciphertext: bytes) -> bytes:
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# LSB steganography helper functions
def set_bit(value, bit):
    return value | (1 << bit)

def clear_bit(value, bit):
    return value & ~(1 << bit)

def set_lsb(value, bit_value):
    if bit_value == 1:
        return set_bit(value, 0)
    else:
        return clear_bit(value, 0)

def embed_data_in_image(image: Image.Image, data: bytes) -> Image.Image:
    data_length = len(data)
    length_bytes = data_length.to_bytes(4, byteorder='big')
    full_data = length_bytes + data
    pixels = image.load()
    width, height = image.size
    bit_idx = 0
    for y in range(height):
        for x in range(width):
            if bit_idx >= len(full_data) * 8:
                return image
            pixel = list(pixels[x, y])
            for channel in range(3):
                if bit_idx >= len(full_data) * 8:
                    break
                byte_idx = bit_idx // 8
                bit_in_byte = 7 - (bit_idx % 8)
                bit_val = (full_data[byte_idx] >> bit_in_byte) & 1
                pixel[channel] = set_lsb(pixel[channel], bit_val)
                bit_idx += 1
            pixels[x, y] = tuple(pixel)
    return image

def extract_data_from_image(image: Image.Image) -> bytes:
    pixels = image.load()
    width, height = image.size
    bits = []
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            for channel in range(3):
                bits.append(pixel[channel] & 1)
    length_bits = bits[:32]
    data_length = 0
    for bit in length_bits:
        data_length = (data_length << 1) | bit
    data_bits = bits[32:32 + data_length * 8]
    data_bytes = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | data_bits[i + j]
        data_bytes.append(byte)
    return bytes(data_bytes)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        mode = request.form.get('mode')
        key = request.form.get('key')
        salt = b'static_salt_1234'

        if mode == 'encrypt':
            image_file = request.files['image']
            url = request.form.get('url')
            username = request.form.get('username')
            password = request.form.get('password')

            image = Image.open(image_file).convert('RGB')
            data_dict = {'url': url, 'username': username, 'password': password}
            json_data = json.dumps(data_dict).encode('utf-8')
            derived_key = derive_key(key.encode('utf-8'), salt)
            encrypted_data = aes_encrypt(derived_key, json_data)
            stego_image = embed_data_in_image(image, encrypted_data)

            img_io = BytesIO()
            stego_image.save(img_io, 'PNG')
            img_io.seek(0)
            return send_file(img_io, mimetype='image/png', as_attachment=True, download_name='stego_image.png')

        elif mode == 'decrypt':
            image_file = request.files['image']
            image = Image.open(image_file).convert('RGB')
            derived_key = derive_key(key.encode('utf-8'), salt)
            encrypted_data = extract_data_from_image(image)
            try:
                decrypted_data = aes_decrypt(derived_key, encrypted_data)
                data_dict = json.loads(decrypted_data.decode('utf-8'))
                return render_template('index.html', decrypted=data_dict)
            except Exception:
                return render_template('index.html', error='Decryption failed: Invalid key or corrupted image.')

    return render_template('index.html')
    
if __name__ == '__main__':
    app.run(debug=True)
