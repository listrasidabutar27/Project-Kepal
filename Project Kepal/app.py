from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)

# Fungsi untuk menyesuaikan panjang kunci
def adjust_key(key, length=16):
    if len(key) < length:
        key += b' ' * (length - len(key))  # Padding jika kunci terlalu pendek
    elif len(key) > length:
        key = key[:length]  # Potong kunci jika terlalu panjang
    return key

# Membuat kunci dan IV
raw_key = b'mykunci123456789'
key = adjust_key(raw_key, 16)  # Sesuaikan panjang kunci menjadi 16 byte
iv = os.urandom(16)  # IV acak sepanjang 16 byte

# Fungsi enkripsi
def encrypt_aes(plaintext, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Convert ciphertext to hexadecimal format
    hex_ciphertext = ciphertext.hex()  # Mengonversi ciphertext ke format hex
    return hex_ciphertext

# Fungsi dekripsi
def decrypt_aes(ciphertext_hex, key, iv):
    ciphertext = bytes.fromhex(ciphertext_hex)  # Konversi dari hex ke biner
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode()

# Halaman Dashboard
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# Halaman Encrypt
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_page():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            plaintext = file.read().decode()
            ciphertext_hex = encrypt_aes(plaintext, key, iv)
            encrypted_file_path = 'encrypted_file.txt'
            # Simpan ciphertext dalam format hexadecimal
            with open(encrypted_file_path, 'w') as encrypted_file:
                encrypted_file.write(ciphertext_hex)  # Menyimpan ciphertext dalam format hex
            return send_file(encrypted_file_path, as_attachment=True)
    return render_template('encrypt.html')

# Halaman Decrypt
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_page():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            ciphertext_hex = file.read().decode()  # Membaca file dalam bentuk hex
            decrypted_text = decrypt_aes(ciphertext_hex, key, iv)
            decrypted_file_path = 'decrypted_file.txt'
            with open(decrypted_file_path, 'w') as decrypted_file:
                decrypted_file.write(decrypted_text)
            return send_file(decrypted_file_path, as_attachment=True)
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)
