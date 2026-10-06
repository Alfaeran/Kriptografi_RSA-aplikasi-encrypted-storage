import os
import rsa

def text_to_hex(text):
    return text.encode('utf-8').hex()

def hex_to_text(hex_str):
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str).decode('utf-8')

def encrypt_message(pubkey, message):
    n, e = pubkey
    hex_message = text_to_hex(message)
    
    m = int(hex_message, 16)
    if m >= n:
        raise ValueError("Pesan terlalu panjang untuk ukuran kunci RSA ini (M harus < n).")
    
    ciphertext_hex = rsa.encrypt(pubkey, hex_message)
    return ciphertext_hex

def decrypt_message(privkey, ciphertext_hex):
    decrypted_hex = rsa.decrypt(privkey, ciphertext_hex)
    return hex_to_text(decrypted_hex)

def save_to_storage(filename, content):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"[Storage] Berhasil menyimpan data ke file: '{filename}'")

def load_from_storage(filename):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File '{filename}' tidak ditemukan.")
    
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    print(f"[Storage] Berhasil membaca data dari file: '{filename}'")
    return content
