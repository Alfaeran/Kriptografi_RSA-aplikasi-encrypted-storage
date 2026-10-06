import os
import rsa

def text_to_hex(text):
    """
    Mengubah teks (string) menjadi format heksadesimal.
    Contoh: 'halo' -> '68616c6f'
    """
    return text.encode('utf-8').hex()

def hex_to_text(hex_str):
    """
    Mengubah format heksadesimal kembali menjadi teks (string).
    """
    # Jika panjang string ganjil, tambahkan '0' di depan agar valid diproses sebagai bytes
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str).decode('utf-8')

def encrypt_message(pubkey, message):
    """
    Mengenkripsi pesan teks menggunakan kunci publik RSA.
    """
    n, e = pubkey
    hex_message = text_to_hex(message)
    
    # Validasi: Nilai pesan (M) dalam RSA harus lebih kecil dari modulus n
    m = int(hex_message, 16)
    if m >= n:
        raise ValueError("Pesan terlalu panjang untuk ukuran kunci RSA ini (M harus < n).")
    
    # Enkripsi menggunakan rsa.py
    ciphertext_hex = rsa.encrypt(pubkey, hex_message)
    return ciphertext_hex

def decrypt_message(privkey, ciphertext_hex):
    """
    Mendekripsi ciphertext heksadesimal kembali ke teks asli menggunakan kunci privat RSA.
    """
    # Dekripsi menggunakan rsa.py
    decrypted_hex = rsa.decrypt(privkey, ciphertext_hex)
    
    # Kembalikan ke teks asli
    return hex_to_text(decrypted_hex)

def save_to_storage(filename, content):
    """
    Menyimpan data (misal ciphertext) ke file penyimpanan (encrypted storage).
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"[Storage] Berhasil menyimpan data ke file: '{filename}'")

def load_from_storage(filename):
    """
    Membaca data dari file penyimpanan (encrypted storage).
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File '{filename}' tidak ditemukan.")
    
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    print(f"[Storage] Berhasil membaca data dari file: '{filename}'")
    return content
