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


# ---- Chunked block mode (needed for messages/files larger than one RSA block) ----

def block_size(n):
    """Max plaintext bytes per block so that every block value stays < n."""
    size = (n.bit_length() - 1) // 8
    if size < 1:
        raise ValueError("Ukuran kunci terlalu kecil untuk menyimpan data.")
    return size


def encrypt_bytes(pubkey, data: bytes) -> str:
    """Encrypt arbitrary bytes as ':'-joined hex blocks."""
    n, _ = pubkey
    size = block_size(n)
    blocks = []
    for i in range(0, len(data), size):
        chunk = data[i:i + size]
        # 0x01 prefix preserves leading zero bytes through the int round-trip
        blocks.append(rsa.encrypt(pubkey, (b"\x01" + chunk).hex()))
    return ":".join(blocks)


def decrypt_bytes(privkey, ciphertext: str) -> bytes:
    """Inverse of encrypt_bytes."""
    out = bytearray()
    for block in ciphertext.strip().split(":"):
        if not block:
            continue
        h = rsa.decrypt(privkey, block)
        if len(h) % 2:
            h = "0" + h
        raw = bytes.fromhex(h)
        if not raw or raw[0] != 1:
            raise ValueError("Kunci privat tidak cocok dengan ciphertext ini.")
        out += raw[1:]
    return bytes(out)
