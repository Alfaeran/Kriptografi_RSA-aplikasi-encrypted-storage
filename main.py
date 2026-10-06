"""
Program Demonstrasi Implementasi RSA - Encrypted Storage
Tema: Aplikasi Encrypted Storage
Kriptografi Semester 5

Menampilkan setiap tahapan RSA secara transparan:
1. Pembangkitan Kunci (Key Generation)
2. Enkripsi dan Penyimpanan ke Storage (Encryption & Storage)
3. Pembacaan dari Storage dan Dekripsi (Retrieval & Decryption)
"""

import rsa
import storage

def main():
    print("=" * 60)
    print("      DEMONSTRASI ALGORITMA RSA - ENCRYPTED STORAGE       ")
    print("=" * 60)

    # -------------------------------------------------------------
    # TAHAP 1: PEMBANGKITAN KUNCI (KEY GENERATION)
    # -------------------------------------------------------------
    print("\n[1] TAHAP PEMBANGKITAN KUNCI (KEY GENERATION)")
    print("-" * 60)
    
    # Ukuran bit untuk RSA (512 bit cukup aman dan cepat untuk demonstrasi)
    key_size = 512
    print(f"[*] Menghasilkan pasangan kunci ({key_size} bit)...")
    
    # Panggil fungsi generate_rsa_key dari rsa.py
    pubkey, privkey = rsa.generate_rsa_key(key_size)
    n, e = pubkey
    _, d = privkey

    print(f"[+] Modulus (n)             : {n}")
    print(f"[+] Public Exponent (e)     : {e}")
    print(f"[+] Private Exponent (d)    : {d}")
    print(f"\n-> Public Key  (n, e)       : ({n}, {e})")
    print(f"-> Private Key (n, d)       : ({n}, {d})")

    # -------------------------------------------------------------
    # TAHAP 2: ENKRIPSI & SIMPAN KE STORAGE
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print("[2] TAHAP ENKRIPSI & PENYIMPANAN KE STORAGE")
    print("-" * 60)
    
    # Input pesan dari pengguna
    default_message = "Data Rahasia: Password123!"
    prompt_text = f"Masukkan pesan yang ingin disimpan [Default: '{default_message}']: "
    user_input = input(prompt_text).strip()
    
    message = user_input if user_input else default_message
    print(f"\n[*] Pesan Asli (Plaintext) : \"{message}\"")

    # Representasi teks ke Hex & Integer
    hex_msg = storage.text_to_hex(message)
    int_msg = int(hex_msg, 16)
    print(f"[*] Plaintext (Hex)         : {hex_msg}")
    print(f"[*] Nilai Integer Pesan (M) : {int_msg}")

    # Proses Enkripsi: C = M^e mod n
    ciphertext_hex = storage.encrypt_message(pubkey, message)
    print(f"\n[+] Rumus Enkripsi          : C = M^e mod n")
    print(f"[+] Ciphertext (Hex)        : {ciphertext_hex}")

    # Simpan ke file storage
    storage_file = "vault.enc"
    storage.save_to_storage(storage_file, ciphertext_hex)

    # -------------------------------------------------------------
    # TAHAP 3: BACA DARI STORAGE & DEKRIPSI
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print("[3] TAHAP MEMBACA DARI STORAGE & DEKRIPSI")
    print("-" * 60)
    
    # Baca ciphertext dari storage
    loaded_ciphertext = storage.load_from_storage(storage_file)
    print(f"[*] Ciphertext terbaca      : {loaded_ciphertext}")

    # Proses Dekripsi: M = C^d mod n
    decrypted_message = storage.decrypt_message(privkey, loaded_ciphertext)
    
    # Ambil nilai integer dan hex hasil dekripsi untuk ditampilkan
    decrypted_hex = storage.text_to_hex(decrypted_message)
    decrypted_int = int(decrypted_hex, 16)

    print(f"\n[+] Rumus Dekripsi          : M = C^d mod n")
    print(f"[+] Nilai Integer Hasil (M) : {decrypted_int}")
    print(f"[+] Plaintext (Hex)         : {decrypted_hex}")
    print(f"[+] Pesan Hasil Dekripsi    : \"{decrypted_message}\"")

    # Verifikasi Integritas
    print("\n" + "-" * 60)
    if message == decrypted_message:
        print("[✓] VERIFIKASI BERHASIL: Pesan hasil dekripsi PERSIS SAMA dengan aslinya!")
    else:
        print("[X] VERIFIKASI GAGAL: Pesan berbeda!")
    print("=" * 60)

if __name__ == "__main__":
    main()
