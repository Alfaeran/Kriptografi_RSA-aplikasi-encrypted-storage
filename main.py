import rsa
import storage

def main():
    print("=" * 60)
    print("      DEMONSTRASI ALGORITMA RSA - ENCRYPTED STORAGE       ")
    print("=" * 60)

    print("\n[1] TAHAP KEY GENERATION")
    print("-" * 60)
    
    key_size = 512
    print(f"[*] Menghasilkan pasangan kunci ({key_size} bit)...")
    
    pubkey, privkey = rsa.generate_rsa_key(key_size)
    n, e = pubkey
    _, d = privkey

    print(f"[+] Modulus (n)             : {n}")
    print(f"[+] Public Exponent (e)     : {e}")
    print(f"[+] Private Exponent (d)    : {d}")
    print(f"\n-> Public Key  (n, e)       : ({n}, {e})")
    print(f"-> Private Key (n, d)       : ({n}, {d})")


    print("\n[2] TAHAP ENKRIPSI & PENYIMPANAN KE STORAGE")
    print("-" * 60)
    
    message = input("Masukkan pesan yang ingin disimpan: ").strip()
    print(f"\n[*] Pesan Asli (Plaintext) : \"{message}\"")

    hex_msg = storage.text_to_hex(message)
    int_msg = int(hex_msg, 16)
    print(f"[*] Plaintext (Hex)         : {hex_msg}")
    print(f"[*] Nilai Integer Pesan (M) : {int_msg}")

    ciphertext_hex = storage.encrypt_message(pubkey, message)
    print(f"\n[+] Rumus Enkripsi          : C = M^e mod n")
    print(f"[+] Ciphertext (Hex)        : {ciphertext_hex}")

    storage_file = "vault.enc"
    storage.save_to_storage(storage_file, ciphertext_hex)


    print("\n[3] TAHAP MEMBACA DARI STORAGE & DEKRIPSI")
    print("-" * 60)
    
    loaded_ciphertext = storage.load_from_storage(storage_file)
    print(f"[*] Ciphertext terbaca      : {loaded_ciphertext}")

    decrypted_message = storage.decrypt_message(privkey, loaded_ciphertext)
    
    decrypted_hex = storage.text_to_hex(decrypted_message)
    decrypted_int = int(decrypted_hex, 16)

    print(f"\n[+] Rumus Dekripsi          : M = C^d mod n")
    print(f"[+] Nilai Integer Hasil (M) : {decrypted_int}")
    print(f"[+] Plaintext (Hex)         : {decrypted_hex}")
    print(f"[+] Pesan Hasil Dekripsi    : \"{decrypted_message}\"")

    print("\n" + "-" * 60)
    if message == decrypted_message:
        print("[✓] VERIFIKASI BERHASIL: Pesan hasil dekripsi PERSIS SAMA dengan aslinya!")
    else:
        print("[X] VERIFIKASI GAGAL: Pesan berbeda!")
    print("=" * 60)

if __name__ == "__main__":
    main()
