# Kriptografi_RSA-aplikasi-encrypted-storage

Implementasi RSA dari nol (tanpa pustaka kriptografi) beserta antarmuka web untuk
membangkitkan kunci, mengenkripsi data, menyimpan ciphertext, dan mendekripsinya kembali.

## Menjalankan

```bash
python server.py          # buka http://127.0.0.1:8765
python main.py            # versi CLI (demo satu siklus)
python e2e_test.py        # uji end-to-end di peramban (butuh playwright)
```

`e2e_test.py` memerlukan sekali persiapan:

```bash
pip install playwright && playwright install chromium
```

## Berkas

| Berkas | Isi |
|---|---|
| `rsa.py` | Miller-Rabin, pembangkitan prima, `generate_rsa_key_parts`, `encrypt`, `decrypt` |
| `storage.py` | konversi teks/hex, mode blok (`encrypt_bytes` / `decrypt_bytes`), baca-tulis berkas |
| `server.py` | server HTTP pustaka-standar; menyajikan `ui.html` dan REST API |
| `ui.html` | antarmuka tiga panel: Key Bench, Enkripsi & Simpan, Vault & Dekripsi |
| `main.py` | demonstrasi CLI alur lengkap |
| `e2e_test.py` | 30 pemeriksaan end-to-end lewat Chromium |
| `vault.json` | penyimpanan ciphertext (dibuat otomatis) |

## Catatan keamanan

Ini adalah **RSA buku teks** untuk keperluan pembelajaran, bukan untuk melindungi data nyata:

- Tanpa padding (OAEP/PKCS#1). RSA tanpa padding bersifat deterministik - plainteks yang
  sama selalu menghasilkan ciphertext yang sama, sehingga rentan terhadap analisis.
- Setiap blok dienkripsi sendiri-sendiri (mode mirip ECB), jadi pola dalam data panjang
  masih terlihat pada ciphertext.
- Kunci privat **tidak pernah ditulis ke disk** - hanya ada di layar dan di memori peramban.
  Pengguna wajib menyimpannya sendiri; `vault.json` hanya memuat ciphertext dan parameter publik.
- Server hanya mengikat `127.0.0.1` dan tidak terbuka ke jaringan.

Untuk penggunaan nyata, pakai `cryptography` dengan RSA-OAEP, atau enkripsi hibrida
(AES-GCM untuk data, RSA untuk kunci AES).
