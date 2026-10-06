"""Matrix test: every entry situation x every key size, encrypt and decrypt.

For each key size (256/512/1024/2048) this generates a fresh keypair and runs
the full scenario list: normal payloads, boundary sizes around the RSA block,
binary and unicode content, wrong keys, swapped keys, corrupted ciphertext,
and the vault lifecycle.

Runs against its own server on a free port with a throwaway vault, so the
real vault.json is never touched.

Run:  python matrix_test.py            (all sizes)
      python matrix_test.py 256 512    (only these sizes)
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE) if os.path.basename(HERE) == "test" else HERE
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import rsa
import storage

ALL_SIZES = (256, 512, 1024, 2048)

rows = []            # (size, scenario, ok, detail)
port = None
VAULT_PATH = None


def post(path, body):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=120)), 200
    except urllib.error.HTTPError as exc:
        return json.load(exc), exc.code


def vault_list():
    return json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/vault"))


def enc(pub, data, filename="uji.bin", label=""):
    return post("/api/encrypt", {"n": pub["n"], "e": pub["e"], "label": label,
                                 "filename": filename,
                                 "data": base64.b64encode(data).decode()})


def dec(n, d, entry_id):
    return post("/api/decrypt", {"n": n, "d": d, "id": entry_id})


def record(size, scenario, ok, detail=""):
    rows.append((size, scenario, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  [{size:>4}] {scenario}"
          + (f"   <- {detail}" if detail and not ok else ""))


def roundtrip(size, k, scenario, payload, filename="uji.bin"):
    """Encrypt then decrypt a payload; assert the bytes survive exactly."""
    e, code = enc(k, payload, filename)
    if code != 200:
        record(size, scenario, False, f"enkripsi ditolak: {e.get('error')}")
        return None
    d, code = dec(k["n"], k["d"], e["id"])
    if code != 200:
        record(size, scenario, False, f"dekripsi ditolak: {d.get('error')}")
        return None
    got = base64.b64decode(d["data"])
    record(size, scenario, got == payload, f"{len(got)} byte vs {len(payload)} byte")
    return e


def run_size(size):
    print(f"\n=== kunci {size} bit " + "=" * 42)
    t0 = time.perf_counter()
    k, code = post("/api/keygen", {"bits": size})
    if code != 200:
        return record(size, "keygen", False, k.get("error"))
    record(size, f"keygen ({round((time.perf_counter() - t0) * 1000)} ms)", True)

    n_i, e_i, d_i = int(k["n"]), int(k["e"]), int(k["d"])
    block = storage.block_size(n_i)
    record(size, f"blok {block} byte, n = {n_i.bit_length()} bit",
           n_i.bit_length() == size and block >= 1)

    # --- key material is mathematically sound --------------------------
    p, q, phi = int(k["p"]), int(k["q"]), int(k["phi"])
    record(size, "p x q == n", p * q == n_i)
    record(size, "e x d == 1 mod phi(n)", e_i * d_i % phi == 1)
    record(size, "p dan q berbeda", p != q)
    record(size, "p dan q prima", rsa.is_prime(p) and rsa.is_prime(q))

    # --- payload situations, including block boundaries -----------------
    roundtrip(size, k, "payload 1 byte", b"A")
    roundtrip(size, k, f"tepat 1 blok penuh ({block} B)", b"Z" * block)
    roundtrip(size, k, f"1 blok + 1 byte ({block + 1} B)", b"Z" * (block + 1))
    roundtrip(size, k, f"tepat 2 blok ({block * 2} B)", b"Z" * (block * 2))
    roundtrip(size, k, "null byte di awal", b"\x00\x00\x00data")
    roundtrip(size, k, "semua nilai byte 0-255", bytes(range(256)))
    roundtrip(size, k, "teks unicode", "Rahasia ujian - unicode cek - ok".encode("utf-8"))
    roundtrip(size, k, "payload 4 KB", os.urandom(4096))
    roundtrip(size, k, "nama berkas unicode", b"isi", "laporan akhir.pdf")

    # --- label behaviour -------------------------------------------------
    e1, _ = enc(k, b"x", "tanpa-label.bin", "")
    record(size, "label kosong jatuh ke nama berkas", e1.get("label") == "tanpa-label.bin",
           str(e1.get("label")))
    e2, _ = enc(k, b"x", "a.bin", "L" * 200)
    record(size, "label sangat panjang dipotong ke 80", len(e2.get("label", "")) == 80,
           str(len(e2.get("label", ""))))

    # --- rejected inputs --------------------------------------------------
    r, code = enc(k, b"", "kosong.bin")
    record(size, "berkas kosong ditolak", code == 400 and "kosong" in r.get("error", ""),
           f"{code} {r.get('error')}")
    r, code = post("/api/encrypt", {"n": k["n"], "e": k["e"], "data": "aGk="})
    record(size, "tanpa nama berkas ditolak", code == 400 and "wajib" in r.get("error", ""),
           f"{code} {r.get('error')}")
    r, code = post("/api/encrypt", {"n": k["n"], "e": k["e"],
                                    "data": "!!bukan-base64!!", "filename": "x.bin"})
    record(size, "base64 rusak ditolak", code == 400 and "base64" in r.get("error", ""),
           f"{code} {r.get('error')}")
    r, code = post("/api/encrypt", {"n": "abc", "e": k["e"], "data": "aGk=", "filename": "x"})
    record(size, "modulus bukan angka ditolak", code == 400, f"{code} {r.get('error')}")

    # --- wrong-key situations: must error, never return wrong plaintext ---
    good = roundtrip(size, k, "entri referensi untuk uji kunci salah", b"rahasia penting")
    if good:
        r, code = dec(k["n"], "3", good["id"])
        record(size, "d salah ditolak", code == 400, f"{code} {r.get('error')}")

        other, _ = post("/api/keygen", {"bits": size})
        r, code = dec(k["n"], other["d"], good["id"])
        record(size, "d dari kunci lain ditolak", code == 400, f"{code} {r.get('error')}")

        r, code = dec(other["n"], other["d"], good["id"])
        record(size, "pasangan kunci lain sepenuhnya ditolak", code == 400,
               f"{code} {r.get('error')}")

        r, code = dec(k["n"], k["e"], good["id"])
        record(size, "e dipakai sebagai d ditolak", code == 400, f"{code} {r.get('error')}")

        # a different key SIZE must be caught by the bit-length guard
        small = 256 if size != 256 else 512
        o2, _ = post("/api/keygen", {"bits": small})
        r, code = dec(o2["n"], o2["d"], good["id"])
        record(size, f"kunci {small} bit pada entri {size} bit ditolak",
               code == 400 and "bit" in r.get("error", "").lower(),
               f"{code} {r.get('error')}")

        r, code = dec(k["n"], k["d"], "id-tidak-ada")
        record(size, "id entri tidak dikenal ditolak", code == 400, f"{code} {r.get('error')}")

        # the right key must still work after all those rejections
        r, code = dec(k["n"], k["d"], good["id"])
        record(size, "kunci benar tetap berhasil setelah percobaan salah",
               code == 200 and base64.b64decode(r["data"]) == b"rahasia penting")

    # --- corrupted ciphertext on disk is detected ------------------------
    bad = roundtrip(size, k, "entri referensi untuk uji korupsi", b"data utuh")
    if bad:
        store = json.load(open(VAULT_PATH, encoding="utf-8"))
        for row in store:
            if row["id"] == bad["id"]:
                row["ciphertext"] = "zzzz:" + row["ciphertext"]
        with open(VAULT_PATH, "w", encoding="utf-8") as f:
            json.dump(store, f)
        r, code = dec(k["n"], k["d"], bad["id"])
        record(size, "ciphertext rusak terdeteksi", code == 400, f"{code} {r.get('error')}")

    # --- determinism: textbook RSA has no padding, so this MUST hold -----
    a, _ = enc(k, b"pesan sama", "a.bin")
    b, _ = enc(k, b"pesan sama", "b.bin")
    store = {x["id"]: x for x in json.load(open(VAULT_PATH, encoding="utf-8"))}
    record(size, "RSA tanpa padding bersifat deterministik (kelemahan terdokumentasi)",
           store[a["id"]]["ciphertext"] == store[b["id"]]["ciphertext"])

    # --- vault lifecycle --------------------------------------------------
    listed = vault_list()
    record(size, "ciphertext tidak pernah dikirim ke daftar vault",
           all("ciphertext" not in x for x in listed["entries"]))
    record(size, "metadata entri lengkap",
           all({"id", "label", "kind", "bits", "blocks", "created", "glyph"} <= set(x)
               for x in listed["entries"]))
    record(size, "semua entri baru bertipe file",
           all(x["kind"] == "file" for x in listed["entries"]))

    r, code = post("/api/delete", {"id": a["id"]})
    record(size, "hapus entri berhasil", code == 200 and r.get("ok"))
    r, code = post("/api/delete", {"id": a["id"]})
    record(size, "hapus dua kali ditolak", code == 400, f"{code} {r.get('error')}")
    r, code = dec(k["n"], k["d"], a["id"])
    record(size, "entri terhapus tidak bisa didekripsi", code == 400)

    # --- clear the vault between sizes so counts stay meaningful ----------
    for row in json.load(open(VAULT_PATH, encoding="utf-8")):
        post("/api/delete", {"id": row["id"]})


def main():
    global port, VAULT_PATH
    sizes = [int(a) for a in sys.argv[1:]] or list(ALL_SIZES)
    unsupported = [s for s in sizes if s not in ALL_SIZES]
    if unsupported:
        sys.exit(f"ukuran kunci tidak didukung: {unsupported}; pilih dari {list(ALL_SIZES)}")

    tmp = tempfile.mkdtemp(prefix="rsavault-matrix-")
    VAULT_PATH = os.path.join(tmp, "vault.json")

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    env = {**os.environ, "PORT": str(port), "VAULT_FILE": VAULT_PATH,
           "PYTHONIOENCODING": "utf-8"}
    srv = subprocess.Popen([sys.executable, "server.py"], cwd=ROOT, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/vault", timeout=1).read()
                break
            except Exception:
                if srv.poll() is not None:
                    sys.exit("server mati:\n" + srv.stderr.read().decode(errors="replace"))
                time.sleep(0.1)
        else:
            sys.exit("server tidak merespons")

        print(f"vault uji : {VAULT_PATH}")
        print("vault asli: TIDAK tersentuh")
        for size in sizes:
            run_size(size)
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 62)
    for size in sizes:
        got = [r for r in rows if r[0] == size]
        bad_ = [r for r in got if not r[2]]
        print(f"  {size:>4} bit : {len(got) - len(bad_):>2}/{len(got)} lulus"
              + (f"   GAGAL: {', '.join(r[1] for r in bad_)}" if bad_ else ""))
    failed = [r for r in rows if not r[2]]
    print("=" * 62)
    print(f"total {len(rows) - len(failed)}/{len(rows)} lulus")
    if failed:
        sys.exit(1)
    print("Semua situasi entri lulus untuk setiap ukuran kunci.")


if __name__ == "__main__":
    main()
