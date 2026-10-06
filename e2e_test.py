"""End-to-end check: drives ui.html in a real browser through the full
keygen -> encrypt -> store -> decrypt -> wrong-key -> delete cycle.

Run:  python e2e_test.py          (needs: pip install playwright && playwright install chromium)
Exits non-zero on any failure. Leaves the vault as it found it.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.join(HERE, "vault.json")
BACKUP = VAULT + ".e2e-backup"
SECRET = "Rahasia ujian kriptografi 2026 - unicode cek dan teks yang cukup panjang " * 3

checks, failures = [], []


def check(name, cond, detail=""):
    (checks if cond else failures).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  <- {detail}" if detail and not cond else ""))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit("playwright tidak terpasang: pip install playwright && playwright install chromium")

    if os.path.exists(VAULT):
        shutil.copy2(VAULT, BACKUP)

    port = free_port()
    env = {**os.environ, "PORT": str(port), "PYTHONIOENCODING": "utf-8"}
    srv = subprocess.Popen([sys.executable, "server.py"], cwd=HERE, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/api/vault", timeout=1).read()
                break
            except Exception:
                if srv.poll() is not None:
                    sys.exit("server mati saat start:\n" + srv.stderr.read().decode(errors="replace"))
                time.sleep(0.1)
        else:
            sys.exit("server tidak merespons")

        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 950})
            errors = []
            page.on("pageerror", lambda e: errors.append("pageerror: " + str(e)))
            # The suite deliberately provokes HTTP 400s (wrong key, empty input);
            # Chromium logs each as a console error. Those are expected and handled
            # in-app, so filter them out and keep every other console error fatal.
            page.on("console", lambda m: m.type == "error"
                    and "Failed to load resource" not in m.text
                    and errors.append("console: " + m.text))
            page.goto(base, wait_until="load")

            # --- first viewport communicates the workflow -------------------
            check("judul halaman benar", "RSA Vault" in page.title())
            check("tiga panel alur terlihat", page.locator("section").count() == 3)
            check("vault mulai kosong atau terisi rapi",
                  page.locator("#vault .empty, #vault .entry").count() >= 1)
            # [hidden] must actually hide: display:grid rules once beat the UA rule
            check("panel kunci tersembunyi sebelum keygen", page.locator("#kg-keys").is_hidden())
            check("parameter tersembunyi sebelum keygen", page.locator("#kg-params").is_hidden())
            check("input berkas tersembunyi di mode teks", page.locator("#w-file").is_hidden())

            # --- 01 keygen --------------------------------------------------
            page.select_option("#bits", "512")
            page.click("#kg")
            page.wait_for_selector("#kg-keys:not([hidden])", timeout=60_000)
            check("keycard publik & privat tampil", page.locator(".keycard").count() == 2)
            check("glyph sidik kunci tergambar", page.locator("#gl-pub i").count() == 25)
            check("enam parameter matematis tampil", page.locator("#kg-params .param").count() == 6)
            check("toast sukses keygen muncul", page.locator(".toast.ok").count() >= 1)

            n = page.input_value("#e-n")
            check("modulus terisi otomatis ke form enkripsi", n.isdigit() and len(n) > 100,
                  f"n={n[:24]} len={len(n)}")

            # verify p*q == n and e*d == 1 mod phi, read straight off the screen
            vals = {}
            for row in page.locator("#kg-params .param").all():
                vals[row.locator("em").inner_text()] = int(row.locator("dd").inner_text())
            check("p x q == n (terlihat di UI)", vals["p"] * vals["q"] == vals["n"])
            check("e x d == 1 mod phi(n)", vals["e"] * vals["d"] % vals["phi(n)"] == 1)

            # --- 02 encrypt -------------------------------------------------
            page.fill("#label", "catatan ujian")
            page.fill("#plain", SECRET)
            page.click("#enc")
            page.wait_for_selector("#enc-out .out", timeout=30_000)
            tape = page.inner_text("#enc-out .formula")
            check("math tape menampilkan C = M^e mod n", "mod" in tape and "^" in tape, tape[:70])
            check("ciphertext pratinjau tampil", len(page.inner_text("#enc-out pre")) > 40)
            check("entri masuk ke vault", page.locator("#vault .entry").count() >= 1)
            check("entri terpilih otomatis",
                  page.locator('#vault .entry[aria-current="true"]').count() == 1)
            check("tombol dekripsi aktif", page.is_enabled("#dec"))
            check("plainteks dibersihkan dari form", page.input_value("#plain") == "")

            # --- tab switching actually swaps the visible input --------------
            page.click("#tab-file")
            check("mode berkas menampilkan input berkas", page.locator("#w-file").is_visible())
            check("mode berkas menyembunyikan textarea", page.locator("#w-text").is_hidden())
            page.click("#tab-text")
            check("kembali ke mode teks", page.locator("#w-text").is_visible()
                  and page.locator("#w-file").is_hidden())

            # --- wrong key must be rejected, not silently wrong -------------
            page.fill("#d-d", "3")
            page.click("#dec")
            page.wait_for_selector("#dec-out .err", timeout=30_000)
            check("kunci privat salah ditolak dengan pesan jelas",
                  len(page.inner_text("#dec-out .err")) > 10,
                  page.inner_text("#dec-out .err"))

            # --- mismatched modulus bit-length rejected ---------------------
            page.fill("#d-n", "15")
            page.click("#dec")
            page.wait_for_selector("#dec-out .err", timeout=30_000)
            check("modulus beda ukuran ditolak",
                  "bit" in page.inner_text("#dec-out .err").lower(),
                  page.inner_text("#dec-out .err"))

            # --- 03 decrypt with the real key -------------------------------
            page.click('[data-use="dec"]')
            page.click("#dec")
            page.wait_for_selector("#dec-out .out", timeout=30_000)
            got = page.inner_text("#dec-out pre")
            check("plainteks pulih persis sama", got == SECRET,
                  f"len {len(got)} vs {len(SECRET)}")

            # --- empty input validated --------------------------------------
            page.fill("#plain", "   ")
            page.click("#enc")
            page.wait_for_selector("#enc-out .err", timeout=10_000)
            check("teks kosong ditolak", "Tidak ada teks" in page.inner_text("#enc-out .err"))

            # --- responsive: no horizontal overflow on a phone --------------
            for w, h, name in ((1440, 950, "desktop"), (390, 844, "ponsel")):
                page.set_viewport_size({"width": w, "height": h})
                page.wait_for_timeout(260)
                over = page.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")
                check(f"tanpa scroll horizontal di {name} ({w}px)", over <= 1, f"lebih {over}px")
            page.set_viewport_size({"width": 1440, "height": 950})

            # --- cleanup through the UI (also tests delete) ------------------
            page.locator("#vault .entry").first.click()
            page.once("dialog", lambda d: d.accept())
            page.click("#del")
            page.wait_for_timeout(600)
            check("entri terhapus lewat UI", page.locator("#vault .entry").count() == 0
                  or page.locator("#vault .empty").count() == 1)

            check("tanpa error JavaScript", not errors, "; ".join(errors[:3]))

            page.screenshot(path=os.path.join(HERE, "ui-screenshot.png"), full_page=True)
            print("\n  screenshot -> ui-screenshot.png")
            browser.close()
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
        if os.path.exists(BACKUP):
            os.replace(BACKUP, VAULT)
        elif os.path.exists(VAULT) and json.load(open(VAULT, encoding="utf-8")) == []:
            os.remove(VAULT)

    print(f"\n{len(checks)} lulus, {len(failures)} gagal")
    if failures:
        print("gagal: " + ", ".join(failures))
        sys.exit(1)
    print("Semua pemeriksaan end-to-end lulus.")


if __name__ == "__main__":
    main()
