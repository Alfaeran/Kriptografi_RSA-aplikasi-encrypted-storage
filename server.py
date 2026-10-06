"""Local HTTP server for the RSA encrypted-storage UI.

Stdlib only. Binds to 127.0.0.1 - the vault is never exposed to the network.
Private keys are NEVER written to disk: the user holds them and pastes one back
to decrypt. Only ciphertext and public parameters are persisted.
"""
import base64
import json
import os
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import rsa
import storage

HERE = os.path.dirname(os.path.abspath(__file__))
# VAULT_FILE lets tests point at a throwaway vault instead of the real one
VAULT = os.environ.get("VAULT_FILE") or os.path.join(HERE, "vault.json")
MAX_BODY = 8 * 1024 * 1024          # 8 MiB request cap
KEY_SIZES = (256, 512, 1024, 2048)  # offered bit lengths
HEX_RE = re.compile(r"\A[0-9a-fA-F]+(:[0-9a-fA-F]+)*\Z")


def load_vault():
    try:
        with open(VAULT, encoding="utf-8") as f:
            entries = json.load(f)
        return entries if isinstance(entries, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_vault(entries):
    tmp = VAULT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    os.replace(tmp, VAULT)  # atomic: a crash mid-write cannot truncate the vault


def fingerprint(n):
    """Deterministic 25-bit visual glyph for a modulus, so a user can eyeball
    whether a pasted key belongs to an entry without revealing the key."""
    h = n % (1 << 25)
    return [bool(h >> i & 1) for i in range(25)]


def big_int(raw, field):
    try:
        v = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{field} harus berupa bilangan bulat.")
    if v < 2:
        raise ValueError(f"{field} tidak valid (harus >= 2).")
    return v


class Handler(BaseHTTPRequestHandler):
    server_version = "RSAVault"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path}")

    # ---- plumbing -------------------------------------------------------
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        blob = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(blob)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("Data terlalu besar (maksimum 8 MB).")
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            raise ValueError("Body permintaan bukan JSON yang valid.")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "ui.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if self.path == "/api/vault":
            entries = [
                {k: v for k, v in e.items() if k != "ciphertext"} for e in load_vault()
            ]
            return self._send(200, {"entries": entries[::-1], "sizes": KEY_SIZES})
        self._send(404, {"error": "Tidak ditemukan."})

    def do_POST(self):
        route = {
            "/api/keygen": self.keygen,
            "/api/encrypt": self.encrypt,
            "/api/decrypt": self.decrypt,
            "/api/delete": self.drop_entry,
        }.get(self.path)
        if not route:
            return self._send(404, {"error": "Tidak ditemukan."})
        try:
            self._send(200, route(self._body()))
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:  # unexpected: report, never leak a stack trace
            self._send(500, {"error": f"Kesalahan internal: {type(exc).__name__}"})

    # ---- endpoints ------------------------------------------------------
    def keygen(self, req):
        bits = req.get("bits")
        if bits not in KEY_SIZES:
            raise ValueError(f"Panjang kunci harus salah satu dari {list(KEY_SIZES)}.")
        t0 = time.perf_counter()
        k = rsa.generate_rsa_key_parts(bits)
        return {
            **{key: str(val) for key, val in k.items()},
            "bits": bits,
            "block_bytes": storage.block_size(k["n"]),
            "ms": round((time.perf_counter() - t0) * 1000),
            "glyph": fingerprint(k["n"]),
        }

    def encrypt(self, req):
        n = big_int(req.get("n"), "Modulus n")
        e = big_int(req.get("e"), "Eksponen publik e")
        filename = (req.get("filename") or "").strip()[:120]
        if not filename:
            raise ValueError("Nama berkas wajib diisi - hanya berkas yang dapat dienkripsi.")
        label = (req.get("label") or "").strip()[:80] or filename

        try:
            data = base64.b64decode(req.get("data") or "", validate=True)
        except Exception:
            raise ValueError("Berkas tidak dapat dibaca (base64 rusak).")

        if not data:
            raise ValueError("Berkas kosong - tidak ada yang dapat dienkripsi.")
        if len(data) > MAX_BODY:
            raise ValueError("Data terlalu besar (maksimum 8 MB).")

        t0 = time.perf_counter()
        ciphertext = storage.encrypt_bytes((n, e), data)
        entries = load_vault()
        entry = {
            "id": uuid.uuid4().hex[:12],
            "label": label,
            "kind": "file",
            "filename": filename,
            "bytes": len(data),
            "blocks": ciphertext.count(":") + 1 if ciphertext else 0,
            "n_tail": str(n)[-8:],
            "bits": n.bit_length(),
            "glyph": fingerprint(n),
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ciphertext": ciphertext,
        }
        entries.append(entry)
        save_vault(entries)

        first = ciphertext.split(":")[0] if ciphertext else ""
        return {
            **{k: v for k, v in entry.items() if k != "ciphertext"},
            "ms": round((time.perf_counter() - t0) * 1000),
            "preview": ciphertext[:160],
            "tape": {
                "m": str(int.from_bytes(b"\x01" + data[: storage.block_size(n)], "big")),
                "e": str(e),
                "n": str(n),
                "c": str(int(first, 16)) if first else "0",
            },
        }

    def decrypt(self, req):
        n = big_int(req.get("n"), "Modulus n")
        d = big_int(req.get("d"), "Eksponen privat d")
        entries = load_vault()
        entry = next((x for x in entries if x["id"] == req.get("id")), None)
        if not entry:
            raise ValueError("Entri tidak ditemukan di vault.")
        if not HEX_RE.match(entry["ciphertext"] or "0"):
            raise ValueError("Ciphertext tersimpan rusak.")
        if n.bit_length() != entry["bits"]:
            raise ValueError(
                f"Modulus tidak cocok: entri ini {entry['bits']} bit, "
                f"kunci yang dimasukkan {n.bit_length()} bit."
            )

        t0 = time.perf_counter()
        data = storage.decrypt_bytes((n, d), entry["ciphertext"])
        ms = round((time.perf_counter() - t0) * 1000)

        out = {"id": entry["id"], "kind": entry["kind"], "ms": ms,
               "filename": entry.get("filename"), "bytes": len(data)}
        if entry["kind"] == "file":
            out["data"] = base64.b64encode(data).decode()
        else:
            try:
                out["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Hasil dekripsi bukan teks UTF-8 yang valid - "
                                 "kunci privat kemungkinan salah.")
        return out

    def drop_entry(self, req):
        entries = load_vault()
        kept = [x for x in entries if x["id"] != req.get("id")]
        if len(kept) == len(entries):
            raise ValueError("Entri tidak ditemukan di vault.")
        save_vault(kept)
        return {"ok": True, "remaining": len(kept)}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8765))
    print(f"RSA Encrypted Storage  ->  http://127.0.0.1:{port}")
    print("Ctrl+C untuk berhenti.\n")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
