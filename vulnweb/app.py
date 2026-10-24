"""
VulnWeb - Aplikasi web SENGAJA RENTAN untuk latihan red team / pentest pribadi.
HANYA jalankan di localhost / jaringan lokal lu sendiri. JANGAN deploy ke internet publik.

Daftar kerentanan yang sengaja ditanam (OWASP Top 10 2021):
 A01 Broken Access Control   -> /profile?id=  (IDOR)
 A02 Cryptographic Failures  -> password disimpan pakai MD5 tanpa salt
 A03 Injection               -> /login (SQL Injection), /guestbook (Stored XSS)
 A04 Insecure Design         -> /reset_password tanpa verifikasi identitas
 A05 Security Misconfiguration -> debug=True, verbose error, secret key lemah
 A06 Vulnerable Components   -> lihat requirements.txt (versi lawas sengaja)
 A07 Identification & Auth Failures -> tanpa rate limit, session gampang ditebak
 A08 Software & Data Integrity Failures -> /load_config pakai pickle (insecure deserialization)
 A09 Logging & Monitoring Failures -> tidak ada logging sama sekali
 A10 SSRF                    -> /fetch mengambil URL dari input user tanpa validasi
 Bonus: Command Injection    -> /ping
 Bonus: Unrestricted File Upload -> /upload
"""

import sqlite3
import hashlib
import os
import pickle
import base64
import subprocess
import requests
from flask import Flask, request, render_template, redirect, session, g, make_response

app = Flask(__name__)
# A05: secret key lemah & hardcoded
app.secret_key = "123456"

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnweb.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "logs")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        email TEXT,
        is_admin INTEGER DEFAULT 0
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS guestbook (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        message TEXT
    )""")

    # A02: MD5 tanpa salt
    def md5(p):
        return hashlib.md5(p.encode()).hexdigest()

    cur = db.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        db.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?,?,?,?)",
                   ("admin", md5("admin123"), "admin@vulnweb.local", 1))
        db.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?,?,?,?)",
                   ("budi", md5("budi123"), "budi@vulnweb.local", 0))
        db.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?,?,?,?)",
                   ("siti", md5("siti123"), "siti@vulnweb.local", 0))
    db.commit()
    db.close()


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


# ---------------- A03: SQL Injection ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_hash = hashlib.md5(password.encode()).hexdigest()

        # VULNERABLE: query dibangun pakai string formatting, bukan parameterized query
        query = f"SELECT id, username, is_admin FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        db = get_db()
        try:
            cur = db.execute(query)
            row = cur.fetchone()
        except sqlite3.OperationalError as e:
            # A05: error database ditampilkan mentah ke user
            return render_template("login.html", error=f"DB error: {e} | Query: {query}")

        if row:
            session["user_id"] = row[0]
            session["username"] = row[1]
            session["is_admin"] = row[2]
            return redirect("/profile?id=" + str(row[0]))
        else:
            error = "Login gagal"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- A01: Broken Access Control / IDOR ----------------
@app.route("/profile")
def profile():
    # VULNERABLE: tidak cek apakah id yang diminta = id user yang login
    user_id = request.args.get("id", "")
    db = get_db()
    cur = db.execute("SELECT id, username, email, is_admin FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return "User tidak ditemukan", 404
    return render_template("profile.html", profile=row, me=session.get("username"))


# ---------------- A03: Stored XSS ----------------
@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        db.execute("INSERT INTO guestbook (name, message) VALUES (?, ?)", (name, message))
        db.commit()
    entries = db.execute("SELECT name, message FROM guestbook ORDER BY id DESC").fetchall()
    # VULNERABLE: template guestbook.html me-render message pakai |safe (lihat template)
    return render_template("guestbook.html", entries=entries)


# ---------------- A04: Insecure Design (reset password tanpa verifikasi) ----------------
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        new_password = request.form.get("new_password", "")
        # VULNERABLE: tidak ada verifikasi email/OTP, siapa saja bisa reset password siapa saja
        db = get_db()
        new_hash = hashlib.md5(new_password.encode()).hexdigest()
        db.execute("UPDATE users SET password = ? WHERE username = ?", (new_hash, username))
        db.commit()
        message = f"Password untuk {username} berhasil direset."
    return render_template("reset_password.html", message=message)


# ---------------- A10: SSRF ----------------
@app.route("/fetch", methods=["GET", "POST"])
def fetch_url():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            # VULNERABLE: server melakukan request ke URL manapun yang diinput user,
            # termasuk ke alamat internal (127.0.0.1, 169.254.169.254, dll)
            resp = requests.get(url, timeout=5)
            result = resp.text[:2000]
        except Exception as e:
            result = f"Error: {e}"
    return render_template("fetch.html", result=result)


# ---------------- Bonus: Command Injection ----------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABLE: input user langsung masuk ke shell command
        cmd = f"ping -c 1 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            output = e.output
    return render_template("ping.html", output=output)


# ---------------- Bonus: Unrestricted File Upload ----------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # VULNERABLE: tidak ada validasi ekstensi/tipe file, nama file tidak disanitasi
            save_path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(save_path)
            message = f"File tersimpan di /uploads/{f.filename}"
    return render_template("upload.html", message=message)


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # VULNERABLE: file yang diupload (termasuk .py/.php/.html) bisa diakses & dieksekusi browser
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(path):
        return "Not found", 404
    with open(path, "rb") as fh:
        data = fh.read()
    resp = make_response(data)
    return resp


# ---------------- A08: Insecure Deserialization ----------------
@app.route("/load_config", methods=["GET", "POST"])
def load_config():
    result = None
    if request.method == "POST":
        blob = request.form.get("config", "")
        try:
            # VULNERABLE: pickle.loads terhadap data dari user bisa eksekusi kode arbitrer
            data = pickle.loads(base64.b64decode(blob))
            result = f"Config loaded: {data}"
        except Exception as e:
            result = f"Error: {e}"
    return render_template("load_config.html", result=result)


# ---------------- A05: Security Misconfiguration (robots.txt bocorin path admin) ----------------
@app.route("/robots.txt")
def robots():
    resp = make_response("User-agent: *\nDisallow: /admin-x7k9/\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp


# ---------------- A01: Broken Access Control (admin panel tanpa cek auth sama sekali) ----------------
@app.route("/admin-x7k9")
def admin_panel():
    # VULNERABLE: "tersembunyi" cuma karena URL-nya nggak gampang ditebak (security through obscurity),
    # begitu ketemu, tidak ada pengecekan session/role admin sama sekali.
    return render_template("admin.html")


# ---------------- Path Traversal / LFI -> bocorin .env ----------------
@app.route("/admin-x7k9/logs")
def admin_logs():
    filename = request.args.get("file", "access.log")
    # VULNERABLE: nama file dari user digabung langsung ke path, tidak ada sanitasi "..",
    # jadi bisa dipakai buat baca file di luar folder logs/, termasuk .env di root project
    path = os.path.join(LOGS_DIR, filename)
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except Exception as e:
        content = f"Error: {e}"
    return render_template("admin_logs.html", filename=filename, content=content)


if __name__ == "__main__":
    init_db()
    # A05: debug=True di "production" -> membuka Werkzeug debugger/RCE, host 0.0.0.0 expose ke jaringan
    app.run(host="0.0.0.0", port=5000, debug=True)
