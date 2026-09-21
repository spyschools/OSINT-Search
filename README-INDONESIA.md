# osintS34rCh v2.0 — instalasi di Kali Linux

## Kenapa versi lama error

Kali sekarang memakai Python 3.11+ dan PEP 668. Skrip lama gagal di dua tempat:
`pip install` ditolak karena environment "externally managed", dan sebagian besar
library yang di-import (`google`, `opencnam`, `fullcontact`, `dnsdumpster`,
`censys.ipv4`, `validators.ip_address.ipv4`) sudah tidak ada atau APInya berubah.

## Cara pasang (pilih salah satu)

### 1. Virtualenv — paling aman, disarankan

```bash
cd ~/osintS34rCh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python osintS34rCh.py -t example.com --crt
```

### 2. Paket apt Kali (tanpa venv)

```bash
sudo apt update
sudo apt install -y python3-requests python3-phonenumbers python3-pyfiglet
chmod +x osintS34rCh.py
./osintS34rCh.py -t example.com --crt
```

### 3. pip sistem (tidak disarankan, bisa merusak paket apt)

```bash
pip install --break-system-packages -r requirements.txt
```

Hanya `requests` yang wajib. Tanpa `phonenumbers` modul telepon dilewati,
tanpa `pyfiglet` banner tampil polos.

## Config

Dibuat otomatis saat pertama kali dijalankan:

```
~/.config/osintS34rCh/config.ini
```

Isi API key yang Anda punya. Modul tanpa key otomatis dilewati dengan pesan,
tidak bikin skrip mati. Bisa juga lewat environment variable:
`HIBP_API_KEY`, `SHODAN_API_KEY`, `CENSYS_PAT`, `CENSYS_ORG_ID`,
`WHATCMS_API_KEY`, `DNSDUMPSTER_API_KEY`.

## Yang jalan tanpa API key

crt.sh, HackerTarget (zone transfer, host search, reverse DNS, extract links),
generator Google dork, lookup nomor telepon (offline), link iknowwhatyoudownload.

## Contoh

```bash
./osintS34rCh.py -t example.com              # semua modul domain
./osintS34rCh.py -t example.com --crt        # subdomain dari crt.sh
./osintS34rCh.py -t example.com -d all       # semua dork
./osintS34rCh.py -t 8.8.8.8 --shodan
./osintS34rCh.py -u https://example.com --extract
./osintS34rCh.py -e target@mail.com          # butuh key HIBP
./osintS34rCh.py -p +6281234567890
```

## Layanan yang dihapus

| Modul lama | Alasan |
|---|---|
| Pipl | layanan konsumen ditutup 2023 |
| FullContact person API v2 | endpoint dimatikan |
| OpenCNAM (CallerID) | layanan tutup — diganti lookup offline phonenumbers |
| TowerData email validation | API tidak lagi tersedia publik |
| library `google` (scraping) | Google blokir scraping, selalu captcha — diganti generator URL dork |
| Censys `censys.ipv4` | API lama dimatikan, diganti Censys Platform v3 (PAT + Org ID) |
| DNSDumpster scraping | sekarang resmi pakai API key |
| HIBP API v2 | diganti v3 (wajib API key berbayar) |

Gunakan hanya pada aset milik sendiri atau target yang sudah memberi izin tertulis.
