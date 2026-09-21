#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
osintS34rCh v2.0 - OSINT recon helper (refactor 2026)

Versi ini dirombak agar jalan di Kali Linux terbaru (Python 3.11+).
Hanya dependensi yang masih hidup yang dipakai: requests (wajib),
phonenumbers & pyfiglet (opsional).

Gunakan hanya pada target yang Anda miliki atau yang sudah memberi izin
tertulis (pentest/bug bounty). Anda bertanggung jawab atas penggunaannya.
"""

import argparse
import configparser
import ipaddress
import json
import os
import re
import sys
import urllib.parse
import webbrowser

try:
    import requests
except ImportError:
    sys.exit("[!] Modul 'requests' belum ada.\n"
             "    sudo apt install python3-requests\n"
             "    atau: pip install requests")

# --- dependensi opsional -----------------------------------------------------
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as pn_timezone
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False

try:
    from pyfiglet import Figlet
    HAS_FIGLET = True
except ImportError:
    HAS_FIGLET = False

__version__ = "2.0"

TIMEOUT = 25
UA = f"osintS34rCh/{__version__} (+https://github.com/)"

# --- endpoint ----------------------------------------------------------------
HIBP_BREACH = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_PASTE = "https://haveibeenpwned.com/api/v3/pasteaccount/"
CRT_URL = "https://crt.sh/"
DNSDUMPSTER_API = "https://api.dnsdumpster.com/domain/"
WHATCMS_API = "https://whatcms.org/API/Tech"
SHODAN_HOST = "https://api.shodan.io/shodan/host/"
SHODAN_SEARCH = "https://api.shodan.io/shodan/host/search"
CENSYS_HOST = "https://api.platform.censys.io/v3/global/asset/host/"
HT_PAGELINKS = "https://api.hackertarget.com/pagelinks/?q="
HT_ZONETRANSFER = "https://api.hackertarget.com/zonetransfer/?q="
HT_HOSTSEARCH = "https://api.hackertarget.com/hostsearch/?q="
HT_REVERSEDNS = "https://api.hackertarget.com/reversedns/?q="
IKWYD_URL = "https://iknowwhatyoudownload.com/en/peer/?ip="

# --- google hacking dorks ----------------------------------------------------
DORKS = {
    "dir_list": 'intitle:"index of"',
    "files": 'ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR '
             'ext:cfg OR ext:ora OR ext:ini OR ext:log OR ext:config',
    "docs": 'ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR '
            'ext:pptx OR ext:xls OR ext:xlsx OR ext:csv',
    "db": 'ext:sql OR ext:dbf OR ext:mdb OR inurl:"laravel.log"',
    "login": 'inurl:login OR intitle:admin intitle:login OR inurl:wp-login.php',
    "sql": '"index of" "database.sql" OR "sql.gz" OR "sql.tar" OR "dbbackup"',
    "sensitive": 'ext:log intext:password OR intext:admin OR intext:root',
    "php": 'ext:php intitle:phpinfo OR inurl:phpMyAdmin OR inurl:login.php.bak',
    "subdomain": '-www',
}

DEFAULT_CONFIG = """\
; osintS34rCh config
; Kosongkan kalau tidak punya key - modul terkait otomatis dilewati.

[hibp]
; https://haveibeenpwned.com/API/Key  (berbayar)
api_key =

[shodan]
; https://account.shodan.io/
api_key =

[censys]
; https://platform.censys.io -> Personal Access Token + Organization ID
pat =
org_id =

[whatcms]
; https://whatcms.org/API
api_key =

[dnsdumpster]
; https://dnsdumpster.com/developer/ (akun gratis)
api_key =
"""

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


# =============================================================================
# util
# =============================================================================
def banner():
    if HAS_FIGLET:
        print(Figlet(font="slant").renderText("osintS34rCh"))
    else:
        print("\n  osintS34rCh v%s\n" % __version__)


def info(msg):
    print("[*] " + msg)


def warn(msg):
    print("[!] " + msg)


def section(title):
    print("\n" + "=" * 60)
    print("-> " + title)
    print("=" * 60)


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_email(value):
    return bool(EMAIL_RE.match(value))


def is_domain(value):
    return bool(DOMAIN_RE.match(value))


def hostname_of(url):
    """Ambil hostname dari URL, tambahkan skema kalau belum ada."""
    if "://" not in url:
        url = "http://" + url
    return urllib.parse.urlparse(url).hostname or ""


def session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "application/json"})
    return s


def get(url, **kwargs):
    """GET dengan penanganan error jaringan supaya skrip tidak crash."""
    kwargs.setdefault("timeout", TIMEOUT)
    try:
        return session().get(url, **kwargs)
    except requests.exceptions.SSLError as e:
        warn("SSL error: %s" % e)
    except requests.exceptions.ConnectTimeout:
        warn("Timeout saat konek ke %s" % url)
    except requests.exceptions.ReadTimeout:
        warn("Server tidak membalas tepat waktu: %s" % url)
    except requests.exceptions.ConnectionError as e:
        warn("Gagal konek (cek internet/DNS/proxy): %s" % e.__class__.__name__)
    except requests.exceptions.RequestException as e:
        warn("Request gagal: %s" % e)
    return None


def as_json(resp):
    if resp is None:
        return None
    try:
        return resp.json()
    except ValueError:
        warn("Balasan server bukan JSON (HTTP %s)." % resp.status_code)
        return None


# =============================================================================
# config
# =============================================================================
def config_path(custom=None):
    if custom:
        return os.path.abspath(os.path.expanduser(custom))
    env = os.environ.get("OSINTS34RCH_CONFIG")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "osintS34rCh", "config.ini")


def load_config(custom=None):
    path = config_path(custom)
    if not os.path.isfile(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(DEFAULT_CONFIG)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        info("File config dibuat: %s" % path)
        info("Isi API key yang Anda punya, lalu jalankan lagi.")
        info("Modul tanpa key tetap bisa dipakai (crt.sh, hackertarget, dork, phone).")
        print()

    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")

    def value(section_name, option, env_name):
        env_value = os.environ.get(env_name)
        if env_value:
            return env_value.strip()
        try:
            return cfg.get(section_name, option).strip()
        except (configparser.NoSectionError, configparser.NoOptionError):
            return ""

    return {
        "path": path,
        "hibp": value("hibp", "api_key", "HIBP_API_KEY"),
        "shodan": value("shodan", "api_key", "SHODAN_API_KEY"),
        "censys_pat": value("censys", "pat", "CENSYS_PAT"),
        "censys_org": value("censys", "org_id", "CENSYS_ORG_ID"),
        "whatcms": value("whatcms", "api_key", "WHATCMS_API_KEY"),
        "dnsdumpster": value("dnsdumpster", "api_key", "DNSDUMPSTER_API_KEY"),
    }


# =============================================================================
# modul: email
# =============================================================================
def haveibeenpwned(email, api_key):
    section("Have I Been Pwned")

    if not api_key:
        warn("HIBP butuh API key berbayar. Lewati.")
        info("Cek manual gratis: https://haveibeenpwned.com/")
        return

    headers = {"hibp-api-key": api_key, "User-Agent": UA}
    print("\n[@] Target: %s\n" % email)
    quoted = urllib.parse.quote(email, safe="")

    for label, url in (("Data Breaches", HIBP_BREACH), ("Pastes", HIBP_PASTE)):
        print("--- %s ---" % label)
        resp = get(url + quoted, headers=headers,
                   params={"truncateResponse": "false"})
        if resp is None:
            continue
        if resp.status_code == 404:
            info("Tidak ada hasil untuk %s." % label.lower())
            print()
            continue
        if resp.status_code == 401:
            warn("API key HIBP ditolak (401).")
            return
        if resp.status_code == 429:
            warn("Kena rate limit HIBP (429). Tunggu sebentar.")
            return
        if resp.status_code != 200:
            warn("HTTP %s dari HIBP." % resp.status_code)
            continue

        data = as_json(resp) or []
        for item in data:
            name = item.get("Title") or item.get("Name") or item.get("Source", "?")
            print("\n[*] %s" % name)
            for key in ("Domain", "BreachDate", "Date", "PwnCount", "EmailCount",
                        "Id", "Source"):
                if item.get(key):
                    print("    %-11s: %s" % (key, item[key]))
            if item.get("DataClasses"):
                print("    Data bocor: %s" % ", ".join(item["DataClasses"]))
        print()


# =============================================================================
# modul: domain
# =============================================================================
def crt_sh(domain):
    section("crt.sh (Certificate Transparency)")
    print("\n[@] Target: %s\n" % domain)

    resp = get(CRT_URL, params={"q": "%." + domain, "output": "json"},
               headers={"User-Agent": UA})
    if resp is None:
        return
    if resp.status_code != 200:
        warn("crt.sh membalas HTTP %s (server sering overload, coba lagi)."
             % resp.status_code)
        return

    data = as_json(resp)
    if not data:
        info("Tidak ada sertifikat yang cocok.")
        return

    names = set()
    for cert in data:
        for name in str(cert.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name:
                names.add(name)

    info("%d sertifikat, %d subdomain unik:\n" % (len(data), len(names)))
    for name in sorted(names):
        print("    " + name)


def dnsdumpster(domain, api_key):
    section("DNSDumpster")

    if not api_key:
        warn("DNSDumpster sekarang wajib API key (akun gratis ada).")
        info("Daftar: https://dnsdumpster.com/developer/")
        return

    resp = get(DNSDUMPSTER_API + domain, headers={"X-API-Key": api_key})
    if resp is None:
        return
    if resp.status_code == 401:
        warn("API key DNSDumpster ditolak (401).")
        return
    if resp.status_code != 200:
        warn("HTTP %s dari DNSDumpster." % resp.status_code)
        return

    data = as_json(resp)
    if not data:
        return

    print("\n[@] Target: %s" % domain)
    for record_type, records in data.items():
        if not records:
            continue
        print("\n[*] %s" % str(record_type).upper())
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict):
                    flat = ", ".join("%s=%s" % (k, v) for k, v in record.items()
                                     if not isinstance(v, (dict, list)))
                    print("    - " + flat)
                else:
                    print("    - %s" % record)
        else:
            print("    %s" % records)


def dns_zone_transfer(domain):
    section("DNS Zone Transfer (HackerTarget)")
    resp = get(HT_ZONETRANSFER + domain, headers={"Accept": "text/plain"})
    if resp is not None:
        print("\n" + resp.text.strip())


def host_search(domain):
    section("Host Search (HackerTarget)")
    resp = get(HT_HOSTSEARCH + domain, headers={"Accept": "text/plain"})
    if resp is not None:
        print("\n" + resp.text.strip())


def google_hacking(domain, names, open_browser=False):
    section("Google Hacking")
    print("\nGoogle memblokir scraping otomatis, jadi skrip ini membuat URL-nya")
    print("untuk Anda buka sendiri (pakai --open untuk langsung ke browser).\n")

    for name in names:
        query = "site:%s %s" % (domain, DORKS[name])
        url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)
        print("[*] %-10s %s" % (name, url))
        if open_browser:
            webbrowser.open(url)


# =============================================================================
# modul: IP / host
# =============================================================================
def shodan_lookup(target, api_key):
    section("Shodan")

    if not api_key:
        warn("Shodan API key kosong. Lewati.")
        return

    print("\n[@] Target: %s\n" % target)

    if is_ip(target):
        resp = get(SHODAN_HOST + target, params={"key": api_key})
        if resp is None:
            return
        if resp.status_code == 404:
            info("Shodan belum punya data untuk IP ini.")
            return
        if resp.status_code in (401, 403):
            warn("API key Shodan ditolak (HTTP %s)." % resp.status_code)
            return
        host = as_json(resp)
        if not host:
            return
        for label, key in (("Organisasi", "org"), ("ISP", "isp"), ("OS", "os"),
                           ("Kota", "city"), ("Negara", "country_name"),
                           ("Kode pos", "postal_code"), ("ASN", "asn"),
                           ("Terakhir update", "last_update")):
            print("[*] %-16s: %s" % (label, host.get(key) or "N/A"))
        if host.get("hostnames"):
            print("[*] Hostname       : %s" % ", ".join(host["hostnames"]))
        if host.get("ports"):
            print("[*] Port terbuka   : %s"
                  % ", ".join(str(p) for p in sorted(host["ports"])))
        for item in host.get("data", []):
            product = item.get("product") or "?"
            version = item.get("version") or ""
            print("    - %s/%s  %s %s" % (item.get("port"),
                                          item.get("transport", "tcp"),
                                          product, version))
    else:
        resp = get(SHODAN_SEARCH, params={"key": api_key,
                                          "query": "hostname:%s" % target})
        if resp is None:
            return
        if resp.status_code in (401, 403):
            warn("Pencarian Shodan butuh membership berbayar (HTTP %s)."
                 % resp.status_code)
            return
        data = as_json(resp)
        if not data or not data.get("matches"):
            info("Tidak ada hasil Shodan untuk %s." % target)
            return
        info("Total: %s hasil (ditampilkan %d)\n"
             % (data.get("total", "?"), len(data["matches"])))
        for match in data["matches"]:
            loc = match.get("location", {})
            print("[*] %s:%s  %s  %s / %s"
                  % (match.get("ip_str"), match.get("port"),
                     match.get("product") or "-",
                     loc.get("city") or "-", loc.get("country_name") or "-"))


def censys_lookup(ip, pat, org_id):
    section("Censys Platform")

    if not pat or not org_id:
        warn("Censys butuh Personal Access Token + Organization ID.")
        info("API lama (api_id/api_secret) sudah dimatikan Censys.")
        return

    headers = {
        "Authorization": "Bearer " + pat,
        "X-Organization-ID": org_id,
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
    }
    resp = get(CENSYS_HOST + ip, headers=headers)
    if resp is None:
        return
    if resp.status_code in (401, 403):
        warn("Kredensial Censys ditolak (HTTP %s)." % resp.status_code)
        return
    if resp.status_code == 404:
        info("Censys tidak punya data untuk IP ini.")
        return
    if resp.status_code != 200:
        warn("HTTP %s dari Censys." % resp.status_code)
        return

    data = as_json(resp) or {}
    host = data
    for key in ("result", "resource", "host"):
        if isinstance(host, dict) and isinstance(host.get(key), dict):
            host = host[key]

    print("\n[@] IP: %s" % host.get("ip", ip))
    location = host.get("location", {})
    if location:
        print("[*] Lokasi   : %s, %s" % (location.get("city", "N/A"),
                                         location.get("country", "N/A")))
    autonomous = host.get("autonomous_system", {})
    if autonomous:
        print("[*] AS       : %s (%s)" % (autonomous.get("name", "N/A"),
                                          autonomous.get("asn", "N/A")))
    for service in host.get("services", []):
        print("    - %s/%s  %s" % (service.get("port"),
                                   service.get("transport_protocol", ""),
                                   service.get("protocol")
                                   or service.get("service_name", "")))
    if not host.get("services"):
        print(json.dumps(data, indent=2)[:2000])


def reverse_dns(ip):
    section("Reverse DNS (HackerTarget)")
    resp = get(HT_REVERSEDNS + ip, headers={"Accept": "text/plain"})
    if resp is not None:
        print("\n" + resp.text.strip())


def torrent_link(ip):
    section("Riwayat Torrent")
    print("\n[*] " + IKWYD_URL + ip)


# =============================================================================
# modul: URL
# =============================================================================
def whatcms(url, api_key):
    section("WhatCMS")

    if not api_key:
        warn("WhatCMS API key kosong. Lewati.")
        return

    resp = get(WHATCMS_API, params={"key": api_key, "url": url})
    data = as_json(resp)
    if not data:
        return

    result = data.get("result", {})
    code = result.get("code")
    if code != 200:
        warn("WhatCMS: %s (code %s)" % (result.get("msg", "error"), code))
        return

    print("\n[@] Target: %s\n" % url)
    for tech in data.get("results", []):
        version = tech.get("version") or ""
        cats = ", ".join(tech.get("categories", []))
        print("[*] %-24s %-10s %s" % (tech.get("name", "?"), version, cats))


def extract_urls(url):
    section("Extract Links (HackerTarget)")
    resp = get(HT_PAGELINKS + url, headers={"Accept": "text/plain"})
    if resp is not None:
        print("\n" + resp.text.strip())


# =============================================================================
# modul: telepon
# =============================================================================
def phone_lookup(number):
    section("Phone Number")

    if not HAS_PHONENUMBERS:
        warn("Modul phonenumbers belum terpasang: pip install phonenumbers")
        return

    if not number.startswith("+"):
        warn("Nomor harus format internasional, contoh: +6281234567890")
        return

    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as e:
        warn("Nomor tidak bisa diparsing: %s" % e)
        return

    valid = phonenumbers.is_valid_number(parsed)
    print("\n[*] Nomor      : %s"
          % phonenumbers.format_number(
              parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    print("[*] Valid      : %s" % ("ya" if valid else "tidak"))
    print("[*] Kode negara: +%s" % parsed.country_code)
    print("[*] Wilayah    : %s" % (geocoder.description_for_number(parsed, "en")
                                   or "N/A"))
    print("[*] Operator   : %s" % (carrier.name_for_number(parsed, "en") or "N/A"))
    print("[*] Zona waktu : %s" % ", ".join(pn_timezone.time_zones_for_number(parsed)))

    number_type = phonenumbers.number_type(parsed)
    type_names = {value: name
                  for name, value in vars(phonenumbers.PhoneNumberType).items()
                  if name.isupper() and isinstance(value, int)}
    print("[*] Tipe       : %s" % type_names.get(number_type, number_type))
    print("\n[-] Lookup CallerID/CNAM dihapus: layanan OpenCNAM sudah tutup.")


# =============================================================================
# CLI
# =============================================================================
def build_parser():
    parser = argparse.ArgumentParser(
        prog="osintS34rCh.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="osintS34rCh v%s - OSINT recon helper" % __version__,
        epilog="""\
contoh:
  ./osintS34rCh.py -t example.com                 # semua modul domain
  ./osintS34rCh.py -t example.com --crt           # crt.sh saja
  ./osintS34rCh.py -t example.com -d all --open   # semua dork, buka browser
  ./osintS34rCh.py -t 8.8.8.8 --shodan
  ./osintS34rCh.py -u https://example.com --cms
  ./osintS34rCh.py -e target@mail.com
  ./osintS34rCh.py -p +6281234567890

dork: """ + ", ".join(DORKS) + """

config: ~/.config/osintS34rCh/config.ini
Pakai hanya pada target yang Anda miliki atau yang sudah memberi izin.
""")

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-e", metavar="EMAIL", dest="email")
    target_group.add_argument("-t", metavar="DOMAIN|IP", dest="target")
    target_group.add_argument("-u", metavar="URL", dest="url")
    target_group.add_argument("-p", metavar="PHONE", dest="phone")

    parser.add_argument("--pwned", action="store_true", help="HIBP saja")
    parser.add_argument("--crt", action="store_true", help="crt.sh saja")
    parser.add_argument("--dns", action="store_true",
                        help="DNSDumpster + zone transfer + host search")
    parser.add_argument("--shodan", action="store_true")
    parser.add_argument("--censys", action="store_true")
    parser.add_argument("--torrent", action="store_true")
    parser.add_argument("--cms", action="store_true", help="WhatCMS saja")
    parser.add_argument("--extract", action="store_true", help="ekstrak link saja")
    parser.add_argument("-d", "--dork", metavar="NAME",
                        help="google dork: %s, atau 'all'" % "|".join(DORKS))
    parser.add_argument("--open", action="store_true",
                        help="buka URL dork di browser")
    parser.add_argument("-c", "--config", metavar="FILE",
                        help="path file config alternatif")
    parser.add_argument("-V", "--version", action="version",
                        version="osintS34rCh " + __version__)
    return parser


def run_email(args, cfg):
    if not is_email(args.email):
        sys.exit("[!] Format email tidak valid.")
    haveibeenpwned(args.email, cfg["hibp"])


def run_target(args, cfg):
    target = args.target
    picked = any([args.crt, args.dns, args.shodan, args.censys,
                  args.torrent, args.dork])

    if is_ip(target):
        if not picked or args.shodan:
            shodan_lookup(target, cfg["shodan"])
        if not picked or args.censys:
            censys_lookup(target, cfg["censys_pat"], cfg["censys_org"])
        if not picked or args.dns:
            reverse_dns(target)
        if not picked or args.torrent:
            torrent_link(target)
        return

    if not is_domain(target):
        sys.exit("[!] Target harus domain atau IP yang valid.")

    if args.dork:
        names = list(DORKS) if args.dork == "all" else [args.dork]
        unknown = [n for n in names if n not in DORKS]
        if unknown:
            sys.exit("[!] Dork tidak dikenal: %s" % ", ".join(unknown))
        google_hacking(target, names, args.open)
        if picked and not any([args.crt, args.dns, args.shodan, args.censys]):
            return

    if not picked or args.crt:
        crt_sh(target)
    if not picked or args.dns:
        dnsdumpster(target, cfg["dnsdumpster"])
        dns_zone_transfer(target)
        host_search(target)
    if not picked or args.shodan:
        shodan_lookup(target, cfg["shodan"])
    if not picked:
        google_hacking(target, list(DORKS), args.open)


def run_url(args, cfg):
    url = args.url
    if not hostname_of(url):
        sys.exit("[!] URL tidak valid.")
    picked = args.cms or args.extract
    if not picked or args.cms:
        whatcms(url, cfg["whatcms"])
    if not picked or args.extract:
        extract_urls(url)


def main():
    args = build_parser().parse_args()
    cfg = load_config(args.config)
    banner()

    if args.email:
        run_email(args, cfg)
    elif args.target:
        run_target(args, cfg)
    elif args.url:
        run_url(args, cfg)
    elif args.phone:
        phone_lookup(args.phone)

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Dibatalkan pengguna.")
