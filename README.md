# osintS34rCh v2.0 — Kali Linux install guide

## Why the old version was broken

Kali now ships Python 3.11+ with PEP 668. The old script failed in two places:
`pip install` was rejected because the environment is "externally managed", and
most of the imported libraries (`google`, `opencnam`, `fullcontact`,
`dnsdumpster`, `censys.ipv4`, `validators.ip_address.ipv4`) are either gone or
their APIs have changed.

## Installation (pick one)

### 1. Virtualenv — safest, recommended

```bash
cd ~/osintS34rCh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python osintS34rCh.py -t example.com --crt
```

### 2. Kali apt packages (no venv)

```bash
sudo apt update
sudo apt install -y python3-requests python3-phonenumbers python3-pyfiglet
chmod +x osintS34rCh.py
./osintS34rCh.py -t example.com --crt
```

### 3. System pip (not recommended, can break apt packages)

```bash
pip install --break-system-packages -r requirements.txt
```

Only `requests` is required. Without `phonenumbers` the phone module is
skipped; without `pyfiglet` the banner prints as plain text.

## Config

Created automatically on first run:

```
~/.config/osintS34rCh/config.ini
```

Fill in whichever API keys you have. A module without a key is skipped with a
message instead of crashing the script. Keys can also be supplied via
environment variables: `HIBP_API_KEY`, `SHODAN_API_KEY`, `CENSYS_PAT`,
`CENSYS_ORG_ID`, `WHATCMS_API_KEY`, `DNSDUMPSTER_API_KEY`.

## What works without any API key

crt.sh, HackerTarget (zone transfer, host search, reverse DNS, extract links),
the Google dork URL generator, offline phone number lookup, and the
iknowwhatyoudownload link.

## Examples

```bash
./osintS34rCh.py -t example.com              # all domain modules
./osintS34rCh.py -t example.com --crt        # subdomains from crt.sh only
./osintS34rCh.py -t example.com -d all       # all dorks
./osintS34rCh.py -t 8.8.8.8 --shodan
./osintS34rCh.py -u https://example.com --extract
./osintS34rCh.py -e target@mail.com          # requires an HIBP key
./osintS34rCh.py -p +6281234567890
```

## Services removed

| Old module | Reason |
|---|---|
| Pipl | consumer service shut down in 2023 |
| FullContact person API v2 | endpoint retired |
| OpenCNAM (CallerID) | service shut down — replaced with offline phonenumbers lookup |
| TowerData email validation | API no longer publicly available |
| `google` library (scraping) | Google blocks scraping with a captcha wall — replaced with a dork URL generator |
| Censys `censys.ipv4` | legacy API retired, replaced with Censys Platform v3 (PAT + Org ID) |
| DNSDumpster scraping | now officially requires an API key |
| HIBP API v2 | replaced with v3 (requires a paid API key) |

Use this only against assets you own or targets that have given you written
authorization.
