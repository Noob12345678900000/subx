# SubX

> **Subdomain Buster + Full-Site Crawler with Colored Output**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Issues](https://img.shields.io/github/issues/Noob12345678900000/subx)
![Forks](https://img.shields.io/github/forks/Noob12345678900000/subx?style=social)
![Stars](https://img.shields.io/github/stars/Noob12345678900000/subx?style=social)

**SubX** is a fast, asynchronous subdomain enumeration and web crawler tool with **real-time colored output**, **screenshot capture**, **DNS resolution**, and **robots.txt compliance**. Perfect for **OSINT, bug bounty, and red teaming** (with permission).

---

## Features

| Feature | Status |
|-------|--------|
| Subdomain brute-force (custom wordlists) | Done |
| DNS A/AAAA resolution (shows IPs) | Done |
| Full-site crawling (all internal links) | Done |
| Colored terminal output (Green: Internal, Cyan: External, Red: Error) | Done |
| `robots.txt` respect | Done |
| `--screenshots` with Playwright (Chromium) | Done |
| High concurrency (100+ async requests) | Done |
| Export results to JSON | Done |
| Polite crawling (rate limiting) | Done |

---

## Screenshot

<code>
[+] SUBDOMAIN: admin.target.com          → 192.168.1.100
[+] SUBDOMAIN: api.target.com            → 104.21.3.45
[INT] https://admin.target.com/login
[EXT] https://github.com/target
[Screenshot] Screenshot: admin.target.com_login.png
[+] Results saved to output/results.json
</code>

---

## Installation

<code>
# Clone the repo
git clone https://github.com/Noob12345678900000/subx.git
cd subx

# Install dependencies
pip install aiohttp beautifulsoup4 colorama robotexclusionrulesparser playwright dnspython

# Install Chromium for screenshots
playwright install chromium
</code>

---

## Usage

<code>
# Basic scan
python3 subx.py example.com

# With custom wordlist + screenshots
python3 subx.py tesla.com -w wordlists/subdomains.txt --screenshots -o tesla_scan

# Use built-in email or service subdomains
python3 subx.py target.com -w wordlists/email_subdomains.txt
</code>

### Arguments

| Flag | Description |
|------|-----------|
| `target` | Target domain (e.g. `example.com`) |
| `-w, --wordlist` | Path to custom wordlist |
| `--screenshots` | Capture homepage screenshots |
| `-o, --output` | Output directory (default: `subx_output`) |

---

## Output

<code>
subx_output/
├── results.json
└── screenshots/
    ├── www.example.com_.png
    ├── admin.example.com_login.png
    └── ...
</code>

---

## Wordlists (Included)

- `wordlists/email_subdomains.txt` – 50 email-related subdomains (`mail`, `webmail`, `smtp`, etc.)
- `wordlists/services_subdomains.txt` – 50 non-email services (`admin`, `api`, `grafana`, etc.)

> Add your own or use [SecLists](https://github.com/danielmiessler/SecLists)

---

## Example Wordlist Snippet

<code>
mail
webmail
smtp
admin
api
dev
staging
vpn
grafana
kibana
</code>

---

## Legal & Ethical Use

> **Only scan systems you have explicit permission to test.**  
> Unauthorized scanning may violate laws (CFAA, GDPR, etc.).

---

## Contributing

1. Fork it
2. Create your feature branch (<code>git checkout -b feature/new</code>)
3. Commit (<code>git commit -m 'Add new feature'</code>)
4. Push (<code>git push origin feature/new</code>)
5. Open a Pull Request

---

## License

[MIT License](LICENSE) – Free to use, modify, and distribute.

---

## Author

**Noob12345678900000**  
GitHub: [@Noob12345678900000](https://github.com/Noob12345678900000)

---

**Happy Hacking (Ethically)!**
