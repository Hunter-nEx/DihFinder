# 🔍 Dihfinder

### *Advanced Async Web Path Discovery & Fuzzing Scanner*

<p align="center">
  <strong>v3.1</strong> &nbsp;•&nbsp; Built by <a href="#-author">nEx</a> &nbsp;•&nbsp; Python 3.8+ &nbsp;•&nbsp; Single File
</p>

---

## 📖 Table of Contents

- [🎯 Introduction](#-introduction)
- [✨ Key Features](#-key-features)
- [⚙️ Installation](#️-installation)
- [🚀 Quick Start](#-quick-start)
- [📋 Command-Line Flags](#-command-line-flags)
- [🛠️ Common Scan Recipes](#️-common-scan-recipes)
- [📊 Output Formats](#-output-formats)
- [🚦 Severity Classification](#-severity-classification)
- [🧠 How False-Positive Filtering Works](#-how-false-positive-filtering-works)
- [⌨️ Ctrl+C Behavior](#-ctrlc-behavior)
- [📱 Termux (Android)](#-termux-android)
- [💡 Pro Tips](#-pro-tips)
- [⚖️ Legal & Ethical](#️-legal--ethical)
- [👤 Author](#-author)
- [📜 License](#-license)

---

## 🎯 Introduction

**Dihfinder** is a fast, async web path discovery and fuzzing tool built in pure Python. It scans any web target against a built-in list of **1,375+ real common paths** — covering admin panels, config files, `.env` secrets, backups, version-control folders (`.git`, `.svn`), API endpoints, CMS/framework-specific paths (WordPress, Laravel, Joomla, Drupal, Rails, Spring Actuator), and more.

What makes it different from a basic dirbuster:

- 🔄 **Multi-level scanning** — automatically recurses into discovered directories (`/admin/` → `/admin/config.php` → deeper), up to `--depth` levels, so you find paths that flat wordlists miss.
- 🛡️ **Zero false positives** — baseline random-path probing detects wildcard/soft-404 responses, boring login-redirects are filtered, tiny "not found" bodies are dropped, SPA shells and default server pages are detected. Only real findings reach your report.
- 🎨 **Severity-aware** — each finding is auto-classified `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` based on path name + HTTP status + body keywords (passwords, secrets, tokens, AWS keys, etc.).
- 📄 **Three report formats** — a beautiful self-contained dark-theme **HTML** report (sortable, filterable, clickable URLs), machine-readable **JSON**, and plain **TXT** for backwards compatibility.
- 🔧 **Pro features** — proxy support, custom headers/cookies for authenticated scans, status & size filters, Ctrl+C-safe partial saves, per-level throughput stats, and retry-with-backoff for flaky targets.

Single file, no external wordlist needed, runs anywhere Python + `aiohttp` + `rich` are installed (including Termux). Perfect for bug-bounty recon, pentest enumeration, or auditing your own exposed assets.

---

## ✨ Key Features

| Category | Features |
|---|---|
| 🔍 **Wordlist** | 1,375+ real common web paths built-in (admin, config, backup, API, CMS, version-control, framework-specific, etc.) |
| ⚡ **Async** | High-concurrency async I/O via `aiohttp` — 20+ threads default, tunable up to 100+ |
| 🔄 **Multi-level** | Auto-recurses into discovered directories up to `--depth` (default 3 → `/a/b/c`) |
| 🛡️ **Anti-false-positive** | 5-layer filtering: baseline wildcard detection, default-server-page detection, SPA-shell detection, HTML-404-in-200 detection, post-scan body-hash dedup |
| 🎨 **Severity** | Auto-classifies CRITICAL / HIGH / MEDIUM / LOW / INFO based on path + status + body keywords |
| 📊 **HTML report** | Dark theme, sortable columns, severity + status-code filter buttons, clickable URLs, print-friendly |
| 📄 **JSON report** | Full machine-readable output with metadata + per-level stats — perfect for `jq` / piping |
| 📝 **TXT report** | Plain text, one finding per line (backwards-compatible) |
| 🔧 **Proxy** | HTTP/HTTPS/SOCKS proxy support (`--proxy`) — works with Burp / ZAP / SOCKS5 |
| 🔑 **Auth** | Custom headers / cookies / Bearer tokens (`-H`, repeatable) for authenticated scans |
| 🎛️ **Filters** | `--include-status` (keep only certain codes), `--match-size` (keep only certain sizes) |
| ⌨️ **Safe interrupt** | Ctrl+C saves partial findings to whichever report format you specified |
| 📈 **Stats** | Per-level throughput (req/s), error count, dedup-removed count, total duration |
| 📦 **Single file** | No external wordlist, no compiled binaries, no config files — one script, anywhere |

---

## ⚙️ Installation

### Prerequisites

- **Python 3.8+**
- `aiohttp` and `rich` Python packages

### Install

```bash
pip install aiohttp rich
```

That's it. Clone the repo or just download `dihfinder.py` — it's a single self-contained file with the 1,375-path wordlist embedded.

```bash
https://github.com/nEx-Hrx/DihFinder/edit/main/README.md
cd dihfinder
python3 dihfinder.py --help
```

---

## 🚀 Quick Start

```bash
# Basic scan (prints to terminal only)
python3 dihfinder.py https://example.com

# Scan + generate HTML report
python3 dihfinder.py https://example.com --html report.html

# Deep scan with all 3 report formats
python3 dihfinder.py https://example.com -d 3 -t 30 \
  --html report.html --json report.json -o report.txt
```

The target can be with or without `http://` / `https://` — Dihfinder auto-prepends `http://` if missing.

---

## 📋 Command-Line Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `target` | — | *(required)* | Target URL (e.g. `https://example.com`) |
| `--threads N` | `-t N` | `20` | Concurrent request count |
| `--depth N` | `-d N` | `3` | Multi-level scan depth (`1` = root only, `2` = `/dir/x`, `3` = `/dir/x/y`) |
| `--timeout N` | — | `10` | Per-request timeout in seconds |
| `--extensions LIST` | `-x LIST` | *(none)* | Comma-separated extensions to also try (e.g. `php,html,bak`) |
| `--wordlist FILE` | `-w FILE` | *(built-in)* | Custom wordlist file (one path per line, `#` = comment) |
| `--ua STRING` | — | `Mozilla/5.0 (compatible; Dihfinder/3.1)` | Custom User-Agent |
| `--output FILE` | `-o FILE` | *(none)* | Save findings to a plain-text file |
| `--html FILE` | — | *(none)* | Generate a styled, sortable HTML report |
| `--json FILE` | — | *(none)* | Generate a machine-readable JSON report |
| `--proxy URL` | — | *(none)* | Route requests through HTTP/HTTPS/SOCKS proxy |
| `--header 'K: V'` | `-H 'K: V'` | *(none)* | Add a custom HTTP header (**repeatable**) |
| `--include-status LIST` | — | *(all)* | Only keep these status codes (e.g. `200,401,403`) |
| `--match-size LIST` | — | *(all)* | Only keep these response sizes (bytes). 401/403 always kept. |

---

## 🛠️ Common Scan Recipes

### ⚡ Quick recon (fast, shallow)

```bash
python3 dihfinder.py https://target.com -d 1 -t 30
```

Only scans root-level paths, 30 threads. Finishes in seconds.

### 🐢 Deep scan (thorough, slow)

```bash
python3 dihfinder.py https://target.com -d 3 -t 15 --timeout 15
```

Recurses 3 levels deep, fewer threads to be gentle, longer timeout for slow servers.

### 🐘 PHP target with extension brute

```bash
python3 dihfinder.py https://target.com -x php,bak,old,txt,zip --html report.html
```

Tries `admin`, `admin.php`, `admin.bak`, `admin.old`, `admin.txt`, `admin.zip` for every wordlist entry.

### 🪟 IIS / ASP.NET target

```bash
python3 dihfinder.py https://target.com -x aspx,asp,config,bak --html report.html
```

### 📊 Generate all 3 report formats

```bash
python3 dihfinder.py https://target.com \
  --html report.html --json report.json -o report.txt
```

### 🔑 Authenticated scan (with cookie / token)

```bash
python3 dihfinder.py https://target.com \
  -H "Cookie: session=abc123; csrftoken=xyz" \
  -H "Authorization: Bearer eyJhbGciOi..." \
  --html authed_report.html
```

### 🕵️ Through Burp Suite / ZAP proxy

```bash
python3 dihfinder.py https://target.com --proxy http://127.0.0.1:8080 --html report.html
```

### 🎯 Filter to only interesting statuses

```bash
python3 dihfinder.py https://target.com --include-status 200,401,403,500 --html report.html
```

Drops 301/302 noise, keeps auth gates (401/403) and server errors (500).

### 📝 Custom wordlist

```bash
python3 dihfinder.py https://target.com -w /path/to/mywordlist.txt --html report.html
```

Wordlist format: one path per line, blank lines and `#`-prefixed lines ignored.

---

## 📊 Output Formats

### 🎨 HTML Report (`--html`)

A self-contained dark-theme HTML file — no internet needed to view. Features:

- **Header** with `Dihfinder v3.1` branding + `developed by nEx` badge
- **8 stat cards**: Total Requests, Total Findings, Critical/High/Medium/Low/Info counts, Duration
- **Scan Metadata** block: target, host, date, duration, wordlist size, depth, concurrency, errors
- **Scan Levels Breakdown** table: per-level requests / findings / duration / throughput (req/s)
- **Findings table** with:
  - 🖱️ Click any column header to **sort** (severity / status / URL / size / time / keywords)
  - 🚦 **Severity filter buttons**: `ALL` / `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`
  - 🔢 **Status-code filter buttons**: `ALL` / `200 (10)` / `302 (1)` / `403 (3)` / ... — one per distinct status, each showing count
  - 🔍 **Text search box**: filter by URL / path / keyword
  - All three filters combine (e.g. `CRITICAL` + `200` + `admin` = critical 200s containing "admin")
  - 🔗 URLs are clickable (open in new tab)
  - 🎨 Color-coded severity badges and HTTP status pills (2xx green / 3xx yellow / 4xx orange / 5xx red)
- 🖨️ **Print-friendly**: press Ctrl+P, filters auto-hide

### 📄 JSON Report (`--json`)

```bash
python3 dihfinder.py https://target.com --json report.json
```

Perfect for piping into other tools, diffing scans over time, or SIEM ingestion. Structure:

```json
{
  "tool": "Dihfinder",
  "version": "3.1",
  "author": "nEx",
  "target": "https://target.com",
  "scan_date": "2026-07-10 14:30:00",
  "scan_duration_sec": 142.3,
  "total_requests": 16500,
  "total_findings": 28,
  "errors": 0,
  "severity_counts": {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 8, "LOW": 3, "INFO": 2},
  "level_stats": [
    {"level": 1, "requests": 1375, "findings": 23, "duration": 12.4},
    {"level": 2, "requests": 11000, "findings": 5, "duration": 89.1}
  ],
  "findings": [
    {
      "url": "https://target.com/.env",
      "path": ".env",
      "status": 200,
      "length": 247,
      "time": 0.21,
      "keywords": ["pwd", "secret", "aws"],
      "severity": "CRITICAL",
      "body_hash": "a1b2c3d4...",
      "body_preview": "DB_PASSWORD=hunter2\nAPI_KEY=sk_live_abc123..."
    }
  ]
}
```

**Quick `jq` examples:**

```bash
# All CRITICAL findings, just URLs
jq -r '.findings[] | select(.severity=="CRITICAL") | .url' report.json

# Count by status code
jq -r '.findings | group_by(.status) | map({status: .[0].status, count: length})' report.json

# Findings containing "admin" in path
jq -r '.findings[] | select(.path | test("admin")) | .url' report.json
```

### 📝 TXT Report (`-o`)

Plain text, one finding per line — backwards-compatible with classic dirb-style tools:

```
# Dihfinder v3.1 (by nEx)
# Target: https://target.com
# Requests: 16500 | Findings: 28 | Errors: 0
# Date: 2026-07-10 14:30:00

[CRITICAL] 200 https://target.com/.env size=247B time=0.21s kw=pwd,secret,aws
[CRITICAL] 200 https://target.com/wp-config.php size=184B time=0.18s kw=pwd,database
[HIGH] 403 https://target.com/admin/ size=9B time=0.15s kw=admin
```

---

## 🚦 Severity Classification

Dihfinder auto-assigns severity based on **path name + HTTP status + body keywords**:

| Severity | When it's assigned |
|---|---|
| 🔴 **CRITICAL** | 200 OK on a sensitive path (`.env`, `wp-config.php`, `.git/config`, `backup.sql`, etc.) OR body contains passwords / secrets / API keys / AWS credentials / private keys / tokens |
| 🟠 **HIGH** | 401/403 on a sensitive path, OR 200 OK on an admin/panel/login path |
| 🟡 **MEDIUM** | 401/403 on an admin path, OR HTTP 500 (server error = path exists but crashed) |
| 🔵 **LOW** | 401/403 on a generic path, OR interesting redirect (not to `/login`/`/`) |
| 🟢 **INFO** | 200 OK on a non-sensitive path with no body keywords |

---

## 🧠 How False-Positive Filtering Works

Dihfinder v3.1 uses **5 layers** of filtering to ensure zero fake results:

### Layer 1: Baseline Wildcard Detection
Before scanning, Dihfinder requests 5 random non-existent paths. If ≥3 return the same non-404 status, that status is flagged as "wildcard" and length-tolerance filtering widens to 20%.

### Layer 2: Default Server Page Detection
Drops Apache "It works!", Nginx "Welcome to nginx", IIS welcome pages — these are always fake findings.

### Layer 3: SPA Shell Detection
Drops React/Vue/Angular/Next/Nuxt `index.html` shells that get served for every unknown path by client-side routers. Requires 2+ SPA markers AND no sensitive keywords in body.

### Layer 4: HTML-404-in-200 Detection
Catches `<title>404`, `<title>Not Found`, "404 not found", "could not be found", "route not found", etc. — even when HTTP status is 200.

### Layer 5: Post-Scan Body-Hash Dedup
After the scan, groups all findings by body hash. If 3+ findings share the exact same body, they're dropped as a wildcard fingerprint. **Skips 401/403** (auth gates legitimately return identical "Forbidden" bodies — those ARE real findings).

---

## ⌨️ Ctrl+C Behavior

Pressing Ctrl+C mid-scan is safe:

- ✅ Partial findings are kept in memory
- ✅ If you passed `--html` / `--json` / `-o`, the partial report is still written
- ✅ You'll see `[!] Scan interrupted - saving partial results...`

```bash
python3 dihfinder.py https://target.com -d 3 --html report.html
# press Ctrl+C halfway through -> report.html still gets written with what was found so far
```

---

## 📱 Termux (Android)

```bash
pkg update && pkg install python
pip install aiohttp rich

# copy dihfinder.py to your storage, then:
python3 /storage/emulated/0/Music/dihfinder.py https://target.com \
  --html /storage/emulated/0/Music/report.html

# open report.html in Chrome / Firefox / any browser
```

---

## 💡 Pro Tips

### 🎛️ Tune threads for the target

| Target type | Recommended |
|---|---|
| Fast VPS / CDN | `-t 50` |
| Shared hosting | `-t 10` |
| Gov / edu / slow sites | `-t 5 --timeout 20` |

### 💾 Save all 3 formats every time

```bash
python3 dihfinder.py https://target.com --html r.html --json r.json -o r.txt
```

### 📅 Diff two scans over time (monitoring)

```bash
jq -r '.findings[].url' r.json | sort > urls_week1.txt
# ... one week later ...
jq -r '.findings[].url' r.json | sort > urls_week2.txt
diff urls_week1.txt urls_week2.txt   # new paths exposed?
```

### 🔑 Authenticated recon with cookie capture

```bash
# 1. log in via browser, copy cookie from devtools
python3 dihfinder.py https://target.com \
  -H "Cookie: PHPSESSID=abc123; wordpress_logged_in=admin" \
  --html authed_report.html -d 2
```

### 🎯 Skip 3xx noise, focus on actionable

```bash
python3 dihfinder.py https://target.com --include-status 200,401,403,500 --html r.html
```

---

## ⚖️ Legal & Ethical

> ⚠️ **Only scan hosts you own or have explicit written permission to test.**

Unauthorized scanning may violate:

- 🇺🇸 Computer Fraud and Abuse Act (CFAA) — US
- 🇬🇧 Computer Misuse Act — UK
- 🇮🇳 Information Technology Act — India
- 🌐 Similar laws in other jurisdictions

**Use for:**

- ✅ Bug bounty programs (within scope)
- ✅ Authorized penetration tests
- ✅ Auditing your own infrastructure
- ✅ Security research on intentionally vulnerable labs (HackTheBox, TryHackMe, OWASP Juice Shop)

---

## 👤 Author

**nEx** — independent security tooling developer.

- 🛠️ Tool: **Dihfinder v3.1**
- 🧱 Language: Python 3.8+
- 📦 Dependencies: `aiohttp`, `rich`
- 📄 License: MIT

> Built with ❤️ for the security community. Break things (legally).

---

## 📜 License

```
MIT License

Copyright (c) 2026 nEx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  <strong>Dihfinder v3.1</strong> &nbsp;•&nbsp; by <strong>nEx</strong><br>
  <sub>⭐ If this tool helped you, consider starring the repo.</sub>
</p>
