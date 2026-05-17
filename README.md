# Dcrawler

**AI-Powered Dark Web OSINT & Threat Intelligence Tool**

Dcrawler is a command-line OSINT framework that searches multiple Tor-based search engines simultaneously, scrapes hidden service pages, automatically extracts indicators of compromise (IOCs), and optionally uses a large language model to refine queries, filter noise, and write structured threat intelligence reports. All session data is stored in a locally encrypted SQLite database and is browsable through a built-in web dashboard.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [How It Works](#how-it-works)
3. [Architecture](#architecture)
4. [Features](#features)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Configuration](#configuration)
8. [Usage](#usage)
9. [All CLI Options](#all-cli-options)
10. [Analysis Presets](#analysis-presets)
11. [Supported LLM Models](#supported-llm-models)
12. [New Features In Depth](#new-features-in-depth)
13. [Web Dashboard](#web-dashboard)
14. [Docker](#docker)
15. [Storage and Encryption](#storage-and-encryption)
16. [Output Files](#output-files)
17. [Legal and Ethical Notice](#legal-and-ethical-notice)

---

## What It Does

Dcrawler is built for security researchers, threat intelligence analysts, and OSINT investigators who need to monitor dark web activity. Given a search query — for example `"ransomware group leaked data"` — it will:

1. Route all traffic through Tor so the investigation origin is anonymised
2. Query up to 16 onion search engines at the same time
3. Scrape the most relevant hidden service pages for raw content
4. Automatically extract structured IOCs (IPs, emails, crypto wallets, hashes, CVEs, .onion URLs) from every scraped page
5. Calculate a 0–100 threat score for the session based on IOC density and high-risk keyword signals
6. Optionally use an AI model to refine the query, filter results, and produce a structured intelligence report
7. Save everything — results, scraped content, IOCs, summaries — in a locally encrypted database
8. Generate HTML and plain-text reports you can share or archive
9. Display it all in a local web dashboard with tag filtering, session notes, and one-click exports

---

## How It Works

### The Pipeline

```
User query
    │
    ▼
[entrypoint.sh]
  └─ Checks if Tor is running, waits for bootstrap, then launches dcrawler.py
    │
    ▼
[LLM mode only] Query Refinement
  └─ The LLM rewrites the query into 5 words or fewer, optimised for dark web search engines
    │
    ▼
Concurrent Dark Web Search  (search.py)
  └─ ThreadPoolExecutor fans out to up to 16 onion search engines over Tor SOCKS5
  └─ Falls back to clearweb Ahmia proxy if all onion engines fail
  └─ Parses result links and titles from each engine's HTML response
  └─ Deduplicates by normalised URL
    │
    ▼
[LLM mode only] Result Filtering
  └─ LLM receives the full link list, selects up to 20 most relevant results
    │
    ▼
Concurrent Page Scraping  (scrape.py)
  └─ Threaded scraper fetches each page over Tor SOCKS5
  └─ Strips scripts/styles, extracts clean text, truncates to 2000 chars
  └─ Uses rotating user-agent strings and automatic retry with back-off
    │
    ▼
IOC Extraction  (ioc_extractor.py)  ← NEW
  └─ Regex scans every scraped page for: onion URLs, IPv4, emails,
     Bitcoin, Ethereum, Monero, MD5, SHA1, SHA256, CVEs
  └─ Deduplicates, filters false positives, captures surrounding context
  └─ Saves structured artifacts to the database
    │
    ▼
Threat Score  (ioc_extractor.py)  ← NEW
  └─ Scores 0–100 based on: IOC count, high-risk keyword density,
     result volume, and scrape volume
  └─ Labels: LOW / MEDIUM / HIGH / CRITICAL
    │
    ▼
[LLM mode only] Intelligence Summary
  └─ LLM receives all scraped content and generates a structured report
     using one of four analysis presets
    │
    ▼
Storage  (storage.py)
  └─ Session metadata, results, IOC artifacts, and AI summary stored in
     Fernet-encrypted SQLite — sensitive fields never written in plaintext
    │
    ▼
Reports  (reporter.py)
  └─ HTML and plain-text reports written to the reports/ directory
    │
    ▼
Dashboard  (dashboard.py)
  └─ Flask web UI — browse sessions, view scraped content and IOCs,
     download reports, export to JSON/CSV, filter by tag
```

### Tor Routing

All HTTP traffic to `.onion` addresses is routed through a SOCKS5 proxy at `127.0.0.1:9050`. The `entrypoint.sh` script starts the Tor daemon if it is not already running, waits up to 90 seconds for a complete bootstrap, then hands off to `dcrawler.py`. Clearweb addresses (used only as search-engine fallbacks) skip the proxy.

### Encryption

Scraped page content and AI-generated summaries are encrypted with **Fernet symmetric encryption** (AES-128-CBC + HMAC-SHA256) before being written to SQLite. The key is stored in `.dcrawler.key` with file permissions set to `600`. Only the running process can decrypt the data, and the key file is never committed to version control.

---

## Architecture

```
Dcrawler/
├── dcrawler.py        Main entry point — CLI parser, raw mode, LLM mode, bulk mode, export
├── search.py          Concurrent onion search engine queries over Tor
├── scrape.py          Threaded Tor-aware page scraper
├── llm.py             LLM orchestration — query refinement, result filtering, summary generation
├── llm_utils.py       Model registry — maps model names to LangChain classes and credentials
├── config.py          Loads and sanitises API keys from .env
├── storage.py         Encrypted SQLite persistence — sessions, results, artifacts, audit log, export
├── ioc_extractor.py   Regex-based IOC extraction and threat scoring          ← NEW
├── reporter.py        HTML and plain-text report generators + health checker
├── dashboard.py       Flask web dashboard with JSON API and export endpoints
├── health.py          Standalone health check module
├── entrypoint.sh      Tor bootstrap wrapper script
├── Dockerfile         Self-contained Docker image with Tor included
├── requirements.txt   Python dependencies
└── .env.example       Template for API keys and path overrides
```

---

## Features

| Feature | Description |
|---|---|
| **Dark web search** | Queries up to 16 onion search engines concurrently over Tor; falls back to clearweb Ahmia if all fail |
| **LLM query refinement** | AI rewrites your query for dark web search engines before searching |
| **LLM result filtering** | AI selects the top 20 most relevant results from the full result list |
| **LLM intelligence summary** | Structured report generated from scraped content using a configurable analysis preset |
| **Raw mode** | Search + scrape with zero API keys — no LLM required |
| **Auto IOC extraction** | Extracts IPs, emails, crypto addresses, file hashes, CVEs, .onion URLs from scraped pages |
| **Threat score** | 0–100 risk score (LOW / MEDIUM / HIGH / CRITICAL) per session |
| **Bulk query mode** | Process a file of queries in sequence with a single command |
| **JSON / CSV export** | Export any session or all sessions for SIEM or external tool integration |
| **Session tagging & notes** | Annotate investigations with tags and free-text notes; filter by tag in the dashboard |
| **Multiple LLM providers** | OpenAI, Anthropic, Google Gemini, OpenRouter, Ollama, llama.cpp |
| **Analysis presets** | `threat_intel`, `ransomware_malware`, `personal_identity`, `corporate_espionage` |
| **Encrypted storage** | Sensitive fields encrypted with Fernet before being written to SQLite |
| **Web dashboard** | Full Flask UI — sessions, scraped content, IOCs, report downloads, export, audit log |
| **HTML + text reports** | Per-session formatted reports saved to the `reports/` directory |
| **Docker support** | Single container with Tor included; pass API keys as environment variables |

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10 or newer | Tested on 3.10, 3.11, 3.12 |
| Tor | The `tor` package or Tor Browser bundle must be installed and reachable on port 9050 |
| LLM API key | Only required for LLM mode. Raw mode (`--no-llm`) needs no API key |

### Python dependencies

```
bs4              HTML parsing for search results and scraped pages
pysocks          SOCKS5 proxy support for Tor routing
requests         HTTP client used for scraping
python-dotenv    Loads .env configuration
langchain-openai     OpenAI provider for LangChain
langchain-ollama     Ollama (local) provider
langchain-anthropic  Anthropic provider
langchain_community  Community LLM integrations
langchain_google_genai  Google Gemini provider
cryptography     Fernet encryption for stored data
flask            Web dashboard
```

---

## Installation

### Step 1 — Install Tor

Tor must be installed on the host machine. The `entrypoint.sh` script will start it automatically if it is not already running.

**Debian / Ubuntu / Kali Linux:**
```bash
sudo apt update && sudo apt install -y tor
```

**macOS (Homebrew):**
```bash
brew install tor
```

**Arch Linux:**
```bash
sudo pacman -S tor
```

**Windows:**
Download and install the [Tor Expert Bundle](https://www.torproject.org/download/tor/) and ensure `tor.exe` is on your PATH.

---

### Step 2 — Clone the Repository

```bash
git clone https://github.com/your-username/Dcrawler.git
cd Dcrawler
```

---

### Step 3 — Create a Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate.bat     # Windows CMD
# .venv\Scripts\Activate.ps1     # Windows PowerShell
```

---

### Step 4 — Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Step 5 — Configure API Keys

```bash
cp .env.example .env
```

Open `.env` and fill in the keys for whichever providers you want to use:

```env
# OpenAI  (gpt-4.1, gpt-5-mini, gpt-5-nano, etc.)
OPENAI_API_KEY=sk-...

# Anthropic  (claude-sonnet-4-5, claude-sonnet-4-0)
ANTHROPIC_API_KEY=sk-ant-...

# Google Gemini  (gemini-2.5-flash, gemini-2.5-pro)
GOOGLE_API_KEY=AIza...

# OpenRouter  (access hundreds of models via one key)
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1

# Ollama local server  (llama3, mistral, etc.)
OLLAMA_BASE_URL=http://127.0.0.1:11434

# llama.cpp OpenAI-compatible local server
LLAMA_CPP_BASE_URL=http://127.0.0.1:8080

# Optional path overrides
DCRAWLER_DB=dcrawler.db
DCRAWLER_KEY=.dcrawler.key
DCRAWLER_REPORTS=reports
```

**You only need keys for the providers you actually use.** For `--no-llm` (raw) mode, no API keys are needed at all.

---

### Step 6 — Verify Installation

```bash
python dcrawler.py --health
```

Expected output when everything is working:

```
──────────────────────────────────────────────────
  SYSTEM HEALTH  [2026-05-17 13:56:09 UTC]
  Overall: HEALTHY
──────────────────────────────────────────────────
  ✓ TOR          UP        note=SOCKS5 proxy reachable
  ✓ DATABASE     UP        sessions=0  results=0  scraped=0
  ✓ REPORTS      UP        count=0  path=reports
──────────────────────────────────────────────────
```

If Tor shows as `DOWN`, make sure Tor is installed and the `entrypoint.sh` script has execute permission:

```bash
chmod +x entrypoint.sh
./entrypoint.sh --health
```

---

## Configuration

All settings are controlled through environment variables, which can be set in a `.env` file in the project root. The `.env` file is loaded automatically on startup.

### API Keys

| Variable | Provider | Required for |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI | GPT models |
| `ANTHROPIC_API_KEY` | Anthropic | Claude models |
| `GOOGLE_API_KEY` | Google | Gemini models |
| `OPENROUTER_API_KEY` | OpenRouter | Any model via OpenRouter |
| `OPENROUTER_BASE_URL` | OpenRouter | OpenRouter routing (default provided) |
| `OLLAMA_BASE_URL` | Ollama | Local Ollama models |
| `LLAMA_CPP_BASE_URL` | llama.cpp | Local llama.cpp server |

### Path Overrides

| Variable | Default | Purpose |
|---|---|---|
| `DCRAWLER_DB` | `dcrawler.db` | SQLite database file |
| `DCRAWLER_KEY` | `.dcrawler.key` | Fernet encryption key file |
| `DCRAWLER_REPORTS` | `reports` | Directory for HTML/text reports |

---

## Usage

### Recommended — Use the Entrypoint Script

The `entrypoint.sh` script handles Tor startup automatically. It checks whether Tor is already running on port 9050; if not, it starts the daemon, waits up to 90 seconds for a full bootstrap, then launches Dcrawler.

```bash
chmod +x entrypoint.sh
./entrypoint.sh "your search query"
```

Pass any `dcrawler.py` option after the query:

```bash
./entrypoint.sh "ransomware leaks" --no-llm --report both
./entrypoint.sh "stolen credentials" --preset threat_intel --report html
./entrypoint.sh "apt29 tools" --tag "apt,nation-state" --note "Client X incident"
```

---

### Direct Python (Tor must already be running on port 9050)

```bash
python dcrawler.py "ransomware leaks"
```

---

### Mode 1 — Raw Mode (no API key required)

Raw mode searches the dark web and scrapes pages without any LLM involvement. It runs IOC extraction and threat scoring on the scraped content and produces a links report and a content report.

```bash
# Basic raw search
./entrypoint.sh "credit card dumps" --no-llm

# More results, more scraping, both report formats
./entrypoint.sh "ransomware group" --no-llm --max-results 50 --max-scrape 10 --report both

# Tag the session and add an investigator note
./entrypoint.sh "leaked credentials site" --no-llm --tag "creds,breach" --note "Client A investigation"

# Skip IOC extraction (faster, useful for quick link collection)
./entrypoint.sh "dark web forums" --no-llm --no-ioc
```

**Raw mode output per session:**

```
[*] Mode: RAW (no LLM)  |  Query: 'ransomware leak site'
[*] Session ID: 004bf36e7030bc51925e0ba2
[*] Searching dark web (Tor required)...
[*] Found 236 unique links.
[*] Scraping content from 5 pages...
[*] Successfully scraped 5 pages.
[*] Extracting IOCs from scraped content...
[*] Found 14 IOCs (2 types).
[*] Threat Score: 62/100  [HIGH]
[*] Links report   → reports/links_004bf36e7030bc51925e0ba2.txt
[*] Content report → reports/content_004bf36e7030bc51925e0ba2.txt
[*] Links HTML     → reports/links_004bf36e7030bc51925e0ba2.html
[*] Content HTML   → reports/content_004bf36e7030bc51925e0ba2.html
[*] Raw investigation complete.
[*] View in dashboard: python dashboard.py → http://127.0.0.1:5000/session/004bf36e7030bc51925e0ba2
```

---

### Mode 2 — LLM Mode (default)

Full pipeline: AI query refinement → dark web search → AI result filtering → scraping → IOC extraction → AI intelligence summary.

```bash
# Default — auto-selects whichever LLM key is available in .env
./entrypoint.sh "ransomware leaks"

# Specify a preset and model
./entrypoint.sh "new ransomware group" --preset ransomware_malware -m claude-sonnet-4-5 --report both

# Identity / PII investigation
./entrypoint.sh "john doe email breach" --preset personal_identity --report html

# Corporate leak investigation with tag and note
./entrypoint.sh "company X source code leak" --preset corporate_espionage \
    --tag "corporate,ir" --note "Suspected insider threat — initial recon"
```

**LLM mode output per session:**

```
[*] Mode: LLM  |  Model: claude-sonnet-4-5  |  Preset: threat_intel
[*] Query: 'ransomware leaks'
[*] Refining query...
[*] Refined: 'ransomware leak data dump'
[*] Searching dark web (Tor required)...
[*] Found 183 unique results.
[*] Filtering results with LLM...
[*] Filtered to 12 relevant sources.
[*] Scraping 12 pages...
[*] Scraped 9 pages.
[*] Extracting IOCs from scraped content...
[*] Found 31 IOCs (5 types).
[*] Threat Score: 78/100  [CRITICAL]
[*] Generating intelligence summary...

============================================================
                    INTELLIGENCE FINDINGS
============================================================
1. Input Query: ransomware leaks
2. Source Links Referenced for Analysis
   ...
3. Investigation Artifacts
   ...
4. Key Insights
   ...
5. Next Steps
   ...
============================================================
```

---

### Mode 3 — Bulk Query Mode

Process a file containing multiple queries in sequence. Useful for batch investigations or automated monitoring workflows.

**Create a query file** (`queries.txt`):
```
# Lines starting with # are ignored
ransomware group new
leaked database credentials
zero day exploit sale
dark web carding forum
apt malware tools
```

**Run the bulk job:**
```bash
./entrypoint.sh --query-file queries.txt --no-llm --max-results 30 --max-scrape 5 \
    --report both --tag "batch-2026-05"
```

**Bulk summary output:**
```
[*] Bulk mode: 5 queries from queries.txt

============================================================
  [1/5] Query: ransomware group new
...
============================================================
  BULK SUMMARY  (5 sessions)
============================================================
  [HIGH       68]  a1b2c3d4e5f6a1b2c3d4e5f6  ransomware group new
  [MEDIUM     34]  b2c3d4e5f6a1b2c3d4e5f6a1  leaked database credentials
  [CRITICAL   82]  c3d4e5f6a1b2c3d4e5f6a1b2  zero day exploit sale
  [LOW        12]  d4e5f6a1b2c3d4e5f6a1b2c3  dark web carding forum
  [MEDIUM     41]  e5f6a1b2c3d4e5f6a1b2c3d4  apt malware tools
============================================================
```

---

### Mode 4 — Export

Export session data for use with SIEMs, spreadsheets, or other OSINT tools.

```bash
# Export a single session to JSON
python dcrawler.py --export 004bf36e7030bc51925e0ba2 --format json

# Export a single session to CSV
python dcrawler.py --export 004bf36e7030bc51925e0ba2 --format csv

# Export all sessions to CSV (one row per session)
python dcrawler.py --export all --format csv

# Export all sessions to JSON
python dcrawler.py --export all --format json
```

**JSON export structure:**
```json
{
  "session": {
    "session_id": "004bf36e...",
    "query": "ransomware leak site",
    "model": "none",
    "preset": "raw",
    "result_count": 30,
    "scrape_count": 5,
    "threat_score": 62,
    "tags": "live-test,ransomware",
    "notes": "Live Tor network test",
    "created_at": "2026-05-17T13:58:04+00:00",
    "finished_at": "2026-05-17T13:58:49+00:00",
    "summary": "..."
  },
  "results": [...],
  "artifacts": [...],
  "audit_log": [...]
}
```

**CSV export** contains two sections: Results (URL, title, scraped status) and IOC Artifacts (kind, value, context).

Export is also available from the dashboard via `GET /api/export/<session_id>?format=json|csv` and `GET /api/export/all?format=json|csv`, and via the **Download JSON / Download CSV** buttons on each session detail page.

---

### Utility Commands

```bash
# Check system health (Tor, database, reports directory)
python dcrawler.py --health

# Launch the web dashboard
python dcrawler.py --dashboard
# or directly:
python dashboard.py
```

---

## All CLI Options

```
python dcrawler.py [query] [options]
```

### Query options

| Option | Default | Description |
|---|---|---|
| `query` | — | Search query, e.g. `"ransomware leaks"` |
| `--query-file FILE` | — | File with one query per line; run all in sequence |

### Mode

| Option | Default | Description |
|---|---|---|
| `--no-llm` | off | Raw mode: search + scrape only, no LLM required |

### LLM options

| Option | Default | Description |
|---|---|---|
| `-m`, `--model MODEL` | auto | LLM model to use; omit to auto-select from `.env` keys |
| `--preset PRESET` | `threat_intel` | Analysis preset; see [Analysis Presets](#analysis-presets) |

### Search and scrape

| Option | Default | Description |
|---|---|---|
| `-t`, `--threads N` | `4` | Number of concurrent search and scrape threads |
| `--max-results N` | `50` | Maximum unique search results to collect |
| `--max-scrape N` | `10` | Maximum pages to fully scrape for content |

### Output

| Option | Default | Description |
|---|---|---|
| `--report FORMAT` | `both` | Report format: `html`, `txt`, `both`, or `none` |
| `--export ID\|all` | — | Export a session (or `all`) and exit; use with `--format` |
| `--format FORMAT` | `json` | Export format: `json` or `csv` |

### Investigation metadata

| Option | Default | Description |
|---|---|---|
| `--tag TAGS` | — | Comma-separated tags, e.g. `"apt,ransomware"` |
| `--note TEXT` | — | Free-text investigator note attached to this session |

### Storage

| Option | Default | Description |
|---|---|---|
| `--no-save` | off | Skip saving results to the database |
| `--no-ioc` | off | Skip automatic IOC extraction |

### Utility

| Option | Default | Description |
|---|---|---|
| `--health` | — | Show system health and exit |
| `--dashboard` | — | Launch the web dashboard and exit |

---

## Analysis Presets

Presets control the system prompt used during the LLM intelligence summary step. Each preset focuses the AI on a different threat type.

### `threat_intel` (default)

General-purpose threat intelligence. Extracts source links, investigation artifacts, key insights, and suggested next-steps for any dark web query.

**Output sections:**
- Source Links Referenced
- Investigation Artifacts (emails, IPs, crypto addresses, domains, threat actor info, malware names, TTPs)
- Key Insights (3–5 specific, evidence-based findings)
- Next Steps (follow-on queries and investigative actions)

### `ransomware_malware`

Focused on ransomware groups, malware families, and attack infrastructure.

**Output sections:**
- Source Links Referenced
- Malware / Ransomware Indicators (hashes, C2 servers, payload names, MITRE ATT&CK TTPs)
- Threat Actor Profile (group aliases, known victims, sector targeting)
- Key Insights
- Next Steps (hunting queries, detection rules, containment actions)

### `personal_identity`

Focused on PII exposure, identity theft, and doxxing.

**Output sections:**
- Source Links Referenced
- Exposed PII Artifacts (type, value, source context)
- Breach / Marketplace Sources Identified
- Exposure Risk Assessment
- Key Insights
- Next Steps (protective actions, further queries)

### `corporate_espionage`

Focused on corporate data leaks, insider threats, and competitive intelligence.

**Output sections:**
- Source Links Referenced
- Leaked Corporate Artifacts (credentials, source code, documents, databases)
- Threat Actor / Broker Activity
- Business Impact Assessment
- Key Insights
- Next Steps (IR actions, legal considerations, further investigation)

---

## Supported LLM Models

If you omit `-m`, Dcrawler auto-selects a model based on which API keys are present in `.env`.

| Provider | Model IDs |
|---|---|
| OpenAI | `gpt-4.1`, `gpt-5.1`, `gpt-5.2`, `gpt-5-mini`, `gpt-5-nano` |
| Anthropic | `claude-sonnet-4-5`, `claude-sonnet-4-0` |
| Google Gemini | `gemini-2.5-flash`, `gemini-2.5-flash-lite`, `gemini-2.5-pro` |
| OpenRouter | Any model slug from openrouter.ai (pass the exact slug as `-m`) |
| Ollama | Any model pulled locally, e.g. `llama3`, `mistral`, `gemma2` |
| llama.cpp | Any model served on the local llama.cpp HTTP server |

---

## New Features In Depth

### Auto IOC Extraction

After every scrape, Dcrawler scans each page for indicators of compromise using compiled regex patterns. Extracted IOCs are stored in the `artifacts` table and displayed in the dashboard and reports.

**Detected IOC types:**

| Type | Pattern |
|---|---|
| `.onion` URL | 16–56 base32 chars + `.onion` |
| IPv4 address | Standard dotted-quad, with false-positive filtering |
| Email address | RFC-like pattern |
| Bitcoin address | Legacy (`1…`, `3…`) and SegWit (`bc1…`) |
| Ethereum address | `0x` + 40 hex chars |
| Monero address | `4` + 93 base58 chars |
| SHA-256 hash | 64 hex chars, boundary-checked |
| SHA-1 hash | 40 hex chars, boundary-checked |
| MD5 hash | 32 hex chars, boundary-checked |
| CVE ID | `CVE-YYYY-NNNNN` format |

**False-positive suppression:**
- Private/loopback IPs (`127.0.0.1`, `0.0.0.0`, `192.168.x.x`) are filtered
- Hash patterns embedded inside longer hex strings are skipped
- Short hashes are skipped if already matched as a longer type

**Disable IOC extraction:**
```bash
python dcrawler.py "query" --no-ioc
```

---

### Threat Score

Each session receives a 0–100 threat score calculated from:

| Signal | Points |
|---|---|
| IOC count | +2 per IOC, capped at 30 |
| High-risk keyword hits | +4 per keyword (ransomware, zero-day, breach, botnet, APT, exfiltration, etc.), capped at 40 |
| Result count > 20 | +10 |
| Result count > 40 | +5 additional |
| Scrape count > 5 | +10 |
| Scrape count > 10 | +5 additional |
| Maximum | 100 |

**Score labels:**

| Score | Label |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

The score is shown in the CLI after each session, stored in the database, and displayed as a colour-coded badge in the dashboard (grey → LOW, blue → MEDIUM, yellow → HIGH, red → CRITICAL).

---

### Session Tagging & Notes

Attach searchable metadata to any investigation at the time of the run:

```bash
./entrypoint.sh "ransomware group" \
    --tag "apt,ransomware,client-a" \
    --note "Initial triage for incident IR-2026-0042"
```

- **Tags** are comma-separated strings stored in the database. The dashboard `/sessions` page shows tag badges and supports filtering: `/sessions?tag=apt` returns only sessions tagged with `apt`.
- **Notes** are free-text strings shown on the session detail page.
- Both are included in JSON and CSV exports.

---

### Bulk Query Mode

Run multiple queries from a plain-text file. Blank lines and lines beginning with `#` are ignored.

```bash
# queries.txt
# Threat actor monitoring
lockbit ransomware new victims
blackcat alphv leak
clop moveit targets

# Credential markets
combo list credit card 2026
stealer log telegram
```

```bash
./entrypoint.sh --query-file queries.txt --no-llm --threads 8 \
    --max-results 30 --max-scrape 5 --report both --tag "monthly-sweep"
```

Each query creates a separate session, artifacts, and reports. The final bulk summary table shows every session ID with its threat score label for quick triage.

---

### JSON / CSV Export

**Single session — JSON (full detail):**
```bash
python dcrawler.py --export <session_id> --format json
# writes: export_<session_id>.json
```

The JSON file contains four top-level keys: `session` (all metadata including tags, notes, threat score), `results` (all found links), `artifacts` (all IOCs with context), `audit_log` (session event history).

**Single session — CSV (structured):**
```bash
python dcrawler.py --export <session_id> --format csv
# writes: export_<session_id>.csv
```

The CSV file contains two sections: a Results table (URL, title, scraped status) and an IOC Artifacts table (kind, value, context).

**All sessions — CSV (summary):**
```bash
python dcrawler.py --export all --format csv
# writes: dcrawler_export_all.csv
```

One row per session: session_id, query, model, preset, result_count, scrape_count, threat_score, tags, notes, created_at, finished_at.

**All sessions — JSON (list):**
```bash
python dcrawler.py --export all --format json
# writes: dcrawler_export_all.json
```

---

## Web Dashboard

Launch the dashboard to browse all past investigations in a browser:

```bash
python dashboard.py
# or:
python dcrawler.py --dashboard
```

Open `http://127.0.0.1:5000` in your browser.

### Pages

| URL | Description |
|---|---|
| `/` | Summary stats (total sessions, links, scraped pages, artifacts) and recent investigations with threat score badges |
| `/sessions` | Full searchable, filterable list of all investigations with tags, threat scores, and status |
| `/sessions?tag=<tag>` | Filter sessions by tag |
| `/session/<id>` | Full investigation detail: AI summary, scraped content cards, IOC artifact table, all found links, download buttons |
| `/health` | Live status of Tor, database, and reports directory |
| `/audit` | Audit log of all session lifecycle events |

### Report Downloads

Each session detail page includes buttons to download:
- HTML intelligence report
- Plain-text intelligence report
- Session data as JSON
- Session IOCs and results as CSV

### JSON API

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Aggregate counts (sessions, results, scraped, artifacts) |
| `GET /api/health` | System health (Tor, DB, reports) |
| `GET /api/sessions` | List of all sessions (last 200) |
| `GET /api/session/<id>` | Full session detail including results and artifacts |
| `GET /api/export/<id>?format=json` | Download session as JSON |
| `GET /api/export/<id>?format=csv` | Download session as CSV |
| `GET /api/export/all?format=json` | Download all sessions as JSON list |
| `GET /api/export/all?format=csv` | Download all sessions as CSV summary |

---

## Docker

Build and run in a self-contained container. The Docker image includes Tor, so no separate Tor installation is needed on the host.

### Build

```bash
docker build -t dcrawler .
```

### Run — Raw mode (no API key required)

```bash
docker run --rm -it dcrawler "ransomware leaks" --no-llm --report both
```

### Run — LLM mode

```bash
docker run --rm -it \
  -e OPENAI_API_KEY=sk-... \
  dcrawler "stolen credentials" --preset threat_intel --report html
```

### Run — Persist reports and database

```bash
docker run --rm -it \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/dcrawler.db:/app/dcrawler.db" \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  dcrawler "apt group tools" --preset ransomware_malware
```

---

## Storage and Encryption

All investigation data is stored in a local SQLite database (`dcrawler.db` by default).

### What is stored

| Table | Contents |
|---|---|
| `sessions` | Query, model, preset, result/scrape counts, AI summary (encrypted), tags, notes, threat score, timestamps |
| `results` | Found URLs and titles; scraped page content (encrypted) |
| `artifacts` | Extracted IOCs with kind, value, and context |
| `audit_logs` | Session lifecycle events (SESSION_START, SESSION_COMPLETE, SESSION_ERROR, SESSION_DELETE) |

### Encryption

Sensitive fields — scraped page content and AI-generated summaries — are encrypted with **Fernet** (AES-128-CBC + HMAC-SHA256) before being written to disk. The encryption key is generated automatically on first run and saved to `.dcrawler.key` with file permissions set to `600`.

All dashboard and API reads decrypt the data transparently at the application layer.

### Security recommendations

- Never commit `.dcrawler.key` or `.env` to version control (both are in `.gitignore`)
- Store `.dcrawler.key` securely; losing it means losing access to previously encrypted data
- Use the `DCRAWLER_DB` environment variable to move the database to an encrypted volume
- Run with `--no-save` for one-off queries that should not be persisted

### Path overrides

```env
DCRAWLER_DB=/secure/volume/dcrawler.db
DCRAWLER_KEY=/secure/volume/.dcrawler.key
DCRAWLER_REPORTS=/secure/volume/reports
```

---

## Output Files

Reports are saved to the `reports/` directory (configurable with `DCRAWLER_REPORTS`).

### LLM mode reports

| File | Description |
|---|---|
| `report_<session_id>.html` | Full HTML intelligence report with summary, artifacts, source links |
| `report_<session_id>.txt` | Plain-text version of the same report |

### Raw mode reports

| File | Description |
|---|---|
| `links_<session_id>.html` | HTML table of all found links |
| `links_<session_id>.txt` | Plain-text links list |
| `content_<session_id>.html` | HTML cards with scraped page content |
| `content_<session_id>.txt` | Plain-text scraped content |

### Export files

| File | Description |
|---|---|
| `export_<session_id>.json` | Full session data (results, artifacts, audit log) |
| `export_<session_id>.csv` | Results + IOC artifacts in CSV format |
| `dcrawler_export_all.json` | All sessions as a JSON list |
| `dcrawler_export_all.csv` | All sessions summary in CSV format |

---

## Legal and Ethical Notice

Dcrawler is intended **exclusively for authorised security research, threat intelligence gathering, and OSINT investigations**. Use of this tool must comply with all applicable local, national, and international laws and regulations.

- **Do not use this tool to target individuals or organisations without explicit written authorisation.**
- Accessing dark web content may be restricted or illegal in certain jurisdictions. You are solely responsible for determining the legality of your use.
- Do not use Dcrawler to facilitate, assist, or enable any illegal activity.
- All findings and exported data should be handled in accordance with your organisation's data classification and handling policies.
- The authors accept no liability for misuse of this tool.

This tool is provided for **defensive and research purposes only**.
