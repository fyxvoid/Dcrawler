# Dcrawler

**AI-Powered Dark Web OSINT Tool**

Dcrawler searches multiple Tor-based search engines, scrapes hidden service pages, and uses an LLM to refine queries, filter noise, and generate actionable threat intelligence summaries. All session data is stored in an encrypted local SQLite database and viewable through a web dashboard.

---

## Features

| Feature | Description |
|---|---|
| Dark web search | Queries multiple onion search engines concurrently over Tor |
| LLM integration | Refines queries, filters irrelevant results, and writes intelligence summaries |
| Raw (no-LLM) mode | Search + scrape with zero API keys required |
| Multiple LLM providers | OpenAI, Anthropic, Google Gemini, OpenRouter, Ollama, llama.cpp |
| Analysis presets | `threat_intel`, `ransomware_malware`, `personal_identity`, `corporate_espionage` |
| Encrypted storage | All results and summaries stored in Fernet-encrypted SQLite |
| Web dashboard | Flask UI to browse sessions, scraped content, and audit logs |
| Report export | HTML and plain-text reports per investigation |

---

## Requirements

- Python 3.10+
- Tor (`tor` package or Tor Browser bundle)
- An API key for at least one LLM provider (only needed for LLM mode)

---

## Installation

### 1. Install Tor

**Debian / Ubuntu / Kali:**
```bash
sudo apt install tor
```

**macOS:**
```bash
brew install tor
```

### 2. Clone and set up Python environment

```bash
git clone <repo-url>
cd Dcrawler

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure API keys

Copy the example env file and fill in the keys for providers you want to use:

```bash
cp .env.example .env
```

Edit `.env`:

```env
# OpenAI
OPENAI_API_KEY=sk-...

# Anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Google Gemini
GOOGLE_API_KEY=...

# OpenRouter (access to many models via one key)
OPENROUTER_API_KEY=...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1

# Local models — leave base URLs empty to use defaults
OLLAMA_BASE_URL=http://127.0.0.1:11434
LLAMA_CPP_BASE_URL=
```

Only the keys for providers you use are required. For `--no-llm` (raw) mode, no keys are needed at all.

---

## Usage

### Recommended: use the entrypoint script

The script starts Tor automatically if it is not already running, waits for full bootstrap, then launches Dcrawler.

```bash
chmod +x entrypoint.sh
./entrypoint.sh "your search query"
```

Pass any `dcrawler.py` flags after the query:

```bash
./entrypoint.sh "ransomware leaks" --no-llm --report both
./entrypoint.sh "stolen credentials" --preset threat_intel --report html
```

### Direct Python (Tor must already be on port 9050)

```bash
python dcrawler.py "ransomware leaks"
```

---

## Modes

### LLM mode (default)

Full pipeline: query refinement → search → LLM filtering → scrape → AI summary.

```bash
./entrypoint.sh "ransomware leaks"
./entrypoint.sh "ransomware leaks" --preset ransomware_malware --report both
./entrypoint.sh "leaked credentials" -m claude-sonnet-4-5 --report html
```

Requires at least one API key in `.env`.

### Raw mode (`--no-llm`)

Search and scrape only — no API key needed. Produces two separate output files: a links report and a content report.

```bash
./entrypoint.sh "dark web forums" --no-llm
./entrypoint.sh "dark web forums" --no-llm --report both --max-results 30
```

---

## All CLI Options

```
python dcrawler.py [query] [options]
```

| Option | Default | Description |
|---|---|---|
| `query` | — | Search query (required unless using `--health` or `--dashboard`) |
| `--no-llm` | off | Raw mode: search + scrape only, no LLM |
| `-m`, `--model` | auto | LLM model to use (auto-selects from available keys) |
| `--preset` | `threat_intel` | Analysis preset for LLM summary |
| `-t`, `--threads` | `4` | Concurrent search/scrape threads |
| `--max-results` | `50` | Max search results to collect |
| `--max-scrape` | `10` | Max pages to scrape for content |
| `--report` | `both` | Report format: `html`, `txt`, `both`, or `none` |
| `--no-save` | off | Skip saving results to the local database |
| `--health` | — | Show system health status and exit |
| `--dashboard` | — | Launch the web dashboard and exit |

### Analysis presets (`--preset`)

| Preset | Use case |
|---|---|
| `threat_intel` | General threat intelligence gathering (default) |
| `ransomware_malware` | Ransomware groups, malware campaigns, leak sites |
| `personal_identity` | PII exposure, identity theft, doxxing |
| `corporate_espionage` | Data breaches, insider threats, corporate leaks |

### Supported models (`-m`)

| Provider | Example model IDs |
|---|---|
| OpenAI | `gpt-4.1`, `gpt-5-mini` |
| Anthropic | `claude-sonnet-4-5`, `claude-sonnet-4-0` |
| Google | `gemini-2.5-flash`, `gemini-2.5-pro` |
| OpenRouter | Any model slug from openrouter.ai |
| Ollama | Any model pulled locally, e.g. `llama3`, `mistral` |
| llama.cpp | Any model served on the local llama.cpp HTTP server |

Omit `-m` to let Dcrawler auto-select from whichever keys are present in `.env`.

---

## Examples

```bash
# Raw mode — no API key, saves links + content reports
./entrypoint.sh "credit card dumps" --no-llm --report both

# Threat intel with default model, HTML report
./entrypoint.sh "new ransomware group" --preset threat_intel --report html

# Identity investigation with a specific Anthropic model
./entrypoint.sh "john doe email leak" --preset personal_identity -m claude-sonnet-4-5

# Quick search, no storage, no reports
./entrypoint.sh "zero day exploits" --no-save --report none

# Check system health (Tor, database, reports directory)
python dcrawler.py --health

# Open the web dashboard
python dcrawler.py --dashboard
```

---

## Web Dashboard

Launch the dashboard to browse all past investigations:

```bash
python dashboard.py
# or
python dcrawler.py --dashboard
```

Open `http://127.0.0.1:5000` in a browser.

**Dashboard pages:**

| URL | Description |
|---|---|
| `/` | Summary statistics and recent investigations |
| `/sessions` | Full list of all investigations (searchable) |
| `/session/<id>` | Individual session: summary, scraped content, links, artifacts |
| `/health` | Live status of Tor, database, and reports directory |
| `/audit` | Audit log of all session events |

**Report downloads** are available on each session page (HTML and text).

**JSON API:**

```
GET /api/stats
GET /api/health
GET /api/sessions
GET /api/session/<id>
```

---

## Docker

Build and run in a self-contained container (Tor included):

```bash
docker build -t dcrawler .
docker run --rm -it dcrawler "ransomware leaks" --no-llm
docker run --rm -it -e OPENAI_API_KEY=sk-... dcrawler "stolen data" --preset threat_intel
```

---

## Storage and encryption

All data is persisted in a local SQLite database (`dcrawler.db` by default). Sensitive fields (scraped content, AI summaries) are encrypted with Fernet symmetric encryption. The key is stored in `.dcrawler.key` (created automatically on first run, permissions set to `600`).

Override paths via environment variables:

```env
DCRAWLER_DB=dcrawler.db
DCRAWLER_KEY=.dcrawler.key
DCRAWLER_REPORTS=reports
```

Never commit `.dcrawler.key` or `.env` to version control.

---

## Output files

Reports are saved to the `reports/` directory (configurable with `DCRAWLER_REPORTS`):

| File pattern | Description |
|---|---|
| `report_<session_id>.html` | LLM mode HTML report |
| `report_<session_id>.txt` | LLM mode text report |
| `links_<session_id>.html` | Raw mode links HTML |
| `links_<session_id>.txt` | Raw mode links text |
| `content_<session_id>.html` | Raw mode content HTML |
| `content_<session_id>.txt` | Raw mode content text |

---

## Legal and ethical notice

Dcrawler is intended for **authorized security research, threat intelligence, and OSINT investigations only**. Accessing dark web content may be illegal in some jurisdictions. You are solely responsible for ensuring your use complies with applicable laws and your organization's policies. Do not use this tool to target individuals or organizations without proper authorization.
