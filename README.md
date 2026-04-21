# Dcrawler

Dcrawler (formerly Robin) is an AI-Powered Dark Web OSINT Tool. 
It searches, scrapes, and uses an LLM to filter and summarize threat intelligence data from the dark web.

## Features
- **Complete CLI**: Streamlined command-line interface for fast and effective intelligence gathering.
- **Dark Web Search**: Searches multiple onion search engines concurrently using Tor.
- **LLM Integration**: Refines queries, filters irrelevant results, and generates actionable summaries based on user-defined threat intel presets.
- **Robust Scraping**: Reliable and threaded scraping of Tor hidden services.

## Setup
1. Ensure Tor is installed.
2. Install Python requirements: `pip install -r requirements.txt`
3. Configure your API keys in the `.env` file.

## Usage
Run via the entrypoint script:
```bash
./entrypoint.sh "ransomware leaks"
```
Or directly via Python (if Tor is already running on port 9050):
```bash
python3 dcrawler.py "ransomware leaks" -m <model_name>
```
