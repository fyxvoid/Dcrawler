import argparse
import sys
import os
from pathlib import Path

# --- Environment Awareness ---
def ensure_venv():
    """Ensure the script runs within the project's virtual environment."""
    # Find the project root (where .venv should be)
    project_root = Path(__file__).parent.resolve()
    venv_path = project_root / ".venv"
    venv_python = venv_path / "bin" / "python3"
    
    # If we are already in the venv, or no venv exists, just continue
    # sys.prefix changes when in a venv
    if sys.prefix == str(venv_path) or not venv_python.exists():
        return

    # If we are NOT in the venv but it exists, re-execute using venv python
    # Set an env var to avoid infinite recursion if something goes wrong
    if os.environ.get("_DCRAWLER_REEXEC") == "1":
        return

    os.environ["_DCRAWLER_REEXEC"] = "1"
    try:
        os.execv(str(venv_python), [str(venv_python)] + sys.argv)
    except Exception:
        # If execv fails, just continue and hope for the best
        pass

# Only attempt auto-switch if not explicitly disabled
if os.environ.get("DCRAWLER_NO_VENV") != "1":
    ensure_venv()

try:
    from dotenv import load_dotenv
    from llm import get_llm, refine_query, filter_results, generate_summary
    from search import get_search_results
    from scrape import scrape_multiple
    from llm_utils import get_model_choices
except ImportError as e:
    print(f"\n[!] Missing dependency: {e}")
    print("[!] Please ensure you are using the virtual environment.")
    print("[!] Try running: ./entrypoint.sh \"your query\"")
    print("[!] Or install dependencies: pip install -r requirements.txt")
    sys.exit(1)

# Load environment variables from .env
load_dotenv()

def main():
    # Fetch available models to show in help or use as default
    available_models = get_model_choices()
    default_model = "gpt-4.1" if "gpt-4.1" in available_models else (available_models[0] if available_models else None)

    parser = argparse.ArgumentParser(
        description="Dcrawler CLI: AI-Powered Dark Web OSINT Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("query", help="The dark web search query (e.g., 'ransomware leaks')")
    parser.add_argument("-m", "--model", default=default_model, help=f"LLM model to use. Available: {', '.join(available_models) if available_models else 'None'}")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent scraping/search threads")
    parser.add_argument("--max-results", type=int, default=50, help="Maximum raw search results to consider")
    parser.add_argument("--max-scrape", type=int, default=10, help="Maximum filtered results to scrape for content")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not args.model:
        print("Error: No LLM models available. Please check your .env file and API keys.")
        sys.exit(1)

    print(f"[*] Starting investigation for: '{args.query}'")
    print(f"[*] Using model: {args.model}")

    try:
        # 1. Initialize LLM
        llm = get_llm(args.model)

        # 2. Refine Query
        print("[*] Refining query for dark web search engines...")
        refined_query = refine_query(llm, args.query)
        print(f"[*] Refined query: '{refined_query}'")

        # 3. Search Dark Web
        print("[*] Searching dark web (Tor required)...")
        results = get_search_results(refined_query, max_workers=args.threads)
        print(f"[*] Found {len(results)} unique results.")

        if not results:
            print("[!] No results found. Try a different query.")
            return

        # Cap results
        if len(results) > args.max_results:
            results = results[:args.max_results]

        # 4. Filter Results
        print("[*] Filtering results using LLM...")
        filtered = filter_results(llm, refined_query, results)
        print(f"[*] Filtered down to {len(filtered)} relevant sources.")

        if not filtered:
            print("[!] LLM filtered out all results. Try a more specific query.")
            return

        # Cap filtered results
        if len(filtered) > args.max_scrape:
            filtered = filtered[:args.max_scrape]

        # 5. Scrape Content
        print(f"[*] Scraping content from {len(filtered)} pages...")
        scraped_content = scrape_multiple(filtered, max_workers=args.threads)
        print(f"[*] Successfully scraped {len(scraped_content)} pages.")

        if not scraped_content:
            print("[!] Failed to scrape any content. Check your Tor connection.")
            return

        # 6. Generate Summary
        print("[*] Generating intelligence summary...")
        # Use default 'threat_intel' preset for CLI
        summary = generate_summary(llm, args.query, scraped_content)

        print("\n" + "="*60)
        print("                      INTELLIGENCE FINDINGS")
        print("="*60)
        print(summary)
        print("="*60)
        print(f"\n[*] Investigation complete.")

    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
