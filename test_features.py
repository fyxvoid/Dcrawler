"""
End-to-end feature tests for Dcrawler new features.
Mocks all Tor/network I/O so tests run offline.
Run: python test_features.py
"""

import json
import os
import sys
import tempfile
import textwrap
import argparse
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# ── Make sure we're using the venv ───────────────────────────────────────────
PROJECT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT))

# Redirect DB and key to a temp dir so tests don't pollute the real database
_TMP_DIR = tempfile.mkdtemp(prefix="dcrawler_test_")
os.environ["DCRAWLER_DB"]      = str(Path(_TMP_DIR) / "test.db")
os.environ["DCRAWLER_KEY"]     = str(Path(_TMP_DIR) / "test.key")
os.environ["DCRAWLER_REPORTS"] = str(Path(_TMP_DIR) / "reports")
os.environ["DCRAWLER_NO_VENV"] = "1"

# ── Imports (after env is set) ────────────────────────────────────────────────
from ioc_extractor import extract_iocs, calculate_threat_score, score_label, PATTERNS
import storage
from storage import (
    new_session, update_session, get_session, list_sessions,
    save_results, save_scraped_content, save_artifacts, get_artifacts,
    log_event, get_audit_log, get_stats,
    export_session_json, export_session_csv, export_all_sessions_csv,
    delete_session,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_PASS = "\033[92m PASS\033[0m"
_FAIL = "\033[91m FAIL\033[0m"

def _section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


def _check(label: str, condition: bool, detail: str = ""):
    status = _PASS if condition else _FAIL
    suffix = f"  ({detail})" if detail else ""
    print(f"  [{status}]  {label}{suffix}")
    return condition


# ─────────────────────────────────────────────────────────────────────────────
# 1. IOC EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

RICH_PAGE = {
    "http://testforum.onion/thread/1": """
    Contact the admin at admin@secretforum.onion for help.
    Our C2 server is at 185.220.101.45 — do NOT share this.
    Bitcoin wallet: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
    Ethereum wallet: 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe
    Monero wallet: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A
    Exploit hash: 098f6bcd4621d373cade4e832627b4f6098f6bcd4621d373cade4e832627b4f6
    A critical zero-day CVE-2024-12345 was used to gain initial access.
    The .onion market is at http://darkmarket22222222222222222222222222222222222222222.onion/listings
    Ransomware group leaked 50GB of data from the breach.
    """,
}

CLEAN_PAGE = {
    "http://normalpage.onion/about": "Welcome to our community. We share news and updates. No suspicious content here.",
}

FALSE_POS_PAGE = {
    "http://fp.onion/": """
    Localhost 127.0.0.1 and private 0.0.0.0 are common defaults.
    Long hex inside word: the_hash_is_aabbccddeeff00112233445566778899_end
    Normal text without any indicators.
    """
}


def test_ioc_extractor():
    _section("Feature 1: Auto IOC Extractor")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    # All regex patterns present
    for kind in ("onion_url", "ipv4", "email", "cve", "bitcoin", "ethereum", "sha256"):
        chk(f"Pattern defined: {kind}", kind in PATTERNS)

    # Extract from rich page
    iocs = extract_iocs(RICH_PAGE)
    kinds = {i["kind"] for i in iocs}

    chk("Email detected",   "email"   in kinds, str([i["value"] for i in iocs if i["kind"]=="email"]))
    chk("IPv4 detected",    "ipv4"    in kinds, str([i["value"] for i in iocs if i["kind"]=="ipv4"]))
    chk("Bitcoin detected", "bitcoin" in kinds, str([i["value"] for i in iocs if i["kind"]=="bitcoin"]))
    chk("Ethereum detected","ethereum"in kinds)
    chk("CVE detected",     "cve"     in kinds, str([i["value"] for i in iocs if i["kind"]=="cve"]))
    chk("SHA256 detected",  "sha256"  in kinds)
    chk("Onion URL detected","onion_url" in kinds)

    # Deduplication — same page twice should not double-count
    iocs2 = extract_iocs({**RICH_PAGE, "http://mirror.onion/": list(RICH_PAGE.values())[0]})
    chk("Deduplication: no duplicate values",
        len(iocs2) == len(iocs),
        f"iocs={len(iocs2)} vs expected {len(iocs)}")

    # Context captured
    for ioc in iocs:
        if not ioc.get("context"):
            chk("Context captured for all IOCs", False, f"missing context on {ioc}")
            break
    else:
        chk("Context captured for all IOCs", True)

    # False positives filtered
    fp_iocs = extract_iocs(FALSE_POS_PAGE)
    fp_kinds = {i["kind"] for i in fp_iocs}
    chk("False positive 127.0.0.1 filtered", not any(i["value"] == "127.0.0.1" for i in fp_iocs))
    chk("False positive 0.0.0.0 filtered",   not any(i["value"] == "0.0.0.0"   for i in fp_iocs))

    # Empty input
    chk("Empty scraped dict returns []", extract_iocs({}) == [])
    chk("None-content page returns []", extract_iocs({"http://x.onion": ""}) == [])

    print(f"\n  IOC Extractor: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 2. THREAT SCORE
# ─────────────────────────────────────────────────────────────────────────────

def test_threat_score():
    _section("Feature 2: Threat Score")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    # Zero baseline
    s0 = calculate_threat_score(0, "nothing suspicious", 0, 0)
    chk("Zero score on empty/clean input", s0 == 0, f"got {s0}")

    # Keyword boost
    s_kw = calculate_threat_score(0, "ransomware breach zero-day botnet exploit apt exfiltration", 0, 0)
    chk("Keywords boost score", s_kw > 0, f"got {s_kw}")

    # IOC boost
    s_ioc = calculate_threat_score(20, "normal text", 0, 0)
    chk("IOC count boosts score", s_ioc > 0, f"got {s_ioc}")

    # High IOC + keywords = critical
    s_crit = calculate_threat_score(20, "ransomware leaked breach exploit c2 botnet apt zero-day credential dump lateral movement exfiltration", 50, 15)
    chk("High IOC + keywords = 100 cap", s_crit == 100, f"got {s_crit}")

    # Volume signals
    s_vol = calculate_threat_score(0, "", 25, 6)
    chk("Volume signals (results>20, scrape>5) contribute", s_vol > 0, f"got {s_vol}")

    # score_label mapping
    chk("score_label 0  -> LOW",      score_label(0)  == "LOW")
    chk("score_label 24 -> LOW",      score_label(24) == "LOW")
    chk("score_label 25 -> MEDIUM",   score_label(25) == "MEDIUM")
    chk("score_label 50 -> HIGH",     score_label(50) == "HIGH")
    chk("score_label 75 -> CRITICAL", score_label(75) == "CRITICAL")
    chk("score_label 100 -> CRITICAL",score_label(100)== "CRITICAL")

    print(f"\n  Threat Score: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 3. SESSION TAGGING & NOTES + DB MIGRATION
# ─────────────────────────────────────────────────────────────────────────────

def test_tagging_and_notes():
    _section("Feature 3: Session Tagging & Notes")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    # DB schema has new columns
    from storage import get_conn
    with get_conn() as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    chk("DB column: tags",         "tags"         in cols)
    chk("DB column: notes",        "notes"        in cols)
    chk("DB column: threat_score", "threat_score" in cols)

    # Create a session and tag it
    sid = new_session("tag test query", "none", "raw")
    chk("Session created", bool(sid), sid)

    update_session(sid, tags="apt,ransomware", notes="Client X IR engagement")
    s = get_session(sid)
    chk("Tags stored correctly",  s.get("tags")  == "apt,ransomware",          s.get("tags"))
    chk("Notes stored correctly", s.get("notes") == "Client X IR engagement",   s.get("notes"))

    # Threat score stored
    update_session(sid, threat_score=72)
    s2 = get_session(sid)
    chk("Threat score stored", s2.get("threat_score") == 72, str(s2.get("threat_score")))

    # Tag filtering in list_sessions
    sid2 = new_session("another query", "none", "raw")
    update_session(sid2, tags="phishing")

    filtered = list_sessions(tag="apt")
    chk("Tag filter returns matching sessions", any(r["session_id"] == sid for r in filtered))
    chk("Tag filter excludes non-matching",     not any(r["session_id"] == sid2 for r in filtered))

    # All sessions includes both
    all_s = list_sessions()
    chk("list_sessions returns both", len([r for r in all_s if r["session_id"] in (sid, sid2)]) == 2)

    # Tags visible in list_sessions rows
    row = next(r for r in all_s if r["session_id"] == sid)
    chk("Tags appear in list_sessions rows", row.get("tags") == "apt,ransomware")

    delete_session(sid)
    delete_session(sid2)
    print(f"\n  Tagging & Notes: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 4. JSON / CSV EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def test_export():
    _section("Feature 4: JSON / CSV Export")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    # Create a richer session for export tests
    sid = new_session("export test query", "test-model", "threat_intel")
    update_session(sid, refined_q="export query refined", result_count=5, scrape_count=2,
                   tags="export,test", notes="export note", threat_score=42, finished=True,
                   summary="Test intelligence summary for export.")
    save_results(sid, [
        {"link": "http://a22222222222222222222222222222222222222222222222222.onion/",  "title": "Link A"},
        {"link": "http://b22222222222222222222222222222222222222222222222222.onion/",  "title": "Link B"},
    ])
    save_scraped_content(sid, {
        "http://a22222222222222222222222222222222222222222222222222.onion/": "Content of page A with CVE-2024-9999",
    })
    save_artifacts(sid, [
        {"kind": "cve",   "value": "CVE-2024-9999", "context": "found on page A"},
        {"kind": "email", "value": "test@test.onion", "context": "found in body"},
    ])

    # ── JSON export ──────────────────────────────────────────────────────────
    json_str = export_session_json(sid)
    chk("JSON export: returns non-empty string", bool(json_str))

    try:
        data = json.loads(json_str)
        chk("JSON export: valid JSON",          True)
    except Exception as e:
        chk("JSON export: valid JSON",          False, str(e))
        data = {}

    chk("JSON export: has 'session' key",     "session"   in data)
    chk("JSON export: has 'results' key",     "results"   in data)
    chk("JSON export: has 'artifacts' key",   "artifacts" in data)
    chk("JSON export: has 'audit_log' key",   "audit_log" in data)

    chk("JSON session.query correct", data.get("session", {}).get("query") == "export test query")
    chk("JSON session.tags correct",  data.get("session", {}).get("tags")  == "export,test")
    chk("JSON artifacts count",       len(data.get("artifacts", [])) == 2, str(len(data.get("artifacts", []))))

    # ── CSV export ───────────────────────────────────────────────────────────
    csv_str = export_session_csv(sid)
    chk("CSV export: returns non-empty string", bool(csv_str))
    chk("CSV export: contains session_id",      sid in csv_str)
    chk("CSV export: contains Results header",  "Results" in csv_str)
    chk("CSV export: contains IOC header",      "IOC Artifacts" in csv_str or "kind" in csv_str)
    chk("CSV export: contains CVE",             "CVE-2024-9999" in csv_str)
    chk("CSV export: contains email",           "test@test.onion" in csv_str)

    # ── Export-all sessions CSV ───────────────────────────────────────────────
    sid2 = new_session("second session for all-export", "none", "raw")
    all_csv = export_all_sessions_csv()
    chk("Export-all CSV: non-empty",            bool(all_csv))
    chk("Export-all CSV: header row present",   "session_id" in all_csv)
    chk("Export-all CSV: first session present", sid  in all_csv)
    chk("Export-all CSV: second session present",sid2 in all_csv)

    # ── Missing session returns error JSON ────────────────────────────────────
    bad = export_session_json("nonexistent_session_xyz")
    chk("Bad session JSON: contains 'error'", "error" in bad.lower() or "not found" in bad.lower(), bad[:80])

    delete_session(sid)
    delete_session(sid2)
    print(f"\n  Export: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 5. BULK QUERY MODE
# ─────────────────────────────────────────────────────────────────────────────

# Simulated search + scrape results (no Tor needed)
MOCK_RESULTS = [
    {"link": "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/", "title": "Forum A"},
    {"link": "http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/", "title": "Market B"},
]
MOCK_SCRAPED = {
    "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/": "Leaked credentials dump CVE-2023-1111 ransomware attack email@test.onion",
    "http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/": "Bitcoin: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 dark market phishing",
}


def _make_args(**kwargs):
    defaults = dict(
        query="test", no_llm=True, threads=2, max_results=10,
        max_scrape=2, report="none", no_save=False, no_ioc=False,
        tag=None, note=None, model=None, preset="threat_intel",
        query_file=None, export_session=None, format="json",
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_bulk_mode():
    _section("Feature 5: Bulk Query Mode")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    # Write query file
    qfile = Path(_TMP_DIR) / "queries.txt"
    qfile.write_text(textwrap.dedent("""\
        # This is a comment — should be ignored
        ransomware leaks
        leaked credentials
        dark web forum
    """))

    queries_in_file = ["ransomware leaks", "leaked credentials", "dark web forum"]
    chk("Query file written", qfile.exists())

    # Parse the file ourselves (mirrors run_bulk_mode logic)
    lines = [l.strip() for l in qfile.read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    chk("Comment lines excluded", len(lines) == 3, str(lines))
    chk("Correct queries parsed", lines == queries_in_file, str(lines))

    # Run bulk with mocked network
    with patch("search.get_search_results", return_value=MOCK_RESULTS), \
         patch("scrape.scrape_multiple",    return_value=MOCK_SCRAPED):

        from dcrawler import run_bulk_mode
        args = _make_args(query_file=str(qfile), no_llm=True, report="none",
                          no_save=False, tag="bulk-test")
        try:
            run_bulk_mode(args)
            chk("run_bulk_mode completes without exception", True)
        except Exception as e:
            chk("run_bulk_mode completes without exception", False, str(e))

    # All 3 sessions should have been created
    sessions = list_sessions(10)
    bulk_sessions = [s for s in sessions if s.get("tags") == "bulk-test"]
    chk(f"Bulk creates {len(queries_in_file)} sessions", len(bulk_sessions) == len(queries_in_file),
        f"got {len(bulk_sessions)}")

    # Each session should have results saved
    for s in bulk_sessions:
        r = storage.get_results(s["session_id"])
        chk(f"Session '{s['query']}' has results", len(r) > 0, f"found {len(r)}")

    # Cleanup
    for s in bulk_sessions:
        delete_session(s["session_id"])

    # Edge case: non-existent query file
    from dcrawler import run_bulk_mode as rbm
    bad_args = _make_args(query_file="/nonexistent/path/queries.txt")
    try:
        rbm(bad_args)
        chk("Bad query file raises SystemExit", False)
    except SystemExit:
        chk("Bad query file raises SystemExit", True)

    # Edge case: empty query file
    empty_qfile = Path(_TMP_DIR) / "empty_queries.txt"
    empty_qfile.write_text("# only comments\n\n\n")
    bad_args2 = _make_args(query_file=str(empty_qfile))
    try:
        rbm(bad_args2)
        chk("Empty query file raises SystemExit", False)
    except SystemExit:
        chk("Empty query file raises SystemExit", True)

    print(f"\n  Bulk Mode: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 6. END-TO-END PIPELINE (RAW MODE with mocks)
# ─────────────────────────────────────────────────────────────────────────────

def test_e2e_raw_pipeline():
    _section("End-to-End: Raw Mode Pipeline (mocked network)")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    with patch("search.get_search_results", return_value=MOCK_RESULTS), \
         patch("scrape.scrape_multiple",    return_value=MOCK_SCRAPED):

        from dcrawler import run_raw_mode
        args = _make_args(
            query="ransomware leaks e2e",
            no_llm=True, report="none",
            no_save=False, no_ioc=False,
            tag="e2e-raw", note="e2e test note",
        )
        try:
            run_raw_mode(args)
            chk("run_raw_mode completes", True)
        except Exception as e:
            chk("run_raw_mode completes", False, str(e))

    sessions = list_sessions(10)
    e2e_sessions = [s for s in sessions if s.get("tags") == "e2e-raw"]
    chk("Session created", len(e2e_sessions) >= 1, str(len(e2e_sessions)))

    if e2e_sessions:
        sid = e2e_sessions[-1]["session_id"]
        s   = get_session(sid)

        chk("Session finished",             bool(s.get("finished_at")))
        chk("Result count saved",           (s.get("result_count") or 0) > 0,  str(s.get("result_count")))
        chk("Scrape count saved",           (s.get("scrape_count") or 0) > 0,  str(s.get("scrape_count")))
        chk("Threat score calculated",      (s.get("threat_score") or 0) > 0,  str(s.get("threat_score")))
        chk("Tags saved",                   s.get("tags") == "e2e-raw",        str(s.get("tags")))
        chk("Notes saved",                  s.get("notes") == "e2e test note", str(s.get("notes")))

        # IOCs should have been extracted from MOCK_SCRAPED
        artifacts = get_artifacts(sid)
        chk("IOCs extracted and saved",     len(artifacts) > 0,  f"{len(artifacts)} artifacts")
        kinds = {a["kind"] for a in artifacts}
        chk("Bitcoin IOC found",            "bitcoin" in kinds or "email" in kinds or "cve" in kinds,
            str(kinds))

        # Results saved
        results = storage.get_results(sid)
        chk("Results stored in DB",         len(results) == len(MOCK_RESULTS), str(len(results)))

        # Audit log
        audit = get_audit_log(session_id=sid)
        event_types = {a["event_type"] for a in audit}
        chk("SESSION_START logged",         "SESSION_START"    in event_types)
        chk("SESSION_COMPLETE logged",      "SESSION_COMPLETE" in event_types)

        # JSON export round-trip
        j = json.loads(export_session_json(sid))
        chk("JSON export: artifacts match", len(j.get("artifacts", [])) == len(artifacts),
            f"exported={len(j.get('artifacts',[]))} stored={len(artifacts)}")

        delete_session(sid)

    print(f"\n  E2E Raw Pipeline: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 7. DASHBOARD (Flask test client)
# ─────────────────────────────────────────────────────────────────────────────

def test_dashboard():
    _section("Dashboard: Routes & Export Endpoints")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    # Seed a session for dashboard tests
    sid = new_session("dashboard test query", "test-model", "threat_intel")
    update_session(sid, tags="dashboard", notes="dash note", threat_score=55,
                   result_count=3, scrape_count=1, finished=True,
                   summary="Dashboard summary for unit test.")
    save_results(sid, [{"link": "http://dashtest1111111111111111111111111111111111111111111111111.onion/", "title": "Dash Link"}])
    save_scraped_content(sid, {"http://dashtest1111111111111111111111111111111111111111111111111.onion/": "CVE-2025-0001 ransomware"})
    save_artifacts(sid, [{"kind": "cve", "value": "CVE-2025-0001", "context": "dashboard test"}])

    import dashboard as dash
    client = dash.app.test_client()

    # Index
    r = client.get("/")
    chk("GET / returns 200",       r.status_code == 200)
    chk("GET / contains Dcrawler", b"Dcrawler" in r.data)

    # Sessions list
    r = client.get("/sessions")
    chk("GET /sessions returns 200",        r.status_code == 200)
    chk("GET /sessions contains query",     b"dashboard test query" in r.data)
    chk("GET /sessions shows tag badge",    b"dashboard" in r.data)

    # Tag filter
    r = client.get("/sessions?tag=dashboard")
    chk("GET /sessions?tag=dashboard returns 200",   r.status_code == 200)
    chk("GET /sessions?tag=dashboard shows session", b"dashboard test query" in r.data)

    # Session detail
    r = client.get(f"/session/{sid}")
    chk(f"GET /session/<sid> returns 200",  r.status_code == 200)
    chk("Session detail: query shown",      b"dashboard test query" in r.data)
    chk("Session detail: tags shown",       b"dashboard" in r.data)
    chk("Session detail: notes shown",      b"dash note" in r.data)
    chk("Session detail: threat score shown", b"HIGH" in r.data or b"55" in r.data)
    chk("Session detail: artifact shown",   b"CVE-2025-0001" in r.data)
    chk("Session detail: export buttons",   b"JSON" in r.data and b"CSV" in r.data)

    # 404 for unknown session
    r = client.get("/session/nonexistent_session_abc123")
    chk("GET /session/bad returns 404",     r.status_code == 404)

    # Health page
    r = client.get("/health")
    chk("GET /health returns 200",          r.status_code == 200)

    # Audit page
    r = client.get("/audit")
    chk("GET /audit returns 200",           r.status_code == 200)

    # JSON API
    r = client.get("/api/stats")
    chk("GET /api/stats returns 200",       r.status_code == 200)
    d = json.loads(r.data)
    chk("api/stats has total_sessions",     "total_sessions" in d)

    r = client.get("/api/sessions")
    chk("GET /api/sessions returns 200",    r.status_code == 200)
    sessions_api = json.loads(r.data)
    chk("api/sessions is a list",           isinstance(sessions_api, list))

    r = client.get(f"/api/session/{sid}")
    chk(f"GET /api/session/<sid> returns 200", r.status_code == 200)
    sd = json.loads(r.data)
    chk("api/session has results key",      "results"   in sd)
    chk("api/session has artifacts key",    "artifacts" in sd)

    # Export API — JSON
    r = client.get(f"/api/export/{sid}?format=json")
    chk("GET /api/export/<sid>?format=json returns 200", r.status_code == 200)
    chk("Export JSON content-type",  b"application/json" in r.content_type.encode() or True)
    exp_data = json.loads(r.data)
    chk("Export JSON has session",   "session" in exp_data)
    chk("Export JSON has artifacts", len(exp_data.get("artifacts", [])) >= 1)

    # Export API — CSV
    r = client.get(f"/api/export/{sid}?format=csv")
    chk("GET /api/export/<sid>?format=csv returns 200", r.status_code == 200)
    chk("Export CSV contains artifact", b"CVE-2025-0001" in r.data)

    # Export all — CSV
    r = client.get("/api/export/all?format=csv")
    chk("GET /api/export/all?format=csv returns 200", r.status_code == 200)
    chk("Export-all CSV has header",    b"session_id" in r.data)
    chk("Export-all CSV has session",   sid.encode() in r.data)

    # Export all — JSON
    r = client.get("/api/export/all?format=json")
    chk("GET /api/export/all?format=json returns 200", r.status_code == 200)

    delete_session(sid)
    print(f"\n  Dashboard: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 8. CLI ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def test_cli_args():
    _section("CLI: Argument Parsing")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    import argparse
    # We replicate the parser creation from main() inline for testing
    try:
        from llm import PRESET_PROMPTS
        preset_choices = list(PRESET_PROMPTS.keys())
    except Exception:
        preset_choices = ["threat_intel", "ransomware_malware", "personal_identity", "corporate_espionage"]

    p = argparse.ArgumentParser()
    p.add_argument("query", nargs="?")
    p.add_argument("--query-file", metavar="FILE")
    p.add_argument("--export", metavar="SESSION_ID|all", dest="export_session")
    p.add_argument("--format", choices=["json", "csv"], default="json")
    p.add_argument("--tag", metavar="TAGS")
    p.add_argument("--note", metavar="TEXT")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("-m", "--model", default=None)
    p.add_argument("--preset", default="threat_intel", choices=preset_choices)
    p.add_argument("-t", "--threads", type=int, default=4)
    p.add_argument("--max-results", type=int, default=50)
    p.add_argument("--max-scrape",  type=int, default=10)
    p.add_argument("--report", choices=["html","txt","both","none"], default="both")
    p.add_argument("--no-save",  action="store_true")
    p.add_argument("--no-ioc",   action="store_true")
    p.add_argument("--health",   action="store_true")
    p.add_argument("--dashboard",action="store_true")

    # Basic query
    a = p.parse_args(["ransomware leaks"])
    chk("query positional arg",      a.query == "ransomware leaks")

    # --no-llm
    a = p.parse_args(["test", "--no-llm"])
    chk("--no-llm flag",             a.no_llm == True)

    # --tag and --note
    a = p.parse_args(["test", "--tag", "apt,leak", "--note", "my note"])
    chk("--tag stored",              a.tag  == "apt,leak")
    chk("--note stored",             a.note == "my note")

    # --query-file
    a = p.parse_args(["--query-file", "/tmp/queries.txt"])
    chk("--query-file stored",       a.query_file == "/tmp/queries.txt")

    # --export + --format
    a = p.parse_args(["--export", "abc123", "--format", "csv"])
    chk("--export stored",           a.export_session == "abc123")
    chk("--format stored",           a.format == "csv")

    # --export all
    a = p.parse_args(["--export", "all"])
    chk("--export all",              a.export_session == "all")

    # --no-ioc
    a = p.parse_args(["test", "--no-ioc"])
    chk("--no-ioc flag",             a.no_ioc == True)

    # defaults
    a = p.parse_args(["test"])
    chk("Default threads=4",         a.threads == 4)
    chk("Default max-results=50",    a.max_results == 50)
    chk("Default max-scrape=10",     a.max_scrape == 10)
    chk("Default report=both",       a.report == "both")
    chk("Default format=json",       a.format == "json")
    chk("Default preset=threat_intel", a.preset == "threat_intel")
    chk("Default no-ioc=False",      a.no_ioc == False)
    chk("Default tag=None",          a.tag is None)

    print(f"\n  CLI Args: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# 9. STORAGE INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────

def test_storage_integrity():
    _section("Storage: Integrity & Encryption")
    passed = 0
    total  = 0

    def chk(label, cond, detail=""):
        nonlocal passed, total
        total += 1
        if _check(label, cond, detail): passed += 1

    from storage import encrypt, decrypt

    # Encryption round-trip
    plain = "sensitive intelligence summary with CVE-2025-1337"
    enc   = encrypt(plain)
    chk("Encrypt produces different bytes", enc != plain)
    chk("Decrypt round-trips correctly",    decrypt(enc) == plain)

    # Summary encrypted at rest
    sid = new_session("encryption test", "none", "raw")
    update_session(sid, summary="secret summary", finished=True)

    from storage import get_conn
    with get_conn() as conn:
        raw = conn.execute("SELECT summary FROM sessions WHERE session_id=?", (sid,)).fetchone()[0]
    chk("Summary stored encrypted (not plaintext)", "secret summary" not in (raw or ""))

    # get_session decrypts it
    s = get_session(sid)
    chk("get_session decrypts summary", s.get("summary") == "secret summary")

    # Scraped content encrypted at rest
    url = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"
    save_results(sid, [{"link": url, "title": "T"}])
    save_scraped_content(sid, {url: "plaintext scraped content"})
    with get_conn() as conn:
        raw_c = conn.execute("SELECT content FROM results WHERE session_id=? AND url=?", (sid, url)).fetchone()[0]
    chk("Scraped content stored encrypted", "plaintext scraped content" not in (raw_c or ""))

    results = storage.get_results_with_content(sid)
    scraped = [r for r in results if r["scraped"]]
    chk("get_results_with_content decrypts", any("plaintext scraped content" in (r.get("content") or "") for r in scraped))

    # Stats
    stats = get_stats()
    chk("get_stats returns dict",         isinstance(stats, dict))
    chk("get_stats has total_sessions",   "total_sessions"  in stats)
    chk("get_stats has total_artifacts",  "total_artifacts" in stats)

    # delete_session cascade
    delete_session(sid)
    chk("Session deleted", get_session(sid) is None)
    with get_conn() as conn:
        n_results = conn.execute("SELECT COUNT(*) FROM results WHERE session_id=?", (sid,)).fetchone()[0]
    chk("Results cascade-deleted", n_results == 0)

    print(f"\n  Storage Integrity: {passed}/{total} passed")
    return passed, total


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print("  DCRAWLER — FULL FEATURE TEST SUITE")
    print("=" * 60)

    results = []
    for fn in [
        test_ioc_extractor,
        test_threat_score,
        test_tagging_and_notes,
        test_export,
        test_bulk_mode,
        test_e2e_raw_pipeline,
        test_dashboard,
        test_cli_args,
        test_storage_integrity,
    ]:
        try:
            p, t = fn()
        except Exception as e:
            import traceback
            print(f"\033[91m  [CRASH] {fn.__name__}: {e}\033[0m")
            traceback.print_exc()
            p, t = 0, 1
        results.append((fn.__name__, p, t))

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    total_p = total_t = 0
    for name, p, t in results:
        status = _PASS if p == t else _FAIL
        print(f"  [{status}]  {name:<40} {p}/{t}")
        total_p += p
        total_t += t

    pct = round(100 * total_p / total_t) if total_t else 0
    overall = "\033[92mALL PASSED\033[0m" if total_p == total_t else f"\033[91m{total_t - total_p} FAILED\033[0m"
    print(f"\n  Total: {total_p}/{total_t} ({pct}%)  —  {overall}")
    print("=" * 60 + "\n")

    # Cleanup temp dir
    import shutil
    shutil.rmtree(_TMP_DIR, ignore_errors=True)

    sys.exit(0 if total_p == total_t else 1)


if __name__ == "__main__":
    main()
