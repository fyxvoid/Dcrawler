"""
IOC (Indicator of Compromise) Extractor
Extracts structured intelligence artifacts from raw scraped text using regex.
"""
import re

# Private IPs / localhost that are false positives
_SKIP_IPV4 = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.0.1",
    "192.168.1.1", "10.0.0.1", "172.16.0.1",
}

PATTERNS: dict[str, re.Pattern] = {
    "onion_url": re.compile(
        r'\b(?:https?://)?[a-z2-7]{16,56}\.onion(?:/[^\s"<>]*)?',
        re.IGNORECASE,
    ),
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    "cve": re.compile(
        r'\bCVE-\d{4}-\d{4,7}\b',
        re.IGNORECASE,
    ),
    "bitcoin": re.compile(
        r'\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
    ),
    "ethereum": re.compile(
        r'\b0x[a-fA-F0-9]{40}\b'
    ),
    "monero": re.compile(
        r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    ),
    "sha256": re.compile(
        r'\b[a-fA-F0-9]{64}\b'
    ),
    "sha1": re.compile(
        r'\b[a-fA-F0-9]{40}\b'
    ),
    "md5": re.compile(
        r'\b[a-fA-F0-9]{32}\b'
    ),
}

_CONTEXT_WINDOW = 80  # chars of surrounding text for context


def _ctx(text: str, match: re.Match) -> str:
    s = max(0, match.start() - _CONTEXT_WINDOW)
    e = min(len(text), match.end() + _CONTEXT_WINDOW)
    return text[s:e].replace("\n", " ").strip()


def _is_hash_boundary_ok(text: str, match: re.Match) -> bool:
    """Return False if the match is embedded inside a longer hex string."""
    s, e = match.start(), match.end()
    if s > 0 and text[s - 1] in "0123456789abcdefABCDEF":
        return False
    if e < len(text) and text[e] in "0123456789abcdefABCDEF":
        return False
    return True


def extract_iocs(scraped: dict[str, str]) -> list[dict]:
    """
    Extract IOCs from {url: page_text} dict.
    Returns artifact dicts compatible with storage.save_artifacts().
    """
    seen: set[tuple[str, str]] = set()
    artifacts: list[dict] = []

    for url, text in scraped.items():
        if not text:
            continue
        src_tag = url[:70]

        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group().strip()
                key = (kind, value.lower())
                if key in seen:
                    continue

                # Kind-specific filters
                if kind == "ipv4" and value in _SKIP_IPV4:
                    continue
                if kind in ("md5", "sha1", "sha256") and not _is_hash_boundary_ok(text, match):
                    continue
                # SHA1 / MD5 lengths are subsets of longer patterns — skip if already found as sha256/sha1
                if kind == "sha1" and ("sha256", value.lower()) in seen:
                    continue
                if kind == "md5" and (
                    ("sha1", value.lower()) in seen or ("sha256", value.lower()) in seen
                ):
                    continue

                seen.add(key)
                artifacts.append({
                    "kind": kind,
                    "value": value,
                    "context": f"[src: {src_tag}] {_ctx(text, match)}",
                })

    return artifacts


# ── Threat Score ─────────────────────────────────────────────────────────────

_HIGH_RISK_KEYWORDS = [
    "ransomware", "zero-day", "0day", "breach", "leaked", "leak",
    "credential", "exploit", "apt", "malware", "backdoor", "c2",
    "command and control", "rootkit", "botnet", "phishing", "credential dump",
    "password dump", "database dump", "doxed", "doxxed", "ttp",
    "initial access", "exfiltration", "lateral movement", "privilege escalation",
]


def calculate_threat_score(
    ioc_count: int,
    scraped_text: str,
    result_count: int = 0,
    scrape_count: int = 0,
) -> int:
    """Return a 0-100 threat score based on IOC density and keyword signals."""
    score = 0

    # IOCs found (up to 30 points)
    score += min(ioc_count * 2, 30)

    # High-risk keyword hits (up to 40 points)
    text_lower = scraped_text.lower()
    kw_hits = sum(1 for kw in _HIGH_RISK_KEYWORDS if kw in text_lower)
    score += min(kw_hits * 4, 40)

    # Volume signals (up to 30 points)
    if result_count > 20:
        score += 10
    if result_count > 40:
        score += 5
    if scrape_count > 5:
        score += 10
    if scrape_count > 10:
        score += 5

    return min(score, 100)


def score_label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"
