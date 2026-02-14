#!/usr/bin/env python3
"""
IP Address Web Search Query Generator

Generates structured search queries to find an IP address's public footprint
across threat intelligence platforms, abuse databases, WHOIS registries,
paste sites, and more.

Usage:
  python ip_web_search.py 8.8.8.8
  python ip_web_search.py 192.168.1.1 --open-browser
  python ip_web_search.py 24.189.157.220 -o json
"""

import argparse
import json
import re
import sys
import urllib.parse
import webbrowser


# ---------------------------------------------------------------------------
# IP address validation
# ---------------------------------------------------------------------------
def is_valid_ipv4(ip: str) -> bool:
    """Check whether a string is a valid IPv4 address."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True


def is_valid_ipv6(ip: str) -> bool:
    """Basic check for IPv6 address format."""
    pattern = re.compile(
        r"^("
        r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"          # full
        r"([0-9a-fA-F]{1,4}:){1,7}:|"                         # trailing ::
        r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"        # ::x
        r"::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|"       # leading ::
        r"::)$"
    )
    return bool(pattern.match(ip.strip()))


def validate_ip(ip: str) -> str:
    """Validate and return the IP address, or raise ValueError."""
    ip = ip.strip()
    if is_valid_ipv4(ip) or is_valid_ipv6(ip):
        return ip
    raise ValueError(f"Invalid IP address: {ip}")


# ---------------------------------------------------------------------------
# Search query generation
# ---------------------------------------------------------------------------

SITE_CATEGORIES = {
    "Threat Intelligence": [
        "abuseipdb.com",
        "virustotal.com",
        "shodan.io",
        "greynoise.io",
        "talosintelligence.com",
        "threatcrowd.org",
        "otx.alienvault.com",
        "censys.io",
    ],
    "WHOIS / Registry": [
        "whois.com",
        "arin.net",
        "ripe.net",
        "apnic.net",
        "lacnic.net",
        "afrinic.net",
    ],
    "Blacklists / Reputation": [
        "mxtoolbox.com",
        "spamhaus.org",
        "barracudacentral.org",
        "projecthoneypot.org",
    ],
    "Paste / Data Leak Sites": [
        "pastebin.com",
        "pastie.org",
        "justpaste.it",
    ],
    "Forums / Abuse Reports": [],  # handled by special queries below
}


def generate_search_queries(ip_address: str) -> list[dict]:
    """
    Build a list of categorized Google-dork search queries for an IP address.
    Returns list of dicts: {category, query, url}
    """
    queries: list[dict] = []
    seen: set[str] = set()
    quoted = f'"{ip_address}"'

    def add(category: str, query: str):
        if query not in seen:
            seen.add(query)
            url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)
            queries.append({"category": category, "query": query, "url": url})

    # General web presence
    add("General", quoted)
    add("General", f'{quoted} intitle:"forum" OR intitle:"abuse" OR intitle:"blacklist"')
    add("General", f'{quoted} intitle:"log" OR intitle:"scan" OR intitle:"report"')
    add("General", f'{quoted} filetype:log OR filetype:csv OR filetype:txt')

    # Site-specific
    for category, sites in SITE_CATEGORIES.items():
        for site in sites:
            add(category, f'{quoted} site:{site}')

    # Forums / Abuse Reports (keyword-based, not site-specific)
    add("Forums / Abuse Reports", f'{quoted} "abuse report" OR "spam report"')
    add("Forums / Abuse Reports", f'{quoted} "port scan" OR "brute force" OR "intrusion"')
    add("Forums / Abuse Reports", f'{quoted} site:reddit.com')
    add("Forums / Abuse Reports", f'{quoted} site:stackoverflow.com OR site:serverfault.com')

    return queries


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
SECTION_WIDTH = 70


def print_queries_text(ip_address: str, queries: list[dict]):
    """Pretty-print the generated queries grouped by category."""
    print()
    print("=" * SECTION_WIDTH)
    print("  IP ADDRESS — WEB SEARCH QUERY GENERATOR")
    print("=" * SECTION_WIDTH)

    print(f"\n  Target IP:  {ip_address}")

    # Group by category
    by_cat: dict[str, list[dict]] = {}
    for q in queries:
        by_cat.setdefault(q["category"], []).append(q)

    print(f"  Total queries generated: {len(queries)}")

    for cat, items in by_cat.items():
        print(f"\n--- {cat} ({len(items)} queries) {'-' * max(0, SECTION_WIDTH - len(cat) - 16)}")
        for i, item in enumerate(items, 1):
            print(f"  {i:>3}. {item['query']}")
            print(f"       {item['url']}")

    print()
    print("=" * SECTION_WIDTH)
    print("  All queries target PUBLIC search engine results only.")
    print("  No private databases or restricted sources are accessed.")
    print("=" * SECTION_WIDTH)
    print()


def print_queries_json(ip_address: str, queries: list[dict]):
    """Output queries as JSON."""
    output = {
        "input": ip_address,
        "total_queries": len(queries),
        "queries": queries,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_web_search(ip_address: str, open_browser: bool = False,
                   output_format: str = "text") -> list[dict]:
    """
    Main entry point — generate and optionally display web search queries.
    Returns the list of query dicts for programmatic use.
    """
    ip_address = validate_ip(ip_address)
    queries = generate_search_queries(ip_address)

    if output_format == "json":
        print_queries_json(ip_address, queries)
    else:
        print_queries_text(ip_address, queries)

    if open_browser:
        general = [q for q in queries if q["category"] == "General"][:3]
        for q in general:
            webbrowser.open(q["url"])

    return queries


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate public web search queries for an IP address.",
        epilog=(
            "Examples:\n"
            "  python ip_web_search.py 8.8.8.8\n"
            "  python ip_web_search.py 24.189.157.220 --open-browser\n"
            "  python ip_web_search.py 192.168.1.1 -o json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "ip",
        help="IP address to search for (IPv4 or IPv6)",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open top search queries in your default web browser",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        run_web_search(args.ip, open_browser=args.open_browser,
                       output_format=args.output)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
