#!/usr/bin/env python3
"""
IP Address Web Search Query Generator

Generates structured search queries to find an IP address's public footprint
across threat intelligence, geolocation, network tools, and more.

Can be used standalone or imported by ip_lookup.py (via --web-search flag).

Usage:
  python phone_web_search.py 192.168.1.1
  python phone_web_search.py 8.8.8.8 --open-browser
  python phone_web_search.py 2001:db8::1 -o json
"""

import argparse
import json
import re
import sys
import urllib.parse
import webbrowser


# ---------------------------------------------------------------------------
# IP address formatting
# ---------------------------------------------------------------------------
def format_ip_address(ip_address: str) -> list[str]:
    """
    Generates multiple format variants of an IP address
    so search queries cover how the address might appear online.
    """
    ip = ip_address.strip()
    formats = set()
    formats.add(ip)

    # Check if it's an IPv4 address
    ipv4_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip)
    if ipv4_match:
        octets = [int(o) for o in ipv4_match.groups()]
        # Standard dotted decimal
        standard = '.'.join(str(o) for o in octets)
        formats.add(standard)
        # Zero-padded format (e.g., 008.008.008.008)
        padded = '.'.join(f'{o:03d}' for o in octets)
        formats.add(padded)
        # With CIDR-style references commonly searched
        formats.add(f'{standard}/24')
        formats.add(f'{standard}/32')
        # Subnet (first three octets) for broader searches
        subnet = '.'.join(str(o) for o in octets[:3]) + '.*'
        formats.add(subnet)
        # Decimal/integer representation
        decimal_ip = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        formats.add(str(decimal_ip))
        # Hexadecimal representation
        hex_ip = f'0x{decimal_ip:08X}'
        formats.add(hex_ip)
    else:
        # IPv6 — add as-is and try a compressed/expanded form
        formats.add(ip)
        # Remove leading zeros in groups for compressed search
        compressed = re.sub(r'\b0+(\w)', r'\1', ip)
        formats.add(compressed)

    return sorted(formats)


# ---------------------------------------------------------------------------
# Search query generation
# ---------------------------------------------------------------------------

# Categories of sites to search
SITE_CATEGORIES = {
    "Threat Intelligence": [
        "virustotal.com",
        "abuseipdb.com",
        "threatcrowd.org",
        "alienvault.com",
        "talosintelligence.com",
        "threatminer.org",
        "ibm.com/xforce",
    ],
    "IP / Network Lookup": [
        "shodan.io",
        "censys.io",
        "ipinfo.io",
        "whatismyipaddress.com",
        "iplocation.net",
        "db-ip.com",
        "ipvoid.com",
    ],
    "Geolocation": [
        "maxmind.com",
        "ip-api.com",
        "iplocation.net",
        "geoiptool.com",
    ],
    "Blacklists / Reputation": [
        "spamhaus.org",
        "barracudacentral.org",
        "mxtoolbox.com",
        "multirbl.valli.org",
        "stopforumspam.com",
    ],
    "Paste / Data Leak Sites": [
        "pastebin.com",
        "justpaste.it",
        "ghostbin.com",
    ],
    "Forums / Community": [
        "reddit.com",
        "stackoverflow.com",
        "serverfault.com",
        "security.stackexchange.com",
    ],
}


def generate_search_queries(ip_formats: list[str]) -> list[dict]:
    """
    Builds a list of categorized Google-dork search queries.
    Returns list of dicts: {category, query, url}
    """
    queries = []
    seen = set()

    def add(category: str, query: str):
        if query not in seen:
            seen.add(query)
            url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)
            queries.append({"category": category, "query": query, "url": url})

    for fmt in ip_formats:
        quoted = f'"{fmt}"'

        # General web presence
        add("General", quoted)
        add("General", f'{quoted} intitle:"abuse" OR intitle:"report"')
        add("General", f'{quoted} intitle:"scan" OR intitle:"vulnerability"')
        add("General", f'{quoted} filetype:log')
        add("General", f'{quoted} filetype:csv')

        # Site-specific
        for category, sites in SITE_CATEGORIES.items():
            for site in sites:
                add(category, f'{quoted} site:{site}')

    return queries


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
SECTION_WIDTH = 70


def print_queries_text(ip_input: str, formats: list[str], queries: list[dict]):
    """Pretty-print the generated queries grouped by category."""
    print()
    print("=" * SECTION_WIDTH)
    print("  IP ADDRESS — WEB SEARCH QUERY GENERATOR")
    print("=" * SECTION_WIDTH)

    print(f"\n  Input IP:  {ip_input}")
    print(f"  Format variants searched ({len(formats)}):")
    for f in formats:
        print(f"    - {f}")

    # Group by category
    by_cat: dict[str, list[dict]] = {}
    for q in queries:
        by_cat.setdefault(q["category"], []).append(q)

    print(f"\n  Total queries generated: {len(queries)}")

    for cat, items in by_cat.items():
        print(f"\n--- {cat} ({len(items)} queries) {'-' * (SECTION_WIDTH - len(cat) - 16)}")
        for i, item in enumerate(items, 1):
            print(f"  {i:>3}. {item['query']}")
            print(f"       {item['url']}")

    print()
    print("=" * SECTION_WIDTH)
    print("  All queries target PUBLIC search engine results only.")
    print("  No private databases or restricted sources are accessed.")
    print("=" * SECTION_WIDTH)
    print()


def print_queries_json(ip_input: str, formats: list[str], queries: list[dict]):
    """Output queries as JSON."""
    output = {
        "input": ip_input,
        "formats": formats,
        "total_queries": len(queries),
        "queries": queries,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_web_search(ip_str: str, open_browser: bool = False,
                   output_format: str = "text") -> list[dict]:
    """
    Main entry point — generate and optionally display web search queries.
    Returns the list of query dicts for programmatic use.
    """
    formats = format_ip_address(ip_str)
    queries = generate_search_queries(formats)

    if output_format == "json":
        print_queries_json(ip_str, formats, queries)
    else:
        print_queries_text(ip_str, formats, queries)

    if open_browser:
        # Open just the top general queries (not all — that would be overwhelming)
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
            "  python phone_web_search.py 192.168.1.1\n"
            "  python phone_web_search.py 8.8.8.8 --open-browser\n"
            "  python phone_web_search.py 2001:db8::1 -o json\n"
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
    run_web_search(args.ip, open_browser=args.open_browser,
                   output_format=args.output)


if __name__ == "__main__":
    main()
