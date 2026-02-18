#!/usr/bin/env python3
"""
Person Name OSINT Web Search Query Generator

Generates structured search queries to find a person's public footprint
across social media, directories, public records, device identifiers, and more.

All searches target publicly available information only.

Usage:
  python name_search.py "John Smith"
  python name_search.py "Jane Doe" --location "Chicago, IL" --address "123 Main St"
  python name_search.py "John Smith" --proxy http://127.0.0.1:8080
  python name_search.py "John Smith" -o json
  python name_search.py "John Smith" --open-browser
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
import webbrowser


# ---------------------------------------------------------------------------
# Site categories
# ---------------------------------------------------------------------------
SITE_CATEGORIES = {
    "Social Media": [
        "facebook.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "instagram.com",
        "reddit.com",
        "pinterest.com",
        "tiktok.com",
        "nextdoor.com",
    ],
    "Business Directories": [
        "yelp.com",
        "bbb.org",
        "yellowpages.com",
        "manta.com",
        "chamberofcommerce.com",
    ],
    "People / Public Records": [
        "whitepages.com",
        "truepeoplesearch.com",
        "fastpeoplesearch.com",
        "spokeo.com",
        "beenverified.com",
        "thatsThem.com",
        "411.com",
    ],
    "Paste / Data Leak Sites": [
        "pastebin.com",
        "justpaste.it",
        "ghostbin.com",
    ],
    "Court / Government Records": [
        "publicrecords.searchsystems.net",
        "judyrecords.com",
    ],
}


# ---------------------------------------------------------------------------
# Query generation
# ---------------------------------------------------------------------------
def generate_search_queries(name: str, location: str = "",
                            address: str = "") -> list[dict]:
    """Build categorized Google-dork queries for a person's name."""
    queries = []
    seen = set()

    quoted = f'"{name}"'
    loc = f' "{location}"' if location else ""
    addr = f' "{address}"' if address else ""
    # Combine location + address as context filters
    ctx = addr + loc

    def add(category: str, query: str):
        if query not in seen:
            seen.add(query)
            url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)
            queries.append({"category": category, "query": query, "url": url})

    # General presence
    add("General", quoted + ctx)
    add("General", f"{quoted}{ctx} email")
    add("General", f"{quoted}{ctx} phone")
    add("General", f"{quoted}{ctx} address")
    add("General", f'{quoted}{ctx} intitle:"contact" OR intitle:"about"')
    add("General", f"{quoted}{ctx} filetype:pdf")

    # Site-specific
    for category, sites in SITE_CATEGORIES.items():
        for site in sites:
            add(category, f"{quoted}{ctx} site:{site}")

    # Device & digital identifier searches — looks for MAC, UID, UUID
    # associated with this person in public leaks, forums, paste sites
    identifier_sites = ["pastebin.com", "justpaste.it", "ghostbin.com",
                        "reddit.com", "github.com", "stackoverflow.com"]
    add("Device & Digital Identifiers", f'{quoted} "MAC address"')
    add("Device & Digital Identifiers", f'{quoted} "MAC address" OR "mac addr"'
        f' site:pastebin.com OR site:justpaste.it')
    add("Device & Digital Identifiers", f'{quoted} UID OR uuid')
    add("Device & Digital Identifiers",
        f'{quoted} uuid site:pastebin.com OR site:justpaste.it')
    add("Device & Digital Identifiers", f'{quoted} "device id" OR "device_id"')
    add("Device & Digital Identifiers", f'{quoted} "hardware id" OR "hwid"')
    for site in identifier_sites:
        add("Device & Digital Identifiers",
            f'{quoted} ("MAC" OR "UUID" OR "UID") site:{site}')

    return queries


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
SECTION_WIDTH = 70


def print_queries_text(name: str, location: str, address: str,
                       queries: list[dict]):
    print()
    print("=" * SECTION_WIDTH)
    print("  PERSON NAME — WEB SEARCH QUERY GENERATOR")
    print("=" * SECTION_WIDTH)
    print(f"\n  Name:      {name}")
    if address:
        print(f"  Address:   {address}")
    if location:
        print(f"  Location:  {location}")

    by_cat: dict[str, list[dict]] = {}
    for q in queries:
        by_cat.setdefault(q["category"], []).append(q)

    print(f"\n  Total queries generated: {len(queries)}")

    for cat, items in by_cat.items():
        print(f"\n--- {cat} ({len(items)} queries) "
              f"{'-' * max(0, SECTION_WIDTH - len(cat) - 16)}")
        for i, item in enumerate(items, 1):
            print(f"  {i:>3}. {item['query']}")
            print(f"       {item['url']}")

    print()
    print("=" * SECTION_WIDTH)
    print("  All queries target PUBLIC search engine results only.")
    print("  No private databases or restricted sources are accessed.")
    print("=" * SECTION_WIDTH)
    print()


def print_queries_json(name: str, location: str, address: str,
                       queries: list[dict]):
    output = {
        "name": name,
        "address": address,
        "location": location,
        "total_queries": len(queries),
        "queries": queries,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_name_search(name: str, location: str = "", address: str = "",
                    proxy: str = "", open_browser: bool = False,
                    output_format: str = "text") -> list[dict]:
    """Generate and display OSINT search queries for a person's name."""
    queries = generate_search_queries(name, location=location, address=address)

    if output_format == "json":
        print_queries_json(name, location, address, queries)
    else:
        print_queries_text(name, location, address, queries)

    if proxy:
        print(f"  [proxy] Tunnel set: {proxy}")
        print("  [proxy] Route your browser or fetch requests through this proxy.\n")

    if open_browser:
        # Build opener with proxy if one is provided
        if proxy:
            handler = urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}
            )
            opener = urllib.request.build_opener(handler)
            urllib.request.install_opener(opener)

        general = [q for q in queries if q["category"] == "General"][:3]
        for q in general:
            webbrowser.open(q["url"])

    return queries


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate public web search queries for a person's name.",
        epilog=(
            "Examples:\n"
            '  python name_search.py "John Smith"\n'
            '  python name_search.py "Jane Doe" --location "Chicago, IL"\n'
            '  python name_search.py "John Smith" --address "123 Main St"\n'
            '  python name_search.py "John Smith" --proxy http://127.0.0.1:8080\n'
            '  python name_search.py "John Smith" -o json\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "name",
        help='Full name to search for (e.g. "John Smith")',
    )
    parser.add_argument(
        "--location",
        default="",
        help="City or state to narrow results (e.g. 'Chicago, IL')",
    )
    parser.add_argument(
        "--address",
        default="",
        help="Street address to further narrow results (e.g. '123 Main St')",
    )
    parser.add_argument(
        "--proxy",
        default="",
        metavar="URL",
        help="Proxy tunnel URL to route requests through (e.g. http://127.0.0.1:8080)",
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
    run_name_search(
        args.name,
        location=args.location,
        address=args.address,
        proxy=args.proxy,
        open_browser=args.open_browser,
        output_format=args.output,
    )


if __name__ == "__main__":
    main()
