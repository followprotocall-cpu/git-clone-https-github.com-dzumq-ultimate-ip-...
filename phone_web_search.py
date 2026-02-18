#!/usr/bin/env python3
"""
Phone Number Web Search Query Generator

Generates structured search queries to find a phone number's public footprint
across social media, directories, public records, business listings, and more.

Can be used standalone or imported by phone_lookup.py (via --web-search flag).

Usage:
  python phone_web_search.py 123-456-7890
  python phone_web_search.py +14155552671 --open-browser
  python phone_web_search.py 4155552671 -o json
"""

import argparse
import json
import re
import sys
import urllib.parse
import webbrowser


# ---------------------------------------------------------------------------
# Phone number formatting
# ---------------------------------------------------------------------------
def format_phone_number(phone_number: str) -> list[str]:
    """
    Generates multiple common format variants of a phone number
    so search queries cover how the number might appear online.
    """
    digits = re.sub(r"\D", "", phone_number)

    formats = set()
    formats.add(digits)

    if len(digits) == 10:
        # US-style 10-digit
        a, b, c = digits[:3], digits[3:6], digits[6:]
        formats.update([
            f"({a}) {b}-{c}",       # (123) 456-7890
            f"{a}-{b}-{c}",         # 123-456-7890
            f"{a}.{b}.{c}",         # 123.456.7890
            f"{a} {b} {c}",         # 123 456 7890
            f"+1{digits}",          # +11234567890
            f"+1 {a}-{b}-{c}",     # +1 123-456-7890
            f"1-{a}-{b}-{c}",      # 1-123-456-7890
        ])
    elif len(digits) == 11 and digits.startswith("1"):
        # US with leading country code
        d = digits[1:]
        a, b, c = d[:3], d[3:6], d[6:]
        formats.update([
            d,
            f"({a}) {b}-{c}",
            f"{a}-{b}-{c}",
            f"{a}.{b}.{c}",
            f"{a} {b} {c}",
            f"+1{d}",
            f"+1 {a}-{b}-{c}",
            f"1-{a}-{b}-{c}",
        ])
    else:
        # International — just add common separators
        formats.add(phone_number.strip())
        if phone_number.startswith("+"):
            formats.add(phone_number.lstrip("+"))

    return sorted(formats)


# ---------------------------------------------------------------------------
# Search query generation
# ---------------------------------------------------------------------------

# Categories of sites to search
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
    "Classifieds / Marketplace": [
        "craigslist.org",
        "offerup.com",
        "facebook.com/marketplace",
    ],
    "Court / Government Records": [
        "publicrecords.searchsystems.net",
        "judyrecords.com",
    ],
}


def generate_search_queries(phone_formats: list[str]) -> list[dict]:
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

    for fmt in phone_formats:
        quoted = f'"{fmt}"'

        # General web presence
        add("General", quoted)
        add("General", f'{quoted} intitle:"contact" OR intitle:"about"')
        add("General", f'{quoted} intitle:"phone" OR intitle:"directory"')
        add("General", f'{quoted} filetype:pdf')

        # Site-specific
        for category, sites in SITE_CATEGORIES.items():
            for site in sites:
                add(category, f'{quoted} site:{site}')

    return queries


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
SECTION_WIDTH = 70


def print_queries_text(phone_input: str, formats: list[str], queries: list[dict]):
    """Pretty-print the generated queries grouped by category."""
    print()
    print("=" * SECTION_WIDTH)
    print("  PHONE NUMBER — WEB SEARCH QUERY GENERATOR")
    print("=" * SECTION_WIDTH)

    print(f"\n  Input number:  {phone_input}")
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


def print_queries_json(phone_input: str, formats: list[str], queries: list[dict]):
    """Output queries as JSON."""
    output = {
        "input": phone_input,
        "formats": formats,
        "total_queries": len(queries),
        "queries": queries,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Public API (importable by phone_lookup.py)
# ---------------------------------------------------------------------------
def run_web_search(phone_str: str, open_browser: bool = False,
                   output_format: str = "text") -> list[dict]:
    """
    Main entry point — generate and optionally display web search queries.
    Returns the list of query dicts for programmatic use.
    """
    formats = format_phone_number(phone_str)
    queries = generate_search_queries(formats)

    if output_format == "json":
        print_queries_json(phone_str, formats, queries)
    else:
        print_queries_text(phone_str, formats, queries)

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
        description="Generate public web search queries for a phone number.",
        epilog=(
            "Examples:\n"
            "  python phone_web_search.py 415-555-2671\n"
            "  python phone_web_search.py +14155552671 --open-browser\n"
            "  python phone_web_search.py 4155552671 -o json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "phone",
        help="Phone number to search for (any format)",
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
    run_web_search(args.phone, open_browser=args.open_browser,
                   output_format=args.output)


if __name__ == "__main__":
    main()
