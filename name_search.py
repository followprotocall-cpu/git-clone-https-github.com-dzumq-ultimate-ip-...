#!/usr/bin/env python3
"""
Person Name OSINT Tool

Generates Google-dork search queries AND optionally queries live APIs to
find a person's public footprint across social media, directories, data
breaches, WiFi networks, email services, GitHub, Shodan, and Censys.

All sources are public or require an API key you sign up for yourself.
Proxies and user-agents rotate automatically from config.py.

Usage:
  python name_search.py "John Smith"
  python name_search.py "Jane Doe" --location "Chicago, IL" --address "123 Main St"
  python name_search.py "John Smith" --email john@example.com --domain example.com
  python name_search.py "John Smith" --mac "AA:BB:CC:DD:EE:FF"
  python name_search.py "John Smith" --proxy http://127.0.0.1:8080
  python name_search.py "John Smith" -o json
"""

import argparse
import json
import urllib.parse
import urllib.request
import webbrowser

# Try to import API lookup module (requires 'requests' library)
try:
    from api_lookup import (
        lookup_hibp, lookup_wigle_mac, lookup_emailrep,
        lookup_hunter, lookup_shodan, lookup_censys, lookup_github,
    )
    from config import get_random_proxy, get_random_ua, PROXIES
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False


# ---------------------------------------------------------------------------
# Site categories for Google-dork queries
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
# Google-dork query generation
# ---------------------------------------------------------------------------
def generate_search_queries(name: str, location: str = "",
                            address: str = "") -> list[dict]:
    """Build categorized Google-dork search queries for a person's name."""
    queries = []
    seen = set()

    quoted = f'"{name}"'
    loc = f' "{location}"' if location else ""
    addr = f' "{address}"' if address else ""
    ctx = addr + loc  # address + location as narrowing context

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

    # Site-specific queries
    for category, sites in SITE_CATEGORIES.items():
        for site in sites:
            add(category, f"{quoted}{ctx} site:{site}")

    # Device & digital identifier searches
    identifier_sites = [
        "pastebin.com", "justpaste.it", "ghostbin.com",
        "reddit.com", "github.com", "stackoverflow.com",
    ]
    add("Device & Digital Identifiers", f'{quoted} "MAC address"')
    add("Device & Digital Identifiers",
        f'{quoted} "MAC address" OR "mac addr" site:pastebin.com OR site:justpaste.it')
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
# Live API lookups
# ---------------------------------------------------------------------------
def run_api_lookups(name: str, email: str = "", mac: str = "",
                    domain: str = "", proxy: str = "auto") -> dict:
    """
    Call all relevant live APIs and return a combined results dict.
    Only runs lookups where required input (email/mac/domain) is provided.
    """
    if not API_AVAILABLE:
        return {"api_error": "api_lookup.py or 'requests' library not available"}

    results = {}
    parts = name.strip().split()
    first = parts[0] if parts else name
    last = parts[-1] if len(parts) > 1 else ""

    # GitHub — always run (no extra input needed)
    results["github"] = lookup_github(name, proxy=proxy)

    # Shodan — search by name (finds org pages, profiles, etc.)
    results["shodan"] = lookup_shodan(f'"{name}"', proxy=proxy)

    # Censys — search by name
    results["censys"] = lookup_censys(name, proxy=proxy)

    # Email-gated lookups
    if email:
        results["hibp"] = lookup_hibp(email, proxy=proxy)
        results["emailrep"] = lookup_emailrep(email, proxy=proxy)
        if domain:
            results["hunter"] = lookup_hunter(first, last, domain, proxy=proxy)

    # MAC-gated lookup
    if mac:
        results["wigle"] = lookup_wigle_mac(mac, proxy=proxy)

    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
SECTION_WIDTH = 70


def _sep(title: str = ""):
    pad = max(0, SECTION_WIDTH - len(title) - 5)
    print(f"\n--- {title} {'-' * pad}")


def print_api_results(api_data: dict):
    """Pretty-print results from all live API lookups."""
    if "api_error" in api_data:
        print(f"\n  [!] {api_data['api_error']}")
        return

    # GitHub
    gh = api_data.get("github", {})
    _sep("GitHub")
    if "github_error" in gh:
        print(f"  Error: {gh['github_error']}")
    else:
        print(f"  Total matches: {gh.get('github_total', 0)}")
        for u in gh.get("github_users", []):
            print(f"    @{u['login']}  {u['profile_url']}  [{u['type']}]")

    # Shodan
    sh = api_data.get("shodan", {})
    _sep("Shodan")
    if "shodan_error" in sh:
        print(f"  Error: {sh['shodan_error']}")
    else:
        print(f"  Total results: {sh.get('shodan_total', 0)}")
        for r in sh.get("shodan_results", []):
            print(f"    {r['ip']}:{r['port']}  {r.get('org','')}  "
                  f"{r.get('city','')}, {r.get('country','')}")

    # Censys
    ce = api_data.get("censys", {})
    _sep("Censys")
    if "censys_error" in ce:
        print(f"  Error: {ce['censys_error']}")
    else:
        print(f"  Total results: {ce.get('censys_total', 0)}")
        for r in ce.get("censys_results", []):
            print(f"    {r['ip']}  ports:{r['services']}  {r.get('country','')}")

    # HIBP
    hibp = api_data.get("hibp", {})
    if hibp:
        _sep("Have I Been Pwned")
        if "hibp_error" in hibp:
            print(f"  Error: {hibp['hibp_error']}")
        else:
            count = hibp.get("hibp_breach_count", 0)
            print(f"  Breach count: {count}")
            for b in hibp.get("hibp_breaches", []):
                print(f"    [{b['date']}] {b['name']} ({b['domain']}) — "
                      f"{', '.join(b['data_classes'][:4])}")

    # EmailRep
    er = api_data.get("emailrep", {})
    if er:
        _sep("EmailRep")
        if "emailrep_error" in er:
            print(f"  Error: {er['emailrep_error']}")
        else:
            print(f"  Reputation:          {er.get('emailrep_reputation')}")
            print(f"  Suspicious:          {er.get('emailrep_suspicious')}")
            print(f"  Credentials leaked:  {er.get('emailrep_credentials_leaked')}")
            print(f"  Malicious activity:  {er.get('emailrep_malicious_activity')}")
            print(f"  Profiles:            {', '.join(er.get('emailrep_profiles', []))}")

    # Hunter
    hu = api_data.get("hunter", {})
    if hu:
        _sep("Hunter.io")
        if "hunter_error" in hu:
            print(f"  Error: {hu['hunter_error']}")
        else:
            print(f"  Found email:  {hu.get('hunter_email')}  "
                  f"(confidence: {hu.get('hunter_score')}%)")
            print(f"  Position:     {hu.get('hunter_position')}")
            for src in hu.get("hunter_sources", [])[:3]:
                print(f"  Source:       {src}")

    # WiGLE
    wi = api_data.get("wigle", {})
    if wi:
        _sep("WiGLE (MAC / WiFi)")
        if "wigle_error" in wi:
            print(f"  Error: {wi['wigle_error']}")
        else:
            print(f"  Networks found: {wi.get('wigle_total_found', 0)}")
            for n in wi.get("wigle_networks", []):
                print(f"    SSID: {n['ssid']}  MAC: {n['mac']}  "
                      f"{n.get('city','')}, {n.get('region','')}, {n.get('country','')}")
                print(f"      Coords: {n.get('lat')}, {n.get('lon')}  "
                      f"Last seen: {n.get('last_seen')}")


def print_queries_text(name: str, location: str, address: str,
                       queries: list[dict], api_data: dict = None):
    print()
    print("=" * SECTION_WIDTH)
    print("  PERSON NAME — OSINT LOOKUP")
    print("=" * SECTION_WIDTH)
    print(f"\n  Name:      {name}")
    if address:
        print(f"  Address:   {address}")
    if location:
        print(f"  Location:  {location}")

    if api_data:
        print_api_results(api_data)

    by_cat: dict[str, list[dict]] = {}
    for q in queries:
        by_cat.setdefault(q["category"], []).append(q)

    print(f"\n\n  Total search queries generated: {len(queries)}")
    for cat, items in by_cat.items():
        print(f"\n--- {cat} ({len(items)} queries) "
              f"{'-' * max(0, SECTION_WIDTH - len(cat) - 16)}")
        for i, item in enumerate(items, 1):
            print(f"  {i:>3}. {item['query']}")
            print(f"       {item['url']}")

    print()
    print("=" * SECTION_WIDTH)
    print("  All information is from PUBLIC sources only.")
    print("  No private or protected data was accessed.")
    print("=" * SECTION_WIDTH)
    print()


def print_queries_json(name: str, location: str, address: str,
                       queries: list[dict], api_data: dict = None):
    output = {
        "name": name,
        "address": address,
        "location": location,
        "api_results": api_data or {},
        "total_queries": len(queries),
        "queries": queries,
    }
    print(json.dumps(output, indent=2, default=str))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_name_search(name: str, location: str = "", address: str = "",
                    email: str = "", mac: str = "", domain: str = "",
                    proxy: str = "auto", open_browser: bool = False,
                    live_apis: bool = False,
                    output_format: str = "text") -> dict:
    """Generate search queries and optionally run live API lookups."""
    queries = generate_search_queries(name, location=location, address=address)
    api_data = None

    if live_apis:
        print("  [*] Running live API lookups (proxy pool active)...")
        api_data = run_api_lookups(name, email=email, mac=mac,
                                   domain=domain, proxy=proxy)

    if output_format == "json":
        print_queries_json(name, location, address, queries, api_data)
    else:
        print_queries_text(name, location, address, queries, api_data)

    if open_browser:
        if proxy and proxy != "auto" and API_AVAILABLE:
            handler = urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}
            )
            opener = urllib.request.build_opener(handler)
            urllib.request.install_opener(opener)

        general = [q for q in queries if q["category"] == "General"][:3]
        for q in general:
            webbrowser.open(q["url"])

    return {"queries": queries, "api": api_data}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OSINT tool — search by name with live API lookups and proxy rotation.",
        epilog=(
            "Examples:\n"
            '  python name_search.py "John Smith"\n'
            '  python name_search.py "Jane Doe" --location "Chicago, IL" --address "123 Main St"\n'
            '  python name_search.py "John Smith" --email john@acme.com --domain acme.com --live\n'
            '  python name_search.py "John Smith" --mac "AA:BB:CC:DD:EE:FF" --live\n'
            '  python name_search.py "John Smith" --proxy http://127.0.0.1:8080 --live\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("name", help='Full name (e.g. "John Smith")')
    parser.add_argument("--location", default="",
                        help="City or state to narrow results")
    parser.add_argument("--address", default="",
                        help="Street address to narrow results")
    parser.add_argument("--email", default="",
                        help="Email address for HIBP and EmailRep lookups")
    parser.add_argument("--mac", default="",
                        help="MAC address for WiGLE WiFi network lookup")
    parser.add_argument("--domain", default="",
                        help="Company domain for Hunter.io email discovery")
    parser.add_argument("--proxy", default="auto", metavar="URL",
                        help="Proxy URL (default: auto-rotate from config.py pool)")
    parser.add_argument("--live", action="store_true",
                        help="Run live API lookups (requires API keys in config.py / env vars)")
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text")
    parser.add_argument("--open-browser", action="store_true",
                        help="Open top queries in your browser")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    run_name_search(
        args.name,
        location=args.location,
        address=args.address,
        email=args.email,
        mac=args.mac,
        domain=args.domain,
        proxy=args.proxy,
        open_browser=args.open_browser,
        live_apis=args.live,
        output_format=args.output,
    )


if __name__ == "__main__":
    main()
