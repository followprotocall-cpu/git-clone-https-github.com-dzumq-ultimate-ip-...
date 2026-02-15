#!/usr/bin/env python3
"""
IP Address Lookup & Web Search Query Generator

Performs live lookups against free public APIs (ip-api.com, ipwhois.app,
ipapi.co) and generates structured OSINT search queries for deeper
investigation across threat intelligence, geolocation, and network tools.

Usage:
  python phone_web_search.py 24.189.157.220
  python phone_web_search.py 24.189.157.220 67.83.243.7
  python phone_web_search.py 8.8.8.8 --open-browser
  python phone_web_search.py 2001:db8::1 -o json
  python phone_web_search.py 24.189.157.220 --shodan-key YOUR_KEY
"""

import argparse
import json
import re
import socket
import sys
import urllib.parse
import urllib.request
import urllib.error
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

    ipv4_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip)
    if ipv4_match:
        octets = [int(o) for o in ipv4_match.groups()]
        standard = '.'.join(str(o) for o in octets)
        formats.add(standard)
        padded = '.'.join(f'{o:03d}' for o in octets)
        formats.add(padded)
        formats.add(f'{standard}/24')
        formats.add(f'{standard}/32')
        subnet = '.'.join(str(o) for o in octets[:3]) + '.*'
        formats.add(subnet)
        decimal_ip = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        formats.add(str(decimal_ip))
        hex_ip = f'0x{decimal_ip:08X}'
        formats.add(hex_ip)
    else:
        formats.add(ip)
        compressed = re.sub(r'\b0+(\w)', r'\1', ip)
        formats.add(compressed)

    return sorted(formats)


# ---------------------------------------------------------------------------
# Live API lookups (free, no key required)
# ---------------------------------------------------------------------------
_USER_AGENT = "IPLookupTool/1.0"


def _http_get_json(url: str, timeout: int = 10) -> dict | None:
    """Helper to GET a URL and parse JSON, returning None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def lookup_ip_api(ip: str) -> dict | None:
    """Query ip-api.com (free, no key, 45 req/min)."""
    url = f"http://ip-api.com/json/{ip}?fields=66846719"
    data = _http_get_json(url)
    if data and data.get("status") == "success":
        return {
            "source": "ip-api.com",
            "ip": data.get("query", ip),
            "country": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "zip": data.get("zip", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "as": data.get("as", ""),
            "asname": data.get("asname", ""),
            "mobile": data.get("mobile", False),
            "proxy": data.get("proxy", False),
            "hosting": data.get("hosting", False),
            "reverse_dns": data.get("reverse", ""),
        }
    return None


def lookup_ipwhois(ip: str) -> dict | None:
    """Query ipwho.is (free, no key, 10k req/month)."""
    url = f"https://ipwho.is/{ip}"
    data = _http_get_json(url)
    if data and data.get("success"):
        conn = data.get("connection", {})
        return {
            "source": "ipwho.is",
            "ip": data.get("ip", ip),
            "country": data.get("country", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "postal": data.get("postal", ""),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "timezone": data.get("timezone", {}).get("id", ""),
            "isp": conn.get("isp", ""),
            "org": conn.get("org", ""),
            "asn": conn.get("asn"),
            "type": data.get("type", ""),
        }
    return None


def lookup_ipapi_co(ip: str) -> dict | None:
    """Query ipapi.co (free tier, 1000 req/day)."""
    url = f"https://ipapi.co/{ip}/json/"
    data = _http_get_json(url)
    if data and not data.get("error"):
        return {
            "source": "ipapi.co",
            "ip": data.get("ip", ip),
            "country": data.get("country_name", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "postal": data.get("postal", ""),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("org", ""),
            "asn": data.get("asn", ""),
            "type": data.get("version", ""),
        }
    return None


def reverse_dns(ip: str) -> str | None:
    """Attempt reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# Optional: API-key-based lookups
# ---------------------------------------------------------------------------
def lookup_shodan(ip: str, api_key: str) -> dict | None:
    """Query Shodan API (requires API key)."""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    data = _http_get_json(url)
    if data and "error" not in data:
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        # Check for VoIP-related ports
        voip_ports = {5060, 5061, 4569, 2000, 1720}
        voip_detected = [p for p in ports if p in voip_ports]
        return {
            "source": "shodan.io",
            "ip": data.get("ip_str", ip),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "os": data.get("os", ""),
            "ports": ports,
            "hostnames": hostnames,
            "vulns": vulns,
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "asn": data.get("asn", ""),
            "voip_ports": voip_detected,
            "voip_detected": len(voip_detected) > 0,
        }
    return None


def lookup_abuseipdb(ip: str, api_key: str) -> dict | None:
    """Query AbuseIPDB API (requires API key)."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    try:
        req = urllib.request.Request(url, headers={
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        info = data.get("data", {})
        return {
            "source": "abuseipdb.com",
            "ip": info.get("ipAddress", ip),
            "is_public": info.get("isPublic"),
            "abuse_confidence": info.get("abuseConfidenceScore"),
            "total_reports": info.get("totalReports"),
            "isp": info.get("isp", ""),
            "domain": info.get("domain", ""),
            "usage_type": info.get("usageType", ""),
            "country": info.get("countryCode", ""),
            "is_tor": info.get("isTor", False),
            "is_whitelisted": info.get("isWhitelisted"),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Combined lookup
# ---------------------------------------------------------------------------
def run_live_lookup(ip: str, shodan_key: str = None,
                    abuseipdb_key: str = None) -> dict:
    """Run all available lookups for a single IP and merge results."""
    result = {"ip": ip, "lookups": []}

    # Reverse DNS
    rdns = reverse_dns(ip)
    if rdns:
        result["reverse_dns"] = rdns

    # Free APIs (try all, keep whatever succeeds)
    for fn in [lookup_ip_api, lookup_ipwhois, lookup_ipapi_co]:
        data = fn(ip)
        if data:
            result["lookups"].append(data)

    # API-key lookups
    if shodan_key:
        data = lookup_shodan(ip, shodan_key)
        if data:
            result["lookups"].append(data)

    if abuseipdb_key:
        data = lookup_abuseipdb(ip, abuseipdb_key)
        if data:
            result["lookups"].append(data)

    return result


# ---------------------------------------------------------------------------
# Search query generation
# ---------------------------------------------------------------------------
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

        add("General", quoted)
        add("General", f'{quoted} intitle:"abuse" OR intitle:"report"')
        add("General", f'{quoted} intitle:"scan" OR intitle:"vulnerability"')
        add("General", f'{quoted} filetype:log')
        add("General", f'{quoted} filetype:csv')

        for category, sites in SITE_CATEGORIES.items():
            for site in sites:
                add(category, f'{quoted} site:{site}')

    return queries


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
SECTION_WIDTH = 70


def print_lookup_text(lookup_result: dict):
    """Pretty-print live lookup results."""
    ip = lookup_result["ip"]
    print()
    print("=" * SECTION_WIDTH)
    print(f"  LIVE LOOKUP — {ip}")
    print("=" * SECTION_WIDTH)

    rdns = lookup_result.get("reverse_dns")
    if rdns:
        print(f"\n  Reverse DNS:  {rdns}")

    lookups = lookup_result.get("lookups", [])
    if not lookups:
        print("\n  No API responded successfully.")
        print("  Try running on a machine with internet access, or provide")
        print("  API keys with --shodan-key / --abuseipdb-key.")
    else:
        for info in lookups:
            source = info.pop("source", "Unknown")
            print(f"\n--- {source} {'-' * (SECTION_WIDTH - len(source) - 5)}")
            for key, value in info.items():
                if value is None or value == "" or value == []:
                    continue
                label = key.replace("_", " ").title()
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                if isinstance(value, bool):
                    value = "Yes" if value else "No"
                print(f"  {label:<26} {value}")

    print()


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


def print_all_json(ip_input: str, formats: list[str], queries: list[dict],
                   lookup_result: dict):
    """Output everything as JSON."""
    output = {
        "input": ip_input,
        "formats": formats,
        "live_lookup": lookup_result,
        "total_queries": len(queries),
        "queries": queries,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_web_search(ip_str: str, open_browser: bool = False,
                   output_format: str = "text",
                   shodan_key: str = None,
                   abuseipdb_key: str = None) -> list[dict]:
    """
    Main entry point — perform live lookup, generate search queries,
    and optionally display results.
    """
    formats = format_ip_address(ip_str)
    queries = generate_search_queries(formats)
    lookup_result = run_live_lookup(ip_str, shodan_key=shodan_key,
                                   abuseipdb_key=abuseipdb_key)

    if output_format == "json":
        print_all_json(ip_str, formats, queries, lookup_result)
    else:
        print_lookup_text(lookup_result)
        print_queries_text(ip_str, formats, queries)

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
        description="Look up IP addresses and generate OSINT web search queries.",
        epilog=(
            "Examples:\n"
            "  python phone_web_search.py 24.189.157.220\n"
            "  python phone_web_search.py 24.189.157.220 67.83.243.7\n"
            "  python phone_web_search.py 8.8.8.8 --open-browser\n"
            "  python phone_web_search.py 8.8.8.8 --shodan-key YOUR_KEY\n"
            "  python phone_web_search.py 2001:db8::1 -o json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "ips",
        nargs="+",
        help="One or more IP addresses to search for (IPv4 or IPv6)",
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
    parser.add_argument(
        "--shodan-key",
        default=None,
        help="Shodan API key for port/service/VoIP detection",
    )
    parser.add_argument(
        "--abuseipdb-key",
        default=None,
        help="AbuseIPDB API key for abuse/reputation data",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    for ip in args.ips:
        run_web_search(ip, open_browser=args.open_browser,
                       output_format=args.output,
                       shodan_key=args.shodan_key,
                       abuseipdb_key=args.abuseipdb_key)


if __name__ == "__main__":
    main()
