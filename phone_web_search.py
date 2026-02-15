#!/usr/bin/env python3
"""
IP Address Lookup & Web Search Query Generator

Performs live lookups against free public APIs (ip-api.com, ipwhois.app,
ipapi.co) and generates structured OSINT search queries for deeper
investigation across threat intelligence, geolocation, and network tools.

Supports HTTP/HTTPS/SOCKS4/SOCKS5 proxy tunneling for environments with
restricted outbound access.

Usage:
  python phone_web_search.py 24.189.157.220
  python phone_web_search.py 24.189.157.220 67.83.243.7
  python phone_web_search.py 8.8.8.8 --open-browser
  python phone_web_search.py 2001:db8::1 -o json
  python phone_web_search.py 24.189.157.220 --shodan-key YOUR_KEY
  python phone_web_search.py 24.189.157.220 --proxy socks5://127.0.0.1:9050
  python phone_web_search.py 24.189.157.220 --proxy http://user:pass@proxy:8080
"""

import argparse
import json
import os
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
# Proxy / tunnel support
# ---------------------------------------------------------------------------
_USER_AGENT = "IPLookupTool/1.0"
_proxy_handler: urllib.request.ProxyHandler | None = None
_opener: urllib.request.OpenerDirector | None = None


def configure_proxy(proxy_url: str | None):
    """
    Set up a global proxy for all HTTP/HTTPS requests.

    Supported formats:
      - http://host:port
      - http://user:pass@host:port
      - https://host:port
      - socks5://host:port   (requires PySocks: pip install pysocks)
      - socks4://host:port
      - socks5h://host:port  (DNS resolved through proxy)

    Also respects the environment variables HTTP_PROXY / HTTPS_PROXY
    if --proxy is not provided.
    """
    global _proxy_handler, _opener

    if not proxy_url:
        # Check environment variables
        env_proxy = (
            os.environ.get("HTTPS_PROXY")
            or os.environ.get("HTTP_PROXY")
            or os.environ.get("https_proxy")
            or os.environ.get("http_proxy")
        )
        if env_proxy:
            proxy_url = env_proxy
        else:
            _opener = None
            return

    scheme = proxy_url.split("://")[0].lower() if "://" in proxy_url else ""

    if scheme in ("socks4", "socks5", "socks5h"):
        # SOCKS proxy — requires PySocks
        try:
            import socks
            from sockshandler import SocksiPyHandler
        except ImportError:
            print("  [!] SOCKS proxy requires PySocks: pip install pysocks")
            print("      Falling back to direct connection.")
            _opener = None
            return

        parsed = urllib.parse.urlparse(proxy_url)
        socks_type = {
            "socks4": socks.SOCKS4,
            "socks5": socks.SOCKS5,
            "socks5h": socks.SOCKS5,
        }[scheme]
        rdns = scheme == "socks5h"
        _opener = urllib.request.build_opener(
            SocksiPyHandler(socks_type, parsed.hostname, parsed.port or 1080,
                            rdns=rdns, username=parsed.username,
                            password=parsed.password)
        )
        print(f"  [*] Using SOCKS proxy: {parsed.hostname}:{parsed.port}")
    else:
        # HTTP/HTTPS proxy
        _proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url,
        })
        _opener = urllib.request.build_opener(_proxy_handler)
        parsed = urllib.parse.urlparse(proxy_url)
        print(f"  [*] Using HTTP proxy: {parsed.hostname}:{parsed.port}")


def _http_get_json(url: str, timeout: int = 10) -> dict | None:
    """Helper to GET a URL and parse JSON, returning None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        if _opener:
            resp = _opener.open(req, timeout=timeout)
        else:
            resp = urllib.request.urlopen(req, timeout=timeout)
        with resp:
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


def forward_dns(hostname: str) -> dict:
    """Resolve a hostname to its A and AAAA records."""
    results = {"A": [], "AAAA": []}
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            addr = info[4][0]
            if addr not in results["A"]:
                results["A"].append(addr)
    except (socket.gaierror, OSError):
        pass
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM):
            addr = info[4][0]
            if addr not in results["AAAA"]:
                results["AAAA"].append(addr)
    except (socket.gaierror, OSError):
        pass
    return results


def dns_lookup(ip: str) -> dict:
    """
    Perform DNS lookups for an IP address:
    - Reverse DNS (PTR record)
    - Forward DNS on the resulting hostname (A/AAAA)
    - Additional DNS queries via public DNS-over-HTTPS (Cloudflare)
    """
    result = {"ptr": None, "hostname": None, "forward_a": [], "forward_aaaa": [],
              "mx": [], "ns": [], "txt": [], "soa": None}

    # Reverse DNS → hostname
    hostname = reverse_dns(ip)
    if hostname:
        result["ptr"] = hostname
        result["hostname"] = hostname

        # Forward DNS on the discovered hostname
        fwd = forward_dns(hostname)
        result["forward_a"] = fwd.get("A", [])
        result["forward_aaaa"] = fwd.get("AAAA", [])

        # Query MX, NS, TXT, SOA for the domain via Cloudflare DoH
        # Extract the base domain (last two labels)
        parts = hostname.rstrip(".").split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        for rtype in ["MX", "NS", "TXT", "SOA"]:
            url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}"
            try:
                req = urllib.request.Request(url, headers={
                    "Accept": "application/dns-json",
                    "User-Agent": _USER_AGENT,
                })
                if _opener:
                    resp = _opener.open(req, timeout=5)
                else:
                    resp = urllib.request.urlopen(req, timeout=5)
                with resp:
                    data = json.loads(resp.read().decode())
                answers = data.get("Answer", [])
                for ans in answers:
                    rdata = ans.get("data", "").strip('"')
                    if rtype == "SOA" and result["soa"] is None:
                        result["soa"] = rdata
                    elif rtype != "SOA":
                        result[rtype.lower()].append(rdata)
            except Exception:
                pass

    return result


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

    # DNS lookups (reverse DNS, forward DNS, MX, NS, TXT, SOA)
    dns_info = dns_lookup(ip)
    result["dns"] = dns_info
    if dns_info.get("ptr"):
        result["reverse_dns"] = dns_info["ptr"]

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
    "DNS / Hostname": [
        "dnsdumpster.com",
        "viewdns.info",
        "securitytrails.com",
        "dnslytics.com",
        "robtex.com",
        "dnschecker.org",
        "completedns.com",
    ],
}


def generate_search_queries(ip_formats: list[str],
                            hostname: str = None) -> list[dict]:
    """
    Builds a list of categorized Google-dork search queries.
    Returns list of dicts: {category, query, url}

    If a hostname was discovered via reverse DNS, additional
    hostname-based queries are generated.
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

    # Hostname-based queries if reverse DNS found a name
    if hostname:
        hq = f'"{hostname}"'
        add("DNS / Hostname", hq)
        add("DNS / Hostname", f'{hq} intitle:"dns" OR intitle:"whois"')
        add("DNS / Hostname", f'{hq} intitle:"subdomain" OR intitle:"certificate"')
        add("DNS / Hostname", f'{hq} filetype:zone OR filetype:conf')
        add("DNS / Hostname", f'site:crt.sh "{hostname}"')

        # Extract base domain and add domain-level queries
        parts = hostname.rstrip(".").split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
            if domain != hostname:
                dq = f'"{domain}"'
                add("DNS / Hostname", f'{dq} site:dnsdumpster.com')
                add("DNS / Hostname", f'{dq} site:securitytrails.com')
                add("DNS / Hostname", f'{dq} site:crt.sh')

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

    # DNS section
    dns = lookup_result.get("dns", {})
    rdns = lookup_result.get("reverse_dns")
    has_dns = rdns or dns.get("forward_a") or dns.get("forward_aaaa") or dns.get("mx") or dns.get("ns")

    if has_dns:
        print(f"\n--- DNS & Hostname {'-' * (SECTION_WIDTH - 19)}")
        if rdns:
            print(f"  {'PTR (Reverse DNS)':<26} {rdns}")
        hostname = dns.get("hostname")
        if hostname and hostname != rdns:
            print(f"  {'Hostname':<26} {hostname}")
        if dns.get("forward_a"):
            print(f"  {'Forward A':<26} {', '.join(dns['forward_a'])}")
        if dns.get("forward_aaaa"):
            print(f"  {'Forward AAAA':<26} {', '.join(dns['forward_aaaa'])}")
        if dns.get("mx"):
            for mx in dns["mx"]:
                print(f"  {'MX':<26} {mx}")
        if dns.get("ns"):
            for ns in dns["ns"]:
                print(f"  {'NS':<26} {ns}")
        if dns.get("txt"):
            for txt in dns["txt"]:
                print(f"  {'TXT':<26} {txt}")
        if dns.get("soa"):
            print(f"  {'SOA':<26} {dns['soa']}")
    elif rdns:
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
    lookup_result = run_live_lookup(ip_str, shodan_key=shodan_key,
                                   abuseipdb_key=abuseipdb_key)
    hostname = lookup_result.get("dns", {}).get("hostname")
    queries = generate_search_queries(formats, hostname=hostname)

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
    parser.add_argument(
        "--proxy",
        default=None,
        help=(
            "Proxy URL for tunneling API requests. Supports: "
            "http://host:port, https://host:port, "
            "socks5://host:port, socks4://host:port, "
            "socks5h://host:port (DNS via proxy). "
            "Also reads HTTP_PROXY/HTTPS_PROXY env vars."
        ),
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Set up proxy tunnel if provided
    configure_proxy(args.proxy)

    for ip in args.ips:
        run_web_search(ip, open_browser=args.open_browser,
                       output_format=args.output,
                       shodan_key=args.shodan_key,
                       abuseipdb_key=args.abuseipdb_key)


if __name__ == "__main__":
    main()
