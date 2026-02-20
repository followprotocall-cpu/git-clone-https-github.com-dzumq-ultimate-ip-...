#!/usr/bin/env python3
"""
IP Address Lookup Tool
======================
Geolocates an IP address using free public APIs.

What this can tell you:
  - Approximate city/country (may be off by 50-100 miles)
  - ISP / hosting provider name
  - Whether it's a VPN, proxy, or datacenter exit node
  - Timezone and region

What this CANNOT tell you:
  - The person's real name or identity
  - Their exact home address
  - Who specifically used the IP

To identify a real person behind an IP, you must:
  1. Report to the platform (TikTok, etc.) with evidence
  2. File a police report for unauthorized account access
  3. Law enforcement can then subpoena the ISP for subscriber info

Usage:
  python ip_lookup.py 8.8.8.8
  python ip_lookup.py 8.8.8.8 --json
  python ip_lookup.py          (interactive mode)
"""

import argparse
import json
import sys

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found. Run: pip install requests")
    sys.exit(1)

# Free HTTPS APIs (no key required)
# Primary:  ipapi.co  — HTTPS, 1000 req/day free
# Fallback: ip-api.com — HTTP, 45 req/min free
PRIMARY_URL  = "https://ipapi.co/{ip}/json/"
FALLBACK_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting,proxy,query"


def _normalize_ipapi_co(raw: dict) -> dict:
    """Normalize ipapi.co response to a common schema."""
    if raw.get("error"):
        return {"error": raw.get("reason", "Invalid IP address or API error.")}
    return {
        "query":       raw.get("ip", ""),
        "country":     raw.get("country_name", "Unknown"),
        "countryCode": raw.get("country_code", "??"),
        "regionName":  raw.get("region", "Unknown"),
        "city":        raw.get("city", "Unknown"),
        "zip":         raw.get("postal", "N/A"),
        "lat":         raw.get("latitude", "N/A"),
        "lon":         raw.get("longitude", "N/A"),
        "timezone":    raw.get("timezone", "Unknown"),
        "isp":         raw.get("org", "Unknown"),
        "org":         raw.get("org", "Unknown"),
        "as":          raw.get("asn", "Unknown"),
        "proxy":       False,   # ipapi.co free tier does not expose this
        "hosting":     False,
    }


def lookup_ip(ip_address: str) -> dict:
    """Geolocate an IP using ipapi.co (HTTPS), with ip-api.com as fallback."""
    ip = ip_address.strip()
    headers = {"User-Agent": "ip-lookup-tool/1.0"}

    # --- Primary: ipapi.co (HTTPS) ---
    try:
        resp = requests.get(PRIMARY_URL.format(ip=ip), headers=headers, timeout=10)
        resp.raise_for_status()
        return _normalize_ipapi_co(resp.json())
    except (requests.exceptions.ProxyError, requests.exceptions.SSLError):
        pass  # fall through to HTTP fallback
    except requests.exceptions.ConnectionError:
        return {"error": "No internet connection. Check your network and try again."}
    except requests.exceptions.Timeout:
        pass  # fall through to HTTP fallback
    except requests.exceptions.HTTPError:
        pass  # fall through to HTTP fallback

    # --- Fallback: ip-api.com (HTTP) ---
    try:
        resp = requests.get(FALLBACK_URL.format(ip=ip), headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "fail":
            return {"error": data.get("message", "API returned failure for this IP.")}
        return data
    except requests.exceptions.ProxyError:
        return {"error": "Proxy blocked the request. Try running this on a direct internet connection."}
    except requests.exceptions.ConnectionError:
        return {"error": "No internet connection. Check your network and try again."}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out. Both APIs may be unavailable."}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP error: {e}"}


def print_results(data: dict) -> None:
    """Print results in a readable format."""
    if "error" in data:
        print(f"\n  ERROR: {data['error']}\n")
        return

    ip = data.get("query", "Unknown")
    country = data.get("country", "Unknown")
    country_code = data.get("countryCode", "??")
    region = data.get("regionName", "Unknown")
    city = data.get("city", "Unknown")
    zip_code = data.get("zip", "N/A")
    lat = data.get("lat", "N/A")
    lon = data.get("lon", "N/A")
    timezone = data.get("timezone", "Unknown")
    isp = data.get("isp", "Unknown")
    org = data.get("org", "Unknown")
    asn = data.get("as", "Unknown")
    is_proxy = data.get("proxy", False)
    is_hosting = data.get("hosting", False)

    # Flag indicators
    flags = []
    if is_proxy:
        flags.append("VPN / Proxy / Tor exit node")
    if is_hosting:
        flags.append("Datacenter / Hosting provider (not a home connection)")

    print()
    print("=" * 50)
    print(f"  IP Address:    {ip}")
    print("=" * 50)
    print(f"  Country:       {country} ({country_code})")
    print(f"  Region:        {region}")
    print(f"  City:          {city}")
    print(f"  ZIP/Postal:    {zip_code}")
    print(f"  Coordinates:   {lat}, {lon}  (approximate)")
    print(f"  Timezone:      {timezone}")
    print()
    print(f"  ISP:           {isp}")
    print(f"  Organization:  {org}")
    print(f"  ASN:           {asn}")
    print()
    if flags:
        print("  *** NOTICE ***")
        for f in flags:
            print(f"  - {f}")
        print("  The attacker may be hiding their real location.")
        print()
    else:
        print("  No VPN/proxy detected (may still be inaccurate).")
        print()
    print("  NEXT STEPS IF YOUR ACCOUNT WAS HACKED:")
    print("  1. Screenshot this information as evidence.")
    print("  2. Report to TikTok: tiktok.com/legal/report/feedback")
    print("  3. File a report at your local police or cyber crime unit.")
    print("  4. Only law enforcement can get real identity from an ISP.")
    print("=" * 50)
    print()


def interactive_mode(output_format: str) -> None:
    """Continuously prompt for IPs until the user quits."""
    print("\nInteractive IP Lookup Mode (type 'quit' or 'exit' to stop)\n")
    while True:
        try:
            ip = input("Enter IP address: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if ip.lower() in ("quit", "exit", "q"):
            print("Exiting.")
            break
        if not ip:
            continue

        data = lookup_ip(ip)
        if output_format == "json":
            print(json.dumps(data, indent=2))
        else:
            print_results(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Look up geolocation and ISP info for an IP address.",
        epilog="Example: python ip_lookup.py 8.8.8.8"
    )
    parser.add_argument(
        "ip",
        nargs="?",
        help="IP address to look up (IPv4 or IPv6). Omit to enter interactive mode."
    )
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        metavar="FORMAT",
        help="Output format: 'text' (default) or 'json'"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Enter interactive mode to look up multiple IPs"
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.interactive or not args.ip:
        interactive_mode(args.output)
        return

    data = lookup_ip(args.ip)

    if args.output == "json":
        print(json.dumps(data, indent=2))
    else:
        print_results(data)


if __name__ == "__main__":
    main()
