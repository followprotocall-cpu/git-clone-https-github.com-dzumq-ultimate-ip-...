#!/usr/bin/env python3
"""
Phone Number Public Information Lookup Tool

Retrieves ONLY publicly available information tied to a phone number.
No illegal data access — uses open-source libraries and free public APIs.

Sources used:
  - Google's libphonenumber (via phonenumbers) — number validation, carrier,
    line type, timezone, geocoding
  - NumVerify API (free tier, optional) — carrier, line type, country info
  - Abstract API (free tier, optional) — similar public metadata

Usage:
  python phone_lookup.py +15551234567
  python phone_lookup.py -i                  # interactive mode
  python phone_lookup.py +15551234567 -o json # JSON output
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

try:
    import phonenumbers
    from phonenumbers import (
        carrier,
        geocoder,
        timezone,
        number_type,
        PhoneNumberType,
    )
except ImportError:
    print("ERROR: 'phonenumbers' library is required.")
    print("Install it with:  pip install phonenumbers")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LINE_TYPE_MAP = {
    PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
    PhoneNumberType.TOLL_FREE: "Toll-Free",
    PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    PhoneNumberType.SHARED_COST: "Shared Cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "UAN (Universal Access Number)",
    PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "Unknown",
}


# ---------------------------------------------------------------------------
# Core lookup using phonenumbers library (offline, no API key needed)
# ---------------------------------------------------------------------------
def lookup_offline(phone_str: str) -> dict:
    """Parse and extract all locally-available metadata from a phone number."""
    try:
        parsed = phonenumbers.parse(phone_str, None)
    except phonenumbers.NumberParseException as exc:
        return {"error": f"Could not parse number: {exc}"}

    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)

    result = {
        "input": phone_str,
        "e164_format": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        ),
        "international_format": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "national_format": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "country_code": parsed.country_code,
        "national_number": parsed.national_number,
        "region_code": phonenumbers.region_code_for_number(parsed),
        "is_valid": valid,
        "is_possible": possible,
        "line_type": LINE_TYPE_MAP.get(number_type(parsed), "Unknown"),
        "carrier": carrier.name_for_number(parsed, "en") or "Unknown / Unlisted",
        "location": geocoder.description_for_number(parsed, "en") or "Unknown",
        "timezones": list(timezone.time_zones_for_number(parsed)) or ["Unknown"],
    }

    # Country name from region code
    region = result["region_code"]
    if region:
        try:
            country_name = geocoder.country_name_for_number(parsed, "en")
            result["country"] = country_name or region
        except Exception:
            result["country"] = region
    else:
        result["country"] = "Unknown"

    return result


# ---------------------------------------------------------------------------
# Optional: NumVerify free API enrichment (public data only)
# Sign up at https://numverify.com for a free API key (250 req/month)
# ---------------------------------------------------------------------------
def lookup_numverify(phone_e164: str, api_key: str) -> dict:
    """Query NumVerify API for additional public carrier/location metadata."""
    # NumVerify expects number without leading '+'
    number = phone_e164.lstrip("+")
    url = (
        f"https://apilayer.net/api/validate"
        f"?access_key={api_key}&number={number}&format=1"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhoneLookupTool/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        if data.get("valid") is not None:
            return {
                "numverify_valid": data.get("valid"),
                "numverify_location": data.get("location", ""),
                "numverify_carrier": data.get("carrier", ""),
                "numverify_line_type": data.get("line_type", ""),
                "numverify_country_name": data.get("country_name", ""),
                "numverify_country_code": data.get("country_code", ""),
            }
        return {"numverify_error": data.get("error", {}).get("info", "Unknown error")}
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        return {"numverify_error": str(exc)}


# ---------------------------------------------------------------------------
# Optional: Abstract API free tier
# Sign up at https://www.abstractapi.com/api/phone-validation-api
# ---------------------------------------------------------------------------
def lookup_abstractapi(phone_e164: str, api_key: str) -> dict:
    """Query Abstract API for additional public phone metadata."""
    url = (
        f"https://phonevalidation.abstractapi.com/v1/"
        f"?api_key={api_key}&phone={phone_e164}"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhoneLookupTool/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        return {
            "abstract_valid": data.get("valid"),
            "abstract_carrier": data.get("carrier", {}).get("name", ""),
            "abstract_type": data.get("type", ""),
            "abstract_country": data.get("country", {}).get("name", ""),
            "abstract_location": data.get("location", ""),
        }
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        return {"abstract_error": str(exc)}


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------
SECTION_WIDTH = 60


def print_banner():
    print()
    print("=" * SECTION_WIDTH)
    print("  PHONE NUMBER — PUBLIC INFORMATION LOOKUP")
    print("=" * SECTION_WIDTH)


def print_section(title: str):
    print()
    print(f"--- {title} {'-' * (SECTION_WIDTH - len(title) - 5)}")


def print_field(label: str, value):
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    print(f"  {label:<26} {value}")


def print_results(data: dict, output_format: str = "text"):
    """Display results in the chosen format."""
    if output_format == "json":
        print(json.dumps(data, indent=2, default=str))
        return

    # Text/table output
    print_banner()

    if "error" in data:
        print(f"\n  ERROR: {data['error']}\n")
        return

    print_section("Number Details")
    print_field("Input:", data.get("input", ""))
    print_field("E.164 Format:", data.get("e164_format", ""))
    print_field("International:", data.get("international_format", ""))
    print_field("National:", data.get("national_format", ""))
    print_field("Valid:", "Yes" if data.get("is_valid") else "No")
    print_field("Possible:", "Yes" if data.get("is_possible") else "No")

    print_section("Carrier / Line Type")
    print_field("Carrier:", data.get("carrier", "Unknown"))
    print_field("Line Type:", data.get("line_type", "Unknown"))

    print_section("Geographic Info")
    print_field("Country:", data.get("country", "Unknown"))
    print_field("Country Code:", f"+{data.get('country_code', '?')}")
    print_field("Region Code:", data.get("region_code", "Unknown"))
    print_field("Location:", data.get("location", "Unknown"))
    print_field("Timezone(s):", data.get("timezones", ["Unknown"]))

    # NumVerify enrichment
    if any(k.startswith("numverify_") for k in data):
        print_section("NumVerify API (Public)")
        if "numverify_error" in data:
            print_field("Status:", f"Error — {data['numverify_error']}")
        else:
            print_field("Valid:", data.get("numverify_valid", ""))
            print_field("Carrier:", data.get("numverify_carrier", ""))
            print_field("Line Type:", data.get("numverify_line_type", ""))
            print_field("Location:", data.get("numverify_location", ""))
            print_field("Country:", data.get("numverify_country_name", ""))

    # Abstract API enrichment
    if any(k.startswith("abstract_") for k in data):
        print_section("Abstract API (Public)")
        if "abstract_error" in data:
            print_field("Status:", f"Error — {data['abstract_error']}")
        else:
            print_field("Valid:", data.get("abstract_valid", ""))
            print_field("Carrier:", data.get("abstract_carrier", ""))
            print_field("Type:", data.get("abstract_type", ""))
            print_field("Country:", data.get("abstract_country", ""))
            print_field("Location:", data.get("abstract_location", ""))

    print_section("Disclaimer")
    print("  All information shown is from PUBLIC sources only.")
    print("  No private or protected data was accessed.")
    print(f"  Lookup performed at: {datetime.now(timezone.utc).isoformat()}")
    print()
    print("=" * SECTION_WIDTH)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Look up publicly available information for a phone number.",
        epilog=(
            "Examples:\n"
            "  python phone_lookup.py +14155552671\n"
            "  python phone_lookup.py +442071234567 -o json\n"
            "  python phone_lookup.py -i\n"
            "  python phone_lookup.py +14155552671 --numverify-key YOUR_KEY\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "phone",
        nargs="?",
        help="Phone number in E.164 or international format (e.g. +14155552671)",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Interactive mode — prompt for numbers repeatedly",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--numverify-key",
        default=None,
        help="NumVerify API key for extra carrier/location data (free tier available)",
    )
    parser.add_argument(
        "--abstract-key",
        default=None,
        help="Abstract API key for extra phone metadata (free tier available)",
    )
    parser.add_argument(
        "--web-search",
        action="store_true",
        help="Also generate OSINT web search queries (social media, directories, etc.)",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open top web search queries in your browser (requires --web-search)",
    )
    return parser


def do_lookup(phone_str: str, args) -> dict:
    """Run the full lookup pipeline for a single number."""
    phone_str = phone_str.strip()

    # Auto-add '+' if user forgot it and number starts with a digit
    if phone_str and phone_str[0].isdigit():
        phone_str = "+" + phone_str

    data = lookup_offline(phone_str)

    if "error" not in data:
        e164 = data["e164_format"]

        if args.numverify_key:
            data.update(lookup_numverify(e164, args.numverify_key))

        if args.abstract_key:
            data.update(lookup_abstractapi(e164, args.abstract_key))

        if getattr(args, "web_search", False):
            try:
                from phone_web_search import run_web_search
                open_browser = getattr(args, "open_browser", False)
                run_web_search(phone_str, open_browser=open_browser,
                               output_format="text")
            except ImportError:
                print("\n  [!] phone_web_search.py not found — skipping web queries.")

    return data


def interactive_mode(args):
    """Loop asking the user for numbers until they quit."""
    print_banner()
    print("\n  Interactive mode — type a phone number or 'quit' to exit.\n")
    while True:
        try:
            raw = input("  Enter phone number: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye.\n")
            break

        if not raw or raw.lower() in ("quit", "exit", "q"):
            print("  Goodbye.\n")
            break

        data = do_lookup(raw, args)
        print_results(data, args.output)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.interactive:
        interactive_mode(args)
    elif args.phone:
        data = do_lookup(args.phone, args)
        print_results(data, args.output)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
