#!/usr/bin/env python3
"""
TikTok Log Analyzer

Parses and analyzes TikTok app telemetry logs (as disclosed by security researcher
fs0c131y: https://gist.github.com/fs0c131y/b4ef278e8863c636964793e1b27f889d).

This tool is intended for security research and privacy analysis to understand
what data TikTok collects during app sessions.

Data sources:
  - Local log file (pass as argument)
  - GitHub Gist (--gist flag, fetches the original disclosure)

Usage:
  python tiktok_log_analyzer.py logs.txt
  python tiktok_log_analyzer.py logs.txt -o json
  python tiktok_log_analyzer.py --gist
  python tiktok_log_analyzer.py --gist --show-events
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from datetime import datetime

# Gist URL for the original TikTok log disclosure by fs0c131y
GIST_RAW_URL = (
    "https://gist.githubusercontent.com/fs0c131y/"
    "b4ef278e8863c636964793e1b27f889d/raw"
)

SECTION_WIDTH = 70


# ---------------------------------------------------------------------------
# Log parser
# ---------------------------------------------------------------------------

def parse_log_blocks(text: str) -> list[dict]:
    """
    Parse the TikTok log format into a list of block dicts.

    Each block has:
      - "type": "session" | "event" | "log" | "unknown"
      - "fields": dict of key -> value string
      - (for type "log") "parsed_json": the parsed JSON payload if available
    """
    blocks = []
    current_type = None
    current_fields: dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if line == "[Log Session]":
            if current_type is not None:
                blocks.append(_finalize_block(current_type, current_fields))
            current_type = "session"
            current_fields = {}

        elif line == "[Log Event]":
            if current_type is not None:
                blocks.append(_finalize_block(current_type, current_fields))
            current_type = "event"
            current_fields = {}

        elif line == "[Log]":
            if current_type is not None:
                blocks.append(_finalize_block(current_type, current_fields))
            current_type = "log"
            current_fields = {}

        elif "=" in line and current_type is not None:
            key, _, value = line.partition("=")
            current_fields[key.strip()] = value.strip()

    if current_type is not None:
        blocks.append(_finalize_block(current_type, current_fields))

    return blocks


def _finalize_block(block_type: str, fields: dict) -> dict:
    block = {"type": block_type, "fields": dict(fields)}

    if block_type == "log" and "value" in fields:
        raw_value = fields["value"].strip()
        # Try to parse as JSON
        try:
            block["parsed_json"] = json.loads(raw_value)
        except (json.JSONDecodeError, ValueError):
            block["parsed_json"] = None

    if block_type == "event" and "ext_json" in fields:
        raw_ext = fields["ext_json"].strip()
        try:
            block["ext_parsed"] = json.loads(raw_ext)
        except (json.JSONDecodeError, ValueError):
            block["ext_parsed"] = None

    return block


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def extract_header(blocks: list[dict]) -> dict | None:
    """Extract the device/app header from [Log] blocks."""
    for block in blocks:
        pj = block.get("parsed_json")
        if isinstance(pj, dict) and "header" in pj:
            return pj["header"]
    return None


def extract_all_events(blocks: list[dict]) -> list[dict]:
    """Collect all event dicts from [Log Event] blocks and [Log] JSON payloads."""
    events = []

    for block in blocks:
        if block["type"] == "event":
            fields = block["fields"]
            ext = block.get("ext_parsed") or {}
            event = {
                "tag": fields.get("tag", ""),
                "category": fields.get("category", ""),
                "label": fields.get("label", "null"),
                "timestamp": fields.get("timestamp", ""),
                "session_id": fields.get("session_id", ""),
                "ext": ext,
                "source": "log_event_block",
            }
            events.append(event)

        elif block["type"] == "log":
            pj = block.get("parsed_json")
            if not isinstance(pj, dict):
                continue
            for evt_list_key in ("event", "event_v3"):
                for evt in pj.get(evt_list_key, []):
                    if not isinstance(evt, dict):
                        continue
                    events.append({
                        "tag": evt.get("tag") or evt.get("event", ""),
                        "category": evt.get("category", evt_list_key),
                        "label": evt.get("label", ""),
                        "timestamp": evt.get("datetime", ""),
                        "session_id": evt.get("session_id", ""),
                        "ext": evt.get("params") or {},
                        "source": "log_json",
                    })

    return events


def extract_network_hosts(blocks: list[dict]) -> list[str]:
    """Pull all hostnames / IPs observed in the logs."""
    hosts = set()

    for block in blocks:
        # From [Log Event] ext_json
        ext = block.get("ext_parsed") or {}
        for key in ("set_host", "upload_host", "host"):
            if key in ext:
                hosts.add(ext[key])

        # From [Log] JSON payload
        pj = block.get("parsed_json")
        if not isinstance(pj, dict):
            continue

        _crawl_hosts(pj, hosts)

    return sorted(hosts)


def _crawl_hosts(obj, hosts: set, depth: int = 0):
    """Recursively search for host-like strings in any JSON structure."""
    if depth > 8:
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in ("host", "set_host", "upload_host", "rip") and isinstance(val, str) and val:
                hosts.add(val)
            _crawl_hosts(val, hosts, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _crawl_hosts(item, hosts, depth + 1)
    elif isinstance(obj, str) and len(obj) > 5:
        # Try to parse nested JSON strings
        if obj.startswith("{") or obj.startswith("["):
            try:
                nested = json.loads(obj)
                _crawl_hosts(nested, hosts, depth + 1)
            except (json.JSONDecodeError, ValueError):
                pass


def extract_device_info(header: dict | None) -> dict:
    """Pull device/app metadata from the header block."""
    if not header:
        return {}
    keys = [
        "device_model", "device_brand", "device_manufacturer",
        "os", "os_version", "os_api", "app_version", "version_code",
        "package", "channel", "display_name", "language",
        "resolution", "cpu_abi", "region", "tz_name",
        "install_id", "aid",
    ]
    return {k: header[k] for k in keys if k in header}


def extract_identifiers(header: dict | None) -> dict:
    """Pull unique identifiers from the header block."""
    if not header:
        return {}
    id_keys = [
        "openudid", "clientudid", "google_aid", "device_id",
        "install_id", "sig_hash",
    ]
    return {k: header[k] for k in id_keys if k in header}


def extract_network_probes(blocks: list[dict]) -> list[dict]:
    """Extract network_observe_report events which show probed external hosts."""
    probes = []
    for block in blocks:
        pj = block.get("parsed_json")
        if not isinstance(pj, dict):
            continue
        for evt in pj.get("event_v3", []):
            if not isinstance(evt, dict):
                continue
            if evt.get("event") == "network_observe_report":
                params = evt.get("params", {})
                raw_detail = params.get("network_status_detail", "")
                if isinstance(raw_detail, str):
                    try:
                        detail = json.loads(raw_detail)
                    except (json.JSONDecodeError, ValueError):
                        detail = {}
                elif isinstance(raw_detail, dict):
                    detail = raw_detail
                else:
                    detail = {}
                for key in detail:
                    if ":" in key and not key.startswith("extra"):
                        host_part = key.rsplit(":", 1)[0]
                        probe_data = detail[key]
                        dns_result = probe_data.get("dns_result", {}) if isinstance(probe_data, dict) else {}
                        probes.append({
                            "host": host_part,
                            "port": key.rsplit(":", 1)[1] if ":" in key else "",
                            "resolved_ip": dns_result.get("ip", ""),
                            "dns_success": dns_result.get("success", None),
                            "datetime": evt.get("datetime", ""),
                        })
    return probes


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_banner():
    print()
    print("=" * SECTION_WIDTH)
    print("  TIKTOK LOG ANALYZER — Security Research Tool")
    print("  Based on public disclosure by fs0c131y")
    print("=" * SECTION_WIDTH)


def print_section(title: str):
    print()
    pad = SECTION_WIDTH - len(title) - 5
    print(f"--- {title} {'-' * max(pad, 1)}")


def print_field(label: str, value, indent: int = 2):
    prefix = " " * indent
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    print(f"{prefix}{label:<30} {value}")


def print_analysis(
    header: dict | None,
    device_info: dict,
    identifiers: dict,
    events: list[dict],
    hosts: list[str],
    probes: list[dict],
    blocks: list[dict],
    show_events: bool = False,
):
    print_banner()

    # --- Summary ---
    n_sessions = sum(1 for b in blocks if b["type"] == "session")
    n_event_blocks = sum(1 for b in blocks if b["type"] == "event")
    n_log_blocks = sum(1 for b in blocks if b["type"] == "log")
    print_section("Summary")
    print_field("Total blocks parsed:", len(blocks))
    print_field("Session blocks:", n_sessions)
    print_field("Event blocks:", n_event_blocks)
    print_field("Log (upload) blocks:", n_log_blocks)
    print_field("Total events extracted:", len(events))
    print_field("Unique hosts observed:", len(hosts))

    # --- Device Info ---
    if device_info:
        print_section("Device & App Info")
        for k, v in device_info.items():
            print_field(f"{k}:", v)

    # --- Identifiers ---
    if identifiers:
        print_section("Unique Identifiers Collected")
        for k, v in identifiers.items():
            print_field(f"{k}:", v)

    # --- Network Hosts ---
    if hosts:
        print_section(f"Network Hosts Observed ({len(hosts)})")
        for h in hosts:
            print(f"    {h}")

    # --- Network Probes ---
    if probes:
        print_section(f"Active Network Probes (network_observe_report)")
        seen = set()
        for p in probes:
            key = f"{p['host']}:{p['port']}"
            if key not in seen:
                seen.add(key)
                ip_part = f" -> {p['resolved_ip']}" if p["resolved_ip"] else ""
                print(f"    {p['host']}:{p['port']}{ip_part}")

    # --- Event frequency ---
    print_section("Top Event Tags")
    tag_counts = Counter(e["tag"] for e in events if e["tag"])
    for tag, count in tag_counts.most_common(20):
        print(f"    {count:>5}  {tag}")

    # --- Event listing ---
    if show_events:
        print_section("All Events (chronological)")
        for e in events:
            ts = e.get("timestamp", "")
            tag = e.get("tag", "")
            cat = e.get("category", "")
            label = e.get("label", "")
            parts = [x for x in [ts, cat, tag, label] if x and x != "null"]
            print(f"    {' | '.join(parts)}")

    print()
    print("=" * SECTION_WIDTH)
    print("  All data shown is from the PUBLIC gist disclosure only.")
    print("  Source: https://gist.github.com/fs0c131y/b4ef278e8863c636964793e1b27f889d")
    print(f"  Analyzed at: {datetime.utcnow().isoformat()}Z")
    print("=" * SECTION_WIDTH)
    print()


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_from_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as exc:
        print(f"ERROR: Cannot read file: {exc}", file=sys.stderr)
        sys.exit(1)


def load_from_gist() -> str:
    print(f"  Fetching log data from GitHub Gist...", file=sys.stderr)
    try:
        req = urllib.request.Request(
            GIST_RAW_URL, headers={"User-Agent": "TikTokLogAnalyzer/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        print(f"ERROR: Failed to fetch gist: {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze TikTok app telemetry logs for security research.\n"
            "Parses the log format disclosed by fs0c131y (gist b4ef278e8863c636964793e1b27f889d)."
        ),
        epilog=(
            "Examples:\n"
            "  python tiktok_log_analyzer.py logs.txt\n"
            "  python tiktok_log_analyzer.py logs.txt -o json\n"
            "  python tiktok_log_analyzer.py --gist\n"
            "  python tiktok_log_analyzer.py --gist --show-events\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        help="Path to TikTok log file to analyze",
    )
    parser.add_argument(
        "--gist",
        action="store_true",
        help="Fetch and analyze the original fs0c131y disclosure gist directly",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--show-events",
        action="store_true",
        help="List all individual events in chronological order",
    )
    return parser


def run_analysis(text: str, output_format: str, show_events: bool):
    blocks = parse_log_blocks(text)
    header = extract_header(blocks)
    device_info = extract_device_info(header)
    identifiers = extract_identifiers(header)
    events = extract_all_events(blocks)
    hosts = extract_network_hosts(blocks)
    probes = extract_network_probes(blocks)

    if output_format == "json":
        output = {
            "summary": {
                "total_blocks": len(blocks),
                "session_blocks": sum(1 for b in blocks if b["type"] == "session"),
                "event_blocks": sum(1 for b in blocks if b["type"] == "event"),
                "log_blocks": sum(1 for b in blocks if b["type"] == "log"),
                "total_events": len(events),
                "unique_hosts": len(hosts),
            },
            "device_info": device_info,
            "identifiers": identifiers,
            "network_hosts": hosts,
            "network_probes": probes,
            "event_tag_frequencies": dict(Counter(e["tag"] for e in events if e["tag"]).most_common()),
        }
        if show_events:
            output["events"] = events
        print(json.dumps(output, indent=2, default=str))
    else:
        print_analysis(
            header, device_info, identifiers, events, hosts, probes, blocks,
            show_events=show_events,
        )


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.gist:
        text = load_from_gist()
    elif args.logfile:
        text = load_from_file(args.logfile)
    else:
        parser.print_help()
        sys.exit(1)

    run_analysis(text, args.output, args.show_events)


if __name__ == "__main__":
    main()
