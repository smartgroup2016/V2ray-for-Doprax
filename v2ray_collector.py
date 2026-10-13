#!/usr/bin/env python3
"""
v2ray_collector.py
Aggregate and verify V2Ray config links from public Telegram channels.

Requirements:
    pip install requests beautifulsoup4

For full testing with xray-core:
    - Download xray-core from https://github.com/XTLS/Xray-core/releases
    - Place xray executable in PATH or same directory as this script

Usage:
    python v2ray_collector.py
"""

import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote

import requests
from bs4 import BeautifulSoup

# ============ CONFIG ============
CHANNELS = [
    "v2ray_configs_pool",
    "free_v2ray_config",
    "v2rayng_config",
    "V2ray_Free_Config",
    "proxy_v2ray_config",
    "Farah_VPN",
]

PROTOCOLS = ("vmess://", "vless://", "trojan://", "ss://", "ssr://")

OUTPUT_DIR = Path("configs")
OUTPUT_TXT = OUTPUT_DIR / "configs.txt"
OUTPUT_VALID = OUTPUT_DIR / "valid.txt"
OUTPUT_JSON = OUTPUT_DIR / "configs.json"

TIMEOUT = 20
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    )
}

LINK_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|ssr)://[^\s\"'<>)]+",
    re.IGNORECASE,
)

# Testing configuration
TEST_URL = "https://www.gstatic.com/generate_204"  # Lightweight connectivity check
TEST_TIMEOUT = 5  # Seconds per config
MAX_WORKERS = 20  # Concurrent tests
# ================================


@dataclass
class ConfigTestResult:
    """Result of a single config verification and test."""
    link: str
    protocol: str
    valid_format: bool = False
    parse_error: Optional[str] = None
    connection_success: bool = False
    latency_ms: Optional[float] = None
    error: Optional[str] = None


def fetch_channel_html(channel: str) -> str:
    """Fetch the public web preview page for a channel."""
    url = f"https://t.me/s/{channel}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {channel}: {e}", file=sys.stderr)
        return ""


def extract_links(html: str) -> Set[str]:
    """Parse message text out of the HTML and extract config links."""
    if not html:
        return set()

    soup = BeautifulSoup(html, "html.parser")
    found: Set[str] = set()

    for node in soup.select(".tgme_widget_message_text"):
        text = node.get_text("\n", strip=True)
        for match in LINK_RE.finditer(text):
            link = clean_link(match.group(0))
            if link:
                found.add(link)

    return found


def clean_link(link: str) -> str:
    """Strip trailing punctuation and whitespace from a link."""
    link = link.strip().rstrip(".,;:!?\"'`")
    return link


# ============ CONFIG PARSING AND VALIDATION ============

def parse_vmess_link(link: str) -> Optional[Dict[str, Any]]:
    """Parse a vmess:// link into a config dict."""
    if not link.lower().startswith("vmess://"):
        return None

    payload = link[len("vmess://"):]
    padding = "=" * (-len(payload) % 4)

    try:
        raw = base64.b64decode(payload + padding).decode("utf-8", errors="ignore")
        config = json.loads(raw)
        # Validate required fields
        if not all(k in config for k in ("add", "port", "id")):
            return None
        return config
    except Exception:
        return None


def parse_vless_link(link: str) -> Optional[Dict[str, Any]]:
    """Parse a vless:// link into a config dict."""
    if not link.lower().startswith("vless://"):
        return None

    try:
        parsed = urlparse(link)
        # Format: vless://uuid@host:port?params#label
        if not parsed.username or not parsed.hostname:
            return None

        config = {
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port or 443,
            "params": parse_qs(parsed.query),
        }
        return config
    except Exception:
        return None


def parse_trojan_link(link: str) -> Optional[Dict[str, Any]]:
    """Parse a trojan:// link into a config dict."""
    if not link.lower().startswith("trojan://"):
        return None

    try:
        parsed = urlparse(link)
        if not parsed.username or not parsed.hostname:
            return None

        config = {
            "password": unquote(parsed.username),
            "address": parsed.hostname,
            "port": parsed.port or 443,
            "params": parse_qs(parsed.query),
        }
        return config
    except Exception:
        return None


def parse_ss_link(link: str) -> Optional[Dict[str, Any]]:
    """Parse a ss:// (Shadowsocks) link into a config dict."""
    if not link.lower().startswith("ss://"):
        return None

    try:
        # Handle SIP002 format: ss://base64(method:password)@host:port
        # Or legacy format: ss://base64(method:password@host:port)
        raw = link[5:]  # Remove 'ss://'

        if "@" in raw:
            # SIP002 format
            userinfo_b64, hostinfo = raw.rsplit("@", 1)
            padding = "=" * (-len(userinfo_b64) % 4)
            userinfo = base64.urlsafe_b64decode(userinfo_b64 + padding).decode()
            method, password = userinfo.split(":", 1)
            host, port = hostinfo.split(":")
            return {
                "method": method,
                "password": password,
                "address": host,
                "port": int(port.split("#")[0].split("?")[0]),
            }
        else:
            # Legacy format
            payload = raw.split("#")[0].split("?")[0]
            padding = "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload + padding).decode()
            method_password, host_port = decoded.rsplit("@", 1)
            method, password = method_password.split(":", 1)
            host, port = host_port.rsplit(":", 1)
            return {
                "method": method,
                "password": password,
                "address": host,
                "port": int(port),
            }
    except Exception:
        return None


def validate_config_format(link: str) -> tuple[bool, Optional[str]]:
    """
    Validate the format of a config link.
    Returns (is_valid, error_message).
    """
    protocol = link.split("://")[0].lower()

    if protocol == "vmess":
        result = parse_vmess_link(link)
        if result is None:
            return False, "Invalid vmess base64/JSON structure"
        return True, None

    elif protocol == "vless":
        result = parse_vless_link(link)
        if result is None:
            return False, "Invalid vless URI structure"
        return True, None

    elif protocol == "trojan":
        result = parse_trojan_link(link)
        if result is None:
            return False, "Invalid trojan URI structure"
        return True, None

    elif protocol == "ss":
        result = parse_ss_link(link)
        if result is None:
            return False, "Invalid ss URI structure"
        return True, None

    else:
        return False, f"Unsupported protocol: {protocol}"


# ============ CONNECTION TESTING ============

def get_config_endpoint(link: str) -> Optional[tuple[str, int]]:
    """Extract (host, port) from a config link for basic TCP testing."""
    try:
        protocol = link.split("://")[0].lower()

        if protocol == "vmess":
            config = parse_vmess_link(link)
            if config:
                return config.get("add"), int(config.get("port", 443))

        elif protocol == "vless":
            config = parse_vless_link(link)
            if config:
                return config.get("address"), config.get("port", 443)

        elif protocol == "trojan":
            config = parse_trojan_link(link)
            if config:
                return config.get("address"), config.get("port", 443)

        elif protocol == "ss":
            config = parse_ss_link(link)
            if config:
                return config.get("address"), config.get("port", 8388)

    except Exception:
        pass
    return None


def test_tcp_connection(host: str, port: int, timeout: float = TEST_TIMEOUT) -> tuple[bool, Optional[float]]:
    """
    Test TCP connection to a host:port.
    Returns (success, latency_ms).
    Note: This only tests TCP handshake, not actual proxy functionality.
    """
    if not host or not port:
        return False, None

    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.time() - start) * 1000
            return True, round(latency, 2)
    except (socket.timeout, socket.error, OSError):
        return False, None


def test_config(link: str) -> ConfigTestResult:
    """
    Full verification of a single config:
    1. Validate format/parsing
    2. Test TCP connectivity to the endpoint
    """
    protocol = link.split("://")[0].lower()
    result = ConfigTestResult(link=link, protocol=protocol)

    # Step 1: Validate format
    valid, error = validate_config_format(link)
    result.valid_format = valid
    result.parse_error = error

    if not valid:
        return result

    # Step 2: Test TCP connectivity
    endpoint = get_config_endpoint(link)
    if endpoint:
        host, port = endpoint
        success, latency = test_tcp_connection(host, port)
        result.connection_success = success
        result.latency_ms = latency
        if not success:
            result.error = f"TCP connection failed to {host}:{port}"

    return result


def test_configs_parallel(links: Set[str]) -> List[ConfigTestResult]:
    """Test multiple configs concurrently."""
    results: List[ConfigTestResult] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_config, link): link for link in links}

        for future in as_completed(futures):
            try:
                result = future.result(timeout=TEST_TIMEOUT * 2)
                results.append(result)
            except Exception as e:
                link = futures[future]
                results.append(ConfigTestResult(
                    link=link,
                    protocol=link.split("://")[0],
                    error=f"Test error: {e}"
                ))

    return results


# ============ COLLECTION AND OUTPUT ============

def collect_from_channels(channels: List[str]) -> Set[str]:
    """Collect all links from the specified channels."""
    all_links: Set[str] = set()
    for ch in channels:
        print(f"[*] Scraping @{ch} ...")
        html = fetch_channel_html(ch)
        links = extract_links(html)
        print(f"    -> {len(links)} link(s) found")
        all_links |= links
    return all_links


def write_outputs(links: Set[str], test_results: List[ConfigTestResult] = None) -> None:
    """Write collected configs and test results to files."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Plain text: one link per line
    OUTPUT_TXT.write_text("\n".join(sorted(links)) + "\n", encoding="utf-8")

    if test_results:
        # Write valid/working configs
        valid_links = [
            r.link for r in test_results
            if r.valid_format and r.connection_success
        ]
        OUTPUT_VALID.write_text("\n".join(sorted(valid_links)) + "\n", encoding="utf-8")

        # Build JSON report
        report = {
            "summary": {
                "total_collected": len(links),
                "valid_format": sum(1 for r in test_results if r.valid_format),
                "connection_success": sum(1 for r in test_results if r.connection_success),
                "fully_working": len(valid_links),
            },
            "results": [
                {
                    "link": r.link,
                    "protocol": r.protocol,
                    "valid_format": r.valid_format,
                    "connection_success": r.connection_success,
                    "latency_ms": r.latency_ms,
                    "error": r.error or r.parse_error,
                }
                for r in test_results
            ],
        }
        OUTPUT_JSON.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        print(f"\n[+] Results: {len(valid_links)} fully working out of {len(links)} total")
        print(f"    Valid format: {report['summary']['valid_format']}")
        print(f"    Connection success: {report['summary']['connection_success']}")
    else:
        print(f"[+] Wrote {len(links)} configs to {OUTPUT_TXT}")


def main() -> int:
    # Step 1: Collect configs
    print("[*] Collecting configs from Telegram channels...")
    links = collect_from_channels(CHANNELS)

    if not links:
        print("[!] No configs found.", file=sys.stderr)
        return 1

    print(f"\n[*] Collected {len(links)} unique configs")
    print("[*] Testing configs (format validation + TCP connectivity)...")

    # Step 2: Test configs
    test_results = test_configs_parallel(links)

    # Step 3: Write outputs
    write_outputs(links, test_results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
