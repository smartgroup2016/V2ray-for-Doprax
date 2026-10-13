#!/usr/bin/env python3
"""
v2ray_collector.py
Aggregate V2Ray config links from public Telegram channels.

Requirements:
    pip install requests beautifulsoup4

Usage:
    python v2ray_collector.py
"""

import base64
import json
import re
import sys
from pathlib import Path
from typing import List, Set

import requests
from bs4 import BeautifulSoup

# ============ CONFIG ============
# Telegram channels to scrape (username without @).
# These must have a PUBLIC web preview at https://t.me/s/<name>
CHANNELS = [
    "VPNBaz",
"PrivateVPNs",
"DirectVPN",
"vpn_Click",
    "Farah_VPN",
]

# Protocols we care about
PROTOCOLS = ("vmess://", "vless://", "trojan://", "ss://", "ssr://")

# Where to write output
OUTPUT_DIR = Path("configs")
OUTPUT_TXT = OUTPUT_DIR / "configs.txt"
OUTPUT_JSON = OUTPUT_DIR / "configs.json"

# HTTP settings
TIMEOUT = 20
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    )
}

# Regex to find any protocol link inside message text
LINK_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|ssr)://[^\s\"'<>)]+",
    re.IGNORECASE,
)
# ================================


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

    # Each message body is inside .tgme_widget_message_text
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


def try_decode_vmess(link: str) -> dict:
    """
    Optionally decode a vmess:// base64 payload into a dict.
    Returns {} if not decodable.
    """
    if not link.lower().startswith("vmess://"):
        return {}
    payload = link[len("vmess://"):]
    # pad base64 if necessary
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.b64decode(payload + padding).decode("utf-8", errors="ignore")
        return json.loads(raw)
    except Exception:
        return {}


def collect_from_channels(channels: List[str]) -> Set[str]:
    all_links: Set[str] = set()
    for ch in channels:
        print(f"[*] Scraping @{ch} ...")
        html = fetch_channel_html(ch)
        links = extract_links(html)
        print(f"    -> {len(links)} link(s) found")
        all_links |= links
    return all_links


def write_outputs(links: Set[str]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Plain text: one link per line
    OUTPUT_TXT.write_text("\n".join(sorted(links)) + "\n", encoding="utf-8")

    # JSON: include parsed metadata when possible
    records = []
    for link in sorted(links):
        record = {"link": link, "protocol": link.split("://", 1)[0]}
        if link.lower().startswith("vmess://"):
            decoded = try_decode_vmess(link)
            if decoded:
                record["decoded"] = decoded
        records.append(record)

    OUTPUT_JSON.write_text(
        json.dumps(records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"[+] Wrote {len(links)} configs to {OUTPUT_TXT} and {OUTPUT_JSON}")


def main() -> int:
    links = collect_from_channels(CHANNELS)
    if not links:
        print("[!] No configs found.", file=sys.stderr)
        return 1
    write_outputs(links)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
