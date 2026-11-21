"""Convert AdGuard Home "blocked services" rules to a plain-domain blocklist.

Reads service IDs from `services.yaml`, downloads the AdGuard services feed, converts the matching
rules to plain hostnames and writes `blocklist.txt`
(one domain per line, suitable as a Blocky denylist source).
"""

import difflib
import re
import sys
from datetime import UTC, datetime

import requests
import yaml

FEED_URL = "https://adguardteam.github.io/HostlistsRegistry/assets/services.json"
CONFIG_FILE = "services.yaml"
OUTPUT_FILE = "blocklist.txt"

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def load_config_ids(path):
    """Return the list of service IDs from `services.yaml`.

    Accepts a `services: [...]` block (the format this repo uses) and, as fallbacks, a flat
    one-ID-per-line text file and a flow-style `services: [a, b]` list. Comment lines start
    with `#`.
    """
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    data = yaml.safe_load(raw)
    if data is None:
        return []
    if isinstance(data, dict):
        return [str(x) for x in data.get("services") or []]
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, str):
        # YAML parses a multi-line plain-text file as one string scalar — fall back to
        # line-based parsing (this also covers .txt flat files).
        return [l.strip() for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")]
    raise SystemExit(f"{path}: unsupported YAML shape {type(data).__name__}")


def fetch_feed(url):
    resp = requests.get(url, timeout=10, headers={"User-Agent": "services-domain-denylist/1.0"})
    resp.raise_for_status()
    return resp.json()


def convert_rule(rule):
    """Return (domain, skip_reason) — exactly one is truthy."""
    rule = rule.strip()
    if "*" in rule:
        return None, "wildcard"
    if "$" in rule:
        return None, "modifier"
    if len(rule) > 1 and rule.startswith("/") and rule.endswith("/"):
        return None, "regex"
    if rule.startswith("||"):
        host = rule[2:]
    elif rule.startswith("|"):
        host = rule[1:]
    else:
        return None, "unsupported"
    host = host.removesuffix("^").rstrip(".").lower()
    if not host:
        return None, "unsupported"
    if IPV4_RE.match(host):
        return None, None  # IPv4 addresses are irrelevant for a DNS sinkhole
    if not HOSTNAME_RE.match(host):
        return None, "invalid-hostname"
    return host, None


def build(feed, ids):
    """Convert all rules for the given service IDs.

    Returns `(domains, per_id_domains, stats, duplicate_ids, feed_size)` and silently skips rules
    that cannot be represented as plain domains (wildcards, modifiers, regexes, IPs).
    """
    by_id = {s["id"]: s for s in feed["blocked_services"]}
    unknown = [i for i in ids if i not in by_id]
    if unknown:
        valid = sorted(by_id)
        print(f"ERROR: unknown service ID(s) in {CONFIG_FILE}: {', '.join(unknown)}", file=sys.stderr)
        for u in unknown:
            near = difflib.get_close_matches(u, valid, n=5, cutoff=0.4)
            print(f"  {u!r}: nearest valid IDs: {near or valid}", file=sys.stderr)
        sys.exit(2)

    domains = set()
    duplicate_ids = set()
    per_id_domains = {}
    stats = {"raw": 0, "wildcard": 0, "modifier": 0, "regex": 0, "unsupported": 0, "invalid-hostname": 0, "ip": 0}
    for sid in ids:
        matched = set()
        for rule in by_id[sid].get("rules", []):
            stats["raw"] += 1
            domain, skip = convert_rule(rule)
            if skip or domain is None:
                if skip:
                    stats[skip] += 1
                    print(f"skip: {sid}: {rule!r} ({skip})", file=sys.stderr)
                else:
                    stats["ip"] += 1
                continue
            matched.add(domain)
            domains.add(domain)
        if sid in per_id_domains:
            duplicate_ids.add(sid)
        per_id_domains[sid] = matched
        if not matched:
            print(f"WARN: service {sid!r} has zero matching rules after conversion", file=sys.stderr)

    return domains, per_id_domains, stats, duplicate_ids, len(by_id)


def main():
    ids = load_config_ids(CONFIG_FILE)
    feed = fetch_feed(FEED_URL)
    domains, per_id, stats, dup_ids, _feed_count = build(feed, ids)

    result = "\n".join(sorted(domains)) + "\n"
    skipped_total = (
        stats["wildcard"]
        + stats["modifier"]
        + stats["regex"]
        + stats["unsupported"]
        + stats["invalid-hostname"]
        + stats["ip"]
    )
    # 3-line header; date only (no clock time) so re-runs produce identical bytes
    header = (
        f"# Generated {datetime.now(UTC):%Y-%m-%d} by generate_denylist.py\n"
        f"# Source: [AdGuard HostlistsRegistry]({FEED_URL})\n"
        f"# Stats: {len(per_id)} services, {stats['raw']} raw rules, {skipped_total} skipped, "
        f"{len(domains)} domains\n"
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(header + result)

    if dup_ids:
        print(f"WARN: duplicated service IDs in {CONFIG_FILE}: {sorted(dup_ids)}", file=sys.stderr)
    print(
        f"OK: {len(per_id)} services, {stats['raw']} raw rules, {skipped_total} skipped, "
        f"{len(domains)} domains -> {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
