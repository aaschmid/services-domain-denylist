# Denylist for services and their domains

Converts the AdGuard Home "blocked services" rule set into a plain-domain denylist
(one domain per line) usable as a DNS-sinkhole blocklist source URL.

One script (`generate_denylist.py`), one config (`services.yaml`), one workflow (`.github/workflows/generate.yml`), one output (`blocklist.txt`).

Note: the plain-domain format is a subset of what AdGuard Home itself would block — rules
needing wildcards, `$dnstype`/`$dnsrewrite`/`$denyallow` modifiers or regexes are skipped (each skip is logged during the generation).

## Configure

Edit `services.yaml` and list the AdGuard service IDs you want blocked. All valid IDs are in the
[services feed](https://adguardteam.github.io/HostlistsRegistry/assets/services.json)
(and shown in the AdGuard Home UI under "Blocked services").

## Generate

The GitHub Action regenerates and commits `blocklist.txt` on every push and weekly:

```sh
uv sync --all-groups
uv run generate_denylist.py
```

`stderr` shows skipped rules with reasons; the script exits non-zero on unknown IDs or failures.

## Works with

Any DNS blocker that accepts plain host/domain lists (lines starting with `#` are comments). Examples:

- **Blocky** (tested with v0.36) — `blocking.denylists` (see below)
- **AdGuard Home** — Filters → DNS blocklists → Add blocklist (custom URL)
- **Pi-hole** — Group Management → Adlists → add the raw URL
- **unbound** — via a `local-zone: "domain refuse"` include generated from the list
- **dnscrypt-proxy** — as a plain-format blacklist in the `[blocked_names]` section

Example for Blocky:

```yaml
blocking:
  denylists:
    services:
      - https://raw.githubusercontent.com/aaschmid/services-domain-denylist/main/blocklist.txt
```
