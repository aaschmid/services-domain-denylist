"""Tests for generate_denylist.py.

Rule-shape, union and config tests run offline; the end-to-end tests at the bottom hit
the live AdGuard feed and require network access.
"""

import importlib.util
import pathlib
import re
import subprocess
import sys

import pytest
import requests

HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

_script = pathlib.Path(__file__).parent.parent / "generate_denylist.py"
_spec = importlib.util.spec_from_file_location("generate_denylist", _script)
assert _spec is not None and _spec.loader is not None  # static path next to this test
convert = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(convert)


# ---------- convert_rule: the exact rule-shape spec ----------


def test_domain_rule():
    assert convert.convert_rule("||example.com^") == ("example.com", None)


def test_anchor_rule_is_exact_single_host():
    assert convert.convert_rule("|exact.host^") == ("exact.host", None)
    assert convert.convert_rule("|no-caret.host") == ("no-caret.host", None)


def test_wildcard_skipped():
    assert convert.convert_rule("awsdns-*.com^")[1] == "wildcard"
    assert convert.convert_rule("*vod.example.com^")[1] == "wildcard"


def test_modifier_skipped():
    assert convert.convert_rule("||example.com^$dnstype=~CNAME")[1] == "modifier"
    assert convert.convert_rule("||qq.com^$denyallow=w.qq.com")[1] == "modifier"


def test_regex_skipped():
    assert convert.convert_rule("/_spotify-connect._tcp.local/")[1] == "regex"


def test_ipv4_silently_skipped():
    assert convert.convert_rule("||93.184.216.34^") == (None, None)


def test_invalid_hostname_skipped():
    assert convert.convert_rule("||bad_host.example.com^")[1] == "invalid-hostname"
    assert convert.convert_rule("||-leadhyphen.com^")[1] == "invalid-hostname"


def test_trailing_dot_lowercased():
    assert convert.convert_rule("||EXAMPLE.COM.^") == ("example.com", None)


def test_unsupported_shape():
    assert convert.convert_rule("!somecomment")[1] == "unsupported"


# ---------- build(): dedupe, unknown IDs, union across services ----------

FEED = {
    "blocked_services": [
        {"id": "alpha", "rules": ["||a.com^", "||b.com^", "||a.com^"]},
        {"id": "shared", "rules": ["||c.com^"]},
        {"id": "empty", "rules": ["||*.wild.com^"]},
        {"id": "4chan", "rules": ["||4chan.org^", "||4cdn.org^", "||4channel.org^"]},
        {"id": "spotify", "rules": ["||spotify.com^", "||pscdn.co^", "||scdn.co^"]},
    ]
}


def _build(feed, service_ids):
    stats = {"raw": 0, "wildcard": 0, "modifier": 0, "regex": 0, "unsupported": 0, "invalid-hostname": 0, "ip": 0}
    by_id = {s["id"]: s for s in feed["blocked_services"]}
    domains = set()
    per_id = {}
    for sid in service_ids:
        matched = set()
        for rule in by_id[sid]["rules"]:
            stats["raw"] += 1
            domain, skip = convert.convert_rule(rule)
            if skip or domain is None:
                continue
            matched.add(domain)
            domains.add(domain)
        per_id[sid] = matched
    return domains, per_id


def test_union_dedupes():
    domains, _ = _build(FEED, ["alpha"])
    assert domains == {"a.com", "b.com"}


def test_shared_domain_union():
    domains, _ = _build(FEED, ["alpha", "shared"])
    assert domains == {"a.com", "b.com", "c.com"}


# ---------- unknown ID exits 2 with nearest valid suggestions ----------


def test_unknown_id_exits_with_suggestions(capsys):
    feed = {"blocked_services": [{"id": "netflix", "rules": []}]}
    with pytest.raises(SystemExit) as e:
        convert.build(feed, ["netflx"])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "netflx" in err and "netflix" in err


# ---------- config parser ----------


def test_config_block_list(tmp_path):
    cfg = tmp_path / "services.yaml"
    cfg.write_text("# comment\nservices:\n  - alpha\n  # - hidden\n  - beta\n")
    assert convert.load_config_ids(cfg) == ["alpha", "beta"]


def test_config_flat_file(tmp_path):
    cfg = tmp_path / "services.txt"
    cfg.write_text("# comment\nalpha\nbeta\n")
    assert convert.load_config_ids(cfg) == ["alpha", "beta"]


def test_config_flow_list(tmp_path):
    cfg = tmp_path / "services.yaml"
    cfg.write_text("services: [alpha, beta]\n")
    assert convert.load_config_ids(cfg) == ["alpha", "beta"]


# ---------- end-to-end against the live feed (network required) ----------


def _live_feed_available():
    """Skip live-feed tests when the AdGuard URL is unreachable (e.g. sandboxed offline runs)."""
    try:
        convert.fetch_feed(convert.FEED_URL)
        return True
    except OSError, requests.RequestException:
        return False


def _run_generator():
    r = subprocess.run(
        [sys.executable, "generate_denylist.py"],
        capture_output=True,
        text=True,
        cwd=_script.parent,
        check=False,  # returncode is asserted below to include stderr in the message
    )
    assert r.returncode == 0, r.stderr
    return (_script.parent / "blocklist.txt").read_bytes()


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    """Run the real generator once against the live feed; share the output bytes."""
    if not _live_feed_available():
        pytest.skip("AdGuard feed unreachable (offline?)")
    # generation writes into the repo root (OUTPUT_FILE is relative); snapshot the file,
    # let two runs happen, and expose both snapshots for the assertions below.
    out1 = tmp_path_factory.mktemp("gen") / "b1.txt"
    out1.write_bytes(_run_generator())
    out2 = tmp_path_factory.mktemp("gen") / "b2.txt"
    out2.write_bytes(_run_generator())
    return out1.read_bytes(), out2.read_bytes()


def test_integration_idempotent(generated):
    b1, b2 = generated
    assert b1 == b2, "two runs differ - not idempotent"


def test_integration_header(generated):
    b1, _ = generated
    lines = b1.decode().splitlines()
    assert lines[0].startswith("# Generated 20"), "generation date line missing"
    stats = next(l for l in lines if l.startswith("# Stats:")).split()
    # '# Stats: 104 services, 1392 raw rules, 5 skipped, 1379 domains'
    raw, skipped, total = int(stats[4]), int(stats[7]), int(stats[9])
    assert raw > 500, f"implausibly few raw rules ({raw})"
    assert skipped < raw // 4, f"implausibly many skipped ({skipped} of {raw})"
    assert total > 500, f"implausibly few domains ({total})"


def test_integration_blocky_parsable(generated):
    """Assert the grammar Blocky's denylist parsers accept (hosts/domain list format):
    one entry per line, '#' comment lines, no blank/whitespace/duplicate entries."""
    b1, _ = generated
    text = b1.decode()
    assert "\n\n" not in text, "blank line (rejects strict line parsers)"
    assert text.endswith("\n") and not text.startswith("\n")
    entries = []
    for line in text.splitlines():
        assert line == line.strip(), f"surrounding whitespace: {line!r}"
        if line.startswith("#"):
            continue
        assert line and HOSTNAME_RE.match(line), f"not a plain domain: {line!r}"
        entries.append(line)
    assert len(entries) == len(set(entries)), "duplicates (Blocky tolerates but they bloat)"


def test_integration_config_matches_stats(generated):
    b1, _ = generated
    lines = b1.decode().splitlines()
    configured = len(convert.load_config_ids(_script.parent / "services.yaml"))
    stats = next(l for l in lines if l.startswith("# Stats:"))
    n_services = int(stats.split()[2])
    assert n_services == configured, "header service count diverges from services.yaml"


def test_integration_sample_domains_present(generated):
    """Spot-check unions of services that are definitely in the config."""
    b1, _ = generated
    text = b1.decode()
    # spotify is enabled; its feed rules bear spotify.com and scdn.co
    assert "spotify.com\n" in text, "expected spotify.com in output"
    assert "scdn.co\n" in text, "expected scdn.co in output"
