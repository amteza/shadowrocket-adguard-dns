#!/usr/bin/env python3
"""Convert HaGeZi's RegEx/Wildcard rules (AdGuard Home syntax) into a Shadowrocket rule set.

Output (in the given output directory, default: current directory):
  hagezi_regex.list -> use with  RULE-SET,<url>,REJECT

Shadowrocket has no domain-regex rule, so:
  |*text*^                         -> DOMAIN-KEYWORD,text        (exact equivalent)
  /^1\\.2\\.3\\.(...)$/ (IP regexes)  -> IP-CIDR ranges              (exact, computed)
  known domain regexes             -> DOMAIN-WILDCARD approximations (APPROX table)
  anything else                    -> skipped and listed in the file header
"""
import ipaddress
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adguard/regex-wildcard-rules.txt"

KEYWORD = re.compile(r"^\|\*([a-z0-9.-]+)\*\^$")
IP_PREFIX = re.compile(r"^/\^(\d{1,3})\\\.(\d{1,3})\\\.(\d{1,3})\\\.")

TRACKERS = re.compile(r"^/\(\^\|\.\+\\-\|\.\+\\\.\)\(([a-z0-9|]+)\)")

# Hand-written approximations for HaGeZi's domain regexes, keyed by the exact
# regex text. If HaGeZi edits one, it falls through to "skipped" (visible in the
# header) rather than producing something wrong.
APPROX = {
    r"/^s?s?gtm\.[a-z0-9-]+\.([a-z]{2,}|[a-z]{2,3}\.[a-z]{2,})$/":
        ["gtm.*.*", "sgtm.*.*", "ssgtm.*.*"],
    r"/^(tags|tagging|tagmanager)\.[a-z0-9-]+\.([a-z]{2,}|[a-z]{2,3}\.[a-z]{2,})$/":
        ["tags.*.*", "tagging.*.*", "tagmanager.*.*"],
    r"/^gtm\-.*\.(appspot\.com|fps\.goog|run\.app)$/":
        ["gtm-*.appspot.com", "gtm-*.fps.goog", "gtm-*.run.app"],
    r"/\-tagging\-.*\.run\.app$/":
        ["*-tagging-*.run.app"],
}


def ip_rules(rule):
    """Expand a regex anchored on the first three octets into IP-CIDR blocks."""
    m = IP_PREFIX.match(rule)
    if not m or not rule.endswith("$/"):
        return None
    rx = re.compile(rule[1:-1])
    a, b, c = m.groups()
    hits = [ipaddress.ip_network(f"{a}.{b}.{c}.{d}/32") for d in range(256)
            if rx.match(f"{a}.{b}.{c}.{d}")]
    return [f"IP-CIDR,{n},no-resolve" for n in ipaddress.collapse_addresses(hits)] or None


def tracker_rules(rule):
    """(^|.+-|.+.)(piwik|matomo|...)\\d*(-[^.]+)?\\.[^.]+\\.[^.]+.*$  -> tool label
    followed by at least two more labels, at the start or after '.' or '-'."""
    m = TRACKERS.match(rule)
    if not m:
        return None
    out = []
    for t in m.group(1).split("|"):
        out += [f"DOMAIN-WILDCARD,{t}*.*.*", f"DOMAIN-WILDCARD,*.{t}*.*.*",
                f"DOMAIN-WILDCARD,*-{t}*.*.*"]
    return out


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    out.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(SOURCE, headers={"User-Agent": "hagezi2shadowrocket"})
    text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8")

    rules, skipped, version = [], [], "?"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            if line.lower().startswith("! version:"):
                version = line.split(":", 1)[1].strip()
            continue
        if m := KEYWORD.match(line):
            rules.append(f"DOMAIN-KEYWORD,{m.group(1)}")
        elif line in APPROX:
            rules += [f"DOMAIN-WILDCARD,{w}" for w in APPROX[line]]
        elif r := ip_rules(line) or tracker_rules(line):
            rules += r
        else:
            skipped.append(line)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tag = f" v{version}" if version != "?" else ""
    header = (f"# HaGeZi RegEx/Wildcard{tag} for Shadowrocket — converted {stamp}\n"
              f"# Source: {SOURCE}\n"
              + "".join(f"# skipped (no Shadowrocket equivalent): {s}\n" for s in skipped))
    (out / "hagezi_regex.list").write_text(
        header + "".join(f"{r}\n" for r in dict.fromkeys(rules)), encoding="utf-8")
    print(f"HaGeZi{tag}: {len(rules)} rules, {len(skipped)} skipped")


if __name__ == "__main__":
    main()
