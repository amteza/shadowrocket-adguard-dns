#!/usr/bin/env python3
"""Convert the AdGuard DNS filter into Shadowrocket rule files.

Outputs (in the given output directory, default: current directory):
  adguard_dns.domainset   -> use with  DOMAIN-SET,<url>,REJECT
  adguard_dns_allow.list  -> use with  RULE-SET,<url>,PROXY   (put it BEFORE the DOMAIN-SET)

Only plain domain rules are converted (||example.com^ and @@||example.com^),
which is ~99.7% of the list. Regex, wildcard (ads.*.example.com) and
partial-match rules (~500) have no DOMAIN-SET equivalent and are skipped.
"""
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE = "https://filters.adtidy.org/dns/filter_1.txt"
DOMAIN = r"([a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+)"
BLOCK = re.compile(rf"^\|\|{DOMAIN}\^(\$important)?$")
BADFILTER = re.compile(rf"^\|\|{DOMAIN}\^\$badfilter$")
# @@||x^ / @@||x^| -> x and subdomains;  @@|x^| -> exactly x
ALLOW = re.compile(rf"^@@(\|\|?){DOMAIN}\^\|?(\$important)?$")


def collapse(domains):
    """Drop domains already covered by a parent domain in the set."""
    keep = []
    for d in sorted(domains, key=lambda x: x.count(".")):
        parts = d.split(".")
        if not any(".".join(parts[i:]) in seen for i in range(1, len(parts) - 1)):
            keep.append(d)
            seen.add(d)
    return keep


seen = set()


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    out.mkdir(parents=True, exist_ok=True)

    req = urllib.request.Request(SOURCE, headers={"User-Agent": "adguard2shadowrocket"})
    text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8")

    block, bad, allow = set(), set(), set()
    version, skipped = "?", 0
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("!"):
            if line.startswith("! version:"):
                version = raw.split(":", 1)[1].strip()
            continue
        if m := BLOCK.match(line):
            block.add(m.group(1))
        elif m := BADFILTER.match(line):
            bad.add(m.group(1))
        elif m := ALLOW.match(line):
            kind = "DOMAIN-SUFFIX" if m.group(1) == "||" else "DOMAIN"
            allow.add(f"{kind},{m.group(2)}")
        else:
            skipped += 1

    block -= bad
    block = collapse(block)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = f"# AdGuard DNS filter v{version} for Shadowrocket — converted {stamp}\n# Source: {SOURCE}\n"

    (out / "adguard_dns.domainset").write_text(
        header + "".join(f".{d}\n" for d in sorted(block)), encoding="utf-8")
    (out / "adguard_dns_allow.list").write_text(
        header + "".join(f"{r}\n" for r in sorted(allow)), encoding="utf-8")

    print(f"version {version}: {len(block)} blocked, {len(allow)} allowed, "
          f"{len(bad)} badfilter removed, {skipped} unsupported rules skipped")


if __name__ == "__main__":
    main()
