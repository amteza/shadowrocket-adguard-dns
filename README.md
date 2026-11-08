# AdGuard DNS filter for Shadowrocket

The [AdGuard DNS filter](https://github.com/AdguardTeam/AdguardSDNSFilter) and [HaGeZi's RegEx/Wildcard rules](https://github.com/hagezi/dns-blocklists) converted into Shadowrocket rule files and refreshed every 6 hours by GitHub Actions.

| File | Shadowrocket rule |
|---|---|
| `adguard_dns_allow.list` | `RULE-SET,https://raw.githubusercontent.com/amteza/shadowrocket-adguard-dns/main/adguard_dns_allow.list,PROXY` |
| `adguard_dns.domainset` | `DOMAIN-SET,https://raw.githubusercontent.com/amteza/shadowrocket-adguard-dns/main/adguard_dns.domainset,REJECT` |
| `adguard_dns_wildcard.list` | `RULE-SET,https://raw.githubusercontent.com/amteza/shadowrocket-adguard-dns/main/adguard_dns_wildcard.list,REJECT` |
| `hagezi_regex.list` | `RULE-SET,https://raw.githubusercontent.com/amteza/shadowrocket-adguard-dns/main/hagezi_regex.list,REJECT` |

Put the allow list **above** the others so AdGuard's exceptions win. Use `DIRECT` instead of `PROXY` for the allow list if you don't route traffic through a proxy.

## What converts

- **AdGuard DNS filter:** plain domain rules go to the domain set; wildcard rules (`||ads.*.example.com^`) become `DOMAIN-WILDCARD`. Regex and partial-match rules have no equivalent and are skipped.
- **HaGeZi RegEx/Wildcard:** `|*text*^` becomes `DOMAIN-KEYWORD` (exact); IP-address regexes become `IP-CIDR` (exact, computed); the tracker and tag-manager regexes become `DOMAIN-WILDCARD` approximations. The random-hex and UUID regexes can't be expressed and are listed as skipped in the file header.

The source lists are © AdGuard and contributors (GPL-3.0) and © HaGeZi (GPL-3.0); see the upstream repositories.
