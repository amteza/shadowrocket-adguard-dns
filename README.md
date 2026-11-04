# AdGuard DNS filter for Shadowrocket

The [AdGuard DNS filter](https://github.com/AdguardTeam/AdguardSDNSFilter) converted into Shadowrocket rule files and refreshed every 6 hours by GitHub Actions.

| File | Shadowrocket rule |
|---|---|
| `adguard_dns_allow.list` | `RULE-SET,https://raw.githubusercontent.com/amteza/shadowrocket-adguard-dns/main/adguard_dns_allow.list,PROXY` |
| `adguard_dns.domainset` | `DOMAIN-SET,https://raw.githubusercontent.com/amteza/shadowrocket-adguard-dns/main/adguard_dns.domainset,REJECT` |

Put the allow list **above** the domain set so AdGuard's exceptions win. Use `DIRECT` instead of `PROXY` for the allow list if you don't route traffic through a proxy.

Only plain domain rules are converted (about 99.6% of the filter). Wildcard, regex and partial-match rules have no `DOMAIN-SET` equivalent and are skipped.

The filter itself is © AdGuard and contributors, licensed under GPL-3.0; see the upstream repository.
