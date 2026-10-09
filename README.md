# caddy-hosttech

Caddy DNS provider for hosttech.eu, built on libdns.
DNS-01 challenges and zone management. Tested with Caddy 2.11.

## Install

    xcaddy build --with github.com/Deroy2112/caddy-hosttech

## Use

    {
        acme_dns hosttech {env.HOSTTECH_API_TOKEN}
    }

API token: hosttech control panel → API → Personal Access Tokens.

## Notes

- Supported types: A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TXT and TLSA.
- The zone apex is `@` in libdns and is written as the API's empty owner.
- TTLs below 600 seconds are raised to 600 (the API minimum).
- `SetRecords` is not atomic. It preserves matching members, updates remaining
  members with PUT, creates additional members, then deletes surplus members.
  A failed write can leave confirmed partial changes or an unknown outcome;
  writes are never retried automatically.
- Writes are serialised per zone within one provider instance. Separate
  instances and processes are not coordinated.
- API reference: <https://api.ns1.hosttech.eu/api/documentation/api.yaml>
