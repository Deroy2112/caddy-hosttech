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

- TTLs below 600s are clamped to 600 (API minimum).
- `SetRecords` does a single PUT for 1:1 RRset replacements; otherwise delete+create.
- `api.yaml` pins the API version this client was written against.
