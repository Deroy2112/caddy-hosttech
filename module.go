// SPDX-License-Identifier: Apache-2.0

package hosttech

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(CaddyProvider{})
}

// CaddyProvider wraps the Provider for use as a Caddy module.
type CaddyProvider struct{ *Provider }

// CaddyModule returns the Caddy module information.
func (CaddyProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.hosttech",
		New: func() caddy.Module { return &CaddyProvider{new(Provider)} },
	}
}

// Provision sets up the module by resolving placeholder values.
func (p *CaddyProvider) Provision(ctx caddy.Context) error {
	p.Provider.APIToken = caddy.NewReplacer().ReplaceAll(p.Provider.APIToken, "")
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens.
//
//	hosttech [<api_token>] {
//	    api_token <api_token>
//	}
func (p *CaddyProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			p.Provider.APIToken = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "api_token":
				if p.Provider.APIToken != "" {
					return d.Err("API token already set")
				}
				if d.NextArg() {
					p.Provider.APIToken = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Provider.APIToken == "" {
		return d.Err("missing API token")
	}
	return nil
}

var (
	_ caddyfile.Unmarshaler = (*CaddyProvider)(nil)
	_ caddy.Provisioner     = (*CaddyProvider)(nil)
)
