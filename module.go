// SPDX-License-Identifier: MIT

package hosttech

import (
	"errors"

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
	if p.Provider == nil {
		return errors.New("missing API token")
	}
	p.APIToken = caddy.NewReplacer().ReplaceAll(p.APIToken, "")
	if p.APIToken == "" {
		return errors.New("missing API token")
	}
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens.
//
//	hosttech [<api_token>] {
//	    api_token <api_token>
//	}
func (p *CaddyProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if p.Provider == nil {
		p.Provider = new(Provider)
	}
	for d.Next() {
		if err := p.readToken(d, false); err != nil {
			return err
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			if d.Val() != "api_token" {
				return d.Err("unrecognized subdirective")
			}
			if err := p.readToken(d, true); err != nil {
				return err
			}
		}
	}
	if p.APIToken == "" {
		return d.Err("missing API token")
	}
	return nil
}

func (p *CaddyProvider) readToken(d *caddyfile.Dispenser, required bool) error {
	if !d.NextArg() {
		if required {
			return d.Err("missing API token")
		}
		return nil
	}
	if p.APIToken != "" {
		return d.Err("API token already set")
	}
	p.APIToken = d.Val()
	if d.NextArg() {
		return d.Err("too many arguments")
	}
	return nil
}

var (
	_ caddyfile.Unmarshaler = (*CaddyProvider)(nil)
	_ caddy.Provisioner     = (*CaddyProvider)(nil)
)
