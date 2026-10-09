// SPDX-License-Identifier: MIT

package hosttech

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestMissingProvisionToken(t *testing.T) {
	t.Setenv("HOSTTECH_UNSET_TEST_TOKEN", "")
	for _, config := range []string{`{}`, `{"api_token":""}`, `{"api_token":"{env.HOSTTECH_UNSET_TEST_TOKEN}"}`} {
		t.Run(config, func(t *testing.T) {
			p := &CaddyProvider{Provider: new(Provider)}
			if err := json.Unmarshal([]byte(config), p); err != nil {
				t.Fatal(err)
			}
			if err := p.Provision(caddy.Context{Context: t.Context()}); err == nil {
				t.Fatal("empty resolved token was accepted")
			}
		})
	}
}
