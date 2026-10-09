// SPDX-License-Identifier: MIT

package hosttech

import (
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

type dnsProvider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordSetter
	libdns.RecordDeleter
	libdns.ZoneLister
}

func assertRecords(t *testing.T, got, want []libdns.Record) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("records=%d want=%d", len(got), len(want))
	}
	for i, expected := range want {
		if got[i].RR() != expected.RR() || reflect.TypeOf(got[i]) != reflect.TypeOf(expected) {
			t.Fatalf("record %d=%#v want=%#v", i, got[i], expected)
		}
	}
}

func TestProviderBaseline(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Provider", "CaddyProvider"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			f.before = func(r *http.Request) int {
				if r.Header.Get("Accept") != "application/json" {
					t.Errorf("%s request does not accept JSON", r.Method)
				}
				return 0
			}
			var p dnsProvider = f.provider(t)
			if name == "CaddyProvider" {
				p = &CaddyProvider{p.(*Provider)}
			}
			zones, err := p.ListZones(t.Context())
			if err != nil || !reflect.DeepEqual(zones, []libdns.Zone{{Name: "example.com."}, {Name: "second.example."}}) {
				t.Fatalf("ListZones=%v err=%v", zones, err)
			}
			got, err := p.GetRecords(t.Context(), fakeZone+".")
			if err != nil || len(got) != 11 {
				t.Fatalf("GetRecords=%v err=%v", got, err)
			}
			// Specification examples and read probe: five mappings already supported.
			baseline := []libdns.Record{
				libdns.Address{Name: "www", IP: netip.MustParseAddr("1.2.3.4"), TTL: 3600 * time.Second},
				libdns.CNAME{Name: "alias", Target: "site.example.com", TTL: 3600 * time.Second},
				libdns.MX{Name: "mail", Preference: 10, Target: "mail.example.com", TTL: 3600 * time.Second},
				libdns.NS{Name: "sub", Target: "ns1.example.com", TTL: 3600 * time.Second},
				libdns.TXT{Name: "_acme-challenge", Text: "token", TTL: 3600 * time.Second},
			}
			for _, expected := range baseline {
				i := slices.IndexFunc(got, func(rec libdns.Record) bool { return rec.RR() == expected.RR() })
				if i < 0 {
					t.Fatalf("GetRecords missing %#v", expected)
				}
				assertRecords(t, got[i:i+1], []libdns.Record{expected})
			}
			original := fakeRequest(t, f, "GET", "/zones/example.com/records", fakeToken, "", 200)
			inputs := []libdns.Record{
				libdns.Address{Name: "new-a", IP: netip.MustParseAddr("1.2.3.4"), TTL: 3600 * time.Second},
				libdns.CNAME{Name: "new-alias", Target: "site.example.com", TTL: 3600 * time.Second},
				libdns.MX{Name: "new-mail", Preference: 10, Target: "mail.example.com", TTL: 3600 * time.Second},
				libdns.NS{Name: "new-sub", Target: "ns1.example.com", TTL: 3600 * time.Second},
				libdns.TXT{Name: "new", Text: strings.Repeat("x", 300), TTL: 3600 * time.Second},
			}
			created, err := p.AppendRecords(t.Context(), fakeZone+".", inputs)
			if err != nil {
				t.Fatalf("AppendRecords: %v", err)
			}
			assertRecords(t, created, inputs)
			before := fakeRequest(t, f, "GET", "/zones/example.com/records", fakeToken, "", 200)
			oldRecords, appended := original["data"].([]any), before["data"].([]any)
			if len(appended) != len(oldRecords)+5 || !reflect.DeepEqual(appended[:len(oldRecords)], oldRecords) {
				t.Fatalf("AppendRecords changed existing records: %v", before)
			}
			changed := libdns.Address{Name: "www", IP: netip.MustParseAddr("2.3.4.5"), TTL: 3600 * time.Second}
			set, err := p.SetRecords(t.Context(), fakeZone+".", []libdns.Record{changed})
			if err != nil {
				t.Fatalf("SetRecords: %v", err)
			}
			assertRecords(t, set, []libdns.Record{changed})
			before["data"].([]any)[0].(map[string]any)["ipv4"] = "2.3.4.5"
			after := fakeRequest(t, f, "GET", "/zones/example.com/records", fakeToken, "", 200)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("SetRecords changed unrelated records: %v", after)
			}
			deleted, err := p.DeleteRecords(t.Context(), fakeZone+".", []libdns.Record{changed, changed})
			if err != nil {
				t.Fatalf("DeleteRecords: %v", err)
			}
			assertRecords(t, deleted, []libdns.Record{changed})
			before["data"] = before["data"].([]any)[1:]
			after = fakeRequest(t, f, "GET", "/zones/example.com/records", fakeToken, "", 200)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("DeleteRecords changed unrelated records: %v", after)
			}
		})
	}
}

func TestProviderUnauthorized(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"GetRecords", "AppendRecords", "SetRecords", "DeleteRecords", "ListZones"} {
		t.Run("read probe/"+method+" 401", func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			p := f.provider(t)
			p.client.apiToken = ""
			var err error
			var result []libdns.Record
			var zones []libdns.Zone
			rec := []libdns.Record{libdns.TXT{Name: "new", Text: "token", TTL: 3600 * time.Second}}
			switch method {
			case "GetRecords":
				result, err = p.GetRecords(t.Context(), fakeZone)
			case "AppendRecords":
				result, err = p.AppendRecords(t.Context(), fakeZone, rec)
			case "SetRecords":
				result, err = p.SetRecords(t.Context(), fakeZone, rec)
			case "DeleteRecords":
				result, err = p.DeleteRecords(t.Context(), fakeZone, rec)
			case "ListZones":
				zones, err = p.ListZones(t.Context())
			default:
				t.Fatalf("unhandled method %s", method)
			}
			if len(result) != 0 || len(zones) != 0 {
				t.Fatalf("unauthorized call returned records=%v zones=%v", result, zones)
			}
			var apiErr APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 {
				t.Fatalf("error=%v want APIError status 401", err)
			}
		})
	}
}

func TestCaddyModuleBaseline(t *testing.T) {
	t.Setenv("HOSTTECH_FAKE_TOKEN", fakeToken)
	for _, row := range []struct{ name, config, wantError string }{
		{"inline", "hosttech test-token", ""},
		{"block", "hosttech {\n api_token test-token\n}", ""},
		{"placeholder", "hosttech {env.HOSTTECH_FAKE_TOKEN}", ""},
		{"missing", "hosttech", "missing API token"},
		{"duplicate", "hosttech test-token {\n api_token other\n}", "API token already set"},
		{"unknown", "hosttech {\n unknown value\n}", "unrecognized subdirective"},
		{"extra inline", "hosttech test-token test-token", "too many arguments"},
		{"extra block", "hosttech {\n api_token test-token test-token\n}", "too many arguments"},
		{"token as directive", "hosttech {\n test-token\n}", "unrecognized subdirective"},
	} {
		t.Run(row.name, func(t *testing.T) {
			info, err := caddy.GetModule("dns.providers.hosttech")
			if err != nil {
				t.Fatalf("module registration: %v", err)
			}
			p, ok := info.New().(*CaddyProvider)
			if !ok || p.CaddyModule().ID != "dns.providers.hosttech" {
				t.Fatalf("module factory=%#v", p)
			}
			err = p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(row.config))
			if row.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), row.wantError) || strings.Contains(err.Error(), fakeToken) {
					t.Fatalf("parse error=%v want=%s", err, row.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := p.Provision(caddy.Context{Context: t.Context()}); err != nil || p.APIToken != fakeToken {
				t.Fatalf("provision token=%q err=%v", p.APIToken, err)
			}
		})
	}
}
