// SPDX-License-Identifier: MIT

package hosttech

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestOwnerNames(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name, typ, field, want string
		owner                  any
	}{
		{"null apex", "TXT", "name", "@", nil},
		{"empty apex", "TXT", "name", "@", ""},
		{"relative suffix", "TXT", "name", "sub.example.com", "sub.example.com"},
		{"MX owner", "MX", "ownername", "mail", "mail"},
		{"NS owner", "NS", "ownername", "sub", "sub"},
		{"PTR origin", "PTR", "origin", "4.3.2.1", "4.3.2.1"},
		{"SRV apex", "SRV", "service", "_sip._tcp", "_sip._tcp"},
		{"SRV owner", "SRV", "service", "_sip._tcp.sub", "_sip._tcp.sub"},
		{"SRV arbitrary", "SRV", "service", "sip", "sip"},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			f.records[fakeZone] = []fakeObject{{"id": 1, "type": row.typ, "ttl": 3600, row.field: row.owner}}
			got, err := f.provider(t).GetRecords(t.Context(), fakeZone)
			if err != nil || len(got) != 1 || got[0].RR().Name != row.want {
				t.Fatalf("records=%v error=%v want owner=%s", got, err, row.want)
			}
			srv, ok := got[0].(libdns.SRV)
			if !ok {
				return
			}
			if row.name == "SRV arbitrary" {
				if srv.Service != "" || srv.Transport != "" || srv.Name != "sip" {
					t.Fatalf("arbitrary service=%#v", srv)
				}
				return
			}
			if srv.Service != "sip" || srv.Transport != "tcp" {
				t.Fatalf("service=%#v", srv)
			}
		})
	}
}

func TestWriteNamesAndTargets(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name string
		rec  libdns.Record
	}{
		{"apex", libdns.TXT{Name: "@", Text: "token", TTL: 3600 * time.Second}},
		{"SRV owner", libdns.SRV{Service: "sip", Transport: "tcp", Name: "sub", Priority: 1, Weight: 1, Port: 443, Target: "t.example.com", TTL: 3600 * time.Second}},
		{"SRV arbitrary", libdns.SRV{Name: "sip", Priority: 1, Weight: 1, Port: 443, Target: "t.example.com", TTL: 3600 * time.Second}},
		{"CNAME target", libdns.CNAME{Name: "test", Target: "t.example.com.", TTL: 3600 * time.Second}},
		{"MX target", libdns.MX{Name: "test", Preference: 10, Target: "t.example.com.", TTL: 3600 * time.Second}},
		{"NS target", libdns.NS{Name: "test", Target: "t.example.com.", TTL: 3600 * time.Second}},
		{"PTR target", libdns.RR{Name: "4.3.2.1", Type: "PTR", Data: "t.example.com.", TTL: 3600 * time.Second}},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			got, err := f.provider(t).AppendRecords(t.Context(), fakeZone, []libdns.Record{row.rec})
			if err != nil || len(got) != 1 {
				t.Fatalf("records=%v error=%v", got, err)
			}
			want := row.rec.RR()
			want.Data = strings.TrimSuffix(want.Data, ".")
			if got[0].RR() != want {
				t.Fatalf("record=%v want=%v", got[0].RR(), want)
			}
			if row.name == "apex" {
				stored := fakeRequest(t, f, "GET", "/zones/example.com/records/21", fakeToken, "", 200)["data"].(map[string]any)
				if stored["name"] != nil {
					t.Fatalf("apex stored as %v", stored["name"])
				}
			}
		})
	}
}

func TestRefuseEmptyNamesAndNullTargets(t *testing.T) {
	t.Parallel()
	for _, row := range []libdns.Record{
		libdns.TXT{Text: "token"},
		libdns.MX{Name: "test", Target: "."},
		libdns.SRV{Service: "sip", Transport: "tcp", Name: "@", Target: "."},
	} {
		t.Run(row.RR().Type+row.RR().Data, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			p := f.provider(t)
			var calls atomic.Int64
			f.response = func(_ int, body fakeObject) fakeObject { calls.Add(1); return body }
			input := []libdns.Record{libdns.TXT{Name: "valid", Text: "token"}, row}
			got, err := p.AppendRecords(t.Context(), fakeZone, input)
			if err == nil || len(got) != 0 {
				t.Fatalf("append=%v error=%v", got, err)
			}
			got, err = p.SetRecords(t.Context(), fakeZone, input)
			if err == nil || len(got) != 0 {
				t.Fatalf("set=%v error=%v", got, err)
			}
			if calls.Load() != 0 {
				t.Fatalf("refusal made %d API calls", calls.Load())
			}
			if count := len(fakeRequest(t, f, "GET", "/zones/example.com/records", fakeToken, "", 200)["data"].([]any)); count != 11 {
				t.Fatalf("refusal changed records: %d", count)
			}
		})
	}
}
