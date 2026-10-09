// SPDX-License-Identifier: MIT

package hosttech

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

type customRecord struct{ rr libdns.RR }

func (r customRecord) RR() libdns.RR { return r.rr }

func TestAllRecordForms(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	fixtures := make([]fakeObject, 0, 13)
	if err := json.Unmarshal([]byte(fakeRecords), &fixtures); err != nil {
		t.Fatal(err)
	}
	fixtures[2]["name"] = "issuer"
	for _, service := range []string{"_sip._tcp.sub", "sip"} {
		fixtures = append(fixtures, fakeObject{
			"id": 30 + len(fixtures), "type": "SRV", "service": service,
			"priority": 0, "weight": 0, "port": 443, "target": "exchange.example.com", "ttl": 3600,
		})
	}
	f.records[fakeZone] = fixtures
	got, err := f.provider(t).GetRecords(t.Context(), fakeZone)
	if err != nil {
		t.Fatal(err)
	}
	for i, record := range got {
		t.Run(fmt.Sprintf("%s/%d", record.RR().Type, i), func(t *testing.T) {
			t.Parallel()
			pointer := reflect.New(reflect.TypeOf(record))
			pointer.Elem().Set(reflect.ValueOf(record))
			ptr, ok := reflect.TypeAssert[libdns.Record](pointer)
			if !ok {
				t.Fatalf("pointer does not implement Record: %v", pointer)
			}
			for _, input := range []libdns.Record{record, ptr, record.RR(), customRecord{record.RR()}} {
				api := newHosttechFake(t)
				api.records[fakeZone] = nil
				p := api.provider(t)
				created, err := p.AppendRecords(t.Context(), fakeZone, []libdns.Record{input})
				if err != nil || len(created) != 1 {
					t.Fatalf("%T: records=%v error=%v", input, created, err)
				}
				var want fakeObject
				data, err := json.Marshal(fixtures[i])
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &want); err != nil {
					t.Fatal(err)
				}
				delete(want, "id")
				delete(want, "comment")
				if owner, exists := want["name"]; exists && owner == nil {
					want["name"] = ""
				}
				if want["type"] == "AAAA" {
					want["ipv6"] = "2001:db8::1"
				}
				api.mu.Lock()
				body := api.calls[len(api.calls)-1].body
				api.mu.Unlock()
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				var actual fakeObject
				if err := json.Unmarshal(encoded, &actual); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual, want) {
					t.Fatalf("%T: body=%v want=%v", input, actual, want)
				}
			}
		})
	}
}

func TestInputValidationAndTTLFloor(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name  string
		input libdns.Record
	}{
		{"unsupported", libdns.RR{Name: "test", Type: "HTTPS", Data: "1 ."}},
		{"invalid address", libdns.RR{Name: "test", Type: "A", Data: "invalid"}},
		{"nil", nil},
		{"nil pointer", (*libdns.TXT)(nil)},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			p := f.provider(t)
			inputs := []libdns.Record{libdns.TXT{Name: "valid", Text: "token"}, row.input}
			appended, appendErr := p.AppendRecords(t.Context(), fakeZone, inputs)
			set, setErr := p.SetRecords(t.Context(), fakeZone, inputs)
			f.mu.Lock()
			calls := len(f.calls)
			f.mu.Unlock()
			if appendErr == nil || setErr == nil || len(appended) != 0 || len(set) != 0 || calls != 0 {
				t.Fatalf("append=%v err=%v set=%v err=%v calls=%d", appended, appendErr, set, setErr, calls)
			}
		})
	}
	t.Run("ttl 300 raised to 600", func(t *testing.T) {
		t.Parallel()
		f := newHosttechFake(t)
		got, err := f.provider(t).AppendRecords(t.Context(), fakeZone, []libdns.Record{libdns.TXT{Name: "test", Text: "token", TTL: 300 * time.Second}})
		if err != nil || len(got) != 1 || got[0].RR().TTL != 600*time.Second {
			t.Fatalf("records=%v error=%v", got, err)
		}
	})
}

func TestZeroMXPreferenceAndPUTBody(t *testing.T) {
	t.Parallel()
	cname := libdns.CNAME{Name: "alias", Target: "site.example.com", TTL: 7200 * time.Second}
	for _, row := range []struct {
		name  string
		input libdns.Record
		want  libdns.RR
		body  fakeObject
	}{
		{
			"MX zero preference",
			libdns.MX{Name: "mail", Preference: 0, Target: "mail.example.com", TTL: 3600 * time.Second},
			libdns.RR{Type: "MX", Name: "mail", TTL: 3600 * time.Second, Data: "0 mail.example.com"},
			fakeObject{"ownername": "mail", "name": "mail.example.com", "pref": float64(0), "ttl": float64(3600)},
		},
		{
			"CNAME typed", cname,
			libdns.RR{Type: "CNAME", Name: "alias", TTL: 7200 * time.Second, Data: "site.example.com"},
			fakeObject{"cname": "site.example.com", "ttl": float64(7200)},
		},
		{
			"CNAME pointer", &cname,
			libdns.RR{Type: "CNAME", Name: "alias", TTL: 7200 * time.Second, Data: "site.example.com"},
			fakeObject{"cname": "site.example.com", "ttl": float64(7200)},
		},
		{
			"CNAME RR",
			libdns.RR{Type: "CNAME", Name: "alias", TTL: 7200 * time.Second, Data: "site.example.com"},
			libdns.RR{Type: "CNAME", Name: "alias", TTL: 7200 * time.Second, Data: "site.example.com"},
			fakeObject{"cname": "site.example.com", "ttl": float64(7200)},
		},
		{
			"CNAME custom",
			customRecord{libdns.RR{Type: "CNAME", Name: "alias", TTL: 7200 * time.Second, Data: "site.example.com"}},
			libdns.RR{Type: "CNAME", Name: "alias", TTL: 7200 * time.Second, Data: "site.example.com"},
			fakeObject{"cname": "site.example.com", "ttl": float64(7200)},
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			got, err := f.provider(t).SetRecords(t.Context(), fakeZone, []libdns.Record{row.input})
			if err != nil || len(got) != 1 {
				t.Fatalf("records=%v error=%v", got, err)
			}
			if got[0].RR() != row.want {
				t.Fatalf("record=%v want=%v", got[0].RR(), row.want)
			}
			f.mu.Lock()
			body := f.calls[len(f.calls)-1].body
			f.mu.Unlock()
			if !reflect.DeepEqual(body, row.body) {
				t.Fatalf("PUT body=%v want=%v", body, row.body)
			}
		})
	}
}
