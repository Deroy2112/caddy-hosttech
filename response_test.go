// SPDX-License-Identifier: MIT

package hosttech

import (
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestRefuseInvalidResponses(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name, typ, field string
		value            any
	}{
		{"A address", "A", "ipv4", "invalid"},
		{"A family", "A", "ipv4", "2001:db8::1"},
		{"AAAA family", "AAAA", "ipv6", "1.2.3.4"},
		{"AAAA address", "AAAA", "ipv6", "invalid"},
		{"CAA negative flag", "CAA", "flag", "-1"},
		{"CAA large flag", "CAA", "flag", "256"},
		{"CAA decimal flag", "CAA", "flag", "0x80"},
		{"MX negative preference", "MX", "pref", -1},
		{"MX large preference", "MX", "pref", 65536},
		{"SRV negative priority", "SRV", "priority", -1},
		{"SRV large priority", "SRV", "priority", 65536},
		{"SRV negative weight", "SRV", "weight", -1},
		{"SRV large weight", "SRV", "weight", 65536},
		{"SRV negative port", "SRV", "port", -1},
		{"SRV large port", "SRV", "port", 65536},
		{"zero ttl", "TXT", "ttl", 0},
		{"negative ttl", "TXT", "ttl", -1},
		{"duration overflow", "TXT", "ttl", 9223372037},
		{"missing id", "TXT", "id", nil},
		{"unsupported type", "HTTPS", "type", "HTTPS"},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			rec := fakeObject{"id": 10, "type": row.typ, "name": "test", "ttl": 3600}
			rec[row.field] = row.value
			f.records[fakeZone] = []fakeObject{rec}
			p := f.provider(t)
			got, err := p.GetRecords(t.Context(), fakeZone)
			if err == nil || len(got) != 0 || !strings.Contains(err.Error(), row.field) {
				t.Fatalf("records=%v error=%v want refusal naming %s", got, err, row.field)
			}
			if row.field != "id" && !strings.Contains(err.Error(), "10") {
				t.Fatalf("error lacks record ID: %v", err)
			}
		})
	}
}

func TestRefuseMissingResponseData(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name string
		body fakeObject
	}{{"missing", fakeObject{}}, {"null", fakeObject{"data": nil}}} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			f.response = func(int, fakeObject) fakeObject { return row.body }
			p := f.provider(t)
			got, err := p.GetRecords(t.Context(), fakeZone)
			if err == nil || len(got) != 0 {
				t.Fatalf("records=%v error=%v", got, err)
			}
			zones, err := p.ListZones(t.Context())
			if err == nil || len(zones) != 0 {
				t.Fatalf("zones=%v error=%v", zones, err)
			}
		})
	}
}

func TestRefuseInvalidZones(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		field string
		value any
	}{{"id", 0}, {"name", ""}} {
		t.Run(row.field, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			f.zones[0][row.field] = row.value
			got, err := f.provider(t).ListZones(t.Context())
			if err == nil || len(got) != 0 || !strings.Contains(err.Error(), row.field) {
				t.Fatalf("zones=%v error=%v want field %s", got, err, row.field)
			}
		})
	}
}

func TestResponseRefusalStopsWrites(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	f.records[fakeZone][0]["ipv4"] = "invalid"
	p := f.provider(t)
	input := []libdns.Record{libdns.TXT{Name: "test", Text: "token", TTL: 3600 * time.Second}}
	set, setErr := p.SetRecords(t.Context(), fakeZone, input)
	del, delErr := p.DeleteRecords(t.Context(), fakeZone, input)
	if setErr == nil || delErr == nil || len(set) != 0 || len(del) != 0 || len(f.records[fakeZone]) != 11 {
		t.Fatalf("set=%v err=%v delete=%v err=%v", set, setErr, del, delErr)
	}
	f.mu.Lock()
	f.response = func(status int, body fakeObject) fakeObject {
		if status == 201 {
			return fakeObject{"data": nil}
		}
		return body
	}
	f.mu.Unlock()
	created, err := p.AppendRecords(t.Context(), fakeZone, input)
	if err == nil || len(created) != 0 || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("created=%v error=%v want unknown outcome", created, err)
	}
	if len(f.records[fakeZone]) != 12 {
		t.Fatalf("POST was retried or never applied: %d records", len(f.records[fakeZone]))
	}
}
