// SPDX-License-Identifier: MIT

package hosttech

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestDeleteFilters(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name, records string
		filter        libdns.RR
		ids           []int
	}{
		{"PTR target", `[{"id":1,"type":"PTR","origin":"test","name":"one.example","ttl":3600},{"id":2,"type":"PTR","origin":"test","name":"two.example","ttl":3600}]`, libdns.RR{Name: "test", Type: "PTR", Data: "one.example"}, []int{1}},
		{"TXT exact", `[{"id":1,"type":"TXT","name":"test","text":"token","ttl":3600},{"id":2,"type":"TXT","name":"test","text":" token ","ttl":3600},{"id":3,"type":"TXT","name":"test","text":"\"token\"","ttl":3600}]`, libdns.RR{Name: "test", Type: "TXT", Data: "token"}, []int{1}},
		{"IPv6 equality", `[{"id":1,"type":"AAAA","name":"test","ipv6":"2001:0DB8:0000:0000:0000:0000:0000:0001","ttl":3600}]`, libdns.RR{Name: "test", Type: "AAAA", Data: "2001:db8::1"}, []int{1}},
		{"type wildcard with value", `[{"id":1,"type":"MX","ownername":"test","name":"mail.example","pref":10,"ttl":3600},{"id":2,"type":"A","name":"test","ipv4":"1.2.3.4","ttl":3600}]`, libdns.RR{Name: "test", Data: "1.2.3.4"}, []int{2}},
		{"CAA value", `[{"id":1,"type":"CAA","name":"test","flag":"0","tag":"issue","value":"one.example","ttl":3600},{"id":2,"type":"CAA","name":"test","flag":"0","tag":"issue","value":"two.example","ttl":3600}]`, libdns.RR{Name: "test", Type: "CAA", Data: `0 issue "one.example"`}, []int{1}},
		{"target trailing dot", `[{"id":1,"type":"CNAME","name":"test","cname":"one.example","ttl":3600}]`, libdns.RR{Name: "test", Type: "CNAME", Data: "one.example."}, []int{1}},
		{"all wildcards", `[{"id":1,"type":"TXT","name":"test","text":"token","ttl":3600}]`, libdns.RR{Name: "test"}, []int{1}},
		{"ttl mismatch", `[{"id":1,"type":"TXT","name":"test","text":"token","ttl":3600}]`, libdns.RR{Name: "test", Type: "TXT", TTL: 600 * time.Second}, nil},
		{"whole-second ttl", `[{"id":1,"type":"TXT","name":"test","text":"token","ttl":3600}]`, libdns.RR{Name: "test", Type: "TXT", TTL: 3600*time.Second + 500*time.Millisecond}, []int{1}},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			var records []fakeObject
			if err := json.Unmarshal([]byte(row.records), &records); err != nil {
				t.Fatal(err)
			}
			f.records[fakeZone] = records
			got, err := f.provider(t).DeleteRecords(t.Context(), fakeZone, []libdns.Record{row.filter, row.filter})
			if err != nil || len(got) != len(row.ids) {
				t.Fatalf("deleted=%v error=%v want IDs=%v", got, err, row.ids)
			}
			var ids []int
			f.mu.Lock()
			for _, call := range f.calls {
				if call.method == http.MethodDelete {
					var id int
					if _, err := fmt.Sscanf(call.path, "/api/user/v1/zones/example.com/records/%d", &id); err != nil {
						f.mu.Unlock()
						t.Fatal(err)
					}
					ids = append(ids, id)
				}
			}
			f.mu.Unlock()
			if !reflect.DeepEqual(ids, row.ids) {
				t.Fatalf("deleted IDs=%v want=%v", ids, row.ids)
			}
		})
	}
}

func TestInvalidDeleteBatch(t *testing.T) {
	t.Parallel()
	for _, filter := range []libdns.Record{libdns.RR{}, libdns.RR{Name: "www", Type: "A", Data: "invalid"}} {
		t.Run(filter.RR().Type+" invalid", func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			got, err := f.provider(t).DeleteRecords(t.Context(), fakeZone, []libdns.Record{libdns.RR{Name: "www"}, filter})
			f.mu.Lock()
			calls := len(f.calls)
			f.mu.Unlock()
			if err == nil || len(got) != 0 || calls != 0 {
				t.Fatalf("deleted=%v error=%v calls=%d", got, err, calls)
			}
		})
	}
}

func TestDeleteReadbackAndAlreadyGone(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	p := f.provider(t)
	got, err := p.GetRecords(t.Context(), fakeZone)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := p.DeleteRecords(t.Context(), fakeZone, got)
	if err != nil || len(deleted) != 11 {
		t.Fatalf("deleted=%v error=%v", deleted, err)
	}
	remaining, err := p.GetRecords(t.Context(), fakeZone)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("remaining=%v error=%v", remaining, err)
	}
	api := newHosttechFake(t)
	api.records[fakeZone] = api.records[fakeZone][:1]
	api.before = func(r *http.Request) int {
		if r.Method == http.MethodDelete {
			api.records[fakeZone] = nil
			return 404
		}
		return 0
	}
	deleted, err = api.provider(t).DeleteRecords(t.Context(), fakeZone, []libdns.Record{libdns.RR{Name: "www"}})
	if err != nil || len(deleted) != 0 {
		t.Fatalf("already gone=%v error=%v", deleted, err)
	}
}
