//go:build live

// SPDX-License-Identifier: MIT

package hosttech

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

const liveZone = "caddy-hosttech.test"

type liveTransport struct {
	base   http.RoundTripper
	writes atomic.Int32
}

func (l *liveTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		path := "/api/user/v1/zones/" + liveZone + "/records"
		if r.URL.Scheme != "https" || r.URL.Host != "api.ns1.hosttech.eu" ||
			(r.URL.Path != path && !strings.HasPrefix(r.URL.Path, path+"/")) {
			return nil, refuseLiveRequest(r, "live write outside the probe zone refused")
		}
		if l.writes.Add(1) > 50 {
			return nil, refuseLiveRequest(r, "live write budget exhausted")
		}
	}
	return l.base.RoundTrip(r)
}

func refuseLiveRequest(r *http.Request, message string) error {
	if r.Body != nil {
		return errors.Join(errors.New(message), r.Body.Close())
	}
	return errors.New(message)
}

func TestLiveAcceptance(t *testing.T) {
	token := os.Getenv("HOSTTECH_API_TOKEN")
	if token == "" {
		t.Skip("HOSTTECH_API_TOKEN is required for live acceptance")
	}
	p := &Provider{APIToken: token}
	p.initClient()
	p.client.httpClient.Transport = &liveTransport{base: http.DefaultTransport}
	zones, err := p.ListZones(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, zone := range zones {
		found = found || zone.Name == liveZone+"."
	}
	if !found {
		t.Fatal("probe zone is missing")
	}
	initial, err := p.GetRecords(t.Context(), liveZone)
	if err != nil || len(initial) != 0 {
		t.Fatalf("probe zone must be empty: records=%d error=%v", len(initial), err)
	}
	label := "acceptance-" + strings.ToLower(rand.Text())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		records, err := p.GetRecords(ctx, liveZone)
		if err != nil {
			t.Error(err)
			return
		}
		selected := labelledRecords(records, label)
		deleted, err := p.DeleteRecords(ctx, liveZone, selected)
		if err != nil || len(deleted) != len(selected) {
			t.Errorf("cleanup confirmed=%d selected=%d error=%v", len(deleted), len(selected), err)
		}
	})
	input, want := liveInputs(label)
	created, err := p.AppendRecords(t.Context(), liveZone, input)
	if err != nil {
		t.Fatal(err)
	}
	assertLiveRecords(t, created, want, label)
	read, err := p.GetRecords(t.Context(), liveZone)
	if err != nil {
		t.Fatal(err)
	}
	assertLiveRecords(t, read, want, label)
	for i := range want {
		want[i].TTL = 7200 * time.Second
		input[i] = want[i]
	}
	updated, err := p.SetRecords(t.Context(), liveZone, input)
	if err != nil {
		t.Fatal(err)
	}
	assertLiveRecords(t, updated, want, label)
	read, err = p.GetRecords(t.Context(), liveZone)
	if err != nil {
		t.Fatal(err)
	}
	assertLiveRecords(t, read, want, label)
	deleted, err := p.DeleteRecords(t.Context(), liveZone, input)
	if err != nil {
		t.Fatal(err)
	}
	assertLiveRecords(t, deleted, want, label)
	remaining, err := p.GetRecords(t.Context(), liveZone)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("probe zone after deletion: records=%d error=%v", len(remaining), err)
	}
}

func liveInputs(label string) ([]libdns.Record, []libdns.RR) {
	target := label + ".example."
	rows := []libdns.RR{
		{Type: "A", Name: label + "-a", TTL: 300 * time.Second, Data: "192.0.2.10"},
		{Type: "AAAA", Name: label + "-aaaa", Data: "2001:0DB8:0000:0000:0000:0000:0000:0001"},
		{Type: "CAA", Name: label + "-caa", Data: `0 issue "letsencrypt.org"`},
		{Type: "CNAME", Name: label + "-cname", Data: target},
		{Type: "MX", Name: label + "-mx", Data: "0 " + target},
		{Type: "NS", Name: label + "-ns", Data: target},
		{Type: "PTR", Name: "4.3.2.1.in-addr.arpa", Data: target},
		{Type: "SRV", Name: "_autodiscover._tcp", Data: "0 0 443 " + target},
		{Type: "SRV", Name: "_sip._tcp." + label, Data: "0 0 5060 " + target},
		{Type: "TXT", Name: label + "-txt", Data: label},
		{Type: "TXT", Name: "@", Data: label},
	}
	input := make([]libdns.Record, len(rows))
	for i := range rows {
		if rows[i].TTL == 0 {
			rows[i].TTL = 3600 * time.Second
		}
		input[i] = rows[i]
		rows[i].TTL = max(rows[i].TTL, 600*time.Second)
		switch rows[i].Type {
		case "AAAA":
			rows[i].Data = "2001:db8::1"
		case "CNAME", "MX", "NS", "PTR", "SRV":
			rows[i].Data = strings.TrimSuffix(rows[i].Data, ".")
		case "A", "CAA", "TXT":
		default:
			panic("unexpected live fixture type")
		}
	}
	return input, rows
}

func labelledRecords(records []libdns.Record, label string) []libdns.Record {
	var selected []libdns.Record
	for _, record := range records {
		rr := record.RR()
		if strings.Contains(rr.Name, label) || strings.Contains(rr.Data, label) {
			selected = append(selected, record)
		}
	}
	return selected
}

func assertLiveRecords(t *testing.T, records []libdns.Record, want []libdns.RR, label string) {
	t.Helper()
	selected := labelledRecords(records, label)
	if len(selected) != len(want) {
		t.Fatalf("labelled records=%d want=%d", len(selected), len(want))
	}
	counts := make(map[libdns.RR]int, len(selected))
	for _, record := range selected {
		counts[record.RR()]++
	}
	for _, expected := range want {
		if counts[expected] == 0 {
			t.Fatalf("missing expected %s record for %s", expected.Type, expected.Name)
		}
		counts[expected]--
	}
}
