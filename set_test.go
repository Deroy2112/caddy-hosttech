// SPDX-License-Identifier: MIT

package hosttech

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func setFixture(f *hosttechFake, values []string) {
	f.records[fakeZone] = make([]fakeObject, 0, len(values))
	for i, value := range values {
		f.records[fakeZone] = append(f.records[fakeZone], fakeObject{"id": i + 1, "type": "TXT", "name": "test", "text": value, "ttl": 3600})
	}
}

func setInputs(values []string) []libdns.Record {
	result := make([]libdns.Record, 0, len(values))
	for _, value := range values {
		result = append(result, libdns.TXT{Name: "test", Text: value, TTL: 3600 * time.Second})
	}
	return result
}

func TestMinimalSetWrites(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name            string
		existing, input []string
		methods         []string
		count           int
	}{
		{"unchanged", []string{"one", "two", "three"}, []string{"one", "two", "three"}, []string{"GET"}, 3},
		{"one changed", []string{"one", "two", "three"}, []string{"one", "two", "four"}, []string{"GET", "PUT"}, 3},
		{"grow", []string{"one"}, []string{"one", "two"}, []string{"GET", "POST"}, 2},
		{"shrink", []string{"one", "two"}, []string{"one"}, []string{"GET", "DELETE"}, 1},
		{"duplicate input", []string{"one"}, []string{"one", "one"}, []string{"GET"}, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			setFixture(f, row.existing)
			got, err := f.provider(t).SetRecords(t.Context(), fakeZone, setInputs(row.input))
			if err != nil || len(got) != row.count {
				t.Fatalf("records=%v error=%v", got, err)
			}
			f.mu.Lock()
			methods := make([]string, 0, len(f.calls))
			for _, call := range f.calls {
				methods = append(methods, call.method)
			}
			f.mu.Unlock()
			if !reflect.DeepEqual(methods, row.methods) {
				t.Fatalf("calls=%v want=%v", methods, row.methods)
			}
		})
	}
}

func TestSetKeepsTTLFlooredMember(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	setFixture(f, []string{"one"})
	f.records[fakeZone][0]["ttl"] = 600
	got, err := f.provider(t).SetRecords(t.Context(), fakeZone, []libdns.Record{libdns.TXT{Name: "test", Text: "one", TTL: 300 * time.Second}})
	if err != nil || len(got) != 1 || got[0].RR().TTL != 600*time.Second {
		t.Fatalf("records=%v error=%v", got, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 || f.calls[0].method != "GET" {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestSetFailureSteps(t *testing.T) {
	t.Parallel()
	for step := 1; step <= 3; step++ {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			setFixture(f, []string{"old", "extra"})
			writes := 0
			f.before = func(r *http.Request) int {
				if r.Method != "GET" {
					writes++
					if writes == step {
						return 422
					}
				}
				return 0
			}
			inputs := append(setInputs([]string{"new"}), libdns.Address{Name: "other", IP: netip.MustParseAddr("1.2.3.4"), TTL: 3600 * time.Second})
			got, err := f.provider(t).SetRecords(t.Context(), fakeZone, inputs)
			if err == nil || len(got) != step-1 {
				t.Fatalf("confirmed=%v error=%v want %d", got, err, step-1)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			txt := 0
			for _, rec := range f.records[fakeZone] {
				if rec["type"] == "TXT" {
					txt++
				}
			}
			if txt == 0 || writes != step {
				t.Fatalf("TXT count=%d writes=%d", txt, writes)
			}
		})
	}
	t.Run("empty RRset partial POST", func(t *testing.T) {
		t.Parallel()
		f := newHosttechFake(t)
		setFixture(f, nil)
		posts := 0
		f.before = func(r *http.Request) int {
			if r.Method == "POST" {
				posts++
				if posts == 2 {
					return 422
				}
			}
			return 0
		}
		got, err := f.provider(t).SetRecords(t.Context(), fakeZone, setInputs([]string{"one", "two"}))
		if err == nil || len(got) != 1 {
			t.Fatalf("confirmed=%v error=%v", got, err)
		}
		assertRecords(t, got, setInputs([]string{"one"}))
	})
}

func TestSetUnknownOutcome(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	setFixture(f, nil)
	posts := 0
	f.response = func(status int, body fakeObject) fakeObject {
		if status == 201 {
			posts++
			if posts == 2 {
				return fakeObject{"data": nil}
			}
		}
		return body
	}
	got, err := f.provider(t).SetRecords(t.Context(), fakeZone, setInputs([]string{"one", "two"}))
	if err == nil || len(got) != 1 || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("confirmed=%v error=%v", got, err)
	}
	assertRecords(t, got, setInputs([]string{"one"}))
	f.mu.Lock()
	defer f.mu.Unlock()
	if posts != 2 || len(f.records[fakeZone]) != 2 {
		t.Fatalf("posts=%d stored=%d", posts, len(f.records[fakeZone]))
	}
}

func TestParallelSets(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	setFixture(f, []string{"old", "extra"})
	p := f.provider(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, values := range [][]string{{"one", "two"}, {"three", "four"}} {
		go func() {
			<-start
			got, err := p.SetRecords(t.Context(), fakeZone, setInputs(values))
			if err == nil && len(got) != 2 {
				err = fmt.Errorf("returned %d records", len(got))
			}
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	got, err := p.GetRecords(t.Context(), fakeZone)
	if err != nil || len(got) != 2 {
		t.Fatalf("records=%v error=%v", got, err)
	}
	values := []string{got[0].RR().Data, got[1].RR().Data}
	if !reflect.DeepEqual(values, []string{"one", "two"}) && !reflect.DeepEqual(values, []string{"three", "four"}) {
		t.Fatalf("mixed RRset=%v", values)
	}
}

func TestDifferentZonesRunInParallel(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	p := f.provider(t)
	next := p.client.httpClient.Transport
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p.client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && r.URL.Path == "/api/user/v1/zones/example.com/records" {
			close(entered)
			<-release
		}
		return next.RoundTrip(r)
	})
	done := make(chan error, 1)
	go func() {
		got, err := p.SetRecords(t.Context(), fakeZone, setInputs([]string{"one"}))
		if err == nil && len(got) != 1 {
			err = fmt.Errorf("returned %d records", len(got))
		}
		done <- err
	}()
	<-entered
	created, err := p.AppendRecords(t.Context(), "second.example", setInputs([]string{"other"}))
	if err != nil || len(created) != 1 {
		t.Fatalf("other zone=%v error=%v", created, err)
	}
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type observedContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestCanceledZoneWait(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	p := f.provider(t)
	next := p.client.httpClient.Transport
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p.client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" {
			close(entered)
			<-release
		}
		return next.RoundTrip(r)
	})
	first := make(chan error, 1)
	go func() {
		got, err := p.SetRecords(t.Context(), fakeZone, setInputs([]string{"one"}))
		if err == nil && len(got) != 1 {
			err = fmt.Errorf("returned %d records", len(got))
		}
		first <- err
	}()
	<-entered
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &observedContext{Context: base, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		got, err := p.AppendRecords(ctx, fakeZone, setInputs([]string{"two"}))
		if len(got) != 0 {
			err = fmt.Errorf("unexpected confirmed records")
		}
		done <- err
	}()
	<-ctx.entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error=%v", err)
	}
	f.mu.Lock()
	calls := len(f.calls)
	f.mu.Unlock()
	if calls != 0 {
		t.Fatalf("canceled waiter made %d calls", calls)
	}
	once.Do(func() { close(release) })
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}
