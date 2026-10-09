// SPDX-License-Identifier: MIT

package hosttech

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

func TestZonePages(t *testing.T) {
	for _, count := range []int{0, 100, 101, 250} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			f := newHosttechFake(t)
			f.zones = make([]fakeObject, count)
			for i := range f.zones {
				f.zones[i] = fakeObject{"id": i + 1, "name": fmt.Sprintf("zone%d.example", i)}
			}
			zones, err := f.provider(t).ListZones(context.Background())
			if err != nil || len(zones) != count {
				t.Fatalf("zones = %d, error = %v; want %d", len(zones), err, count)
			}
			for i, zone := range zones {
				if want := fmt.Sprintf("zone%d.example.", i); zone.Name != want {
					t.Errorf("zone %d = %q; want %q", i, zone.Name, want)
				}
			}
			if len(f.calls) != count/100+1 {
				t.Fatalf("page count = %d; want %d", len(f.calls), count/100+1)
			}
		})
	}
}

func TestZonePagingStops(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled=%t", cancel), func(t *testing.T) {
			f := newHosttechFake(t)
			f.zones = make([]fakeObject, 101)
			for i := range f.zones {
				f.zones[i] = fakeObject{"id": i + 1, "name": fmt.Sprintf("zone%d.example", i)}
			}
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			f.before = func(r *http.Request) int {
				if r.URL.Query().Get("offset") == "100" {
					return http.StatusInternalServerError
				}
				return 0
			}
			if cancel {
				f.response = func(_ int, body fakeObject) fakeObject {
					stop()
					return body
				}
			}
			zones, err := f.provider(t).ListZones(ctx)
			if err == nil || len(zones) != 0 {
				t.Fatalf("zones = %v, error = %v; want no partial zones and an error", zones, err)
			}
			if cancel && (!errors.Is(err, context.Canceled) || len(f.calls) != 1) {
				t.Fatalf("cancel error = %v, calls = %d; want cancellation after one page", err, len(f.calls))
			}
			if !cancel {
				var apiErr APIError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
					t.Fatalf("error = %v; want API status 500", err)
				}
			}
		})
	}
}

func TestZoneRepeatedPages(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		t.Run(fmt.Sprintf("overlap=%t", overlap), func(t *testing.T) {
			f := newHosttechFake(t)
			count := 100
			if overlap {
				count = 150
			}
			f.zones = make([]fakeObject, count)
			for i := range f.zones {
				f.zones[i] = fakeObject{"id": i + 1, "name": fmt.Sprintf("zone%d.example", i)}
			}
			f.response = func(_ int, body fakeObject) fakeObject {
				if !overlap {
					body["data"] = f.zones
				} else if len(f.calls) == 2 {
					body["data"] = f.zones[50:150]
				}
				return body
			}
			f.before = func(_ *http.Request) int {
				if !overlap && len(f.calls) > 2 {
					t.Error("requested another page after a full page without progress")
					return http.StatusInternalServerError
				}
				return 0
			}
			zones, err := f.provider(t).ListZones(t.Context())
			if !overlap {
				if err == nil || len(zones) != 0 || len(f.calls) != 2 {
					t.Fatalf("zones=%d error=%v calls=%d; want error without partial list after two pages", len(zones), err, len(f.calls))
				}
				return
			}
			if err != nil || len(zones) != 150 || len(f.calls) != 3 {
				t.Fatalf("zones=%d error=%v calls=%d; want 150 unique zones from three pages", len(zones), err, len(f.calls))
			}
			for i, zone := range zones {
				if zone.Name != fmt.Sprintf("zone%d.example.", i) {
					t.Errorf("zone %d=%q; unexpected or duplicate zone", i, zone.Name)
				}
			}
		})
	}
}
