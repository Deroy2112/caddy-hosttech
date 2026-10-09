// SPDX-License-Identifier: MIT

package hosttech

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

func responseProvider(t *testing.T, status int, body, location string) *Provider {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			t.Error("request does not accept JSON")
		}
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
		if n, err := io.WriteString(w, body); err != nil || n != len(body) {
			t.Errorf("writing response: bytes=%d error=%v", n, err)
		}
	}))
	t.Cleanup(server.Close)
	return (&hosttechFake{server: server}).provider(t)
}

func TestClientRedirectAndBodyLimit(t *testing.T) {
	t.Parallel()
	t.Run("302 HTTP redirect", func(t *testing.T) {
		t.Parallel()
		p := responseProvider(t, 302, "", "http://api.ns1.hosttech.eu/other")
		got, err := p.GetRecords(t.Context(), fakeZone)
		var apiErr APIError
		if len(got) != 0 || !errors.As(err, &apiErr) || apiErr.StatusCode != 302 {
			t.Fatalf("records=%v error=%v", got, err)
		}
	})
	for _, size := range []int{10 * 1024 * 1024, 10*1024*1024 + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			t.Parallel()
			prefix := `{"data":[]}`
			body := prefix + strings.Repeat(" ", size-len(prefix))
			got, err := responseProvider(t, 200, body, "").GetRecords(t.Context(), fakeZone)
			if size == 10*1024*1024 {
				if err != nil || len(got) != 0 {
					t.Fatalf("boundary records=%v error=%v", got, err)
				}
				return
			}
			if err == nil || len(got) != 0 || !strings.Contains(err.Error(), "10485760") {
				t.Fatalf("oversized records=%v error=%v", got, err)
			}
		})
	}
}

func TestClientErrorBodies(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name   string
		status int
		body   string
	}{
		{"decoded 422", 422, `{"message":"The given data was invalid.","errors":{"value":["Darf nicht leer sein."],"ttl":["Darf nicht leer sein."]}}`},
		{"HTML 502", 502, "<html>gateway internals " + fakeToken + "</html>"},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			got, err := responseProvider(t, row.status, row.body, "").GetRecords(t.Context(), fakeZone)
			var apiErr APIError
			if len(got) != 0 || !errors.As(err, &apiErr) || apiErr.StatusCode != row.status {
				t.Fatalf("records=%v error=%v", got, err)
			}
			if strings.Contains(err.Error(), "<html>") || strings.Contains(err.Error(), fakeToken) {
				t.Fatalf("unsafe error=%v", err)
			}
			if row.status != 422 {
				if apiErr.Message != "" || apiErr.Errors != nil {
					t.Fatalf("non-JSON response has decoded fields=%#v", apiErr)
				}
				return
			}
			want := "hosttech API error 422: The given data was invalid.; ttl: Darf nicht leer sein.; value: Darf nicht leer sein."
			if apiErr.Error() != want {
				t.Fatalf("error text=%q want=%q", apiErr.Error(), want)
			}
			if apiErr.Message != "The given data was invalid." || !reflect.DeepEqual(apiErr.Errors, map[string][]string{"ttl": {"Darf nicht leer sein."}, "value": {"Darf nicht leer sein."}}) {
				t.Fatalf("decoded error=%#v", apiErr)
			}
		})
	}
}

func TestClientRedactsDecodedErrors(t *testing.T) {
	t.Parallel()
	body := `{"message":"test-token","errors":{"test-token":["test-token"]}}`
	got, err := responseProvider(t, 422, body, "").GetRecords(t.Context(), fakeZone)
	var apiErr APIError
	if len(got) != 0 || !errors.As(err, &apiErr) {
		t.Fatalf("records=%v error=%v", got, err)
	}
	if apiErr.Message != "[redacted]" || !reflect.DeepEqual(apiErr.Errors, map[string][]string{"[redacted]": {"[redacted]"}}) || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("unredacted fields=%#v", apiErr)
	}
}

func TestClientEscapesZone(t *testing.T) {
	t.Parallel()
	f := newHosttechFake(t)
	zone := "weird/a?#"
	f.zones[0]["name"] = zone
	f.records[zone] = []fakeObject{}
	got, err := f.provider(t).GetRecords(t.Context(), zone)
	if err != nil || len(got) != 0 {
		t.Fatalf("records=%v error=%v", got, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 || f.calls[0].path != "/api/user/v1/zones/weird%2Fa%3F%23/records" {
		t.Fatalf("path=%v", f.calls)
	}
}

type closeErrorBody struct {
	io.ReadCloser
	cause error
}

func (b closeErrorBody) Close() error { return errors.Join(b.ReadCloser.Close(), b.cause) }

type readErrorBody struct {
	io.ReadCloser
	cause error
}

func (b readErrorBody) Read(_ []byte) (int, error) { return 0, b.cause }

func TestClientCloseError(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"read", "close"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			p := f.provider(t)
			next := p.client.httpClient.Transport
			cause := errors.New(stage + " failed for " + fakeToken)
			p.client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				resp, err := next.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				if stage == "read" {
					resp.Body = readErrorBody{ReadCloser: resp.Body, cause: cause}
				} else {
					resp.Body = closeErrorBody{ReadCloser: resp.Body, cause: cause}
				}
				return resp, nil
			})
			got, err := p.GetRecords(t.Context(), fakeZone)
			if !errors.Is(err, cause) || len(got) != 0 || !strings.Contains(err.Error(), stage+" failed for [redacted]") || strings.Contains(err.Error(), fakeToken) {
				t.Fatalf("records=%v error=%v", got, err)
			}
			created, err := p.AppendRecords(t.Context(), fakeZone, []libdns.Record{libdns.TXT{Name: "test", Text: "token"}})
			if !errors.Is(err, cause) || len(created) != 0 || !strings.Contains(err.Error(), "outcome unknown") || !strings.Contains(err.Error(), stage+" failed for [redacted]") || strings.Contains(err.Error(), fakeToken) {
				t.Fatalf("created=%v error=%v", created, err)
			}
		})
	}
}

func TestValidationNegotiation(t *testing.T) {
	t.Parallel()
	for _, accept := range []string{"", "application/json"} {
		t.Run("Accept="+accept, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/user/v1/zones/example.com/records",
				strings.NewReader(`{"type":"TXT","name":"test","text":"token","ttl":60}`))
			req.Header.Set("Authorization", "Bearer "+fakeToken)
			req.Header.Set("Accept", accept)
			w := httptest.NewRecorder()
			f.ServeHTTP(w, req)
			want := http.StatusUnprocessableEntity
			if accept == "" {
				want = http.StatusFound
				if w.Header().Get("Location") != "https://api.ns1.hosttech.eu" {
					t.Fatalf("redirect location=%q", w.Header().Get("Location"))
				}
			}
			if w.Code != want {
				t.Fatalf("validation status=%d want=%d", w.Code, want)
			}
		})
	}
}

func TestClientTransportCause(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			f.records[fakeZone] = []fakeObject{{"id": 10, "type": "TXT", "name": "fault-owner", "text": "old", "ttl": 3600}}
			p := f.provider(t)
			next := p.client.httpClient.Transport
			cause := errors.New("dial failed for " + fakeToken)
			p.client.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == method {
					if r.Body != nil {
						return nil, errors.Join(cause, r.Body.Close())
					}
					return nil, cause
				}
				return next.RoundTrip(r)
			})
			var got []libdns.Record
			var err error
			input := []libdns.Record{libdns.TXT{Name: "fault-owner", Text: "new"}}
			switch method {
			case http.MethodGet:
				got, err = p.GetRecords(t.Context(), fakeZone)
			case http.MethodPost:
				got, err = p.AppendRecords(t.Context(), fakeZone, input)
			case http.MethodPut:
				got, err = p.SetRecords(t.Context(), fakeZone, input)
			default:
				t.Fatal("unexpected test method")
			}
			if len(got) != 0 || !errors.Is(err, cause) || !strings.Contains(err.Error(), "dial failed for [redacted]") || strings.Contains(err.Error(), fakeToken) {
				t.Fatalf("records=%v error=%v", got, err)
			}
			if method != http.MethodGet && (!strings.Contains(err.Error(), "TXT") || !strings.Contains(err.Error(), "fault-owner") || !strings.Contains(err.Error(), "outcome unknown")) {
				t.Fatalf("write lacks record identity or unknown outcome: %v", err)
			}
		})
	}
}

func TestClientWriteAPIError(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			owner := "failed-" + fakeToken
			f.records[fakeZone] = []fakeObject{{"id": 10, "type": "TXT", "name": owner, "text": "old", "ttl": 3600}}
			f.before = func(r *http.Request) int {
				if r.Method == method {
					return http.StatusUnprocessableEntity
				}
				return 0
			}
			f.response = func(status int, body fakeObject) fakeObject {
				if status == http.StatusUnprocessableEntity {
					return fakeObject{"message": "The given data was invalid.", "errors": fakeObject{"ttl": []string{"Darf nicht leer sein."}}}
				}
				return body
			}
			p := f.provider(t)
			input := []libdns.Record{libdns.TXT{Name: owner, Text: "new"}}
			var got []libdns.Record
			var err error
			if method == http.MethodPost {
				got, err = p.AppendRecords(t.Context(), fakeZone, input)
			} else {
				got, err = p.SetRecords(t.Context(), fakeZone, input)
			}
			var apiErr APIError
			if len(got) != 0 || !errors.As(err, &apiErr) || apiErr.StatusCode != 422 {
				t.Fatalf("records=%v error=%v", got, err)
			}
			for _, detail := range []string{"TXT", "failed-[redacted]", "The given data was invalid.", "ttl: Darf nicht leer sein."} {
				if !strings.Contains(err.Error(), detail) {
					t.Fatalf("error=%v missing=%q", err, detail)
				}
			}
			if strings.Contains(err.Error(), fakeToken) {
				t.Fatalf("unredacted error=%v", err)
			}
		})
	}
}
