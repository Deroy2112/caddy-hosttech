// SPDX-License-Identifier: MIT

package hosttech

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	fakeZone  = "example.com"
	fakeToken = "test-token"
	// Specification examples with the read probe's owner fields and null comments.
	fakeRecords = `[
		{"id":10,"type":"A","name":"www","ipv4":"1.2.3.4","ttl":3600,"comment":null},
		{"id":11,"type":"AAAA","name":"www","ipv6":"2001:0DB8:0000:0000:0000:0000:0000:0001","ttl":3600,"comment":null},
		{"id":12,"type":"CAA","name":null,"flag":"0","tag":"issue","value":"letsencrypt.org","ttl":3600,"comment":null},
		{"id":13,"type":"CNAME","name":"alias","cname":"site.example.com","ttl":3600,"comment":null},
		{"id":14,"type":"MX","ownername":"mail","name":"mail.example.com","pref":10,"ttl":3600,"comment":null},
		{"id":15,"type":"NS","ownername":"sub","targetname":"ns1.example.com","ttl":3600,"comment":null},
		{"id":16,"type":"PTR","origin":"4.3.2.1","name":"smtp.example.com","ttl":3600,"comment":null},
		{"id":17,"type":"SRV","service":"_autodiscover._tcp","priority":0,"weight":0,"port":443,"target":"exchange.example.com","ttl":3600,"comment":null},
		{"id":18,"type":"TXT","name":"","text":"v=spf1 ip4:1.2.3.4/32 -all","ttl":3600,"comment":null},
		{"id":19,"type":"TLSA","name":"_443._tcp","text":"0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971","ttl":3600,"comment":null},
		{"id":20,"type":"TXT","name":"_acme-challenge","text":"token","ttl":3600,"comment":null}
	]`
)

type fakeObject map[string]any

var fakeRecordFields = map[string][]string{
	"A":     {"name", "ipv4"},
	"AAAA":  {"name", "ipv6"},
	"CAA":   {"name", "flag", "tag", "value"},
	"CNAME": {"name", "cname"},
	"MX":    {"ownername", "name", "pref"},
	"NS":    {"ownername", "targetname"},
	"PTR":   {"origin", "name"},
	"SRV":   {"service", "priority", "weight", "port", "target"},
	"TXT":   {"name", "text"},
	"TLSA":  {"name", "text"},
}

type fakeCall struct {
	method, path string
	body         fakeObject
}

type hosttechFake struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	zones    []fakeObject
	records  map[string][]fakeObject
	nextID   int
	response func(int, fakeObject) fakeObject
	calls    []fakeCall
	before   func(*http.Request) int
}

func newHosttechFake(t *testing.T) *hosttechFake {
	t.Helper()
	var records []fakeObject
	if err := json.Unmarshal([]byte(fakeRecords), &records); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	f := &hosttechFake{
		t: t, nextID: 21, records: map[string][]fakeObject{fakeZone: records, "second.example": {}},
		zones: []fakeObject{
			{"id": 10, "name": fakeZone, "ttl": 10800, "dnssec": false, "dnssec_email": nil},
			{"id": 11, "name": "second.example", "ttl": 10800, "dnssec": false, "dnssec_email": ""},
		},
	}
	f.server = httptest.NewServer(f)
	t.Cleanup(f.server.Close)
	return f
}

func (f *hosttechFake) provider(t *testing.T) *Provider {
	t.Helper()
	target, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("test server URL: %v", err)
	}
	p := &Provider{APIToken: fakeToken}
	p.initClient()
	p.client.httpClient.Transport = fakeTransport{target: target, transport: f.server.Client().Transport}
	return p
}

type fakeTransport struct {
	target    *url.URL
	transport http.RoundTripper
}

func (tr fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != "api.ns1.hosttech.eu" {
		return nil, fmt.Errorf("unexpected test request destination")
	}
	local := req.Clone(req.Context())
	local.URL.Scheme, local.URL.Host = tr.target.Scheme, tr.target.Host
	local.Host = tr.target.Host
	return tr.transport.RoundTrip(local)
}

func (f *hosttechFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{method: r.Method, path: r.URL.RequestURI()})
	if f.before != nil {
		if status := f.before(r); status != 0 {
			f.reply(w, status, fakeObject{"message": ""})
			return
		}
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		f.reply(w, http.StatusUnauthorized, fakeObject{"message": "Unauthenticated."})
		return
	}
	if !strings.HasPrefix(r.URL.EscapedPath(), "/api/user/v1/zones") {
		f.reply(w, http.StatusNotFound, fakeObject{"message": ""})
		return
	}
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/api/user/v1/zones")
	if path == "" && r.Method == http.MethodGet {
		f.listZones(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[1] != "records" {
		f.reply(w, http.StatusNotFound, fakeObject{"message": ""})
		return
	}
	zone, err := url.PathUnescape(parts[0])
	if err != nil {
		f.t.Errorf("invalid zone path: %v", err)
		f.reply(w, http.StatusBadRequest, fakeObject{"message": "Invalid path"})
		return
	}
	for _, z := range f.zones {
		if fmt.Sprint(z["id"]) == zone {
			zone = fmt.Sprint(z["name"])
			break
		}
	}
	if _, exists := f.records[zone]; !exists {
		f.reply(w, http.StatusNotFound, fakeObject{"message": ""})
		return
	}
	id := ""
	if len(parts) == 3 {
		id = parts[2]
	}
	f.recordEndpoint(w, r, zone, id)
}

func (f *hosttechFake) listZones(w http.ResponseWriter, r *http.Request) {
	limit, offset := 100, 0
	for key, dest := range map[string]*int{"limit": &limit, "offset": &offset} {
		if value := r.URL.Query().Get(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				f.t.Errorf("invalid %s query: %q", key, value)
				f.reply(w, http.StatusBadRequest, fakeObject{"message": "Invalid pagination"})
				return
			}
			*dest = n
		}
	}
	offset = min(offset, len(f.zones))
	f.reply(w, http.StatusOK, fakeObject{"data": f.zones[offset : offset+min(limit, len(f.zones)-offset)]})
}

func (f *hosttechFake) recordEndpoint(w http.ResponseWriter, r *http.Request, zone, id string) {
	records := f.records[zone]
	i := slices.IndexFunc(records, func(rec fakeObject) bool { return fmt.Sprint(rec["id"]) == id })
	if id != "" && i < 0 {
		f.reply(w, http.StatusNotFound, fakeObject{"message": ""})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if id != "" {
			f.reply(w, http.StatusOK, fakeObject{"data": records[i]})
			return
		}
		listed := make([]fakeObject, 0, len(records))
		for _, rec := range records {
			if typ := r.URL.Query().Get("type"); typ == "" || rec["type"] == typ {
				listed = append(listed, rec)
			}
		}
		f.reply(w, http.StatusOK, fakeObject{"data": listed})
	case http.MethodPost, http.MethodPut:
		if (r.Method == http.MethodPost && id != "") || (r.Method == http.MethodPut && id == "") {
			f.reply(w, http.StatusMethodNotAllowed, fakeObject{"message": ""})
			return
		}
		f.writeRecord(w, r, zone, i)
	case http.MethodDelete:
		if i < 0 {
			f.reply(w, http.StatusNotFound, fakeObject{"message": ""})
			return
		}
		f.records[zone] = slices.Delete(records, i, i+1)
		w.WriteHeader(http.StatusNoContent)
	default:
		f.reply(w, http.StatusMethodNotAllowed, fakeObject{"message": ""})
	}
}

func (f *hosttechFake) writeRecord(w http.ResponseWriter, r *http.Request, zone string, index int) {
	var body fakeObject
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
		f.t.Errorf("invalid request JSON: %v", err)
		f.reply(w, http.StatusBadRequest, fakeObject{"message": "Invalid JSON"})
		return
	}
	f.calls[len(f.calls)-1].body = maps.Clone(body)
	if r.Method == http.MethodPut {
		body["type"] = f.records[zone][index]["type"]
	}
	if errs := fakeValidation(body, f.records[zone]); len(errs) > 0 {
		f.reply(w, http.StatusUnprocessableEntity, fakeObject{"message": "The given data was invalid.", "errors": errs})
		return
	}
	typ := fmt.Sprint(body["type"])
	rec := fakeObject{"id": f.nextID, "type": typ, "ttl": body["ttl"], "comment": nil}
	for _, field := range append(slices.Clone(fakeRecordFields[typ]), "comment") {
		if value, present := body[field]; present {
			rec[field] = value
		}
	}
	owner := fakeRecordFields[typ][0]
	if r.Method == http.MethodPut && typ == "CNAME" {
		if _, present := body[owner]; !present {
			rec[owner] = f.records[zone][index][owner]
		}
	}
	if value, present := rec[owner]; !present || value == "" {
		rec[owner] = nil
	}
	if r.Method == http.MethodPut {
		rec["id"] = f.records[zone][index]["id"]
		f.records[zone][index] = rec
		f.reply(w, http.StatusOK, fakeObject{"data": rec})
		return
	}
	f.nextID++
	f.records[zone] = append(f.records[zone], rec)
	f.reply(w, http.StatusCreated, fakeObject{"data": rec})
}

func fakeValidation(body fakeObject, records []fakeObject) map[string][]string {
	errs := make(map[string][]string)
	ttl, present := body["ttl"].(float64)
	if !present {
		errs["ttl"] = []string{"Darf nicht leer sein."}
	} else if ttl < 600 {
		errs["ttl"] = []string{"ttl muss mindestens 600 sein."}
	}
	switch body["type"] {
	case "CAA":
		if body["value"] == nil || body["value"] == "" {
			errs["value"] = []string{"Darf nicht leer sein."}
		}
	case "SRV":
		for _, field := range []string{"priority", "weight"} {
			if body[field] == nil {
				errs[field] = []string{"Darf nicht leer sein."}
			}
		}
		if body["target"] == "." {
			errs["target"] = []string{"Kein gültiger Domainname."}
		}
	case "MX":
		if body["name"] == "." {
			errs["name"] = []string{"Kein gültiger Domainname.", "is not valid"}
		}
	case "CNAME":
		if name, present := body["name"].(string); present {
			for _, record := range records {
				fields := fakeRecordFields[fmt.Sprint(record["type"])]
				if len(fields) == 0 {
					continue
				}
				owner := record[fields[0]]
				if owner == name || (name == "" && owner == nil) {
					errs["name"] = []string{"CNAME Name muss innerhalb einer Zone einmalig sein. Auch kein Record eines anderen Typs darf denselben Namen haben."}
					break
				}
			}
		}
		if target, ok := body["cname"].(string); ok && strings.HasSuffix(target, ".") {
			errs["cname"] = []string{"Kein gültiger Domainname."}
		}
	case "A", "AAAA", "NS", "PTR", "TXT", "TLSA":
	default:
		errs["type"] = []string{"Unsupported record type"}
	}
	return errs
}

func (f *hosttechFake) reply(w http.ResponseWriter, status int, body fakeObject) {
	if f.response != nil {
		body = f.response(status, body)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		f.t.Errorf("writing fake response: %v", err)
	}
}
