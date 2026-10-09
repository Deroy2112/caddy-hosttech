// SPDX-License-Identifier: MIT

package hosttech

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
)

func fakeRequest(t *testing.T, f *hosttechFake, method, path, token, body string, wantStatus int) fakeObject {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+"/api/user/v1"+path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	data, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("response body: read=%v close=%v", readErr, closeErr)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, wantStatus, data)
	}
	var result fakeObject
	if len(data) != 0 {
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("response JSON: %v", err)
		}
	}
	return result
}

func TestFakeValidation(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name, method, path, token, body, want string
		status                                int
	}{
		{"read probe/missing token", "GET", "/zones", "", "", `{"message":"Unauthenticated."}`, 401},
		{"write probe/ttl 60", "POST", "/zones/example.com/records", fakeToken, `{"type":"TXT","name":"test","text":"token","ttl":60}`, `{"message":"The given data was invalid.","errors":{"ttl":["ttl muss mindestens 600 sein."]}}`, 422},
		{"write probe/ttl 300", "POST", "/zones/example.com/records", fakeToken, `{"type":"TXT","name":"test","text":"token","ttl":300}`, `{"message":"The given data was invalid.","errors":{"ttl":["ttl muss mindestens 600 sein."]}}`, 422},
		{"write probe/PUT requires ttl", "PUT", "/zones/example.com/records/18", fakeToken, `{"text":"token"}`, `{"message":"The given data was invalid.","errors":{"ttl":["Darf nicht leer sein."]}}`, 422},
		{"write probe/CAA requires value", "POST", "/zones/example.com/records", fakeToken, `{"type":"CAA","name":"","flag":"0","tag":"issue","ttl":3600}`, `{"message":"The given data was invalid.","errors":{"value":["Darf nicht leer sein."]}}`, 422},
		{"write probe/SRV requires priority and weight", "POST", "/zones/example.com/records", fakeToken, `{"type":"SRV","service":"_sip._tcp","port":443,"target":"t.example.com","ttl":3600}`, `{"message":"The given data was invalid.","errors":{"priority":["Darf nicht leer sein."],"weight":["Darf nicht leer sein."]}}`, 422},
		{"CNAME PUT probe/name conflicts with itself", "PUT", "/zones/example.com/records/13", fakeToken, `{"name":"alias","cname":"site.example.com","ttl":7200}`, `{"message":"The given data was invalid.","errors":{"name":["CNAME Name muss innerhalb einer Zone einmalig sein. Auch kein Record eines anderen Typs darf denselben Namen haben."]}}`, 422},
		{"write probe/CNAME trailing dot", "POST", "/zones/example.com/records", fakeToken, `{"type":"CNAME","name":"test","cname":"t.example.com.","ttl":3600}`, `{"message":"The given data was invalid.","errors":{"cname":["Kein gültiger Domainname."]}}`, 422},
		{"write probe/MX null target", "POST", "/zones/example.com/records", fakeToken, `{"type":"MX","ownername":"","name":".","pref":0,"ttl":3600}`, `{"message":"The given data was invalid.","errors":{"name":["Kein gültiger Domainname.","is not valid"]}}`, 422},
		{"write probe/SRV null target", "POST", "/zones/example.com/records", fakeToken, `{"type":"SRV","service":"_sip._tcp","priority":0,"weight":0,"port":443,"target":".","ttl":3600}`, `{"message":"The given data was invalid.","errors":{"target":["Kein gültiger Domainname."]}}`, 422},
		{"write probe/missing record", "DELETE", "/zones/example.com/records/999", fakeToken, "", `{"message":""}`, 404},
		{"specification/Record enum", "POST", "/zones/example.com/records", fakeToken, `{"type":"HTTPS","ttl":3600}`, `{"message":"The given data was invalid.","errors":{"type":["Unsupported record type"]}}`, 422},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			before := fakeRequest(t, f, "GET", "/zones/example.com/records", fakeToken, "", 200)
			got := fakeRequest(t, f, row.method, row.path, row.token, row.body, row.status)
			var want fakeObject
			if err := json.Unmarshal([]byte(row.want), &want); err != nil {
				t.Fatalf("expected fixture: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("body=%v want=%v", got, want)
			}
			after := fakeRequest(t, f, "GET", "/zones/example.com/records", fakeToken, "", 200)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("refused request changed records: %v", after)
			}
		})
	}
}

func TestFakeRecordShapes(t *testing.T) {
	t.Parallel()
	rows := []struct{ name, body, want string }{
		{"specification/ARecord", `{"type":"A","name":"www","ipv4":"1.2.3.4","ttl":3600}`, `{"type":"A","name":"www","ipv4":"1.2.3.4","ttl":3600,"comment":null}`},
		{"write probe/AAAA verbatim", `{"type":"AAAA","name":"www","ipv6":"2001:0DB8:0000:0000:0000:0000:0000:0001","ttl":3600}`, `{"type":"AAAA","name":"www","ipv6":"2001:0DB8:0000:0000:0000:0000:0000:0001","ttl":3600,"comment":null}`},
		{"write probe/CAA value and empty apex", `{"type":"CAA","name":"","flag":"0","tag":"issue","value":"letsencrypt.org","ttl":3600}`, `{"type":"CAA","name":null,"flag":"0","tag":"issue","value":"letsencrypt.org","ttl":3600,"comment":null}`},
		{"specification/CNAMERecord", `{"type":"CNAME","name":"www","cname":"site.example.com","ttl":3600}`, `{"type":"CNAME","name":"www","cname":"site.example.com","ttl":3600,"comment":null}`},
		{"specification/MXRecord zero preference", `{"type":"MX","ownername":"sub","name":"mail.example.com","pref":0,"ttl":3600}`, `{"type":"MX","ownername":"sub","name":"mail.example.com","pref":0,"ttl":3600,"comment":null}`},
		{"read probe/NS targetname without name", `{"type":"NS","ownername":"sub","targetname":"ns1.example.com","ttl":3600}`, `{"type":"NS","ownername":"sub","targetname":"ns1.example.com","ttl":3600,"comment":null}`},
		{"specification/PTRRecord", `{"type":"PTR","origin":"4.3.2.1","name":"smtp.example.com","ttl":3600}`, `{"type":"PTR","origin":"4.3.2.1","name":"smtp.example.com","ttl":3600,"comment":null}`},
		{"write probe/SRV complete service", `{"type":"SRV","service":"_sip._tcp.sub","priority":0,"weight":0,"port":443,"target":"exchange.example.com","ttl":3600}`, `{"type":"SRV","service":"_sip._tcp.sub","priority":0,"weight":0,"port":443,"target":"exchange.example.com","ttl":3600,"comment":null}`},
		{"write probe/SRV arbitrary service drops name", `{"type":"SRV","service":"sip","name":"sub","priority":0,"weight":0,"port":443,"target":"exchange.example.com","ttl":3600}`, `{"type":"SRV","service":"sip","priority":0,"weight":0,"port":443,"target":"exchange.example.com","ttl":3600,"comment":null}`},
		{"write probe/TXT literal at sign", `{"type":"TXT","name":"@","text":"token","ttl":3600}`, `{"type":"TXT","name":"@","text":"token","ttl":3600,"comment":null}`},
		{"specification/TLSARecord", `{"type":"TLSA","name":"_443._tcp","text":"0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971","ttl":3600}`, `{"type":"TLSA","name":"_443._tcp","text":"0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971","ttl":3600,"comment":null}`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			f.records[fakeZone] = nil
			response := fakeRequest(t, f, "POST", "/zones/example.com/records", fakeToken, row.body, 201)
			got := response["data"].(map[string]any)
			id := got["id"]
			read := fakeRequest(t, f, "GET", fmt.Sprintf("/zones/example.com/records/%v", id), fakeToken, "", 200)
			if !reflect.DeepEqual(read, response) {
				t.Fatalf("stored record=%v want=%v", read, response)
			}
			delete(got, "id")
			var want map[string]any
			if err := json.Unmarshal([]byte(row.want), &want); err != nil {
				t.Fatalf("expected fixture: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("record=%v want=%v", got, want)
			}
		})
	}
}

func TestFakeReplacementAndDeletion(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name, method, path, body, want string
		status                         int
	}{
		{"write probe/PUT ignores id and type", "PUT", "/zones/example.com/records/18", `{"id":1,"type":"A","name":"test","text":"changed","ttl":600}`, `{"data":{"id":18,"type":"TXT","name":"test","text":"changed","ttl":600,"comment":null}}`, 200},
		{"write probe/PUT without id and type", "PUT", "/zones/example.com/records/18", `{"name":"test","text":"changed","ttl":600}`, `{"data":{"id":18,"type":"TXT","name":"test","text":"changed","ttl":600,"comment":null}}`, 200},
		{"CNAME PUT probe/omitted name keeps owner", "PUT", "/zones/example.com/records/13", `{"cname":"site.example.com","ttl":7200}`, `{"data":{"id":13,"type":"CNAME","name":"alias","cname":"site.example.com","ttl":7200,"comment":null}}`, 200},
		{"write probe/DELETE 204", "DELETE", "/zones/example.com/records/18", "", "", 204},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			got := fakeRequest(t, f, row.method, row.path, fakeToken, row.body, row.status)
			var want fakeObject
			if row.want != "" {
				if err := json.Unmarshal([]byte(row.want), &want); err != nil {
					t.Fatalf("expected fixture: %v", err)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("response=%v want=%v", got, want)
			}
			if row.method == "DELETE" {
				want = fakeObject{"message": ""}
				got = fakeRequest(t, f, "GET", row.path, fakeToken, "", 404)
			} else {
				got = fakeRequest(t, f, "GET", row.path, fakeToken, "", 200)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("stored record=%v want=%v", got, want)
			}
		})
	}
}

func TestFakeZonePagination(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name, query string
		want        int
	}{
		{"specification/default limit 100", "", 100},
		{"read probe/limit 2", "?limit=2", 2},
		{"specification/offset", "?limit=2&offset=100", 1},
		{"specification/end of list", "?limit=2&offset=101", 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			f.mu.Lock()
			f.zones = make([]fakeObject, 101)
			for i := range f.zones {
				f.zones[i] = fakeObject{"id": i + 1, "name": fmt.Sprintf("zone%d.example", i)}
			}
			f.mu.Unlock()
			got := fakeRequest(t, f, "GET", "/zones"+row.query, fakeToken, "", 200)["data"].([]any)
			if len(got) != row.want {
				t.Fatalf("zones=%d want=%d", len(got), row.want)
			}
			if len(got) > 0 && row.query == "?limit=2&offset=100" && got[0].(map[string]any)["name"] != "zone100.example" {
				t.Fatalf("offset returned %v", got)
			}
		})
	}
}

func TestFakeReadEndpoints(t *testing.T) {
	t.Parallel()
	for _, row := range []struct {
		name, path string
		index      int
		single     bool
	}{
		{"read probe/record list shapes", "/zones/example.com/records", -1, false},
		{"specification/zone ID and single record", "/zones/10/records/17", 7, true},
		{"specification/record type filter", "/zones/example.com/records?type=NS", 5, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f := newHosttechFake(t)
			var fixture []any
			if err := json.Unmarshal([]byte(fakeRecords), &fixture); err != nil {
				t.Fatalf("expected fixture: %v", err)
			}
			var want any = fixture
			if row.single {
				want = fixture[row.index]
			} else if row.index >= 0 {
				want = []any{fixture[row.index]}
			}
			got := fakeRequest(t, f, "GET", row.path, fakeToken, "", 200)
			if !reflect.DeepEqual(got, fakeObject{"data": want}) {
				t.Fatalf("records=%v want=%v", got, want)
			}
		})
	}
}
