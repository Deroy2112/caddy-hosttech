// SPDX-License-Identifier: MIT

package hosttech

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// apiResponse wraps the standard hosttech API response envelope.
type apiResponse[T any] struct {
	Data T `json:"data"`
}

// apiZone represents a zone from the hosttech API.
type apiZone struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	Nameserver  string `json:"nameserver,omitempty"`
	DNSSEC      bool   `json:"dnssec,omitempty"`
	DNSSECEmail string `json:"dnssec_email,omitempty"`
}

func (z *apiZone) toLibdns() libdns.Zone {
	return libdns.Zone{Name: z.Name + "."}
}

// apiRecord is a polymorphic record from the hosttech API.
// The Type field determines which other fields are populated.
type apiRecord struct {
	ip    netip.Addr
	flags uint8
	ID    int    `json:"id,omitempty"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl,omitempty"`

	// A / AAAA / CNAME / TXT / TLSA / CAA
	Name string `json:"name,omitempty"`

	// A
	IPv4 string `json:"ipv4,omitempty"`

	// AAAA
	IPv6 string `json:"ipv6,omitempty"`

	// CNAME
	CName string `json:"cname,omitempty"`

	// MX: ownername is the record name, name is the mail server
	OwnerName string `json:"ownername,omitempty"`
	Pref      uint16 `json:"pref,omitempty"`

	// NS: ownername is the record name, targetname is the nameserver
	TargetName string `json:"targetname,omitempty"`

	// TXT / TLSA
	Text string `json:"text,omitempty"`

	// SRV
	Service  string `json:"service,omitempty"`
	Priority uint16 `json:"priority,omitempty"`
	Weight   uint16 `json:"weight,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Target   string `json:"target,omitempty"`

	// CAA
	Flag  string `json:"flag,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Value string `json:"value,omitempty"`

	// PTR
	Origin string `json:"origin,omitempty"`

	// Comment applies to all record types.
	Comment string `json:"comment,omitempty"`
}

// toLibdns converts a hosttech API record to a typed libdns.Record.
func (r *apiRecord) toLibdns() libdns.Record {
	name := recordName(r)
	switch r.Type {
	case recordTypeA, recordTypeAAAA:
		return libdns.Address{
			Name:         name,
			TTL:          time.Duration(r.TTL) * time.Second,
			IP:           r.ip,
			ProviderData: r.ID,
		}
	case recordTypeCNAME:
		return libdns.CNAME{
			Name:         name,
			TTL:          time.Duration(r.TTL) * time.Second,
			Target:       r.CName,
			ProviderData: r.ID,
		}
	case recordTypeMX:
		return libdns.MX{
			Name:         name,
			TTL:          time.Duration(r.TTL) * time.Second,
			Preference:   r.Pref,
			Target:       r.Name,
			ProviderData: r.ID,
		}
	case recordTypeNS:
		return libdns.NS{
			Name:         name,
			TTL:          time.Duration(r.TTL) * time.Second,
			Target:       r.TargetName,
			ProviderData: r.ID,
		}
	case recordTypeTXT:
		return libdns.TXT{
			Name:         name,
			TTL:          time.Duration(r.TTL) * time.Second,
			Text:         r.Text,
			ProviderData: r.ID,
		}
	case recordTypeSRV:
		return r.srvRecord()
	case recordTypeCAA:
		return libdns.CAA{
			Name:         name,
			TTL:          time.Duration(r.TTL) * time.Second,
			Flags:        r.flags,
			Tag:          r.Tag,
			Value:        r.Value,
			ProviderData: r.ID,
		}
	case recordTypePTR, recordTypeTLSA:
		data := r.Text
		if r.Type == recordTypePTR {
			data = r.Name
		}
		return libdns.RR{
			Name: name,
			TTL:  time.Duration(r.TTL) * time.Second,
			Type: r.Type,
			Data: data,
		}
	default:
		panic("unvalidated record type")
	}
}

// fromLibdns creates a hosttech API record from a libdns.Record.
func fromLibdns(rec libdns.Record) (apiRecord, error) {
	if nilRecord(rec) {
		return apiRecord{}, inputError{field: "record"}
	}
	rr := rec.RR()
	parsed, err := parseInput(rr)
	if err != nil {
		return apiRecord{}, err
	}
	r := apiRecord{Type: rr.Type, TTL: clampTTL(rr.TTL), Name: rr.Name}
	if err := mapParsedRecord(&r, parsed); err != nil {
		return apiRecord{}, err
	}
	normalizeWrite(&r)
	return r, nil
}

func mapParsedRecord(r *apiRecord, parsed libdns.Record) error {
	switch v := parsed.(type) {
	case libdns.Address:
		r.ip = v.IP
		if v.IP.Is4() {
			r.IPv4 = v.IP.String()
		} else {
			r.IPv6 = v.IP.String()
		}
	case libdns.CNAME:
		r.CName = v.Target
	case libdns.MX:
		r.OwnerName, r.Name, r.Pref = v.Name, v.Target, v.Preference
	case libdns.NS:
		r.OwnerName, r.TargetName = v.Name, v.Target
	case libdns.TXT:
		r.Text = v.Text
	case libdns.SRV:
		r.Service, r.Name = v.RR().Name, ""
		r.Priority, r.Weight, r.Port, r.Target = v.Priority, v.Weight, v.Port, v.Target
	case libdns.CAA:
		r.flags = v.Flags
		r.Flag, r.Tag, r.Value = strconv.Itoa(int(v.Flags)), v.Tag, v.Value
	case libdns.RR:
		if v.Type == recordTypePTR {
			r.Origin, r.Name = v.Name, v.Data
		} else {
			r.Text = v.Data
		}
	default:
		return inputError{typ: r.Type, field: fieldData}
	}
	return nil
}

// clampTTL ensures the TTL is at least 600 seconds (hosttech API minimum).
func clampTTL(ttl time.Duration) int {
	seconds := int(ttl / time.Second)
	if seconds < 600 {
		return 600
	}
	return seconds
}

func removeTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

func recordName(r *apiRecord) string {
	switch r.Type {
	case recordTypeMX, recordTypeNS:
		return libdnsOwner(r.OwnerName)
	case recordTypePTR:
		return libdnsOwner(r.Origin)
	case recordTypeSRV:
		return libdnsOwner(r.Service)
	default:
		return libdnsOwner(r.Name)
	}
}

// normalizeName canonicalises root-of-zone representations so that "@" and ""
// compare equal.
func normalizeName(n string) string {
	if n == "@" {
		return ""
	}
	return n
}

func sameValue(a, b *apiRecord) bool {
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case recordTypeA, recordTypeAAAA:
		return a.ip == b.ip
	case recordTypeCNAME:
		return targetValue(a.CName) == targetValue(b.CName)
	case recordTypeMX:
		return mxValue(a) == mxValue(b)
	case recordTypeNS:
		return targetValue(a.TargetName) == targetValue(b.TargetName)
	case recordTypePTR:
		return targetValue(a.Name) == targetValue(b.Name)
	case recordTypeTXT, recordTypeTLSA:
		return a.Text == b.Text
	case recordTypeSRV:
		return srvValue(a) == srvValue(b)
	case recordTypeCAA:
		return caaValue(a) == caaValue(b)
	default:
		panic("unvalidated record type")
	}
}

func targetValue(target string) string {
	if target == "." {
		return target
	}
	return removeTrailingDot(target)
}

func mxValue(r *apiRecord) mxData {
	return mxData{preference: r.Pref, target: targetValue(r.Name)}
}

type mxData struct {
	preference uint16
	target     string
}

func srvValue(r *apiRecord) srvData {
	return srvData{priority: r.Priority, weight: r.Weight, port: r.Port, target: targetValue(r.Target)}
}

type srvData struct {
	priority, weight, port uint16
	target                 string
}

func caaValue(r *apiRecord) caaData {
	return caaData{flag: r.flags, tag: r.Tag, value: r.Value}
}

type caaData struct {
	flag       uint8
	tag, value string
}
