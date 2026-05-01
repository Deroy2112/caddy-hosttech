// SPDX-License-Identifier: Apache-2.0

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

func (z apiZone) toLibdns() libdns.Zone {
	return libdns.Zone{Name: z.Name + "."}
}

// apiRecord is a polymorphic record from the hosttech API.
// The Type field determines which other fields are populated.
type apiRecord struct {
	ID   int    `json:"id,omitempty"`
	Type string `json:"type"`
	TTL  int    `json:"ttl,omitempty"`

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
	Flag string `json:"flag,omitempty"`
	Tag  string `json:"tag,omitempty"`

	// PTR
	Origin string `json:"origin,omitempty"`

	// Comment applies to all record types.
	Comment string `json:"comment,omitempty"`
}

// toLibdns converts a hosttech API record to a typed libdns.Record.
func (r apiRecord) toLibdns(zone string) libdns.Record {
	switch r.Type {
	case "A":
		ip, _ := netip.ParseAddr(r.IPv4)
		return libdns.Address{
			Name:         libdns.RelativeName(r.Name, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			IP:           ip,
			ProviderData: r.ID,
		}
	case "AAAA":
		ip, _ := netip.ParseAddr(r.IPv6)
		return libdns.Address{
			Name:         libdns.RelativeName(r.Name, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			IP:           ip,
			ProviderData: r.ID,
		}
	case "CNAME":
		return libdns.CNAME{
			Name:         libdns.RelativeName(r.Name, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			Target:       r.CName,
			ProviderData: r.ID,
		}
	case "MX":
		return libdns.MX{
			Name:         libdns.RelativeName(r.OwnerName, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			Preference:   r.Pref,
			Target:       r.Name,
			ProviderData: r.ID,
		}
	case "NS":
		return libdns.NS{
			Name:         libdns.RelativeName(r.OwnerName, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			Target:       r.TargetName,
			ProviderData: r.ID,
		}
	case "TXT":
		return libdns.TXT{
			Name:         libdns.RelativeName(r.Name, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			Text:         r.Text,
			ProviderData: r.ID,
		}
	case "SRV":
		return libdns.SRV{
			Service:      r.Service,
			Name:         libdns.RelativeName(r.Name, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			Priority:     r.Priority,
			Weight:       r.Weight,
			Port:         r.Port,
			Target:       r.Target,
			ProviderData: r.ID,
		}
	case "CAA":
		flags, _ := strconv.ParseUint(r.Flag, 10, 8)
		return libdns.CAA{
			Name:         libdns.RelativeName(r.Name, zone),
			TTL:          time.Duration(r.TTL) * time.Second,
			Flags:        uint8(flags),
			Tag:          r.Tag,
			Value:        r.Name,
			ProviderData: r.ID,
		}
	case "PTR", "TLSA":
		name := r.Name
		data := r.Text
		if r.Type == "PTR" {
			name = r.Origin
			data = r.Name
		}
		return libdns.RR{
			Name: name,
			TTL:  time.Duration(r.TTL) * time.Second,
			Type: r.Type,
			Data: data,
		}
	default:
		return libdns.RR{
			Name: r.Name,
			TTL:  time.Duration(r.TTL) * time.Second,
			Type: r.Type,
			Data: r.Text,
		}
	}
}

// fromLibdns creates a hosttech API record from a libdns.Record.
func fromLibdns(rec libdns.Record, zone string) apiRecord {
	rr := rec.RR()
	r := apiRecord{
		Type: rr.Type,
		TTL:  clampTTL(rr.TTL),
	}

	if id, ok := getProviderID(rec); ok {
		r.ID = id
	}

	switch v := rec.(type) {
	case libdns.Address:
		r.Name = v.Name
		if v.IP.Is4() {
			r.Type = "A"
			r.IPv4 = v.IP.String()
		} else {
			r.Type = "AAAA"
			r.IPv6 = v.IP.String()
		}
	case libdns.CNAME:
		r.Name = v.Name
		r.CName = v.Target
	case libdns.MX:
		r.OwnerName = v.Name
		r.Name = v.Target
		r.Pref = v.Preference
	case libdns.NS:
		r.OwnerName = v.Name
		r.TargetName = v.Target
	case libdns.TXT:
		r.Name = v.Name
		r.Text = v.Text
	case libdns.SRV:
		r.Service = v.Service
		r.Name = v.Name
		r.Priority = v.Priority
		r.Weight = v.Weight
		r.Port = v.Port
		r.Target = v.Target
	case libdns.CAA:
		r.Name = v.Name
		r.Flag = strconv.Itoa(int(v.Flags))
		r.Tag = v.Tag
	case libdns.RR:
		r.Name = v.Name
		switch v.Type {
		case "PTR":
			r.Origin = v.Name
			r.Name = v.Data
		case "TLSA":
			r.Text = v.Data
		default:
			r.Text = v.Data
		}
	}

	return r
}

// providerData returns the ProviderData field from a typed libdns.Record, if present.
func providerData(rec libdns.Record) any {
	switch v := rec.(type) {
	case libdns.Address:
		return v.ProviderData
	case libdns.CNAME:
		return v.ProviderData
	case libdns.MX:
		return v.ProviderData
	case libdns.NS:
		return v.ProviderData
	case libdns.TXT:
		return v.ProviderData
	case libdns.SRV:
		return v.ProviderData
	case libdns.CAA:
		return v.ProviderData
	default:
		return nil
	}
}

// getProviderID extracts the hosttech record ID from a libdns.Record's ProviderData.
func getProviderID(rec libdns.Record) (int, bool) {
	id, ok := providerData(rec).(int)
	return id, ok
}

// clampTTL ensures the TTL is at least 600 seconds (hosttech API minimum).
func clampTTL(ttl time.Duration) int {
	seconds := int(ttl.Seconds())
	if seconds < 600 {
		return 600
	}
	return seconds
}

// removeTrailingDot strips a trailing dot from a zone name.
func removeTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

// recordName returns the record's owner name from a hosttech apiRecord,
// regardless of type. Hosttech stores MX/NS owners in OwnerName and PTR
// owners in Origin; all others use Name.
func recordName(r apiRecord) string {
	switch r.Type {
	case "MX", "NS":
		return r.OwnerName
	case "PTR":
		return r.Origin
	default:
		return r.Name
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

// matchesRR reports whether apiRec satisfies the libdns filter defined by want.
// Per [libdns.RecordDeleter] semantics, empty Type/TTL/Data act as wildcards
// while Name is mandatory. Type-specific value comparison is performed by
// re-canonicalising want via fromLibdns so both sides go through the same
// transform, avoiding representation drift.
func matchesRR(apiRec apiRecord, want libdns.RR, zone string) bool {
	if normalizeName(recordName(apiRec)) != normalizeName(want.Name) {
		return false
	}
	if want.Type != "" && apiRec.Type != want.Type {
		return false
	}
	if want.TTL != 0 && apiRec.TTL != int(want.TTL.Seconds()) {
		return false
	}
	if want.Data == "" {
		return true
	}
	parsed, _ := want.Parse()
	return sameValue(apiRec, fromLibdns(parsed, zone))
}

// sameValue compares the type-specific value fields of two apiRecords.
// It assumes both have the same Type (caller is responsible).
func sameValue(a, b apiRecord) bool {
	switch a.Type {
	case "A":
		return a.IPv4 == b.IPv4
	case "AAAA":
		return a.IPv6 == b.IPv6
	case "CNAME":
		return a.CName == b.CName
	case "MX":
		return a.Name == b.Name && a.Pref == b.Pref
	case "NS":
		return a.TargetName == b.TargetName
	case "TXT":
		return txtEqual(a.Text, b.Text)
	case "SRV":
		return a.Service == b.Service &&
			a.Priority == b.Priority &&
			a.Weight == b.Weight &&
			a.Port == b.Port &&
			a.Target == b.Target
	case "CAA":
		return a.Flag == b.Flag && a.Tag == b.Tag && a.Name == b.Name
	default:
		return a.Text == b.Text
	}
}

// txtEqual compares two TXT record values accepting both quoted and unquoted
// forms on either side. libdns stores TXT content unquoted; some APIs return
// it wire-format quoted.
func txtEqual(a, b string) bool {
	return a == b || trimTXTQuotes(a) == trimTXTQuotes(b)
}

func trimTXTQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

