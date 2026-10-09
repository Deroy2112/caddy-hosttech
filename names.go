// SPDX-License-Identifier: MIT

package hosttech

import (
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

type inputError struct{ typ, field string }

func (e inputError) Error() string { return fmt.Sprintf("invalid %s record field %s", e.typ, e.field) }

func libdnsOwner(owner string) string {
	if owner == "" {
		return "@"
	}
	return owner
}

func srvOwner(owner string) (service, transport, name string) {
	parts := strings.SplitN(owner, ".", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") ||
		len(parts[0]) < 2 || len(parts[1]) < 2 || (len(parts) == 3 && parts[2] == "") {
		return "", "", libdnsOwner(owner)
	}
	name = "@"
	if len(parts) == 3 {
		name = parts[2]
	}
	return parts[0][1:], parts[1][1:], name
}

func (r *apiRecord) srvRecord() libdns.SRV {
	service, transport, owner := srvOwner(r.Service)
	return libdns.SRV{
		Service: service, Transport: transport, Name: owner, TTL: time.Duration(r.TTL) * time.Second,
		Priority: r.Priority, Weight: r.Weight, Port: r.Port, Target: r.Target, ProviderData: r.ID,
	}
}

func validateNames(records []libdns.Record) error {
	for _, rec := range records {
		rr := rec.RR()
		if rr.Name == "" {
			return inputError{typ: rr.Type, field: fieldName}
		}
		target := ""
		switch rr.Type {
		case recordTypeCNAME, recordTypeNS, recordTypePTR:
			target = rr.Data
		case recordTypeMX, recordTypeSRV:
			if fields := strings.Fields(rr.Data); len(fields) > 0 {
				target = fields[len(fields)-1]
			}
		default:
		}
		if target == "." {
			return inputError{typ: rr.Type, field: "target"}
		}
	}
	return nil
}

func normalizeWrite(r *apiRecord) {
	switch r.Type {
	case recordTypeMX, recordTypeNS:
		r.OwnerName = normalizeName(r.OwnerName)
	case recordTypePTR:
		r.Origin = normalizeName(r.Origin)
	case recordTypeSRV:
	default:
		r.Name = normalizeName(r.Name)
	}
	r.CName = removeTrailingDot(r.CName)
	r.TargetName = removeTrailingDot(r.TargetName)
	r.Target = removeTrailingDot(r.Target)
	if r.Type == recordTypeMX || r.Type == recordTypePTR {
		r.Name = removeTrailingDot(r.Name)
	}
}
