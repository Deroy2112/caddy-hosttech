// SPDX-License-Identifier: MIT

package hosttech

import (
	"errors"
	"net/http"
	"time"

	"github.com/libdns/libdns"
)

type deleteFilter struct {
	rr     libdns.RR
	values map[string]*apiRecord
}

var recordTypes = []string{
	recordTypeA, recordTypeAAAA, recordTypeCAA, recordTypeCNAME, recordTypeMX,
	recordTypeNS, recordTypePTR, recordTypeSRV, recordTypeTXT, recordTypeTLSA,
}

func prepareFilters(records []libdns.Record) ([]deleteFilter, error) {
	result := make([]deleteFilter, 0, len(records))
	for _, rec := range records {
		if nilRecord(rec) {
			return nil, inputError{field: "record"}
		}
		rr := rec.RR()
		if rr.Name == "" {
			return nil, inputError{typ: rr.Type, field: fieldName}
		}
		filter, err := prepareFilter(rr)
		if err != nil {
			return nil, err
		}
		result = append(result, filter)
	}
	return result, nil
}

func prepareFilter(rr libdns.RR) (deleteFilter, error) {
	filter := deleteFilter{rr: rr, values: make(map[string]*apiRecord)}
	if rr.Data == "" {
		return filter, nil
	}
	if rr.Type != "" {
		value, err := filterValue(rr)
		if err != nil {
			return deleteFilter{}, err
		}
		filter.values[rr.Type] = value
		return filter, nil
	}
	for _, typ := range recordTypes {
		candidate := rr
		candidate.Type = typ
		value, err := filterValue(candidate)
		if err != nil {
			continue
		}
		filter.values[typ] = value
	}
	return filter, nil
}

func filterValue(rr libdns.RR) (*apiRecord, error) {
	var parsed libdns.Record
	var err error
	if rr.Type == recordTypeSRV {
		parsed, err = parseSRV(rr)
	} else {
		parsed, err = rr.Parse()
	}
	if err != nil {
		return nil, inputError{typ: rr.Type, field: fieldData}
	}
	value := &apiRecord{Type: rr.Type, Name: rr.Name}
	if err := mapParsedRecord(value, parsed); err != nil {
		return nil, err
	}
	if address, ok := parsed.(libdns.Address); ok && address.RR().Type != rr.Type {
		return nil, inputError{typ: rr.Type, field: "address"}
	}
	return value, nil
}

func matchesRR(rec *apiRecord, filter *deleteFilter) bool {
	want := filter.rr
	if recordName(rec) != want.Name || (want.Type != "" && rec.Type != want.Type) {
		return false
	}
	if want.TTL != 0 && rec.TTL != int(want.TTL/time.Second) {
		return false
	}
	if want.Data == "" {
		return true
	}
	value, ok := filter.values[rec.Type]
	return ok && sameValue(rec, value)
}

func missingRecord(err error) bool {
	var apiErr APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
