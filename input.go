// SPDX-License-Identifier: MIT

package hosttech

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/libdns/libdns"
)

func prepareRecords(records []libdns.Record) ([]apiRecord, error) {
	result := make([]apiRecord, 0, len(records))
	for _, rec := range records {
		mapped, err := fromLibdns(rec)
		if err != nil {
			return nil, err
		}
		result = append(result, mapped)
	}
	return result, nil
}

func parseInput(rr libdns.RR) (libdns.Record, error) {
	if err := validateNames([]libdns.Record{rr}); err != nil {
		return nil, err
	}
	switch rr.Type {
	case recordTypeSRV:
		return parseSRV(rr)
	case recordTypeA, recordTypeAAAA, recordTypeCAA, recordTypeCNAME, recordTypeMX,
		recordTypeNS, recordTypePTR, recordTypeTXT, recordTypeTLSA:
	default:
		return nil, inputError{typ: rr.Type, field: fieldType}
	}
	parsed, err := rr.Parse()
	if err != nil {
		return nil, inputError{typ: rr.Type, field: fieldData}
	}
	if address, ok := parsed.(libdns.Address); ok && address.RR().Type != rr.Type {
		return nil, inputError{typ: rr.Type, field: "address"}
	}
	return parsed, nil
}

func parseSRV(rr libdns.RR) (libdns.SRV, error) {
	fields := strings.Fields(rr.Data)
	if len(fields) != 4 {
		return libdns.SRV{}, inputError{typ: rr.Type, field: fieldData}
	}
	numbers := [3]uint16{}
	for i, field := range []string{"priority", "weight", "port"} {
		number, err := strconv.ParseUint(fields[i], 10, 16)
		if err != nil {
			return libdns.SRV{}, inputError{typ: rr.Type, field: field}
		}
		numbers[i] = uint16(number)
	}
	service, transport, name := srvOwner(rr.Name)
	return libdns.SRV{
		Service: service, Transport: transport, Name: name, TTL: rr.TTL,
		Priority: numbers[0], Weight: numbers[1], Port: numbers[2], Target: fields[3],
	}, nil
}

func nilRecord(rec libdns.Record) bool {
	if rec == nil {
		return true
	}
	value := reflect.ValueOf(rec)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
