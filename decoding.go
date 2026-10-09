// SPDX-License-Identifier: MIT

package hosttech

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"time"
)

type responseError struct {
	kind  string
	id    int
	field string
}

func (e responseError) Error() string {
	return fmt.Sprintf("invalid %s %d field %s", e.kind, e.id, e.field)
}

func (r *apiResponse[T]) UnmarshalJSON(data []byte) error {
	var envelope struct{ Data json.RawMessage }
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decoding response envelope: %w", err)
	}
	if len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) {
		return responseError{kind: "response", field: "data"}
	}
	if err := json.Unmarshal(envelope.Data, &r.Data); err != nil {
		return fmt.Errorf("decoding response data: %w", err)
	}
	return nil
}

func (r *apiRecord) UnmarshalJSON(data []byte) error {
	type wireRecord apiRecord
	var wire wireRecord
	if err := json.Unmarshal(data, &wire); err != nil {
		return recordDecodeError(data, err)
	}
	decoded := apiRecord(wire)
	if err := decoded.validate(); err != nil {
		return err
	}
	*r = decoded
	return nil
}

func recordDecodeError(data []byte, cause error) error {
	var identifier struct{ ID int }
	if err := json.Unmarshal(data, &identifier); err != nil {
		identifier.ID = 0
	}
	field := responseKindRecord
	var typeErr *json.UnmarshalTypeError
	if errors.As(cause, &typeErr) {
		field = typeErr.Field
	}
	return responseError{kind: responseKindRecord, id: identifier.ID, field: field}
}

func (r *apiRecord) validate() error {
	if r.ID <= 0 {
		return responseError{kind: responseKindRecord, id: r.ID, field: "id"}
	}
	if r.TTL < 1 || int64(r.TTL) > math.MaxInt64/int64(time.Second) {
		return responseError{kind: responseKindRecord, id: r.ID, field: "ttl"}
	}
	switch r.Type {
	case recordTypeA, recordTypeAAAA:
		return r.validateAddress()
	case recordTypeCAA:
		flags, err := strconv.ParseUint(r.Flag, 10, 8)
		if err != nil {
			return responseError{kind: responseKindRecord, id: r.ID, field: "flag"}
		}
		r.flags = uint8(flags)
	case recordTypeCNAME, recordTypeMX, recordTypeNS, recordTypePTR, recordTypeSRV, recordTypeTXT, recordTypeTLSA:
	default:
		return responseError{kind: responseKindRecord, id: r.ID, field: "type"}
	}
	return nil
}

func (r *apiRecord) validateAddress() error {
	value, field := r.IPv4, "ipv4"
	if r.Type == recordTypeAAAA {
		value, field = r.IPv6, "ipv6"
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || (r.Type == recordTypeA && !ip.Is4()) || (r.Type == recordTypeAAAA && !ip.Is6()) {
		return responseError{kind: responseKindRecord, id: r.ID, field: field}
	}
	r.ip = ip
	return nil
}

func (z *apiZone) UnmarshalJSON(data []byte) error {
	type wireZone apiZone
	var wire wireZone
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decoding zone: %w", err)
	}
	if wire.ID <= 0 {
		return responseError{kind: "zone", id: wire.ID, field: "id"}
	}
	if wire.Name == "" {
		return responseError{kind: "zone", id: wire.ID, field: "name"}
	}
	*z = apiZone(wire)
	return nil
}

type unknownOutcomeError struct{ cause error }

func (e unknownOutcomeError) Error() string {
	return "record change outcome unknown: " + e.cause.Error()
}

func (e unknownOutcomeError) Unwrap() error { return e.cause }

func requestOutcome(method string, cause error) error {
	if method == "GET" {
		return cause
	}
	return unknownOutcomeError{cause: cause}
}
