// SPDX-License-Identifier: MIT

package hosttech

func recordBody(r *apiRecord, create bool) (map[string]any, error) {
	var body map[string]any
	switch r.Type {
	case recordTypeA:
		body = map[string]any{fieldName: r.Name, "ipv4": r.IPv4}
	case recordTypeAAAA:
		body = map[string]any{fieldName: r.Name, "ipv6": r.IPv6}
	case recordTypeCAA:
		body = map[string]any{fieldName: r.Name, "flag": r.Flag, "tag": r.Tag, "value": r.Value}
	case recordTypeCNAME:
		body = map[string]any{fieldName: r.Name, "cname": r.CName}
	case recordTypeMX:
		body = map[string]any{"ownername": r.OwnerName, fieldName: r.Name, "pref": r.Pref}
	case recordTypeNS:
		body = map[string]any{"ownername": r.OwnerName, "targetname": r.TargetName}
	case recordTypePTR:
		body = map[string]any{"origin": r.Origin, fieldName: r.Name}
	case recordTypeSRV:
		body = map[string]any{
			"service": r.Service, "priority": r.Priority, "weight": r.Weight, "port": r.Port, "target": r.Target,
		}
	case recordTypeTXT, recordTypeTLSA:
		body = map[string]any{fieldName: r.Name, "text": r.Text}
	default:
		return nil, inputError{typ: r.Type, field: "type"}
	}
	body["ttl"] = r.TTL
	if create {
		body["type"] = r.Type
	}
	return body, nil
}
