// SPDX-License-Identifier: Apache-2.0

package hosttech

import (
	"context"
	"fmt"
	"sync"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for the hosttech DNS API.
type Provider struct {
	APIToken string `json:"api_token,omitempty"`

	once   sync.Once
	mu     sync.Mutex
	client *client
}

func (p *Provider) initClient() {
	p.once.Do(func() {
		p.client = newClient(p.APIToken)
	})
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.initClient()

	zoneName := removeTrailingDot(zone)
	records, err := p.client.getRecords(ctx, zoneName)
	if err != nil {
		return nil, err
	}

	result := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		result = append(result, rec.toLibdns(zoneName))
	}
	return result, nil
}

// AppendRecords adds records to the zone and returns the created records.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.initClient()

	zoneName := removeTrailingDot(zone)
	var created []libdns.Record

	for _, rec := range records {
		apiRec := fromLibdns(rec, zone)
		resp, err := p.client.createRecord(ctx, zoneName, apiRec)
		if err != nil {
			return created, err
		}
		created = append(created, resp.toLibdns(zoneName))
	}

	return created, nil
}

// SetRecords enforces the libdns [RecordSetter] contract: for each
// (name, type) pair in the input, the only records in the output zone with
// that pair are those provided in the input. Other RRsets are untouched.
//
// The hosttech API offers no RRset-level replace, so per RRset we delete all
// existing members not reused and create the remaining inputs. Where the
// input and zone each contain exactly one record for that (name, type),
// we issue a single PUT to avoid the delete+create race window.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.initClient()
	zoneName := removeTrailingDot(zone)

	zoneRecs, err := p.client.getRecords(ctx, zoneName)
	if err != nil {
		return nil, fmt.Errorf("listing zone records: %w", err)
	}

	type rrsetKey struct{ name, typ string }
	groups := make(map[rrsetKey][]libdns.Record)
	order := make([]rrsetKey, 0)
	for _, rec := range records {
		rr := rec.RR()
		key := rrsetKey{normalizeName(rr.Name), rr.Type}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], rec)
	}

	var result []libdns.Record
	for _, key := range order {
		inputs := groups[key]

		var existing []apiRecord
		for _, apiRec := range zoneRecs {
			if normalizeName(recordName(apiRec)) == key.name && apiRec.Type == key.typ {
				existing = append(existing, apiRec)
			}
		}

		if len(existing) == 1 && len(inputs) == 1 {
			resp, err := p.client.updateRecord(ctx, zoneName, existing[0].ID, fromLibdns(inputs[0], zone))
			if err != nil {
				return result, fmt.Errorf("updating record %d (%s %s): %w", existing[0].ID, key.name, key.typ, err)
			}
			result = append(result, resp.toLibdns(zoneName))
			continue
		}

		for _, e := range existing {
			if err := p.client.deleteRecord(ctx, zoneName, e.ID); err != nil {
				return result, fmt.Errorf("deleting existing record %d (%s %s): %w", e.ID, key.name, key.typ, err)
			}
		}
		for _, rec := range inputs {
			resp, err := p.client.createRecord(ctx, zoneName, fromLibdns(rec, zone))
			if err != nil {
				return result, fmt.Errorf("creating record (%s %s): %w", key.name, key.typ, err)
			}
			result = append(result, resp.toLibdns(zoneName))
		}
	}

	return result, nil
}

// DeleteRecords implements the libdns [RecordDeleter] contract: records are
// matched by (name, type, TTL, value) — with empty Type/TTL/Data acting as
// wildcards — and missing matches are silently ignored. ProviderData is
// intentionally not consulted: per the libdns spec, correctness must not
// depend on it.
//
// Hosttech's DELETE endpoint addresses records by numeric ID only, so we list
// the zone once per call and issue one DELETE per matched record.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.initClient()
	zoneName := removeTrailingDot(zone)

	zoneRecs, err := p.client.getRecords(ctx, zoneName)
	if err != nil {
		return nil, fmt.Errorf("listing zone records: %w", err)
	}

	var deleted []libdns.Record
	consumed := make(map[int]bool, len(records))

	for _, rec := range records {
		want := rec.RR()
		for _, apiRec := range zoneRecs {
			if consumed[apiRec.ID] {
				continue
			}
			if !matchesRR(apiRec, want, zoneName) {
				continue
			}
			if err := p.client.deleteRecord(ctx, zoneName, apiRec.ID); err != nil {
				return deleted, fmt.Errorf("deleting record %d (%s %s): %w", apiRec.ID, recordName(apiRec), apiRec.Type, err)
			}
			consumed[apiRec.ID] = true
			deleted = append(deleted, apiRec.toLibdns(zoneName))
		}
	}

	return deleted, nil
}

// ListZones lists all available DNS zones.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	p.initClient()

	zones, err := p.client.listZones(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]libdns.Zone, 0, len(zones))
	for _, z := range zones {
		result = append(result, z.toLibdns())
	}
	return result, nil
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
