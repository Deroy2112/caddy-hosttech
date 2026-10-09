// SPDX-License-Identifier: MIT

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
		result = append(result, rec.toLibdns())
	}
	return result, nil
}

// AppendRecords adds records to the zone and returns the created records.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	mapped, err := prepareRecords(records)
	if err != nil {
		return nil, err
	}
	p.initClient()

	zoneName := removeTrailingDot(zone)
	var created []libdns.Record

	for i := range mapped {
		apiRec := mapped[i]
		resp, err := p.client.createRecord(ctx, zoneName, apiRec)
		if err != nil {
			return created, err
		}
		created = append(created, resp.toLibdns())
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
	mapped, err := prepareRecords(records)
	if err != nil {
		return nil, err
	}
	p.initClient()
	zoneName := removeTrailingDot(zone)

	zoneRecs, err := p.client.getRecords(ctx, zoneName)
	if err != nil {
		return nil, fmt.Errorf("listing zone records: %w", err)
	}

	type rrsetKey struct{ name, typ string }
	groups := make(map[rrsetKey][]apiRecord)
	order := make([]rrsetKey, 0)
	for i := range mapped {
		rec := mapped[i]
		key := rrsetKey{normalizeName(recordName(&rec)), rec.Type}
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
			if normalizeName(recordName(&apiRec)) == key.name && apiRec.Type == key.typ {
				existing = append(existing, apiRec)
			}
		}

		if len(existing) == 1 && len(inputs) == 1 {
			resp, err := p.client.updateRecord(ctx, zoneName, existing[0].ID, inputs[0])
			if err != nil {
				return result, fmt.Errorf("updating record %d (%s %s): %w", existing[0].ID, key.name, key.typ, err)
			}
			result = append(result, resp.toLibdns())
			continue
		}

		for _, e := range existing {
			if err := p.client.deleteRecord(ctx, zoneName, e.ID); err != nil {
				return result, fmt.Errorf("deleting existing record %d (%s %s): %w", e.ID, key.name, key.typ, err)
			}
		}
		for _, rec := range inputs {
			resp, err := p.client.createRecord(ctx, zoneName, rec)
			if err != nil {
				return result, fmt.Errorf("creating record (%s %s): %w", key.name, key.typ, err)
			}
			result = append(result, resp.toLibdns())
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
	filters, err := prepareFilters(records)
	if err != nil {
		return nil, err
	}
	p.initClient()
	zoneName := removeTrailingDot(zone)
	zoneRecs, err := p.client.getRecords(ctx, zoneName)
	if err != nil {
		return nil, fmt.Errorf("listing zone records: %w", err)
	}
	var deleted []libdns.Record
	consumed := make(map[int]bool)
	for i := range filters {
		for j := range zoneRecs {
			rec := &zoneRecs[j]
			if consumed[rec.ID] || !matchesRR(rec, &filters[i]) {
				continue
			}
			err := p.client.deleteRecord(ctx, zoneName, rec.ID)
			consumed[rec.ID] = true
			if missingRecord(err) {
				continue
			}
			if err != nil {
				return deleted, fmt.Errorf("deleting record %d: %w", rec.ID, err)
			}
			deleted = append(deleted, rec.toLibdns())
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
