// SPDX-License-Identifier: MIT

package hosttech

import (
	"context"
	"fmt"

	"github.com/libdns/libdns"
)

type (
	rrsetKey struct{ name, typ string }
	setGroup struct {
		inputs   []int
		existing []*apiRecord
	}
	setUpdate struct{ id, index int }
	setWork   struct {
		desired          []*apiRecord
		result           []libdns.Record
		updates          []setUpdate
		creates, deletes []int
	}
)

func recordKey(r *apiRecord) rrsetKey { return rrsetKey{name: recordName(r), typ: r.Type} }
func sameMember(a, b *apiRecord) bool { return a.TTL == b.TTL && sameValue(a, b) }

func uniqueInputs(records []apiRecord) []*apiRecord {
	result := make([]*apiRecord, 0, len(records))
	for i := range records {
		rec := &records[i]
		duplicate := false
		for _, prev := range result {
			if recordKey(prev) == recordKey(rec) && sameMember(prev, rec) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, rec)
		}
	}
	return result
}

func planSet(inputs, existing []apiRecord) *setWork {
	desired := uniqueInputs(inputs)
	w := &setWork{desired: desired, result: make([]libdns.Record, len(desired))}
	groups := make(map[rrsetKey]*setGroup)
	order := make([]rrsetKey, 0)
	for i, rec := range desired {
		key := recordKey(rec)
		if groups[key] == nil {
			groups[key] = &setGroup{}
			order = append(order, key)
		}
		groups[key].inputs = append(groups[key].inputs, i)
	}
	for i := range existing {
		rec := &existing[i]
		if group := groups[recordKey(rec)]; group != nil {
			group.existing = append(group.existing, rec)
		}
	}
	for _, key := range order {
		w.planGroup(groups[key])
	}
	return w
}

func matchingMember(want *apiRecord, existing []*apiRecord, used []bool) int {
	for i, rec := range existing {
		if !used[i] && sameMember(rec, want) {
			return i
		}
	}
	return -1
}

func (w *setWork) planGroup(group *setGroup) {
	used := make([]bool, len(group.existing))
	pending := make([]int, 0, len(group.inputs))
	for _, index := range group.inputs {
		matched := matchingMember(w.desired[index], group.existing, used)
		if matched < 0 {
			pending = append(pending, index)
			continue
		}
		used[matched] = true
		w.result[index] = group.existing[matched].toLibdns()
	}
	remaining := make([]*apiRecord, 0, len(group.existing))
	for i, rec := range group.existing {
		if !used[i] {
			remaining = append(remaining, rec)
		}
	}
	for i, index := range pending {
		if i < len(remaining) {
			w.updates = append(w.updates, setUpdate{id: remaining[i].ID, index: index})
		} else {
			w.creates = append(w.creates, index)
		}
	}
	for i := len(pending); i < len(remaining); i++ {
		w.deletes = append(w.deletes, remaining[i].ID)
	}
}

func (w *setWork) confirmed() []libdns.Record {
	result := make([]libdns.Record, 0, len(w.result))
	for _, rec := range w.result {
		if rec != nil {
			result = append(result, rec)
		}
	}
	return result
}

func (w *setWork) apply(ctx context.Context, c *client, zone string) ([]libdns.Record, error) {
	if err := w.update(ctx, c, zone); err != nil {
		return w.confirmed(), err
	}
	if err := w.create(ctx, c, zone); err != nil {
		return w.confirmed(), err
	}
	for _, id := range w.deletes {
		if err := ctx.Err(); err != nil {
			return w.confirmed(), fmt.Errorf("setting records: %w", err)
		}
		if err := c.deleteRecord(ctx, zone, id); err != nil && !missingRecord(err) {
			return w.confirmed(), err
		}
	}
	return w.confirmed(), nil
}

func (w *setWork) update(ctx context.Context, c *client, zone string) error {
	for _, job := range w.updates {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("setting records: %w", err)
		}
		rec, err := c.updateRecord(ctx, zone, job.id, w.desired[job.index])
		if err != nil {
			return err
		}
		w.result[job.index] = rec.toLibdns()
	}
	return nil
}

func (w *setWork) create(ctx context.Context, c *client, zone string) error {
	for _, index := range w.creates {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("setting records: %w", err)
		}
		rec, err := c.createRecord(ctx, zone, w.desired[index])
		if err != nil {
			return err
		}
		w.result[index] = rec.toLibdns()
	}
	return nil
}
