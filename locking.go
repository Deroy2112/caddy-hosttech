// SPDX-License-Identifier: MIT

package hosttech

import (
	"context"
	"fmt"
	"strings"
)

func (p *Provider) lockZone(ctx context.Context, zone string) (func(), error) {
	if ctx == nil {
		return nil, inputError{field: "context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("waiting for zone write: %w", err)
	}
	key := strings.ToLower(removeTrailingDot(zone))
	p.mu.Lock()
	if p.zones == nil {
		p.zones = make(map[string]chan struct{})
	}
	lock := p.zones[key]
	if lock == nil {
		lock = make(chan struct{}, 1)
		p.zones[key] = lock
	}
	p.mu.Unlock()
	select {
	case lock <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-lock
			return nil, fmt.Errorf("waiting for zone write: %w", err)
		}
		return func() { <-lock }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for zone write: %w", ctx.Err())
	}
}
