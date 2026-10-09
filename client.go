// SPDX-License-Identifier: MIT

package hosttech

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const apiBaseURL = "https://api.ns1.hosttech.eu/api/user/v1"

// APIError represents an error response from the hosttech API.
type APIError struct {
	StatusCode int
	Message    string
	Errors     map[string][]string
}

func (e APIError) Error() string {
	message := fmt.Sprintf("hosttech API error %d", e.StatusCode)
	if e.Message != "" {
		message += ": " + e.Message
	}
	parts := make([]string, 1, len(e.Errors)+1)
	parts[0] = message
	for _, field := range slices.Sorted(maps.Keys(e.Errors)) {
		parts = append(parts, field+": "+strings.Join(e.Errors[field], ", "))
	}
	return strings.Join(parts, "; ")
}

// client handles HTTP communication with the hosttech DNS API.
type client struct {
	apiToken   string
	httpClient *http.Client
}

func newClient(apiToken string) *client {
	return &client{
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *client) listZones(ctx context.Context) ([]apiZone, error) {
	var resp apiResponse[[]apiZone]
	if err := c.doJSON(ctx, http.MethodGet, "/zones", nil, &resp); err != nil {
		return nil, fmt.Errorf("listing zones: %w", err)
	}
	return resp.Data, nil
}

func (c *client) getRecords(ctx context.Context, zone string) ([]apiRecord, error) {
	var resp apiResponse[[]apiRecord]
	path := fmt.Sprintf("/zones/%s/records", url.PathEscape(zone))
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("getting zone records: %w", err)
	}
	return resp.Data, nil
}

func (c *client) createRecord(ctx context.Context, zone string, rec *apiRecord) (apiRecord, error) {
	body, err := recordBody(rec, true)
	if err != nil {
		return apiRecord{}, err
	}
	var resp apiResponse[apiRecord]
	path := fmt.Sprintf("/zones/%s/records", url.PathEscape(zone))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return apiRecord{}, fmt.Errorf("creating %s record %q: %w", c.redact(rec.Type), c.redact(recordName(rec)), err)
	}
	return resp.Data, nil
}

func (c *client) updateRecord(ctx context.Context, zone string, recordID int, rec *apiRecord) (apiRecord, error) {
	body, err := recordBody(rec, false)
	if err != nil {
		return apiRecord{}, err
	}
	var resp apiResponse[apiRecord]
	path := fmt.Sprintf("/zones/%s/records/%s", url.PathEscape(zone), url.PathEscape(strconv.Itoa(recordID)))
	if err := c.doJSON(ctx, http.MethodPut, path, body, &resp); err != nil {
		return apiRecord{}, fmt.Errorf("updating %s record %q (ID %d): %w",
			c.redact(rec.Type), c.redact(recordName(rec)), recordID, err)
	}
	return resp.Data, nil
}

func (c *client) deleteRecord(ctx context.Context, zone string, recordID int) error {
	path := fmt.Sprintf("/zones/%s/records/%s", url.PathEscape(zone), url.PathEscape(strconv.Itoa(recordID)))
	if err := c.doJSON(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("deleting record %d in zone %s: %w", recordID, zone, err)
	}
	return nil
}

// doJSON executes an API request and optionally decodes the JSON response.
func (c *client) doJSON(ctx context.Context, method, path string, body, result any) error {
	req, err := c.request(ctx, method, path, body)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return operationError{operation: "request canceled", cause: err, token: c.apiToken}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return requestOutcome(method, operationError{operation: "hosttech request failed", cause: err, token: c.apiToken})
	}
	data, bodyErr := c.readResponse(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := c.apiError(resp.StatusCode, data)
		return errors.Join(apiErr, bodyErr)
	}
	if bodyErr != nil {
		return requestOutcome(method, bodyErr)
	}
	if err := c.decodeResponse(method, resp.StatusCode, data, result); err != nil {
		return requestOutcome(method, err)
	}
	return nil
}
