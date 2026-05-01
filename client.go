// SPDX-License-Identifier: Apache-2.0

package hosttech

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const apiBaseURL = "https://api.ns1.hosttech.eu/api/user/v1"

// APIError represents an error response from the hosttech API.
type APIError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e APIError) Error() string {
	return fmt.Sprintf("hosttech API error %s: %s", e.Status, e.Body)
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
			Timeout: 30 * time.Second,
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
	path := fmt.Sprintf("/zones/%s/records", zone)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("getting records for zone %s: %w", zone, err)
	}
	return resp.Data, nil
}

func (c *client) createRecord(ctx context.Context, zone string, rec apiRecord) (apiRecord, error) {
	var resp apiResponse[apiRecord]
	path := fmt.Sprintf("/zones/%s/records", zone)
	if err := c.doJSON(ctx, http.MethodPost, path, rec, &resp); err != nil {
		return apiRecord{}, fmt.Errorf("creating record in zone %s: %w", zone, err)
	}
	return resp.Data, nil
}

func (c *client) updateRecord(ctx context.Context, zone string, recordID int, rec apiRecord) (apiRecord, error) {
	var resp apiResponse[apiRecord]
	path := fmt.Sprintf("/zones/%s/records/%d", zone, recordID)
	if err := c.doJSON(ctx, http.MethodPut, path, rec, &resp); err != nil {
		return apiRecord{}, fmt.Errorf("updating record %d in zone %s: %w", recordID, zone, err)
	}
	return resp.Data, nil
}

func (c *client) deleteRecord(ctx context.Context, zone string, recordID int) error {
	path := fmt.Sprintf("/zones/%s/records/%d", zone, recordID)
	if err := c.doJSON(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("deleting record %d in zone %s: %w", recordID, zone, err)
	}
	return nil
}

// doJSON executes an API request and optionally decodes the JSON response.
func (c *client) doJSON(ctx context.Context, method, path string, body any, result any) error {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshalling request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, apiBaseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return APIError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       string(respBody),
		}
	}

	if result != nil {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}
