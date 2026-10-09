// SPDX-License-Identifier: MIT

package hosttech

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxResponseBytes = 10 * 1024 * 1024

type operationError struct {
	operation string
	cause     error
	token     string
}

func (e operationError) Error() string {
	return e.operation + ": " + redactToken(e.cause.Error(), e.token)
}
func (e operationError) Unwrap() error { return e.cause }

type responseBodyError struct {
	operation string
	cause     error
	token     string
}

func (e responseBodyError) Error() string {
	return e.operation + ": " + redactToken(e.cause.Error(), e.token)
}
func (e responseBodyError) Unwrap() error { return e.cause }

type bodyLimitError struct{}

func (bodyLimitError) Error() string {
	return fmt.Sprintf("hosttech response exceeds %d bytes", maxResponseBytes)
}

func (c *client) request(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, operationError{operation: "encoding hosttech request", cause: err, token: c.apiToken}
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBaseURL+path, reader)
	if err != nil {
		return nil, operationError{operation: "creating hosttech request", cause: err, token: c.apiToken}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *client) readResponse(resp *http.Response) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	closeErr := resp.Body.Close()
	var bodyErr error
	if readErr != nil {
		bodyErr = responseBodyError{operation: "reading hosttech response body", cause: readErr, token: c.apiToken}
	}
	if len(data) > maxResponseBytes {
		bodyErr = errors.Join(bodyErr, bodyLimitError{})
	}
	if closeErr != nil {
		bodyErr = errors.Join(bodyErr, responseBodyError{
			operation: "closing hosttech response body", cause: closeErr, token: c.apiToken,
		})
	}
	return data, bodyErr
}

func (c *client) decodeResponse(method string, status int, data []byte, result any) error {
	if method == http.MethodDelete {
		if status != http.StatusNoContent || len(bytes.TrimSpace(data)) != 0 {
			return responseError{kind: "response", field: "delete response"}
		}
		return nil
	}
	if err := json.Unmarshal(data, result); err != nil {
		var invalid responseError
		if errors.As(err, &invalid) {
			return invalid
		}
		return operationError{operation: "invalid hosttech response", cause: err, token: c.apiToken}
	}
	return nil
}

func (c *client) apiError(status int, data []byte) APIError {
	err := APIError{StatusCode: status}
	var body struct {
		Message string              `json:"message"`
		Errors  map[string][]string `json:"errors"`
	}
	if decodeErr := json.Unmarshal(data, &body); decodeErr != nil {
		return err
	}
	err.Message = c.redact(body.Message)
	if body.Errors == nil {
		return err
	}
	err.Errors = make(map[string][]string, len(body.Errors))
	for key, values := range body.Errors {
		redacted := make([]string, len(values))
		for i, value := range values {
			redacted[i] = c.redact(value)
		}
		err.Errors[c.redact(key)] = redacted
	}
	return err
}

func (c *client) redact(value string) string {
	return redactToken(value, c.apiToken)
}

func redactToken(value, token string) string {
	if token == "" {
		return value
	}
	return strings.ReplaceAll(value, token, "[redacted]")
}
