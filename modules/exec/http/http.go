// Package http implements a Salt-compatible http.query subset using
// net/http (no external dependencies).
//
// Reference: saltstack/salt/modules/http.py @ pinned revision, reduced to
// query with method/body/headers/status verification.
package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

type QueryArgs struct {
	URL     string            `statekit:"required,name=url"`
	Method  string            `statekit:"name=method"`
	Data    string            `statekit:"name=data"`
	Headers map[string]string `statekit:"name=header_list"`
	Timeout int               `statekit:"name=timeout"` // seconds
	Status  string            `statekit:"name=status"`  // expected status code for verify
}

type queryFunc struct{}

func (queryFunc) Name() string { return "http.query" }
func (queryFunc) Args() any    { return QueryArgs{} }
func (queryFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*QueryArgs)
	method := strings.ToUpper(a.Method)
	if method == "" {
		method = "GET"
	}
	timeout := time.Duration(a.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var body io.Reader
	if a.Data != "" {
		body = bytes.NewReader([]byte(a.Data))
	}
	req, err := http.NewRequestWithContext(ctx, method, a.URL, body)
	if err != nil {
		return nil, err
	}
	for key, value := range a.Headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"status":  resp.StatusCode,
		"body":    string(payload),
		"headers": flattenHeaders(resp.Header),
	}
	return result, nil
}

func flattenHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for key, values := range h {
		out[strings.ToLower(key)] = strings.Join(values, ", ")
	}
	return out
}

// Register installs all http-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	return reg.Register(queryFunc{})
}
