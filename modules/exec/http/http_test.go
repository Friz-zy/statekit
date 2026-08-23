package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryGetWithHeaders(t *testing.T) {
	var gotPath, gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHeader = r.Header.Get("X-Token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	value, err := (queryFunc{}).Execute(context.Background(), nil, &QueryArgs{
		URL:     server.URL + "/probe",
		Headers: map[string]string{"X-Token": "t0k3n"},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	res := value.(map[string]any)
	if res["status"].(int) != 201 || res["body"] != `{"ok":true}` {
		t.Fatalf("response wrong: %+v", res)
	}
	headers := res["headers"].(map[string]string)
	if headers["content-type"] != "application/json" {
		t.Fatalf("headers = %v", headers)
	}
	if gotPath != "/probe" || gotHeader != "t0k3n" {
		t.Fatalf("request not delivered: path=%q header=%q", gotPath, gotHeader)
	}
}

func TestQueryPostBodyAndMethodOverride(t *testing.T) {
	var method, body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		raw := make([]byte, r.ContentLength)
		r.Body.Read(raw)
		body = string(raw)
	}))
	defer server.Close()

	if _, err := (queryFunc{}).Execute(context.Background(), nil, &QueryArgs{
		URL: server.URL, Method: "post", Data: "payload=1",
	}); err != nil {
		t.Fatal(err)
	}
	if method != "POST" || body != "payload=1" {
		t.Fatalf("method=%q body=%q", method, body)
	}
}

func TestQueryConnectionErrorSurfaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()
	if _, err := (queryFunc{}).Execute(context.Background(), nil, &QueryArgs{URL: url}); err == nil {
		t.Fatal("connection failure must surface as error")
	}
}
