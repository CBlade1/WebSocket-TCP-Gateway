package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseConfig() config {
	return config{Listen: []string{"127.0.0.1:2052"}, Routes: []route{{Name: "service", Path: "/ws/service", Target: "127.0.0.1:2828"}}, AllowedHosts: []string{"localhost:2052"}}
}
func TestConfig(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config)
		valid  bool
	}{
		{"valid", func(*config) {}, true},
		{"no routes", func(c *config) { c.Routes = nil }, false},
		{"remote target", func(c *config) { c.Routes[0].Target = "8.8.8.8:53" }, false},
		{"non-ip target", func(c *config) { c.Routes[0].Target = "localhost:2828" }, false},
		{"reserved path", func(c *config) { c.Routes[0].Path = "/healthz" }, false},
		{"invalid limit", func(c *config) { c.MaxMessageBytes = -1 }, false},
		{"requires CIDRs", func(c *config) { c.RequireTrustedProxy = true }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseConfig()
			tc.mutate(&c)
			_, err := newGateway(c)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
func TestHealth(t *testing.T) {
	g, err := newGateway(baseConfig())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost:2052/healthz", nil)
	out := httptest.NewRecorder()
	g.handler().ServeHTTP(out, req)
	if out.Code != 200 || out.Body.String() != "ok\n" {
		t.Fatalf("status=%d body=%q", out.Code, out.Body.String())
	}
}
func TestLoadRejectsUnknownFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(file, []byte(`{"listen":["127.0.0.1:2052"],"routes":[],"unused":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(file)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unexpected error: %v", err)
	}
}
func TestOriginAndHost(t *testing.T) {
	c := baseConfig()
	c.AllowedOrigins = []string{"https://example.com"}
	g, err := newGateway(c)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost:2052/ws/service", nil)
	req.Header.Set("Origin", "https://other.example")
	if g.originAllowed(req) {
		t.Fatal("unlisted Origin accepted")
	}
	req.Header.Set("Origin", "https://example.com")
	if !g.originAllowed(req) {
		t.Fatal("listed Origin denied")
	}
	if g.permittedHost("wrong.example") {
		t.Fatal("unlisted Host accepted")
	}
}
