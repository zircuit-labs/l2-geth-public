package exp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	native_prometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/zircuit-labs/l2-geth/metrics"
)

func TestCombinedPrometheusHandler(t *testing.T) {
	// Enable geth metrics
	metrics.Enable()

	// Register a geth metric
	gethCounter := metrics.NewRegisteredCounter("test/geth/counter", metrics.DefaultRegistry)
	gethCounter.Inc(42)

	// Register a native prometheus metric (like SLS does)
	slsCounter := native_prometheus.NewCounterVec(
		native_prometheus.CounterOpts{
			Name: "sls_test_counter",
			Help: "A test counter for SLS metrics",
		},
		[]string{"label"},
	)
	native_prometheus.MustRegister(slsCounter)
	slsCounter.WithLabelValues("test_value").Add(123)

	// Clean up after test
	defer func() {
		native_prometheus.Unregister(slsCounter)
	}()

	// Create the combined handler
	handler := combinedPrometheusHandler(metrics.DefaultRegistry)

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/debug/metrics/prometheus", nil)
	rec := httptest.NewRecorder()

	// Serve the request
	handler.ServeHTTP(rec, req)

	// Check response
	resp := rec.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)

	// Verify geth metric is present
	if !strings.Contains(bodyStr, "test_geth_counter") {
		t.Errorf("Expected geth metric 'test_geth_counter' in response, got:\n%s", bodyStr)
	}

	// Verify native prometheus metric (SLS) is present
	if !strings.Contains(bodyStr, "sls_test_counter") {
		t.Errorf("Expected native prometheus metric 'sls_test_counter' in response, got:\n%s", bodyStr)
	}

	// Verify no binary/gzip garbage (should be plain text)
	if strings.Contains(bodyStr, "\x1f\x8b") { // gzip magic bytes
		t.Error("Response contains gzip compressed data, expected plain text")
	}

	// Verify content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("Expected Content-Type 'text/plain', got: %s", contentType)
	}

	t.Logf("Response body:\n%s", bodyStr)
}

// TestCombinedPrometheusHandlerNoCompression verifies that compression is disabled
func TestCombinedPrometheusHandlerNoCompression(t *testing.T) {
	metrics.Enable()

	handler := combinedPrometheusHandler(metrics.DefaultRegistry)

	// Create request with Accept-Encoding: gzip (which would trigger compression if enabled)
	req := httptest.NewRequest(http.MethodGet, "/debug/metrics/prometheus", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Verify response is NOT gzip compressed (no gzip magic bytes)
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		t.Error("Response is gzip compressed, but compression should be disabled")
	}

	// Verify it's readable text
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "TYPE") && !strings.Contains(bodyStr, "gauge") {
		t.Logf("Response might not contain expected prometheus format:\n%s", bodyStr)
	}
}
