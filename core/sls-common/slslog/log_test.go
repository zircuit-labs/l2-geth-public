package slslog

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/log"
	zkrlog "github.com/zircuit-labs/zkr-go-common/log"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

var (
	sourceRegex = regexp.MustCompile(`,?"source":"[^"]+"`)
	lineRegex   = regexp.MustCompile(`"line":\d+`)
	timeRegex   = regexp.MustCompile(`"t":"[^"]+"`)
)

// newTestLogger creates a test logger with a buffer to capture output
func newTestLogger(t *testing.T) (log.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer

	// Save the original default logger to restore after test
	originalLogger := log.Root()
	t.Cleanup(func() {
		log.SetDefault(originalLogger)
	})

	// Set up logger with JSONHandler and GlogHandler
	glogger := log.NewGlogHandler(log.JSONHandler(&buf))
	glogger.Verbosity(log.LevelTrace) // Set to Trace to capture all log levels
	log.SetDefault(log.NewLogger(glogger))

	// Create logger using slslog.New() which will use the root logger we just set
	logger := New()

	return logger, &buf
}

// TestErrorLoggingContainsErrorMessage verifies that error messages appear in log output
// This test replicates the setup from the main function example to ensure error messages
// are properly logged and visible in the output
func TestErrorLoggingContainsErrorMessage(t *testing.T) {
	logger, buf := newTestLogger(t)

	originalError := errors.New("my new test error")
	wrappedError := stacktrace.Wrap(originalError)
	logger.Error("Something something wrapped something", "error", wrappedError)

	expected := `{
		"t": "2021-01-01T00:00:00Z",
		"level": "error",
		"msg": "Something something wrapped something",
		"sls": true,
		"error": "my new test error",
		"error_detail": {
			"github_com/zircuit-labs/zkr-go-common/xerrors_ExtendedError[github_com/zircuit-labs/zkr-go-common/xerrors/stacktrace_StackTrace]": [
				{
					"func": "github.com/zircuit-labs/l2-geth/core/sls-common/slslog.TestErrorLoggingContainsErrorMessage",
					"line": 0
				}
			]
		}
	}`

	actualLogJSON := strings.TrimSpace(buf.String())
	cleanedActual := comparableLog(actualLogJSON)
	assert.JSONEq(t, expected, cleanedActual)
}

func TestNewReturnsLoggerInterface(t *testing.T) {
	logger := New()
	if logger == nil {
		t.Fatal("New() returned nil")
	}

	// Verify it implements log.Logger
	var _ log.Logger = logger
}

func TestNewUsesZKRLogger(t *testing.T) {
	// Capture the output by redirecting stderr
	// (zkr-go-common logger writes to stdout by default)
	logger := New()

	// The logger should be wrapped in an adapter
	adapter, ok := logger.(*slogAdapter)
	if !ok {
		t.Fatal("New() should return a slogAdapter")
	}

	if adapter.inner == nil {
		t.Fatal("adapter should have an inner slog.Logger")
	}
}

func TestNewWithAddsContext(t *testing.T) {
	logger := NewWith("component", "test-component", "version", "1.0")

	// Verify it's a valid logger
	if logger == nil {
		t.Fatal("NewWith() returned nil")
	}

	// The logger should be wrapped in an adapter
	adapter, ok := logger.(*slogAdapter)
	if !ok {
		t.Fatal("NewWith() should return a slogAdapter")
	}

	if adapter.inner == nil {
		t.Fatal("adapter should have an inner slog.Logger")
	}
}

func TestNewLogsWithServiceName(t *testing.T) {
	logger, buf := newTestLogger(t)

	// Use the logger's With to add more context
	testLogger := logger.With("test", "value")

	// Verify methods exist and don't panic, and check output
	testLogger.Info("test message")
	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Error("Info message not logged")
	}
	buf.Reset()

	testLogger.Debug("debug message")
	output = buf.String()
	if !strings.Contains(output, "debug message") {
		t.Error("Debug message not logged")
	}
	buf.Reset()

	testLogger.Warn("warn message")
	output = buf.String()
	if !strings.Contains(output, "warn message") {
		t.Error("Warn message not logged")
	}
	buf.Reset()

	testLogger.Error("error message")
	output = buf.String()
	if !strings.Contains(output, "error message") {
		t.Error("Error message not logged")
	}
}

func TestNewCompatibleWithExistingCode(t *testing.T) {
	// This test verifies that the new implementation is compatible
	// with how SLS components use the logger
	logger, buf := newTestLogger(t)

	// Test case 1: slslog.New()
	logger.Info("info message", "key", "value")
	output := buf.String()
	if !strings.Contains(output, "info message") {
		t.Error("Info message not logged")
	}
	buf.Reset()

	// Test case 2: slslog.NewWith()
	logger2 := NewWith("detector", "hypernative")
	logger2.Info("detector message")
	output = buf.String()
	if !strings.Contains(output, "detector message") {
		t.Error("Detector message not logged")
	}
	buf.Reset()

	// Test case 3: Chaining .With()
	logger3 := New().With("component", "test").With("id", 123)
	logger3.Debug("chained context")
	output = buf.String()
	if !strings.Contains(output, "chained context") {
		t.Error("Chained context message not logged")
	}
	buf.Reset()

	// Test case 4: All log levels
	logger4 := New()
	logger4.Trace("trace")
	output = buf.String()
	if !strings.Contains(output, "trace") {
		t.Error("Trace message not logged")
	}
	buf.Reset()

	logger4.Debug("debug")
	output = buf.String()
	if !strings.Contains(output, "debug") {
		t.Error("Debug message not logged")
	}
	buf.Reset()

	logger4.Info("info")
	output = buf.String()
	if !strings.Contains(output, "info") {
		t.Error("Info message not logged")
	}
	buf.Reset()

	logger4.Warn("warn")
	output = buf.String()
	if !strings.Contains(output, "warn") {
		t.Error("Warn message not logged")
	}
	buf.Reset()

	logger4.Error("error")
	output = buf.String()
	if !strings.Contains(output, "error") {
		t.Error("Error message not logged")
	}
	// Skip Crit test as it calls os.Exit(1)

	// If we got here without panicking, the logger is compatible
}

// TestLoggerOutputFormat verifies the JSON structure when using zkr-go-common
func TestLoggerOutputFormat(t *testing.T) {
	logger, buf := newTestLogger(t)

	logger = NewWith("detector", "test-detector", "version", "v1.0.0")

	// These should produce JSON output with:
	// - service: "sls"
	// - detector: "test-detector"
	// - version: "v1.0.0"
	// - level, time, msg fields

	logger.Info("test message", "extra_key", "extra_value")
	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Error("Info message not logged")
	}
	if !strings.Contains(output, "detector") {
		t.Error("Detector attribute not in output")
	}
	if !strings.Contains(output, "test-detector") {
		t.Error("Detector value not in output")
	}
	buf.Reset()

	logger.Error("error message", "error_code", 500)
	output = buf.String()
	if !strings.Contains(output, "error message") {
		t.Error("Error message not logged")
	}

	// The output format is defined by zkr-go-common/log package
	// and should include structured JSON with service metadata
}

// TestLoggerBackwardCompatibility ensures existing SLS code patterns still work
func TestLoggerBackwardCompatibility(t *testing.T) {
	testCases := []struct {
		name string
		fn   func()
	}{
		{
			name: "detector pattern",
			fn: func() {
				logger := NewWith("detector", "hypernative")
				logger.Info("scanning transaction", "tx_hash", "0x123")
			},
		},
		{
			name: "api handler pattern",
			fn: func() {
				logger := NewWith("rpc_handler", "zirc_api")
				logger.Debug("received request", "method", "eth_call")
			},
		},
		{
			name: "component pattern",
			fn: func() {
				logger := NewWith("component", "RequestStorer")
				logger.Warn("storage full", "capacity", 1000)
			},
		},
		{
			name: "legacy pool pattern",
			fn: func() {
				logger := NewWith("module", "legacypool")
				logger.Error("transaction rejected", "reason", "nonce too low")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic
			tc.fn()
		})
	}
}

// Benchmark tests to ensure no significant performance regression
func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New()
	}
}

func BenchmarkNewWith(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewWith("key", "value")
	}
}

func BenchmarkLogging(b *testing.B) {
	logger := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i)
	}
}

// TestErrorLoggingWithStacktrace demonstrates logging errors wrapped with stacktrace.Wrap()
// This test shows how zkr-go-common's rich error logging works automatically with the adapter
func TestErrorLoggingWithStacktrace(t *testing.T) {
	logger, buf := newTestLogger(t)

	// Create an error and wrap it with stacktrace
	baseErr := errors.New("database connection failed")
	wrappedErr := stacktrace.Wrap(baseErr)

	// Get the underlying slog.Logger to use ErrAttr for rich error logging
	adapter, ok := logger.(*slogAdapter)
	if !ok {
		t.Fatal("Expected logger to be a slogAdapter")
	}

	// Method 1: Direct use of ErrAttr (advanced usage)
	adapter.inner.Error("operation failed", zkrlog.ErrAttr(wrappedErr), "operation", "db_query", "retry_count", 3)
	output := buf.String()
	if !strings.Contains(output, "operation failed") {
		t.Error("Error message not logged")
	}
	if !strings.Contains(output, "database connection failed") {
		t.Error("Error message not in output")
	}
	buf.Reset()

	// Method 2: Automatic rich error logging via adapter
	// The adapter automatically detects "error" key and converts to ErrAttr!
	logger.Error("operation failed (via adapter)", "error", wrappedErr, "operation", "db_query")
	output = buf.String()
	if !strings.Contains(output, "operation failed (via adapter)") {
		t.Error("Adapter error message not logged")
	}
	if !strings.Contains(output, "database connection failed") {
		t.Error("Error message not in adapter output")
	}
}

// TestErrorLoggingComparison shows the difference between standard and rich error logging
func TestErrorLoggingComparison(t *testing.T) {
	logger, buf := newTestLogger(t)
	adapter, ok := logger.(*slogAdapter)
	if !ok {
		t.Fatal("Expected logger to be a slogAdapter")
	}

	// Create a wrapped error
	err := stacktrace.Wrap(errors.New("test error"))

	t.Log("Standard logging (no stack trace):")
	logger.Error("standard error log", "error", err.Error())
	output := buf.String()
	if !strings.Contains(output, "standard error log") {
		t.Error("Standard error log not found")
	}
	if !strings.Contains(output, "test error") {
		t.Error("Error message not in standard output")
	}
	buf.Reset()

	t.Log("\nRich logging (with stack trace via ErrAttr):")
	adapter.inner.Error("rich error log", zkrlog.ErrAttr(err))
	output = buf.String()
	if !strings.Contains(output, "rich error log") {
		t.Error("Rich error log not found")
	}
	if !strings.Contains(output, "test error") {
		t.Error("Error message not in rich output")
	}

	// Note: The rich logging output will include an "error_detail" field with stack trace
	// information in JSON format, showing the call stack where the error was wrapped
}

// TestErrorLoggingWithErrKey tests that the adapter handles both "error" and "err" keys
func TestErrorLoggingWithErrKey(t *testing.T) {
	logger, buf := newTestLogger(t)

	// Create a wrapped error
	wrappedErr := stacktrace.Wrap(errors.New("test error with err key"))

	// Test with "err" key (commonly used in the codebase)
	logger.Error("test with err key", "err", wrappedErr, "component", "DetectorRegistry")
	output := buf.String()
	if !strings.Contains(output, "test with err key") {
		t.Error("Message with err key not logged")
	}
	if !strings.Contains(output, "test error with err key") {
		t.Error("Error message not in output")
	}
	if !strings.Contains(output, "error_detail") {
		t.Error("error_detail not found - err key not converted to ErrAttr")
	}
	buf.Reset()

	// Test with "error" key
	logger.Error("test with error key", "error", wrappedErr, "component", "DetectorRegistry")
	output = buf.String()
	if !strings.Contains(output, "test with error key") {
		t.Error("Message with error key not logged")
	}
	if !strings.Contains(output, "test error with err key") {
		t.Error("Error message not in output")
	}
	if !strings.Contains(output, "error_detail") {
		t.Error("error_detail not found - error key not converted to ErrAttr")
	}

	// Both should produce rich error logging with error_detail
}

// TestErrorKeyVariations tests that the adapter handles different error key variations
func TestErrorKeyVariations(t *testing.T) {
	logger, buf := newTestLogger(t)

	// Create a wrapped error
	wrappedErr := stacktrace.Wrap(errors.New("test error"))

	testCases := []struct {
		name string
		key  string
	}{
		{"lowercase err", "err"},
		{"lowercase error", "error"},
		{"uppercase ERR", "ERR"},
		{"uppercase ERROR", "ERROR"},
		{"mixed case Err", "Err"},
		{"mixed case Error", "Error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()

			// Log with the test key
			logger.Error("test message", tc.key, wrappedErr)
			output := buf.String()

			if !strings.Contains(output, "test message") {
				t.Errorf("Message not logged for key %q", tc.key)
			}
			if !strings.Contains(output, "test error") {
				t.Errorf("Error message not in output for key %q", tc.key)
			}
			if !strings.Contains(output, "error_detail") {
				t.Errorf("error_detail not found for key %q - not converted to ErrAttr", tc.key)
			}
		})
	}
}

func comparableLog(s string) string {
	s = normalizeTime(s)
	s = removeStackSourceFields(s)
	s = removeStackLineNumbers(s)
	return strings.TrimSpace(s)
}

func removeStackSourceFields(log string) string {
	return sourceRegex.ReplaceAllString(log, "")
}

func removeStackLineNumbers(log string) string {
	return lineRegex.ReplaceAllString(log, `"line":0`)
}

func normalizeTime(log string) string {
	return timeRegex.ReplaceAllString(log, `"t":"2021-01-01T00:00:00Z"`)
}
