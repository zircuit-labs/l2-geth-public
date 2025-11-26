package slslog

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/zircuit-labs/l2-geth/log"
)

func TestAdapterImplementsLoggerInterface(t *testing.T) {
	// Verify that slogAdapter implements log.Logger interface
	var buf bytes.Buffer
	sl := slog.New(slog.NewJSONHandler(&buf, nil))
	var _ log.Logger = NewAdapter(sl)
}

func TestAdapterBasicLogging(t *testing.T) {
	var buf bytes.Buffer
	// Set level to LevelTrace to capture all log levels including trace
	sl := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: log.LevelTrace, // -8, lower than Debug
	}))
	logger := NewAdapter(sl)

	// Test Info
	logger.Info("test info", "key", "value")
	if !bytes.Contains(buf.Bytes(), []byte("test info")) {
		t.Error("Info message not logged")
	}
	if !bytes.Contains(buf.Bytes(), []byte("key")) {
		t.Error("Info attributes not logged")
	}
	buf.Reset()

	// Test Debug
	logger.Debug("test debug")
	if !bytes.Contains(buf.Bytes(), []byte("test debug")) {
		t.Error("Debug message not logged")
	}
	buf.Reset()

	// Test Warn
	logger.Warn("test warn")
	if !bytes.Contains(buf.Bytes(), []byte("test warn")) {
		t.Error("Warn message not logged")
	}
	buf.Reset()

	// Test Error
	logger.Error("test error")
	if !bytes.Contains(buf.Bytes(), []byte("test error")) {
		t.Error("Error message not logged")
	}
	buf.Reset()

	// Test Trace
	logger.Trace("test trace")
	if !bytes.Contains(buf.Bytes(), []byte("test trace")) {
		t.Error("Trace message not logged")
	}
}

func TestAdapterWith(t *testing.T) {
	var buf bytes.Buffer
	sl := slog.New(slog.NewJSONHandler(&buf, nil))
	logger := NewAdapter(sl)

	// Test With returns a new logger with additional context
	logger2 := logger.With("component", "detector")
	logger2.Info("test message")

	if !bytes.Contains(buf.Bytes(), []byte("component")) {
		t.Error("With attributes not added")
	}
	if !bytes.Contains(buf.Bytes(), []byte("detector")) {
		t.Error("With attribute value not added")
	}
}

func TestAdapterNew(t *testing.T) {
	var buf bytes.Buffer
	sl := slog.New(slog.NewJSONHandler(&buf, nil))
	logger := NewAdapter(sl)

	// Test New (alias for With)
	logger2 := logger.New("key", "val")
	logger2.Info("test")

	if !bytes.Contains(buf.Bytes(), []byte("key")) {
		t.Error("New attributes not added")
	}
}

func TestAdapterEnabled(t *testing.T) {
	var buf bytes.Buffer
	sl := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	logger := NewAdapter(sl)

	// Info should be enabled
	if !logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info level should be enabled")
	}

	// Debug should not be enabled (level is set to Info)
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Debug level should not be enabled when level is Info")
	}
}

func TestAdapterHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	sl := slog.New(handler)
	logger := NewAdapter(sl)

	// Should return the underlying handler
	if logger.Handler() != handler {
		t.Error("Handler() should return the underlying handler")
	}
}
