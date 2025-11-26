package slslog

import (
	"log/slog"

	"github.com/zircuit-labs/l2-geth/log"
	zkrlog "github.com/zircuit-labs/zkr-go-common/log"
)

// New creates a new SLS logger that inherits the root logger's format
// (JSON, Terminal, or Logfmt as configured via --log.format CLI flag).
// Returns a log.Logger interface compatible with l2-geth code.
//
// The adapter automatically provides rich error logging with stack traces
// when errors are logged with the "error" key.
func New() log.Logger {
	// Get the root logger's handler to inherit the format configuration
	// This maintains the same behavior as the original implementation:
	// log.New("sls", true) which returned Root().With("sls", true)
	rootHandler := log.Root().Handler()

	// Wrap the root handler with zkr-go-common's LoggableErrorHandler
	// This enables rich error logging with stack traces while maintaining
	// the root logger's output format (JSON/Terminal/Logfmt)
	enrichedHandler := zkrlog.NewLoggableErrorHandler(rootHandler)

	// Create a child logger with "sls"=true attribute
	// This is equivalent to the old: log.New("sls", true)
	sl := slog.New(enrichedHandler).With("sls", true)

	// Wrap in adapter to provide automatic rich error logging
	return NewAdapter(sl)
}

// NewWith creates a new SLS logger with additional context attributes.
func NewWith(ctx ...any) log.Logger {
	return New().With(ctx...)
}
