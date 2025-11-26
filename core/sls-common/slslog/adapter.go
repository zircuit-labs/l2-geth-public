package slslog

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/zircuit-labs/l2-geth/log"
	zkrlog "github.com/zircuit-labs/zkr-go-common/log"
)

// slogAdapter wraps a *slog.Logger to implement the log.Logger interface.
// This allows us to use zkr-go-common's logger while maintaining compatibility
// with l2-geth's Logger interface.
type slogAdapter struct {
	inner *slog.Logger
}

// NewAdapter creates a log.Logger adapter around a *slog.Logger
func NewAdapter(sl *slog.Logger) log.Logger {
	return &slogAdapter{inner: sl}
}

// convertErrorsToAttrs scans through key-value pairs and converts any error values
// to use zkrlog.ErrAttr() for rich error logging with stack traces.
func convertErrorsToAttrs(attrs ...any) []any {
	if len(attrs) == 0 {
		return attrs
	}

	// Scan through pairs looking for errors
	result := make([]any, 0, len(attrs))
	for i := 0; i < len(attrs); i++ {
		// Check if we have a next element to form a key-value pair
		if i+1 >= len(attrs) {
			// No more pairs, just append the remaining item
			result = append(result, attrs[i])
			break
		}

		key := attrs[i]
		value := attrs[i+1]

		// Check if this is an error-related key with an error value
		// Catches: "error", "err", "Err", "ERROR", etc.
		if keyStr, ok := key.(string); ok && strings.HasPrefix(strings.ToLower(keyStr), "err") {
			if err, ok := value.(error); ok && err != nil {
				// Replace key-value pair with zkrlog.ErrAttr for rich error logging
				// ErrAttr returns a slog.Attr which wraps the error in LoggableError
				// The slog.Attr can be passed directly as an argument
				result = append(result, zkrlog.ErrAttr(err))
				i++ // Skip the value since we consumed it
				continue
			}
		}

		// Not an error key-value pair, append both key and value
		result = append(result, key, value)
		i++ // Skip value since we just appended it
	}

	return result
}

// With returns a new Logger that has this logger's attributes plus the given attributes
func (a *slogAdapter) With(ctx ...any) log.Logger {
	return &slogAdapter{inner: a.inner.With(ctx...)}
}

// New returns a new Logger that has this logger's attributes plus the given attributes.
// Identical to 'With'.
func (a *slogAdapter) New(ctx ...any) log.Logger {
	return a.With(ctx...)
}

// Log logs a message at the specified level with context key/value pairs
func (a *slogAdapter) Log(level slog.Level, msg string, ctx ...any) {
	a.Write(level, msg, ctx...)
}

// Trace logs a message at the trace level with context key/value pairs.
// Note: slog doesn't have a native Trace level, so we map it to Debug with level -8
func (a *slogAdapter) Trace(msg string, ctx ...any) {
	// Map to l2-geth's LevelTrace (-8)
	ctx = convertErrorsToAttrs(ctx...)
	a.inner.Log(context.Background(), log.LevelTrace, msg, ctx...)
}

// Debug logs a message at the debug level with context key/value pairs
func (a *slogAdapter) Debug(msg string, ctx ...any) {
	ctx = convertErrorsToAttrs(ctx...)
	a.inner.Debug(msg, ctx...)
}

// Info logs a message at the info level with context key/value pairs
func (a *slogAdapter) Info(msg string, ctx ...any) {
	ctx = convertErrorsToAttrs(ctx...)
	a.inner.Info(msg, ctx...)
}

// Warn logs a message at the warn level with context key/value pairs
func (a *slogAdapter) Warn(msg string, ctx ...any) {
	ctx = convertErrorsToAttrs(ctx...)
	a.inner.Warn(msg, ctx...)
}

// Error logs a message at the error level with context key/value pairs
func (a *slogAdapter) Error(msg string, ctx ...any) {
	ctx = convertErrorsToAttrs(ctx...)
	a.inner.Error(msg, ctx...)
}

// Crit logs a message at the crit level with context key/value pairs, and exits.
// Note: slog doesn't have a native Crit level, so we map it to Error at level 12 and exit
func (a *slogAdapter) Crit(msg string, ctx ...any) {
	// Map to l2-geth's LevelCrit (12)
	ctx = convertErrorsToAttrs(ctx...)
	a.inner.Log(context.Background(), log.LevelCrit, msg, ctx...)
	os.Exit(1)
}

// Write logs a message at the specified level
func (a *slogAdapter) Write(level slog.Level, msg string, attrs ...any) {
	if !a.inner.Enabled(context.Background(), level) {
		return
	}
	attrs = convertErrorsToAttrs(attrs...)
	a.inner.Log(context.Background(), level, msg, attrs...)
}

// Enabled reports whether l emits log records at the given context and level.
func (a *slogAdapter) Enabled(ctx context.Context, level slog.Level) bool {
	return a.inner.Enabled(ctx, level)
}

// Handler returns the underlying handler of the inner logger.
func (a *slogAdapter) Handler() slog.Handler {
	return a.inner.Handler()
}
