package storage

import "errors"

// ErrNoDSN is an error returned when no DSN is provided in the configuration.
var ErrNoDSN = errors.New("no DSN provided")
