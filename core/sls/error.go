package sls

import "fmt"

// Error struct defines a custom error type for detector errors,
// including the detector's name, the error, and the transaction hash.
type Error struct {
	DetectorName string
	Err          error
	TxHash       string
}

// NewError creates a new instance of Error with the specified details.
func NewError(detectorName string, err error, txHash string) *Error {
	return &Error{DetectorName: detectorName, Err: err, TxHash: txHash}
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("%s detector error (tx hash: %s): %v", e.DetectorName, e.TxHash, e.Err)
}
