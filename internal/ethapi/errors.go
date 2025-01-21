// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"fmt"

	"github.com/zircuit-labs/l2-geth-public/accounts/abi"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
	"github.com/zircuit-labs/l2-geth-public/core/vm"
)

// revertError is an API error that encompasses an EVM revert with JSON error
// code and a binary data blob.
type revertError struct {
	error
	reason string // revert reason hex encoded
}

// ErrorCode returns the JSON error code for a revert.
// See: https://github.com/zircuit-labs/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
func (e *revertError) ErrorCode() int {
	return 3
}

// ErrorData returns the hex encoded revert reason.
func (e *revertError) ErrorData() interface{} {
	return e.reason
}

// newRevertError creates a revertError instance with the provided revert data.
func newRevertError(revert []byte) *revertError {
	err := vm.ErrExecutionReverted

	reason, errUnpack := abi.UnpackRevert(revert)
	if errUnpack == nil {
		err = fmt.Errorf("%w: %v", vm.ErrExecutionReverted, reason)
	}
	return &revertError{
		error:  err,
		reason: hexutil.Encode(revert),
	}
}

// TxIndexingError is an API error that indicates the transaction indexing is not
// fully finished yet with JSON error code and a binary data blob.
type TxIndexingError struct{}

// NewTxIndexingError creates a TxIndexingError instance.
func NewTxIndexingError() *TxIndexingError { return &TxIndexingError{} }

// Error implement error interface, returning the error message.
func (e *TxIndexingError) Error() string {
	return "transaction indexing is in progress"
}

// ErrorCode returns the JSON error code for a revert.
// See: https://github.com/zircuit-labs/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
func (e *TxIndexingError) ErrorCode() int {
	return -32000 // to be decided
}

// ErrorData returns the hex encoded revert reason.
func (e *TxIndexingError) ErrorData() interface{} { return "transaction indexing is in progress" }

// SLSError is an API error that indicates a generic SLS error.
type SLSError struct{}

func NewSLSError() *SLSError { return &SLSError{} }

func (e *SLSError) Error() string {
	return "SLS error occurred"
}

func (e *SLSError) ErrorCode() int {
	return 83768300 // ASCII values of 'S', 'L', 'S' plus 00
}

func (e *SLSError) ErrorData() interface{} {
	return "SLS error occurred, please try again later"
}

// SLSQuarantineError is an API error that indicates a transaction was sent to quarantine by SLS.
type SLSQuarantineError struct {
	QuarantinedReason string // Reason for quarantining the transaction.
	QuarantinedBy     string // Identifier of the detector that quarantined the transaction.
}

func NewSLSQuarantineError(reason, by string) *SLSQuarantineError {
	return &SLSQuarantineError{
		QuarantinedReason: reason,
		QuarantinedBy:     by,
	}
}

func (e *SLSQuarantineError) Error() string {
	return "transaction sent to quarantine by SLS"
}

func (e *SLSQuarantineError) ErrorCode() int {
	return 83768301 // ASCII values of 'S', 'L', 'S' plus '01'
}

func (e *SLSQuarantineError) ErrorData() interface{} {
	return map[string]string{
		"message":            "transaction quarantined during SLS validation",
		"quarantined_reason": e.QuarantinedReason,
		"quarantined_by":     e.QuarantinedBy,
	}
}
