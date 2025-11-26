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
	"errors"

	"github.com/zircuit-labs/l2-geth/accounts/abi"
	"github.com/zircuit-labs/l2-geth/common/hexutil"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/vm"
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
func (e *revertError) ErrorData() any {
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
func (e *TxIndexingError) ErrorData() any { return "transaction indexing is in progress" }

type callError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Data    string `json:"data,omitempty"`
}

type invalidTxError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func (e *invalidTxError) Error() string  { return e.Message }
func (e *invalidTxError) ErrorCode() int { return e.Code }

const (
	errCodeNonceTooHigh            = -38011
	errCodeNonceTooLow             = -38010
	errCodeIntrinsicGas            = -38013
	errCodeInsufficientFunds       = -38014
	errCodeBlockGasLimitReached    = -38015
	errCodeBlockNumberInvalid      = -38020
	errCodeBlockTimestampInvalid   = -38021
	errCodeSenderIsNotEOA          = -38024
	errCodeMaxInitCodeSizeExceeded = -38025
	errCodeClientLimitExceeded     = -38026
	errCodeInternalError           = -32603
	errCodeInvalidParams           = -32602
	errCodeReverted                = -32000
	errCodeVMError                 = -32015
)

func txValidationError(err error) *invalidTxError {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, core.ErrNonceTooHigh):
		return &invalidTxError{Message: err.Error(), Code: errCodeNonceTooHigh}
	case errors.Is(err, core.ErrNonceTooLow):
		return &invalidTxError{Message: err.Error(), Code: errCodeNonceTooLow}
	case errors.Is(err, core.ErrSenderNoEOA):
		return &invalidTxError{Message: err.Error(), Code: errCodeSenderIsNotEOA}
	case errors.Is(err, core.ErrFeeCapVeryHigh):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams}
	case errors.Is(err, core.ErrTipVeryHigh):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams}
	case errors.Is(err, core.ErrTipAboveFeeCap):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams}
	case errors.Is(err, core.ErrFeeCapTooLow):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams}
	case errors.Is(err, core.ErrInsufficientFunds):
		return &invalidTxError{Message: err.Error(), Code: errCodeInsufficientFunds}
	case errors.Is(err, core.ErrIntrinsicGas):
		return &invalidTxError{Message: err.Error(), Code: errCodeIntrinsicGas}
	case errors.Is(err, core.ErrInsufficientFundsForTransfer):
		return &invalidTxError{Message: err.Error(), Code: errCodeInsufficientFunds}
	case errors.Is(err, core.ErrMaxInitCodeSizeExceeded):
		return &invalidTxError{Message: err.Error(), Code: errCodeMaxInitCodeSizeExceeded}
	}
	return &invalidTxError{
		Message: err.Error(),
		Code:    errCodeInternalError,
	}
}

type invalidParamsError struct{ message string }

func (e *invalidParamsError) Error() string  { return e.message }
func (e *invalidParamsError) ErrorCode() int { return errCodeInvalidParams }

type clientLimitExceededError struct{ message string }

func (e *clientLimitExceededError) Error() string  { return e.message }
func (e *clientLimitExceededError) ErrorCode() int { return errCodeClientLimitExceeded }

type invalidBlockNumberError struct{ message string }

func (e *invalidBlockNumberError) Error() string  { return e.message }
func (e *invalidBlockNumberError) ErrorCode() int { return errCodeBlockNumberInvalid }

type invalidBlockTimestampError struct{ message string }

func (e *invalidBlockTimestampError) Error() string  { return e.message }
func (e *invalidBlockTimestampError) ErrorCode() int { return errCodeBlockTimestampInvalid }

type blockGasLimitReachedError struct{ message string }

func (e *blockGasLimitReachedError) Error() string  { return e.message }

// SLSError is an API error that indicates a generic SLS error.
type SLSError struct{}

func NewSLSError() *SLSError { return &SLSError{} }

func (e *SLSError) Error() string {
	return "SLS error occurred"
}

func (e *SLSError) ErrorCode() int {
	return 83768300 // ASCII values of 'S', 'L', 'S' plus 00
}

func (e *SLSError) ErrorData() any {
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

func (e *SLSQuarantineError) ErrorData() any {
	return map[string]string{
		"message":            "transaction quarantined during SLS validation",
		"quarantined_reason": e.QuarantinedReason,
		"quarantined_by":     e.QuarantinedBy,
	}
}
