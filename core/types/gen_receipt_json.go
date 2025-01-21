// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package types

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
)

var _ = (*receiptMarshaling)(nil)

// MarshalJSON marshals as JSON.
func (r Receipt) MarshalJSON() ([]byte, error) {
	type Receipt struct {
		Type                  hexutil.Uint64  `json:"type,omitempty"`
		PostState             hexutil.Bytes   `json:"root"`
		Status                hexutil.Uint64  `json:"status"`
		CumulativeGasUsed     hexutil.Uint64  `json:"cumulativeGasUsed" gencodec:"required"`
		Bloom                 Bloom           `json:"logsBloom"         gencodec:"required"`
		Logs                  []*Log          `json:"logs"              gencodec:"required"`
		TxHash                common.Hash     `json:"transactionHash" gencodec:"required"`
		ContractAddress       common.Address  `json:"contractAddress"`
		GasUsed               hexutil.Uint64  `json:"gasUsed" gencodec:"required"`
		EffectiveGasPrice     *hexutil.Big    `json:"effectiveGasPrice"`
		BlobGasUsed           hexutil.Uint64  `json:"blobGasUsed,omitempty"`
		BlobGasPrice          *hexutil.Big    `json:"blobGasPrice,omitempty"`
		DepositNonce          *hexutil.Uint64 `json:"depositNonce,omitempty"`
		DepositReceiptVersion *hexutil.Uint64 `json:"depositReceiptVersion,omitempty"`
		BlockHash             common.Hash     `json:"blockHash,omitempty"`
		BlockNumber           *hexutil.Big    `json:"blockNumber,omitempty"`
		TransactionIndex      hexutil.Uint    `json:"transactionIndex"`
		L1GasPrice            *hexutil.Big    `json:"l1GasPrice,omitempty"`
		L1GasUsed             *hexutil.Big    `json:"l1GasUsed,omitempty"`
		L1Fee                 *hexutil.Big    `json:"l1Fee,omitempty"`
		FeeScalar             *big.Float      `json:"l1FeeScalar,omitempty"`
	}
	var enc Receipt
	enc.Type = hexutil.Uint64(r.Type)
	enc.PostState = r.PostState
	enc.Status = hexutil.Uint64(r.Status)
	enc.CumulativeGasUsed = hexutil.Uint64(r.CumulativeGasUsed)
	enc.Bloom = r.Bloom
	enc.Logs = r.Logs
	enc.TxHash = r.TxHash
	enc.ContractAddress = r.ContractAddress
	enc.GasUsed = hexutil.Uint64(r.GasUsed)
	enc.EffectiveGasPrice = (*hexutil.Big)(r.EffectiveGasPrice)
	enc.BlobGasUsed = hexutil.Uint64(r.BlobGasUsed)
	enc.BlobGasPrice = (*hexutil.Big)(r.BlobGasPrice)
	enc.DepositNonce = (*hexutil.Uint64)(r.DepositNonce)
	enc.DepositReceiptVersion = (*hexutil.Uint64)(r.DepositReceiptVersion)
	enc.BlockHash = r.BlockHash
	enc.BlockNumber = (*hexutil.Big)(r.BlockNumber)
	enc.TransactionIndex = hexutil.Uint(r.TransactionIndex)
	enc.L1GasPrice = (*hexutil.Big)(r.L1GasPrice)
	enc.L1GasUsed = (*hexutil.Big)(r.L1GasUsed)
	enc.L1Fee = (*hexutil.Big)(r.L1Fee)
	enc.FeeScalar = r.FeeScalar
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (r *Receipt) UnmarshalJSON(input []byte) error {
	type Receipt struct {
		Type                  *hexutil.Uint64 `json:"type,omitempty"`
		PostState             *hexutil.Bytes  `json:"root"`
		Status                *hexutil.Uint64 `json:"status"`
		CumulativeGasUsed     *hexutil.Uint64 `json:"cumulativeGasUsed" gencodec:"required"`
		Bloom                 *Bloom          `json:"logsBloom"         gencodec:"required"`
		Logs                  []*Log          `json:"logs"              gencodec:"required"`
		TxHash                *common.Hash    `json:"transactionHash" gencodec:"required"`
		ContractAddress       *common.Address `json:"contractAddress"`
		GasUsed               *hexutil.Uint64 `json:"gasUsed" gencodec:"required"`
		EffectiveGasPrice     *hexutil.Big    `json:"effectiveGasPrice"`
		BlobGasUsed           *hexutil.Uint64 `json:"blobGasUsed,omitempty"`
		BlobGasPrice          *hexutil.Big    `json:"blobGasPrice,omitempty"`
		DepositNonce          *hexutil.Uint64 `json:"depositNonce,omitempty"`
		DepositReceiptVersion *hexutil.Uint64 `json:"depositReceiptVersion,omitempty"`
		BlockHash             *common.Hash    `json:"blockHash,omitempty"`
		BlockNumber           *hexutil.Big    `json:"blockNumber,omitempty"`
		TransactionIndex      *hexutil.Uint   `json:"transactionIndex"`
		L1GasPrice            *hexutil.Big    `json:"l1GasPrice,omitempty"`
		L1GasUsed             *hexutil.Big    `json:"l1GasUsed,omitempty"`
		L1Fee                 *hexutil.Big    `json:"l1Fee,omitempty"`
		FeeScalar             *big.Float      `json:"l1FeeScalar,omitempty"`
	}
	var dec Receipt
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Type != nil {
		r.Type = uint8(*dec.Type)
	}
	if dec.PostState != nil {
		r.PostState = *dec.PostState
	}
	if dec.Status != nil {
		r.Status = uint64(*dec.Status)
	}
	if dec.CumulativeGasUsed == nil {
		return errors.New("missing required field 'cumulativeGasUsed' for Receipt")
	}
	r.CumulativeGasUsed = uint64(*dec.CumulativeGasUsed)
	if dec.Bloom == nil {
		return errors.New("missing required field 'logsBloom' for Receipt")
	}
	r.Bloom = *dec.Bloom
	if dec.Logs == nil {
		return errors.New("missing required field 'logs' for Receipt")
	}
	r.Logs = dec.Logs
	if dec.TxHash == nil {
		return errors.New("missing required field 'transactionHash' for Receipt")
	}
	r.TxHash = *dec.TxHash
	if dec.ContractAddress != nil {
		r.ContractAddress = *dec.ContractAddress
	}
	if dec.GasUsed == nil {
		return errors.New("missing required field 'gasUsed' for Receipt")
	}
	r.GasUsed = uint64(*dec.GasUsed)
	if dec.EffectiveGasPrice != nil {
		r.EffectiveGasPrice = (*big.Int)(dec.EffectiveGasPrice)
	}
	if dec.BlobGasUsed != nil {
		r.BlobGasUsed = uint64(*dec.BlobGasUsed)
	}
	if dec.BlobGasPrice != nil {
		r.BlobGasPrice = (*big.Int)(dec.BlobGasPrice)
	}
	if dec.DepositNonce != nil {
		r.DepositNonce = (*uint64)(dec.DepositNonce)
	}
	if dec.DepositReceiptVersion != nil {
		r.DepositReceiptVersion = (*uint64)(dec.DepositReceiptVersion)
	}
	if dec.BlockHash != nil {
		r.BlockHash = *dec.BlockHash
	}
	if dec.BlockNumber != nil {
		r.BlockNumber = (*big.Int)(dec.BlockNumber)
	}
	if dec.TransactionIndex != nil {
		r.TransactionIndex = uint(*dec.TransactionIndex)
	}
	if dec.L1GasPrice != nil {
		r.L1GasPrice = (*big.Int)(dec.L1GasPrice)
	}
	if dec.L1GasUsed != nil {
		r.L1GasUsed = (*big.Int)(dec.L1GasUsed)
	}
	if dec.L1Fee != nil {
		r.L1Fee = (*big.Int)(dec.L1Fee)
	}
	if dec.FeeScalar != nil {
		r.FeeScalar = dec.FeeScalar
	}
	return nil
}
