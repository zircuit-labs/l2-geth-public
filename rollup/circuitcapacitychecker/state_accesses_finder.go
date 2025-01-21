package circuitcapacitychecker

import (
	"errors"
	"fmt"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/crypto"
	"github.com/zircuit-labs/l2-geth-public/log"
)

type AccessValueType uint8

const (
	Account AccessValueType = iota
	Code
	Storage
)

type CodeSourceType uint8

const (
	Address CodeSourceType = iota
	Tx
	Memory
)

type (
	StateAccessesFinder struct{}

	Access struct {
		ValueType AccessValueType
		Value     AccessValue
	}
	AccessValue struct {
		// Address represents account or code
		Address    common.Address
		StorageKey common.Hash
	}
	AccessSet struct {
		StorageKeys []string
		Code        bool
	}

	CodeSource struct {
		SourceType      CodeSourceType
		ContractAddress common.Address
		SourceAddress   *common.Address
	}
)

func accessesToAccessSet(accs []Access) map[common.Address]AccessSet {
	sets := make(map[common.Address]AccessSet)

	for _, acc := range accs {
		accSet := sets[acc.Value.Address]

		switch acc.ValueType {
		case Account:
		case Code:
			accSet.Code = true
		case Storage:
			accSet.StorageKeys = append(accSet.StorageKeys, acc.Value.StorageKey.String())
		default:
			log.Warn("wrong access value type", "value_type", acc.ValueType)
		}

		sets[acc.Value.Address] = accSet
	}

	return sets
}

func NewStateAccessesFinder() *StateAccessesFinder {
	return &StateAccessesFinder{}
}

func (c StateAccessesFinder) GetStateAccesses(block *types.Block, trace *types.BlockTrace) ([]Access, error) {
	if block == nil || trace == nil {
		return nil, errors.New("block or trace is nil")
	}

	var blockAccessTrace []Access
	author := block.Coinbase()

	blockAccessTrace = append(blockAccessTrace, Access{
		ValueType: Account,
		Value: AccessValue{
			Address: author,
		},
	})

	for txIndex, tx := range block.Transactions() {
		if txIndex >= len(trace.Transactions) {
			return nil, fmt.Errorf("trace transactions index out of range: %d", txIndex)
		}
		txData := trace.Transactions[txIndex]
		txExecResult := trace.ExecutionResults[txIndex]
		txAccessTrace, err := c.genStateAccessTrace(tx, txData, txExecResult)
		if err != nil {
			return nil, err
		}
		blockAccessTrace = append(blockAccessTrace, txAccessTrace...)
	}

	return blockAccessTrace, nil
}

func (c StateAccessesFinder) genStateAccessTrace(tx *types.Transaction, txData *types.TransactionData, txExecResult *types.ExecutionResult) ([]Access, error) {
	var callStack []CodeSource
	var accs []Access

	from := txData.From
	accs = append(accs, Access{
		ValueType: Account,
		Value: AccessValue{
			Address: from,
		},
	})

	if tx.To() != nil {
		to := *tx.To()
		callStack = append(callStack, CodeSource{
			SourceType:      Address,
			ContractAddress: to,
		})
		accs = append(accs,
			Access{
				ValueType: Account,
				Value: AccessValue{
					Address: to,
				},
			},
			Access{
				ValueType: Code,
				Value: AccessValue{
					Address: to,
				},
			},
		)
	} else {
		address := crypto.CreateAddress(from, tx.Nonce())
		callStack = append(callStack, CodeSource{
			SourceType:      Tx,
			ContractAddress: address,
		})
		accs = append(accs,
			Access{
				ValueType: Account,
				Value: AccessValue{
					Address: address,
				},
			},
			Access{
				ValueType: Code,
				Value: AccessValue{
					Address: address,
				},
			},
		)
	}

	for index, step := range txExecResult.StructLogs {
		var nextStep *types.StructLogRes
		if index+1 < len(txExecResult.StructLogs) {
			nextStep = txExecResult.StructLogs[index+1]
		}

		codeSource := callStack[len(callStack)-1]

		pushCallStack := nextStep != nil && step.Depth+1 == nextStep.Depth
		popCallStack := nextStep != nil && step.Depth-1 == nextStep.Depth

		switch step.Op {
		case "SSTORE":
			address := codeSource.ContractAddress
			key := common.HexToHash(step.Stack[len(step.Stack)-1])
			accs = append(accs, Access{
				ValueType: Storage,
				Value: AccessValue{
					Address:    address,
					StorageKey: key,
				},
			})
		case "SLOAD":
			address := codeSource.ContractAddress
			key := common.HexToHash(step.Stack[len(step.Stack)-1])
			accs = append(accs, Access{
				ValueType: Storage,
				Value: AccessValue{
					Address:    address,
					StorageKey: key,
				},
			})
		case "SELFBALANCE":
			address := codeSource.ContractAddress
			accs = append(accs, Access{
				ValueType: Account,
				Value: AccessValue{
					Address: address,
				},
			})
		case "CODESIZE", "CODECOPY":
			if codeSource.SourceType == Address {
				address := codeSource.ContractAddress
				if codeSource.SourceAddress != nil {
					address = *codeSource.SourceAddress
				}
				accs = append(accs, Access{
					ValueType: Code,
					Value: AccessValue{
						Address: address,
					},
				})
			}
		case "BALANCE", "EXTCODEHASH":
			address := common.HexToAddress(step.Stack[len(step.Stack)-1])
			accs = append(accs, Access{
				ValueType: Account,
				Value: AccessValue{
					Address: address,
				},
			})
		case "EXTCODESIZE", "EXTCODECOPY":
			address := common.HexToAddress(step.Stack[len(step.Stack)-1])
			accs = append(accs, Access{
				ValueType: Code,
				Value: AccessValue{
					Address: address,
				},
			})
		case "SELFDESTRUCT":
			address := codeSource.ContractAddress
			accs = append(accs, Access{
				ValueType: Account,
				Value: AccessValue{
					Address: address,
				},
			})

			address = common.HexToAddress(step.Stack[len(step.Stack)-1])
			accs = append(accs, Access{
				ValueType: Account,
				Value: AccessValue{
					Address: address,
				},
			})
		case "CREATE", "CREATE2":
			if pushCallStack {
				address := getCallResult(txExecResult.StructLogs[index:])
				if address != (common.Address{}) {
					accs = append(accs,
						Access{
							ValueType: Account,
							Value: AccessValue{
								Address: address,
							},
						},
						Access{
							ValueType: Code,
							Value: AccessValue{
								Address: address,
							},
						},
					)
				}
				callStack = append(callStack, CodeSource{
					SourceType:      Address,
					ContractAddress: address,
				})
			}
		case "CALL", "CALLCODE":
			address := codeSource.ContractAddress
			accs = append(accs, Access{
				ValueType: Account,
				Value: AccessValue{
					Address: address,
				},
			})

			address = common.HexToAddress(step.Stack[len(step.Stack)-2])
			accs = append(accs,
				Access{
					ValueType: Account,
					Value: AccessValue{
						Address: address,
					},
				},
				Access{
					ValueType: Code,
					Value: AccessValue{
						Address: address,
					},
				},
			)
			if pushCallStack {
				callStack = append(callStack, CodeSource{
					SourceType:      Address,
					ContractAddress: address,
				})
			}
		case "DELEGATECALL":
			address := common.HexToAddress(step.Stack[len(step.Stack)-2])
			if address != (common.Address{}) {
				accs = append(accs, Access{
					ValueType: Code,
					Value: AccessValue{
						Address: address,
					},
				})
			}
			if pushCallStack {
				callStack = append(callStack, CodeSource{
					SourceType:      Address,
					ContractAddress: codeSource.ContractAddress,
					SourceAddress:   &address,
				})
			}
		case "STATICCALL":
			address := common.HexToAddress(step.Stack[len(step.Stack)-2])
			if address != (common.Address{}) {
				accs = append(accs, Access{
					ValueType: Code,
					Value: AccessValue{
						Address: address,
					},
				})
			}
			if pushCallStack {
				callStack = append(callStack, CodeSource{
					SourceType:      Address,
					ContractAddress: address,
				})
			}
		default:
			// other opcodes must be ignored
		}

		if popCallStack {
			callStack = callStack[:len(callStack)-1]
		}
	}

	return accs, nil
}

func getCallResult(logs []*types.StructLogRes) common.Address {
	depth := logs[0].Depth
	for _, log := range logs[1:] {
		if log.Depth == depth {
			return common.HexToAddress(log.Stack[len(log.Stack)-1])
		}
	}

	return common.Address{}
}
