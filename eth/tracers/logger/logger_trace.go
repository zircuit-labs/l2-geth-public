package logger

import (
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/core/vm"
)

type traceFunc func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error

// OpcodeExecs the map to load opcodes' trace funcs.
var OpcodeExecs = map[vm.OpCode][]traceFunc{
	vm.CALL:         {traceToAddressCode, traceLastNAddressCode(1), traceContractAccount, traceLastNAddressAccount(1)}, // contract account is the caller, stack.nth_last(1) is the callee's address
	vm.CALLCODE:     {traceToAddressCode, traceLastNAddressCode(1), traceContractAccount, traceLastNAddressAccount(1)}, // contract account is the caller, stack.nth_last(1) is the callee's address
	vm.DELEGATECALL: {traceToAddressCode, traceLastNAddressCode(1)},
	vm.STATICCALL:   {traceToAddressCode, traceLastNAddressCode(1), traceLastNAddressAccount(1)},
	vm.CREATE:       {}, // caller is already recorded in ExtraData.Caller, callee is recorded in CaptureEnter&CaptureExit
	vm.CREATE2:      {}, // caller is already recorded in ExtraData.Caller, callee is recorded in CaptureEnter&CaptureExit
	vm.SLOAD:        {}, // trace storage in `captureState` instead of here, to handle `l.cfg.DisableStorage` flag
	vm.SSTORE:       {}, // trace storage in `captureState` instead of here, to handle `l.cfg.DisableStorage` flag
	vm.SELFDESTRUCT: {traceContractAccount, traceLastNAddressAccount(0)},
	vm.SELFBALANCE:  {traceContractAccount},
	vm.BALANCE:      {traceLastNAddressAccount(0)},
	vm.EXTCODEHASH:  {traceLastNAddressAccount(0)},
	vm.CODESIZE:     {traceContractCode},
	vm.CODECOPY:     {traceContractCode},
	vm.EXTCODESIZE:  {traceLastNAddressCode(0)},
	vm.EXTCODECOPY:  {traceLastNAddressCode(0)},
}

// traceToAddressCode gets tx.to address’s code
func traceToAddressCode(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	if l.env.To == nil {
		return nil
	}
	code := l.env.StateDB.GetCode(*l.env.To)
	extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
	traceCodeWithAddress(l, *l.env.To)
	return nil
}

// traceLastNAddressCode
func traceLastNAddressCode(n int) traceFunc {
	return func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
		stack := scope.Stack
		if stack.Len() <= n {
			return nil
		}
		address := common.Address(stack.Data()[stack.Len()-1-n].Bytes20())
		traceCodeWithAddress(l, address)
		code := l.env.StateDB.GetCode(address)
		extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
		l.statesAffected[address] = struct{}{}
		return nil
	}
}

func traceCodeWithAddress(l *StructLogger, address common.Address) {
	code := l.env.StateDB.GetCode(address)
	keccakCodeHash := l.env.StateDB.GetKeccakCodeHash(address)
	poseidonCodeHash := l.env.StateDB.GetPoseidonCodeHash(address)
	codeSize := l.env.StateDB.GetCodeSize(address)
	l.bytecodes[poseidonCodeHash] = CodeInfo{
		codeSize,
		keccakCodeHash,
		poseidonCodeHash,
		code,
	}
}

// traceContractCode gets the contract's code
func traceContractCode(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	code := l.env.StateDB.GetCode(scope.Contract.Address())
	extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
	return nil
}

// traceStorage get contract's storage at storage_address
func traceStorage(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	if scope.Stack.Len() == 0 {
		return nil
	}
	key := common.Hash(scope.Stack.Peek().Bytes32())
	storage := getWrappedAccountForStorage(l, scope.Contract.Address(), key)
	extraData.StateList = append(extraData.StateList, storage)

	return nil
}

// traceContractAccount gets the contract's account
func traceContractAccount(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	// Get account state.
	state := getWrappedAccountForAddr(l, scope.Contract.Address())
	extraData.StateList = append(extraData.StateList, state)
	l.statesAffected[scope.Contract.Address()] = struct{}{}

	return nil
}

// traceLastNAddressAccount returns func about the last N's address account.
func traceLastNAddressAccount(n int) traceFunc {
	return func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
		stack := scope.Stack
		if stack.Len() <= n {
			return nil
		}

		address := common.Address(stack.Data()[stack.Len()-1-n].Bytes20())
		state := getWrappedAccountForAddr(l, address)
		extraData.StateList = append(extraData.StateList, state)
		l.statesAffected[address] = struct{}{}

		return nil
	}
}

// StorageWrapper will be empty
func getWrappedAccountForAddr(l *StructLogger, address common.Address) *types.AccountWrapper {
	return &types.AccountWrapper{
		Address:        address,
		Nonce:          l.env.StateDB.GetNonce(address),
		Balance:        (*hexutil.Big)(l.env.StateDB.GetBalance(address).ToBig()),
		KeccakCodeHash: l.env.StateDB.GetKeccakCodeHash(address),
		CodeSize:       uint64(l.env.StateDB.GetCodeSize(address)),
	}
}

func getWrappedAccountForStorage(l *StructLogger, address common.Address, key common.Hash) *types.AccountWrapper {
	return &types.AccountWrapper{
		Address:        address,
		Nonce:          l.env.StateDB.GetNonce(address),
		Balance:        (*hexutil.Big)(l.env.StateDB.GetBalance(address).ToBig()),
		KeccakCodeHash: l.env.StateDB.GetKeccakCodeHash(address),
		CodeSize:       uint64(l.env.StateDB.GetCodeSize(address)),
		Storage: &types.StorageWrapper{
			Key:   key.String(),
			Value: l.env.StateDB.GetState(address, key).String(),
		},
	}
}

func getCodeForAddr(l *StructLogger, address common.Address) []byte {
	return l.env.StateDB.GetCode(address)
}
