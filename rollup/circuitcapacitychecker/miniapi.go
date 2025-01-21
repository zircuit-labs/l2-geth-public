package circuitcapacitychecker

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/zircuit-labs/l2-geth-public"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/crypto"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/rpc"
	"github.com/zircuit-labs/l2-geth-public/trie"
)

type (
	MiniBlockChainAPI struct {
		blockchain MiniBlockChain
	}

	MiniBlockChain interface {
		GetHeaderByHash(hash common.Hash) *types.Header
		StateAt(root common.Hash) (*state.StateDB, error)
		StateAtHeader(header *types.Header) (*state.StateDB, error)
		GetCanonicalHash(number uint64) common.Hash
		GetHeaderByNumber(number uint64) *types.Header
		CurrentBlock() *types.Header
		CurrentFinalBlock() *types.Header
		CurrentSafeBlock() *types.Header
		HeaderOrWaitZKTrie(*types.Header) *types.Header
	}
)

// NewMiniBlockChainAPI creates a new Ethereum blockchain API.
func NewMiniBlockChainAPI(b MiniBlockChain) *MiniBlockChainAPI {
	return &MiniBlockChainAPI{blockchain: b}
}

// StateAndHeaderByNumber returns the state and header for the given block
// number. Refer to StateAndHeaderByNumberOrHash for more details.
func (s *MiniBlockChainAPI) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Otherwise resolve the block number and return its state
	header, err := s.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, fmt.Errorf("header %w", ethereum.NotFound)
	}
	stateDb, err := s.blockchain.StateAtHeader(s.blockchain.HeaderOrWaitZKTrie(header))
	if err != nil {
		return nil, nil, err
	}
	return stateDb, header, nil
}

func (s *MiniBlockChainAPI) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return s.blockchain.GetHeaderByHash(hash), nil
}

// StateAndHeaderByNumberOrHash returns the state and header for the given block
// number or hash. As parent block of the requested block is passed as argument
// (see call hierarchy), for ZKTrieSwitch-1 block the ZKTrie state is obtained to
// make codes and proofs ZKTrie-based for ZKTrieSwitch block.
func (s *MiniBlockChainAPI) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return s.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := s.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, fmt.Errorf("header for hash %w", ethereum.NotFound)
		}
		if blockNrOrHash.RequireCanonical && s.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := s.blockchain.StateAtHeader(s.blockchain.HeaderOrWaitZKTrie(header))
		if err != nil {
			return nil, nil, err
		}
		return stateDb, header, nil
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (s *MiniBlockChainAPI) MiniHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	header, err := s.HeaderByNumberOrHash(ctx, blockNrOrHash)
	if header == nil {
		return nil, fmt.Errorf("header %w", ethereum.NotFound)
	}
	return header, err
}

func (s *MiniBlockChainAPI) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return s.HeaderByNumber(ctx, blockNr)
	}

	if hash, ok := blockNrOrHash.Hash(); ok {

		header := s.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && s.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}

		return header, nil
	}

	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (s *MiniBlockChainAPI) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if number == rpc.LatestBlockNumber {
		return s.blockchain.CurrentBlock(), nil
	}
	if number == rpc.FinalizedBlockNumber {
		block := s.blockchain.CurrentFinalBlock()
		if block == nil {
			return nil, errors.New("finalized block not found")
		}
		return block, nil
	}
	if number == rpc.SafeBlockNumber {
		block := s.blockchain.CurrentSafeBlock()
		if block == nil {
			return nil, errors.New("safe block not found")
		}
		return block, nil
	}
	return s.blockchain.GetHeaderByNumber(uint64(number)), nil
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (s *MiniBlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (string, error) {
	state, _, err := s.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return "", err
	}

	code := state.GetCode(address)

	return hex.EncodeToString(code), state.Error()
}

// GetProof returns the Merkle-proof for a given account and optionally some storage keys.
func (s *MiniBlockChainAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*MiniAccountResult, error) {
	header, err := s.MiniHeaderByNumberOrHash(ctx, blockNrOrHash)
	if err != nil {
		return nil, err
	}

	var (
		keys         = make([]common.Hash, len(storageKeys))
		keyLengths   = make([]int, len(storageKeys))
		storageProof = make([]MiniStorageResult, len(storageKeys))
	)
	// Deserialize all keys. This prevents state access on invalid input.
	for i, hexKey := range storageKeys {
		var err error
		keys[i], keyLengths[i], err = decodeHash(hexKey)
		if err != nil {
			return nil, err
		}
	}
	statedb, header, err := s.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if statedb == nil || err != nil {
		return nil, err
	}
	keccakCodeHash := statedb.GetKeccakCodeHash(address)
	poseidonCodeHash := statedb.GetPoseidonCodeHash(address)
	storageRoot := statedb.GetStorageRoot(address)

	if len(keys) > 0 {
		var storageTrie state.Trie
		if !types.IsEmptyTrieRoot(storageRoot) {
			if statedb.IsZktrie() {
				storageTrie, err = trie.NewZkTrie(storageRoot, trie.NewZktrieDatabaseFromTriedb(statedb.Database().TrieDB()))
			} else {
				id := trie.StorageTrieID(header.Root, crypto.Keccak256Hash(address.Bytes()), storageRoot)
				storageTrie, err = trie.NewStateTrie(id, statedb.Database().TrieDB())
			}
			if err != nil {
				return nil, err
			}
		}
		// Create the proofs for the storageKeys.
		for i, key := range keys {
			// Output key encoding is a bit special: if the input was a 32-byte hash, it is
			// returned as such. Otherwise, we apply the QUANTITY encoding mandated by the
			// JSON-RPC spec for getProof. This behavior exists to preserve backwards
			// compatibility with older client versions.
			var outputKey string
			if keyLengths[i] != 32 {
				outputKey = hexutil.EncodeBig(key.Big())
			} else {
				outputKey = hexutil.Encode(key[:])
			}
			if storageTrie == nil {
				storageProof[i] = MiniStorageResult{Key: outputKey, Value: &hexutil.Big{}, Proof: []string{}}
				continue
			}

			proof, err := statedb.GetStorageProof(address, key)
			if err != nil {
				return nil, err
			}

			value := (*hexutil.Big)(statedb.GetState(address, key).Big())
			storageProof[i] = MiniStorageResult{Key: outputKey, Value: value, Proof: toHexSlice(proof)}
		}
	}

	balance := statedb.GetBalance(address).ToBig()
	result := &MiniAccountResult{
		Address:          address,
		Balance:          (*hexutil.Big)(balance),
		KeccakCodeHash:   keccakCodeHash,
		PoseidonCodeHash: poseidonCodeHash,
		CodeSize:         hexutil.Uint64(statedb.GetCodeSize(address)),
		Nonce:            hexutil.Uint64(statedb.GetNonce(address)),
		StorageHash:      storageRoot,
		StorageProof:     storageProof,
	}

	// Force Scroll's logic for ZKTrie, because trie.NewStateTrie fails with 'not
	// found' error due to header.Root not being stored in StateDB.Commit
	if statedb.IsZktrie() {
		log.Debug("ZKTrie logic will be used to get account proof (MiniAPI)")
		proof, err := statedb.GetProof(address)
		if err != nil {
			return nil, fmt.Errorf("get ZKTrie proof from StateDB: %w", err)
		}
		result.AccountProof = toHexSlice(proof)
		return result, statedb.Error()
	}

	log.Debug("Default Trie logic will be used to get account proof (MiniAPI)")
	tr, err := trie.NewStateTrie(trie.StateTrieID(header.Root), statedb.Database().TrieDB())
	if err != nil {
		return nil, err
	}

	var accountProof MiniProofList
	if err = tr.Prove(crypto.Keccak256(address.Bytes()), &accountProof); err != nil {
		return nil, err
	}
	result.AccountProof = accountProof
	return result, statedb.Error()
}

func toHexSlice(b [][]byte) []string {
	r := make([]string, len(b))
	for i := range b {
		r[i] = hexutil.Encode(b[i])
	}
	return r
}

func decodeHash(s string) (h common.Hash, inputLength int, err error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if (len(s) & 1) > 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, 0, errors.New("hex string invalid")
	}
	if len(b) > 32 {
		return common.Hash{}, len(b), errors.New("hex string too long, want at most 32 bytes")
	}
	return common.BytesToHash(b), len(b), nil
}
