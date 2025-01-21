package circuitcapacitychecker

import (
	"context"
	"fmt"
	"sync"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/rpc"
)

type (
	CCCHelper struct {
		backend     *MiniBlockChainAPI
		stateFinder stateFinder
	}

	stateFinder interface {
		GetStateAccesses(block *types.Block, trace *types.BlockTrace) ([]Access, error)
	}
)

func NewCCCHelper(backend *MiniBlockChainAPI, stateFinder stateFinder) *CCCHelper {
	return &CCCHelper{backend: backend, stateFinder: stateFinder}
}

// GetCodesAndProofs retrieves the code and proofs for the accounts accessed in the given block and trace.
func (c CCCHelper) GetCodesAndProofs(block *types.Block, trace *types.BlockTrace, isLatest bool) (map[*common.Address]string, []*MiniAccountResult, error) {
	state, err := c.stateFinder.GetStateAccesses(block, trace)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get state accesses: %w", err)
	}

	blockNum := latestBlock
	if !isLatest {
		blockNum = rpc.BlockNumberOrHashWithHash(block.ParentHash(), false)
	}

	codeMap, proofs := c.fetchCodeAndProofs(state, blockNum)

	return codeMap, proofs, nil
}

// fetchCodeAndProofs concurrently fetches the code and proofs for the given state accesses.
func (c CCCHelper) fetchCodeAndProofs(state []Access, blockNumber rpc.BlockNumberOrHash) (map[*common.Address]string, []*MiniAccountResult) {
	accessSet := accessesToAccessSet(state)

	// We define the Wait group and mutex inside the function to ensure that the instance can be used concurrently.
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		codeMap = make(map[*common.Address]string)
		proofs  = make([]*MiniAccountResult, len(accessSet))
	)

	ctx := context.Background()

	i := 0
	for addr, access := range accessSet {
		if !access.Code {
			wg.Add(1)
			go c.fetchProof(ctx, i, addr, &wg, &mu, access.StorageKeys, blockNumber, proofs)
			i++
			continue
		}

		wg.Add(2)
		go c.fetchCode(ctx, addr, &wg, &mu, blockNumber, codeMap)
		go c.fetchProof(ctx, i, addr, &wg, &mu, access.StorageKeys, blockNumber, proofs)
		i++
	}

	wg.Wait()

	return codeMap, proofs
}

var (
	latestBlock = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
)

func (c CCCHelper) fetchProof(
	ctx context.Context, index int, account common.Address, wg *sync.WaitGroup, mu *sync.Mutex, storageKeys []string,
	block rpc.BlockNumberOrHash, proofs []*MiniAccountResult,
) {
	defer wg.Done()

	proof, err := c.backend.GetProof(ctx, account, storageKeys, block)
	if err != nil {
		log.Warn("failed to get proof for account", "account", account.Hex(), "error", err)
	}

	mu.Lock()
	proofs[index] = proof
	mu.Unlock()
}

func (c CCCHelper) fetchCode(ctx context.Context, account common.Address, wg *sync.WaitGroup, mu *sync.Mutex, block rpc.BlockNumberOrHash, codeMap map[*common.Address]string) {
	defer wg.Done()

	code, err := c.backend.GetCode(ctx, account, block)
	if err != nil {
		log.Warn("failed to get code for account", "account", account.Hex(), "error", err)
	}

	mu.Lock()
	codeMap[&account] = code
	mu.Unlock()
}
