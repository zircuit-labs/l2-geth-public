package types

type BlockConfig struct {
	IsTenrecEnabled bool
}

func (bc *BlockConfig) HasOptimismWithdrawalsRoot(blockTime uint64) bool {
	return bc.IsTenrecEnabled
}

func (bc *BlockConfig) IsTenrec(blockTime uint64) bool {
	return bc.IsTenrecEnabled
}

var (
	DefaultBlockConfig = &BlockConfig{IsTenrecEnabled: false}
	IsthmusBlockConfig = &BlockConfig{IsTenrecEnabled: true}
)
