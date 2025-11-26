// Copyright 2015 The go-ethereum Authors
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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	gomath "math"
	"math/big"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/tyler-smith/go-bip39"

	ethereum "github.com/zircuit-labs/l2-geth"
	"github.com/zircuit-labs/l2-geth/accounts"
	"github.com/zircuit-labs/l2-geth/accounts/keystore"
	"github.com/zircuit-labs/l2-geth/accounts/scwallet"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/common/hexutil"
	"github.com/zircuit-labs/l2-geth/common/math"
	"github.com/zircuit-labs/l2-geth/consensus"
	"github.com/zircuit-labs/l2-geth/consensus/misc/eip1559"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/rawdb"
	slsapiCommon "github.com/zircuit-labs/l2-geth/core/sls-common/slsapi"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/core/vm"
	"github.com/zircuit-labs/l2-geth/crypto"
	"github.com/zircuit-labs/l2-geth/eth/gasestimator"
	"github.com/zircuit-labs/l2-geth/eth/tracers/logger"
	"github.com/zircuit-labs/l2-geth/internal/ethapi/override"
	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/l2-geth/p2p"
	"github.com/zircuit-labs/l2-geth/params"
	"github.com/zircuit-labs/l2-geth/rlp"
	"github.com/zircuit-labs/l2-geth/rpc"
	"github.com/zircuit-labs/l2-geth/trie"
)

//go:generate go tool mockgen -source api.go -destination mock_api.go -package ethapi

// estimateGasErrorRatio is the amount of overestimation eth_estimateGas is
// allowed to produce in order to speed up calculations.
const estimateGasErrorRatio = 0.015

var errBlobTxNotSupported = errors.New("signing blob transactions not supported")

// EthereumAPI provides an API to access Ethereum related information.
type EthereumAPI struct {
	b Backend
}

// NewEthereumAPI creates a new Ethereum protocol API.
func NewEthereumAPI(b Backend) *EthereumAPI {
	return &EthereumAPI{b}
}

// GasPrice returns a suggestion for a gas price for legacy transactions.
func (s *EthereumAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	tipcap, err := s.b.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	if head := s.b.CurrentHeader(); head.BaseFee != nil {
		tipcap.Add(tipcap, head.BaseFee)
	}
	return (*hexutil.Big)(tipcap), err
}

// MaxPriorityFeePerGas returns a suggestion for a gas tip cap for dynamic fee transactions.
func (s *EthereumAPI) MaxPriorityFeePerGas(ctx context.Context) (*hexutil.Big, error) {
	tipcap, err := s.b.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Big)(tipcap), err
}

type feeHistoryResult struct {
	OldestBlock  *hexutil.Big     `json:"oldestBlock"`
	Reward       [][]*hexutil.Big `json:"reward,omitempty"`
	BaseFee      []*hexutil.Big   `json:"baseFeePerGas,omitempty"`
	GasUsedRatio []float64        `json:"gasUsedRatio"`
}

// FeeHistory returns the fee market history.
func (s *EthereumAPI) FeeHistory(ctx context.Context, blockCount math.HexOrDecimal64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*feeHistoryResult, error) {
	oldest, reward, baseFee, gasUsed, err := s.b.FeeHistory(ctx, uint64(blockCount), lastBlock, rewardPercentiles)
	if err != nil {
		return nil, err
	}
	results := &feeHistoryResult{
		OldestBlock:  (*hexutil.Big)(oldest),
		GasUsedRatio: gasUsed,
	}
	if reward != nil {
		results.Reward = make([][]*hexutil.Big, len(reward))
		for i, w := range reward {
			results.Reward[i] = make([]*hexutil.Big, len(w))
			for j, v := range w {
				results.Reward[i][j] = (*hexutil.Big)(v)
			}
		}
	}
	if baseFee != nil {
		results.BaseFee = make([]*hexutil.Big, len(baseFee))
		for i, v := range baseFee {
			results.BaseFee[i] = (*hexutil.Big)(v)
		}
	}
	return results, nil
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up-to-date or has not
// yet received the latest block headers from its pears. In case it is synchronizing:
// - startingBlock: block number this node started to synchronize from
// - currentBlock:  block number this node is currently importing
// - highestBlock:  block number of the highest block header this node has received from peers
// - pulledStates:  number of state entries processed until now
// - knownStates:   number of known state entries that still need to be pulled
func (s *EthereumAPI) Syncing() (any, error) {
	progress := s.b.SyncProgress()

	// Return not syncing if the synchronisation already completed
	if progress.Done() {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]any{
		"startingBlock":          hexutil.Uint64(progress.StartingBlock),
		"currentBlock":           hexutil.Uint64(progress.CurrentBlock),
		"highestBlock":           hexutil.Uint64(progress.HighestBlock),
		"syncedAccounts":         hexutil.Uint64(progress.SyncedAccounts),
		"syncedAccountBytes":     hexutil.Uint64(progress.SyncedAccountBytes),
		"syncedBytecodes":        hexutil.Uint64(progress.SyncedBytecodes),
		"syncedBytecodeBytes":    hexutil.Uint64(progress.SyncedBytecodeBytes),
		"syncedStorage":          hexutil.Uint64(progress.SyncedStorage),
		"syncedStorageBytes":     hexutil.Uint64(progress.SyncedStorageBytes),
		"healedTrienodes":        hexutil.Uint64(progress.HealedTrienodes),
		"healedTrienodeBytes":    hexutil.Uint64(progress.HealedTrienodeBytes),
		"healedBytecodes":        hexutil.Uint64(progress.HealedBytecodes),
		"healedBytecodeBytes":    hexutil.Uint64(progress.HealedBytecodeBytes),
		"healingTrienodes":       hexutil.Uint64(progress.HealingTrienodes),
		"healingBytecode":        hexutil.Uint64(progress.HealingBytecode),
		"txIndexFinishedBlocks":  hexutil.Uint64(progress.TxIndexFinishedBlocks),
		"txIndexRemainingBlocks": hexutil.Uint64(progress.TxIndexRemainingBlocks),
	}, nil
}

// TxPoolAPI offers and API for the transaction pool. It only operates on data that is non-confidential.
type TxPoolAPI struct {
	b Backend
}

// NewTxPoolAPI creates a new tx pool service that gives information about the transaction pool.
func NewTxPoolAPI(b Backend) *TxPoolAPI {
	return &TxPoolAPI{b}
}

// Content returns the transactions contained within the transaction pool.
func (s *TxPoolAPI) Content() map[string]map[string]map[string]*RPCTransaction {
	content := map[string]map[string]map[string]*RPCTransaction{
		"pending": make(map[string]map[string]*RPCTransaction),
		"queued":  make(map[string]map[string]*RPCTransaction),
	}
	pending, queue := s.b.TxPoolContent()
	curHeader := s.b.CurrentHeader()
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// ContentFrom returns the transactions contained within the transaction pool.
func (s *TxPoolAPI) ContentFrom(addr common.Address) map[string]map[string]*RPCTransaction {
	content := make(map[string]map[string]*RPCTransaction, 2)
	pending, queue := s.b.TxPoolContentFrom(addr)
	curHeader := s.b.CurrentHeader()

	// Build the pending transactions
	dump := make(map[string]*RPCTransaction, len(pending))
	for _, tx := range pending {
		dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
	}
	content["pending"] = dump

	// Build the queued transactions
	dump = make(map[string]*RPCTransaction, len(queue))
	for _, tx := range queue {
		dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig())
	}
	content["queued"] = dump

	return content
}

// Status returns the number of pending and queued transaction in the pool.
func (s *TxPoolAPI) Status() map[string]hexutil.Uint {
	pending, queue := s.b.Stats()
	return map[string]hexutil.Uint{
		"pending": hexutil.Uint(pending),
		"queued":  hexutil.Uint(queue),
	}
}

// Inspect retrieves the content of the transaction pool and flattens it into an
// easily inspectable list.
func (s *TxPoolAPI) Inspect() map[string]map[string]map[string]string {
	content := map[string]map[string]map[string]string{
		"pending": make(map[string]map[string]string),
		"queued":  make(map[string]map[string]string),
	}
	pending, queue := s.b.TxPoolContent()

	// Define a formatter to flatten a transaction into a string
	format := func(tx *types.Transaction) string {
		if to := tx.To(); to != nil {
			return fmt.Sprintf("%s: %v wei + %v gas × %v wei", tx.To().Hex(), tx.Value(), tx.Gas(), tx.GasPrice())
		}
		return fmt.Sprintf("contract creation: %v wei + %v gas × %v wei", tx.Value(), tx.Gas(), tx.GasPrice())
	}
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// EthereumAccountAPI provides an API to access accounts managed by this node.
// It offers only methods that can retrieve accounts.
type EthereumAccountAPI struct {
	am *accounts.Manager
}

// NewEthereumAccountAPI creates a new EthereumAccountAPI.
func NewEthereumAccountAPI(am *accounts.Manager) *EthereumAccountAPI {
	return &EthereumAccountAPI{am: am}
}

// Accounts returns the collection of accounts this node manages.
func (s *EthereumAccountAPI) Accounts() []common.Address {
	return s.am.Accounts()
}

// PersonalAccountAPI provides an API to access accounts managed by this node.
// It offers methods to create, (un)lock en list accounts. Some methods accept
// passwords and are therefore considered private by default.
type PersonalAccountAPI struct {
	am        *accounts.Manager
	nonceLock *AddrLocker
	b         Backend
}

// NewPersonalAccountAPI create a new PersonalAccountAPI.
func NewPersonalAccountAPI(b Backend, nonceLock *AddrLocker) *PersonalAccountAPI {
	return &PersonalAccountAPI{
		am:        b.AccountManager(),
		nonceLock: nonceLock,
		b:         b,
	}
}

// ListAccounts will return a list of addresses for accounts this node manages.
func (s *PersonalAccountAPI) ListAccounts() []common.Address {
	return s.am.Accounts()
}

// rawWallet is a JSON representation of an accounts.Wallet interface, with its
// data contents extracted into plain fields.
type rawWallet struct {
	URL      string             `json:"url"`
	Status   string             `json:"status"`
	Failure  string             `json:"failure,omitempty"`
	Accounts []accounts.Account `json:"accounts,omitempty"`
}

// ListWallets will return a list of wallets this node manages.
func (s *PersonalAccountAPI) ListWallets() []rawWallet {
	wallets := make([]rawWallet, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		status, failure := wallet.Status()

		raw := rawWallet{
			URL:      wallet.URL().String(),
			Status:   status,
			Accounts: wallet.Accounts(),
		}
		if failure != nil {
			raw.Failure = failure.Error()
		}
		wallets = append(wallets, raw)
	}
	return wallets
}

// OpenWallet initiates a hardware wallet opening procedure, establishing a USB
// connection and attempting to authenticate via the provided passphrase. Note,
// the method may return an extra challenge requiring a second open (e.g. the
// Trezor PIN matrix challenge).
func (s *PersonalAccountAPI) OpenWallet(url string, passphrase *string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}
	pass := ""
	if passphrase != nil {
		pass = *passphrase
	}
	return wallet.Open(pass)
}

// DeriveAccount requests an HD wallet to derive a new account, optionally pinning
// it for later reuse.
func (s *PersonalAccountAPI) DeriveAccount(url string, path string, pin *bool) (accounts.Account, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return accounts.Account{}, err
	}
	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return accounts.Account{}, err
	}
	if pin == nil {
		pin = new(bool)
	}
	return wallet.Derive(derivPath, *pin)
}

// NewAccount will create a new account and returns the address for the new account.
func (s *PersonalAccountAPI) NewAccount(password string) (common.AddressEIP55, error) {
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return common.AddressEIP55{}, err
	}
	acc, err := ks.NewAccount(password)
	if err == nil {
		addrEIP55 := common.AddressEIP55(acc.Address)
		log.Info("Your new key was generated", "address", addrEIP55.String())
		log.Warn("Please backup your key file!", "path", acc.URL.Path)
		log.Warn("Please remember your password!")
		return addrEIP55, nil
	}
	return common.AddressEIP55{}, err
}

// fetchKeystore retrieves the encrypted keystore from the account manager.
func fetchKeystore(am *accounts.Manager) (*keystore.KeyStore, error) {
	if ks := am.Backends(keystore.KeyStoreType); len(ks) > 0 {
		return ks[0].(*keystore.KeyStore), nil
	}
	return nil, errors.New("local keystore not used")
}

// ImportRawKey stores the given hex encoded ECDSA key into the key directory,
// encrypting it with the passphrase.
func (s *PersonalAccountAPI) ImportRawKey(privkey string, password string) (common.Address, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return common.Address{}, err
	}
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := ks.ImportECDSA(key, password)
	return acc.Address, err
}

// UnlockAccount will unlock the account associated with the given address with
// the given password for duration seconds. If duration is nil it will use a
// default of 300 seconds. It returns an indication if the account was unlocked.
func (s *PersonalAccountAPI) UnlockAccount(ctx context.Context, addr common.Address, password string, duration *uint64) (bool, error) {
	// When the API is exposed by external RPC(http, ws etc), unless the user
	// explicitly specifies to allow the insecure account unlocking, otherwise
	// it is disabled.
	if s.b.ExtRPCEnabled() && !s.b.AccountManager().Config().InsecureUnlockAllowed {
		return false, errors.New("account unlock with HTTP access is forbidden")
	}

	const max = uint64(time.Duration(math.MaxInt64) / time.Second)
	var d time.Duration
	if duration == nil {
		d = 300 * time.Second
	} else if *duration > max {
		return false, errors.New("unlock duration too large")
	} else {
		d = time.Duration(*duration) * time.Second
	}
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return false, err
	}
	err = ks.TimedUnlock(accounts.Account{Address: addr}, password, d)
	if err != nil {
		log.Warn("Failed account unlock attempt", "address", addr, "err", err)
	}
	return err == nil, err
}

// LockAccount will lock the account associated with the given address when it's unlocked.
func (s *PersonalAccountAPI) LockAccount(addr common.Address) bool {
	if ks, err := fetchKeystore(s.am); err == nil {
		return ks.Lock(addr) == nil
	}
	return false
}

// SendTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.From. If the given
// passwd isn't able to decrypt the key it fails.
func (s *PersonalAccountAPI) SendTransaction(ctx context.Context, args TransactionArgs, passwd string) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.from()}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.from())
		defer s.nonceLock.UnlockAddr(args.from())
	}
	if args.IsEIP4844() {
		return common.Hash{}, errBlobTxNotSupported
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b, sidecarConfig{}); err != nil {
		return common.Hash{}, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.ToTransaction(types.LegacyTxType)

	signed, err := wallet.SignTx(account, tx, s.b.ChainConfig().ChainID)
	if err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, signed)
}

// sign is a helper function that signs a transaction with the private key of the given address.
func (api *PersonalAccountAPI) sign(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := api.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Request the wallet to sign the transaction
	return wallet.SignTx(account, tx, api.b.ChainConfig().ChainID)
}

// SignTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.From. If the given passwd isn't
// able to decrypt the key it fails. The transaction is returned in RLP-form, not broadcast
// to other nodes
func (s *PersonalAccountAPI) SignTransaction(ctx context.Context, args TransactionArgs, passwd string) (*SignTransactionResult, error) {
	if args.Gas == nil {
		return nil, errors.New("gas not specified")
	}
	if args.GasPrice == nil && (args.MaxPriorityFeePerGas == nil || args.MaxFeePerGas == nil) {
		return nil, errors.New("missing gasPrice or maxFeePerGas/maxPriorityFeePerGas")
	}
	if args.IsEIP4844() {
		return nil, errBlobTxNotSupported
	}
	if args.Nonce == nil {
		return nil, errors.New("nonce not specified")
	}
	sidecarVersion := types.BlobSidecarVersion0
	if len(args.Blobs) > 0 {
		h := s.b.CurrentHeader()
		if s.b.ChainConfig().IsOsaka(h.Number, h.Time) {
			sidecarVersion = types.BlobSidecarVersion1
		}
	}

	config := sidecarConfig{
		blobSidecarAllowed: true,
		blobSidecarVersion: sidecarVersion,
	}
	if err := args.setDefaults(ctx, s.b, config); err != nil {
		return nil, err
	}
	// Before actually sign the transaction, ensure the transaction fee is reasonable.
	tx := args.ToTransaction(types.LegacyTxType)
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), s.b.RPCTxFeeCap()); err != nil {
		return nil, err
	}
	signed, err := s.sign(args.from(), tx)
	if err != nil {
		return nil, err
	}
	data, err := signed.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// Sign calculates an Ethereum ECDSA signature for:
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message))
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The key used to calculate the signature is decrypted with the given password.
//
// https://github.com/zircuit-labs/l2-geth/wiki/Management-APIs#personal_sign
func (s *PersonalAccountAPI) Sign(ctx context.Context, data hexutil.Bytes, addr common.Address, passwd string) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Assemble sign the data with the wallet
	signature, err := wallet.SignTextWithPassphrase(account, passwd, data)
	if err != nil {
		log.Warn("Failed data sign attempt", "address", addr, "err", err)
		return nil, err
	}
	signature[crypto.RecoveryIDOffset] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	return signature, nil
}

// EcRecover returns the address for the account that was used to create the signature.
// Note, this function is compatible with eth_sign and personal_sign. As such it recovers
// the address of:
// hash = keccak256("\x19Ethereum Signed Message:\n"${message length}${message})
// addr = ecrecover(hash, signature)
//
// Note, the signature must conform to the secp256k1 curve R, S and V values, where
// the V value must be 27 or 28 for legacy reasons.
//
// https://github.com/zircuit-labs/l2-geth/wiki/Management-APIs#personal_ecRecover
func (s *PersonalAccountAPI) EcRecover(ctx context.Context, data, sig hexutil.Bytes) (common.Address, error) {
	if len(sig) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf("signature must be %d bytes long", crypto.SignatureLength)
	}
	if sig[crypto.RecoveryIDOffset] != 27 && sig[crypto.RecoveryIDOffset] != 28 {
		return common.Address{}, errors.New("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.SigToPub(accounts.TextHash(data), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*rpk), nil
}

// InitializeWallet initializes a new wallet at the provided URL, by generating and returning a new private key.
func (s *PersonalAccountAPI) InitializeWallet(ctx context.Context, url string) (string, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return "", err
	}

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	seed := bip39.NewSeed(mnemonic, "")

	switch wallet := wallet.(type) {
	case *scwallet.Wallet:
		return mnemonic, wallet.Initialize(seed)
	default:
		return "", errors.New("specified wallet does not support initialization")
	}
}

// Unpair deletes a pairing between wallet and geth.
func (s *PersonalAccountAPI) Unpair(ctx context.Context, url string, pin string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}

	switch wallet := wallet.(type) {
	case *scwallet.Wallet:
		return wallet.Unpair([]byte(pin))
	default:
		return errors.New("specified wallet does not support pairing")
	}
}

// BlockChainAPI provides an API to access Ethereum blockchain data.
type BlockChainAPI struct {
	b Backend
}

// NewBlockChainAPI creates a new Ethereum blockchain API.
func NewBlockChainAPI(b Backend) *BlockChainAPI {
	return &BlockChainAPI{b}
}

// ChainId is the EIP-155 replay-protection chain id for the current Ethereum chain config.
//
// Note, this method does not conform to EIP-695 because the configured chain ID is always
// returned, regardless of the current head block. We used to return an error when the chain
// wasn't synced up to a block where EIP-155 is enabled, but this behavior caused issues
// in CL clients.
func (api *BlockChainAPI) ChainId() *hexutil.Big {
	return (*hexutil.Big)(api.b.ChainConfig().ChainID)
}

// BlockNumber returns the block number of the chain head.
func (s *BlockChainAPI) BlockNumber() hexutil.Uint64 {
	header, _ := s.b.HeaderByNumber(context.Background(), rpc.LatestBlockNumber) // latest header should always be available
	return hexutil.Uint64(header.Number.Uint64())
}

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (s *BlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	header, err := headerByNumberOrHash(ctx, s.b, blockNrOrHash)
	if err != nil {
		return nil, err
	}

	if s.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if s.b.HistoricalRPCService() != nil {
			var res hexutil.Big
			err := s.b.HistoricalRPCService().CallContext(ctx, &res, "eth_getBalance", address, blockNrOrHash)
			if err != nil {
				return nil, fmt.Errorf("historical backend error: %w", err)
			}
			return &res, nil
		} else {
			return nil, rpc.ErrNoHistoricalFallback
		}
	}

	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	b := state.GetBalance(address).ToBig()
	return (*hexutil.Big)(b), state.Error()
}

// Result structs for GetProof
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

// proofList implements ethdb.KeyValueWriter and collects the proofs as
// hex-strings for delivery to rpc-caller.
type proofList []string

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, hexutil.Encode(value))
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

// GetProof returns the Merkle-proof for a given account and optionally some storage keys.
func (s *BlockChainAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	log.Debug("Got a call to GetProof", "address", address, "storageKeys", storageKeys, "blockNrOrHash", blockNrOrHash)

	header, err := headerByNumberOrHash(ctx, s.b, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	if s.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if s.b.HistoricalRPCService() != nil {
			var res AccountResult
			err := s.b.HistoricalRPCService().CallContext(ctx, &res, "eth_getProof", address, storageKeys, blockNrOrHash)
			if err != nil {
				return nil, fmt.Errorf("historical backend error: %w", err)
			}
			return &res, nil
		} else {
			return nil, rpc.ErrNoHistoricalFallback
		}
	}
	var (
		keys         = make([]common.Hash, len(storageKeys))
		keyLengths   = make([]int, len(storageKeys))
		storageProof = make([]StorageResult, len(storageKeys))
	)
	// Deserialize all keys. This prevents state access on invalid input.
	for i, hexKey := range storageKeys {
		var err error
		keys[i], keyLengths[i], err = decodeHash(hexKey)
		if err != nil {
			return nil, err
		}
	}
	statedb, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if statedb == nil || err != nil {
		return nil, err
	}
	codeHash := statedb.GetCodeHash(address)
	storageRoot := statedb.GetStorageRoot(address)

	if len(keys) > 0 {
		var storageTrie state.Trie
		if storageRoot != types.EmptyRootHash {
			id := trie.StorageTrieID(header.Root, crypto.Keccak256Hash(address.Bytes()), storageRoot)
			storageTrie, err = trie.NewStateTrie(id, statedb.Database().TrieDB())
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
				storageProof[i] = StorageResult{outputKey, &hexutil.Big{}, []string{}}
				continue
			}

			var proof proofList
			if err := storageTrie.Prove(crypto.Keccak256(key.Bytes()), &proof); err != nil {
				return nil, err
			}

			value := (*hexutil.Big)(statedb.GetState(address, key).Big())
			storageProof[i] = StorageResult{outputKey, value, proof}
		}
	}

	balance := statedb.GetBalance(address).ToBig()
	result := &AccountResult{
		Address:      address,
		Balance:      (*hexutil.Big)(balance),
		CodeHash:     codeHash,
		Nonce:        hexutil.Uint64(statedb.GetNonce(address)),
		StorageHash:  storageRoot,
		StorageProof: storageProof,
	}

	log.Debug("Default Trie logic will be used to get account proof")
	tr, err := trie.NewStateTrie(trie.StateTrieID(header.Root), statedb.Database().TrieDB())
	if err != nil {
		return nil, err
	}

	var accountProof proofList
	if err = tr.Prove(crypto.Keccak256(address.Bytes()), &accountProof); err != nil {
		return nil, err
	}
	result.AccountProof = accountProof
	return result, statedb.Error()
}

// decodeHash parses a hex-encoded 32-byte hash. The input may optionally
// be prefixed by 0x and can have a byte length up to 32.
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

// extendBlockRpc adds additional fields to the block rpc response.
func (s *BlockChainAPI) extendBlockRpc(rpcBlock map[string]any) {
	if rpcBlock["hash"] != nil {
		l1Info := rawdb.ReadL1Info(s.b.ChainDb(), rpcBlock["hash"].(common.Hash))
		rpcBlock["l1Info"] = l1Info
	}
}

// GetHeaderByNumber returns the requested canonical block header.
//   - When blockNr is -1 the chain pending header is returned.
//   - When blockNr is -2 the chain latest header is returned.
//   - When blockNr is -3 the chain finalized header is returned.
//   - When blockNr is -4 the chain safe header is returned.
func (api *BlockChainAPI) GetHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (map[string]any, error) {
	header, err := api.b.HeaderByNumber(ctx, number)
	if header != nil && err == nil {
		response := RPCMarshalHeader(header)
		if number == rpc.PendingBlockNumber && api.b.ChainConfig().Optimism == nil {
			// Pending header need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetHeaderByHash returns the requested header by hash.
func (api *BlockChainAPI) GetHeaderByHash(ctx context.Context, hash common.Hash) map[string]any {
	header, _ := api.b.HeaderByHash(ctx, hash)
	if header != nil {
		return RPCMarshalHeader(header)
	}
	return nil
}

// GetBlockByNumber returns the requested canonical block.
//   - When blockNr is -1 the chain pending block is returned.
//   - When blockNr is -2 the chain latest block is returned.
//   - When blockNr is -3 the chain finalized block is returned.
//   - When blockNr is -4 the chain safe block is returned.
//   - When fullTx is true all transactions in the block are returned, otherwise
//     only the transaction hash is returned.
func (api *BlockChainAPI) GetBlockByNumber(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]any, error) {
	block, err := api.b.BlockByNumber(ctx, number)
	if block != nil && err == nil {
		response, err := RPCMarshalBlock(ctx, block, true, fullTx, api.b.ChainConfig(), api.b)
		if err == nil && number == rpc.PendingBlockNumber && api.b.ChainConfig().Optimism == nil {
			// Pending blocks need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetBlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (api *BlockChainAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]any, error) {
	block, err := api.b.BlockByHash(ctx, hash)
	if block != nil {
		return RPCMarshalBlock(ctx, block, true, fullTx, api.b.ChainConfig(), api.b)
	}
	return nil, err
}

// GetBlockByNumberEx returns an extended version of GetBlockByNumber.
//   - Adds L1Info.
func (s *BlockChainAPI) GetBlockByNumberEx(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]any, error) {
	response, err := s.GetBlockByNumber(ctx, number, fullTx)
	if err != nil {
		return nil, err
	}

	s.extendBlockRpc(response)

	return response, nil
}

// GetBlockByHashEX returns an extended version of GetBlockByHash.
//   - Adds L1Info.
func (s *BlockChainAPI) GetBlockByHashEx(ctx context.Context, hash common.Hash, fullTx bool) (map[string]any, error) {
	response, err := s.GetBlockByHash(ctx, hash, fullTx)
	if err != nil {
		return nil, err
	}

	s.extendBlockRpc(response)

	return response, nil
}

// GetUncleByBlockNumberAndIndex returns the uncle block for the given block hash and index.
func (api *BlockChainAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]any, error) {
	block, err := api.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", blockNr, "hash", block.Hash(), "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return RPCMarshalBlock(ctx, block, false, false, api.b.ChainConfig(), api.b)
	}
	return nil, err
}

// GetUncleByBlockHashAndIndex returns the uncle block for the given block hash and index.
func (api *BlockChainAPI) GetUncleByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]any, error) {
	block, err := api.b.BlockByHash(ctx, blockHash)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", block.Number(), "hash", blockHash, "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return RPCMarshalBlock(ctx, block, false, false, api.b.ChainConfig(), api.b)
	}
	return nil, err
}

// GetUncleCountByBlockNumber returns number of uncles in the block for the given block number
func (s *BlockChainAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetUncleCountByBlockHash returns number of uncles in the block for the given block hash
func (s *BlockChainAPI) GetUncleCountByBlockHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (s *BlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	log.Debug("Got a call to GetCode", "address", address, "blockNrOrHash", blockNrOrHash)

	header, err := headerByNumberOrHash(ctx, s.b, blockNrOrHash)
	if err != nil {
		return nil, err
	}

	if s.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if s.b.HistoricalRPCService() != nil {
			var res hexutil.Bytes
			err := s.b.HistoricalRPCService().CallContext(ctx, &res, "eth_getCode", address, blockNrOrHash)
			if err != nil {
				return nil, fmt.Errorf("historical backend error: %w", err)
			}
			return res, nil
		} else {
			return nil, rpc.ErrNoHistoricalFallback
		}
	}

	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	code := state.GetCode(address)
	return code, state.Error()
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
func (s *BlockChainAPI) GetStorageAt(ctx context.Context, address common.Address, hexKey string, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	header, err := headerByNumberOrHash(ctx, s.b, blockNrOrHash)
	if err != nil {
		return nil, err
	}

	if s.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if s.b.HistoricalRPCService() != nil {
			var res hexutil.Bytes
			err := s.b.HistoricalRPCService().CallContext(ctx, &res, "eth_getStorageAt", address, hexKey, blockNrOrHash)
			if err != nil {
				return nil, fmt.Errorf("historical backend error: %w", err)
			}
			return res, nil
		} else {
			return nil, rpc.ErrNoHistoricalFallback
		}
	}

	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	key, _, err := decodeHash(hexKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode storage key: %s", err)
	}
	res := state.GetState(address, key)
	return res[:], state.Error()
}

// The HeaderByNumberOrHash method returns a nil error and nil header
// if the header is not found, but only for nonexistent block numbers. This is
// different from StateAndHeaderByNumberOrHash. To account for this discrepancy,
// headerOrNumberByHash will properly convert the error into an ethereum.NotFound.
func headerByNumberOrHash(ctx context.Context, b Backend, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	header, err := b.HeaderByNumberOrHash(ctx, blockNrOrHash)
	if header == nil {
		return nil, fmt.Errorf("header %w", ethereum.NotFound)
	}
	return header, err
}

// GetBlockReceipts returns the block receipts for the given block hash or number or tag.
func (s *BlockChainAPI) GetBlockReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]map[string]any, error) {
	block, err := s.b.BlockByNumberOrHash(ctx, blockNrOrHash)
	if block == nil || err != nil {
		// When the block doesn't exist, the RPC method should return JSON null
		// as per specification.
		return nil, nil
	}
	receipts, err := s.b.GetReceipts(ctx, block.Hash())
	if err != nil {
		return nil, err
	}
	txs := block.Transactions()
	if len(txs) != len(receipts) {
		return nil, fmt.Errorf("receipts length mismatch: %d vs %d", len(txs), len(receipts))
	}

	// Derive the sender.
	signer := types.MakeSigner(s.b.ChainConfig(), block.Number(), block.Time())

	result := make([]map[string]any, len(receipts))
	for i, receipt := range receipts {
		result[i] = marshalReceipt(receipt, block.Hash(), block.NumberU64(), signer, txs[i], i, s.b.ChainConfig())
	}

	return result, nil
}

// ChainContextBackend provides methods required to implement ChainContext.
type ChainContextBackend interface {
	Engine() consensus.Engine
	HeaderByNumber(context.Context, rpc.BlockNumber) (*types.Header, error)
	ChainConfig() *params.ChainConfig
}

// ChainContext is an implementation of core.ChainContext. It's main use-case
// is instantiating a vm.BlockContext without having access to the BlockChain object.
type ChainContext struct {
	b   ChainContextBackend
	ctx context.Context
}

// NewChainContext creates a new ChainContext object.
func NewChainContext(ctx context.Context, backend ChainContextBackend) *ChainContext {
	return &ChainContext{ctx: ctx, b: backend}
}

func (context *ChainContext) Engine() consensus.Engine {
	return context.b.Engine()
}

func (context *ChainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	// This method is called to get the hash for a block number when executing the BLOCKHASH
	// opcode. Hence no need to search for non-canonical blocks.
	header, err := context.b.HeaderByNumber(context.ctx, rpc.BlockNumber(number))
	if err != nil || header.Hash() != hash {
		return nil
	}
	return header
}

func (context *ChainContext) Config() *params.ChainConfig {
	return context.b.ChainConfig()
}

// ChainlessChainContext is also an implementation of core.ChainContext that doesn't need blockchain object
// Additionally, it contains cache of non-persisted simulated block headers that can be fetched for evm execution.
// Cache map is not safe for concurrent use.
type ChainlessChainContext struct {
	b        ChainContextBackend
	ctx      context.Context
	simCache map[uint64]*types.Header // cache of simulated block headers
}

func NewChainlessChainContext(ctx context.Context, backend ChainContextBackend, headers map[uint64]*types.Header) *ChainlessChainContext {
	return &ChainlessChainContext{
		b:        backend,
		ctx:      ctx,
		simCache: headers,
	}
}

func (rc *ChainlessChainContext) Engine() consensus.Engine {
	return rc.b.Engine()
}

func (rc *ChainlessChainContext) Config() *params.ChainConfig {
	return rc.b.ChainConfig()
}

func (rc *ChainlessChainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	// This method is called to get the hash for a block number when executing the BLOCKHASH opcode
	header, err := rc.b.HeaderByNumber(rc.ctx, rpc.BlockNumber(number))
	if err != nil {
		return nil
	}
	if header.Hash() == hash {
		return header
	}
	header = rc.simCache[number]
	if header == nil || header.Hash() != hash {
		return nil
	}

	return header
}

func doCall(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, overrides *override.StateOverride, blockOverrides *override.BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil, b.ChainConfig(), state)
	if blockOverrides != nil {
		if err := blockOverrides.Apply(&blockCtx); err != nil {
			return nil, err
		}
	}
	rules := b.ChainConfig().Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time)
	precompiles := vm.ActivePrecompiledContracts(rules)
	if err := overrides.Apply(state, precompiles); err != nil {
		return nil, err
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()
	gp := new(core.GasPool)
	if globalGasCap == 0 {
		gp.AddGas(gomath.MaxUint64)
	} else {
		gp.AddGas(globalGasCap)
	}
	return applyMessage(ctx, b, args, state, header, timeout, gp, &blockCtx, &vm.Config{NoBaseFee: true}, precompiles, true)
}

func applyMessage(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, timeout time.Duration, gp *core.GasPool, blockContext *vm.BlockContext, vmConfig *vm.Config, precompiles vm.PrecompiledContracts, skipChecks bool) (*core.ExecutionResult, error) {
	// Get a new instance of the EVM.
	if err := args.CallDefaults(gp.Gas(), blockContext.BaseFee, b.ChainConfig().ChainID); err != nil {
		return nil, err
	}
	msg := args.ToMessage(header.BaseFee, skipChecks, skipChecks)
	// Lower the basefee to 0 to avoid breaking EVM
	// invariants (basefee < feecap).
	if msg.GasPrice.Sign() == 0 {
		blockContext.BaseFee = new(big.Int)
	}
	if msg.BlobGasFeeCap != nil && msg.BlobGasFeeCap.BitLen() == 0 {
		blockContext.BlobBaseFee = new(big.Int)
	}
	evm := b.GetEVM(ctx, state, header, vmConfig, blockContext)
	if precompiles != nil {
		evm.SetPrecompiles(precompiles)
	}
	res, err := applyMessageWithEVM(ctx, evm, msg, timeout, gp)
	// If an internal state error occurred, let that have precedence. Otherwise,
	// a "trie root missing" type of error will masquerade as e.g. "insufficient gas"
	if err := state.Error(); err != nil {
		return nil, err
	}
	return res, err
}

func applyMessageWithEVM(ctx context.Context, evm *vm.EVM, msg *core.Message, timeout time.Duration, gp *core.GasPool) (*core.ExecutionResult, error) {
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	result, err := core.ApplyMessage(evm, msg, gp)

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit)
	}
	return result, nil
}

func DoCall(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	return doCall(ctx, b, args, state, header, overrides, blockOverrides, timeout, globalGasCap)
}

// Call executes the given transaction on the state for the given block number.
//
// Additionally, the caller can specify a batch of contract for fields overriding.
//
// Note, this function doesn't make and changes in the state/blockchain and is
// useful to execute and retrieve values.
func (s *BlockChainAPI) Call(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides) (hexutil.Bytes, error) {
	if blockNrOrHash == nil {
		latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		blockNrOrHash = &latest
	}
	header, err := headerByNumberOrHash(ctx, s.b, *blockNrOrHash)
	if err != nil {
		return nil, err
	}

	if s.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if s.b.HistoricalRPCService() != nil {
			var res hexutil.Bytes
			err := s.b.HistoricalRPCService().CallContext(ctx, &res, "eth_call", args, blockNrOrHash, overrides)
			if err != nil {
				return nil, fmt.Errorf("historical backend error: %w", err)
			}
			return res, nil
		} else {
			return nil, rpc.ErrNoHistoricalFallback
		}
	}

	result, err := DoCall(ctx, s.b, args, *blockNrOrHash, overrides, blockOverrides, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
	if err != nil {
		return nil, err
	}
	// If the result contains a revert reason, try to unpack and return it.
	if len(result.Revert()) > 0 {
		return nil, newRevertError(result.Revert())
	}
	return result.Return(), result.Err
}

// SimulateV1 executes series of transactions on top of a base state.
// The transactions are packed into blocks. For each block, block header
// fields can be overridden. The state can also be overridden prior to
// execution of each block.
//
// Note, this function doesn't make any changes in the state/blockchain and is
// useful to execute and retrieve values.
func (api *BlockChainAPI) SimulateV1(ctx context.Context, opts simOpts, blockNrOrHash *rpc.BlockNumberOrHash) ([]*simBlockResult, error) {
	if len(opts.BlockStateCalls) == 0 {
		return nil, &invalidParamsError{message: "empty input"}
	} else if len(opts.BlockStateCalls) > maxSimulateBlocks {
		return nil, &clientLimitExceededError{message: "too many blocks"}
	}
	if blockNrOrHash == nil {
		n := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		blockNrOrHash = &n
	}
	state, base, err := api.b.StateAndHeaderByNumberOrHash(ctx, *blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	gasCap := api.b.RPCGasCap()
	if gasCap == 0 {
		gasCap = gomath.MaxUint64
	}
	sim := &simulator{
		b:           api.b,
		state:       state,
		base:        base,
		chainConfig: api.b.ChainConfig(),
		// Each tx and all the series of txes shouldn't consume more gas than cap
		gp:             new(core.GasPool).AddGas(gasCap),
		traceTransfers: opts.TraceTransfers,
		validate:       opts.Validation,
		fullTx:         opts.ReturnFullTransactions,
	}
	return sim.execute(ctx, opts.BlockStateCalls)
}

// DoEstimateGas returns the lowest possible gas limit that allows the transaction to run
// successfully at block `blockNrOrHash`. It returns error if the transaction would revert, or if
// there are unexpected failures. The gas limit is capped by both `args.Gas` (if non-nil &
// non-zero) and `gasCap` (if non-zero).
func DoEstimateGas(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides, gasCap uint64) (hexutil.Uint64, error) {
	// Retrieve the base state and mutate it with any overrides
	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return 0, err
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil, b.ChainConfig(), state)
	if blockOverrides != nil {
		if err := blockOverrides.Apply(&blockCtx); err != nil {
			return 0, err
		}
	}
	rules := b.ChainConfig().Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time)
	precompiles := vm.ActivePrecompiledContracts(rules)
	if err := overrides.Apply(state, precompiles); err != nil {
		return 0, err
	}
	// Construct the gas estimator option from the user input
	opts := &gasestimator.Options{
		Config:     b.ChainConfig(),
		Chain:      NewChainContext(ctx, b),
		Header:     header,
		State:      state,
		ErrorRatio: estimateGasErrorRatio,
	}
	// Set any required transaction default, but make sure the gas cap itself is not messed with
	// if it was not specified in the original argument list.
	if args.Gas == nil {
		args.Gas = new(hexutil.Uint64)
	}
	if err := args.CallDefaults(gasCap, header.BaseFee, b.ChainConfig().ChainID); err != nil {
		return 0, err
	}
	call := args.ToMessage(header.BaseFee, true, true)

	// Run the gas estimation and wrap any revertals into a custom return
	estimate, revert, err := gasestimator.Estimate(ctx, call, opts, gasCap)
	if err != nil {
		if errors.Is(err, vm.ErrExecutionReverted) {
			return 0, newRevertError(revert)
		}
		return 0, err
	}
	return hexutil.Uint64(estimate), nil
}

// EstimateGas returns the lowest possible gas limit that allows the transaction to run
// successfully at block `blockNrOrHash`, or the latest block if `blockNrOrHash` is unspecified. It
// returns error if the transaction would revert or if there are unexpected failures. The returned
// value is capped by both `args.Gas` (if non-nil & non-zero) and the backend's RPCGasCap
// configuration (if non-zero).
// Note: Required blob gas is not computed in this method.
func (api *BlockChainAPI) EstimateGas(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides) (hexutil.Uint64, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}

	header, err := headerByNumberOrHash(ctx, api.b, bNrOrHash)
	if err != nil {
		return 0, err
	}

	if api.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if api.b.HistoricalRPCService() != nil {
			var res hexutil.Uint64
			err := api.b.HistoricalRPCService().CallContext(ctx, &res, "eth_estimateGas", args, blockNrOrHash)
			if err != nil {
				return 0, fmt.Errorf("historical backend error: %w", err)
			}
			return res, nil
		} else {
			return 0, rpc.ErrNoHistoricalFallback
		}
	}

	return DoEstimateGas(ctx, api.b, args, bNrOrHash, overrides, blockOverrides, api.b.RPCGasCap())
}

// RPCMarshalHeader converts the given header to the RPC output .
func RPCMarshalHeader(head *types.Header) map[string]any {
	result := map[string]any{
		"number":           (*hexutil.Big)(head.Number),
		"hash":             head.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"miner":            head.Coinbase,
		"difficulty":       (*hexutil.Big)(head.Difficulty),
		"extraData":        hexutil.Bytes(head.Extra),
		"gasLimit":         hexutil.Uint64(head.GasLimit),
		"gasUsed":          hexutil.Uint64(head.GasUsed),
		"timestamp":        hexutil.Uint64(head.Time),
		"transactionsRoot": head.TxHash,
		"receiptsRoot":     head.ReceiptHash,
	}
	if head.BaseFee != nil {
		result["baseFeePerGas"] = (*hexutil.Big)(head.BaseFee)
	}
	if head.WithdrawalsHash != nil {
		result["withdrawalsRoot"] = head.WithdrawalsHash
	}
	if head.BlobGasUsed != nil {
		result["blobGasUsed"] = hexutil.Uint64(*head.BlobGasUsed)
	}
	if head.ExcessBlobGas != nil {
		result["excessBlobGas"] = hexutil.Uint64(*head.ExcessBlobGas)
	}
	if head.ParentBeaconRoot != nil {
		result["parentBeaconBlockRoot"] = head.ParentBeaconRoot
	}
	if head.RequestsHash != nil {
		result["requestsHash"] = head.RequestsHash
	}
	return result
}

// RPCMarshalBlock converts the given block to the RPC output which depends on fullTx. If inclTx is true transactions are
// returned. When fullTx is true the returned block contains full transaction details, otherwise it will only contain
// transaction hashes.
func RPCMarshalBlock(ctx context.Context, block *types.Block, inclTx bool, fullTx bool, config *params.ChainConfig, backend ReceiptGetter) (map[string]any, error) {
	fields := RPCMarshalHeader(block.Header())
	fields["size"] = hexutil.Uint64(block.Size())

	if inclTx {
		formatTx := func(idx int, tx *types.Transaction) any {
			return tx.Hash()
		}
		if fullTx {
			formatTx = func(idx int, tx *types.Transaction) any {
				return newRPCTransactionFromBlockIndex(ctx, block, uint64(idx), config, backend)
			}
		}
		txs := block.Transactions()
		transactions := make([]any, len(txs))
		for i, tx := range txs {
			transactions[i] = formatTx(i, tx)
		}
		fields["transactions"] = transactions
	}
	uncles := block.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes
	if block.Withdrawals() != nil {
		fields["withdrawals"] = block.Withdrawals()
	}
	return fields, nil
}

// RPCTransaction represents a transaction that will serialize to the RPC representation of a transaction
type RPCTransaction struct {
	BlockHash           *common.Hash                 `json:"blockHash"`
	BlockNumber         *hexutil.Big                 `json:"blockNumber"`
	From                common.Address               `json:"from"`
	Gas                 hexutil.Uint64               `json:"gas"`
	GasPrice            *hexutil.Big                 `json:"gasPrice"`
	GasFeeCap           *hexutil.Big                 `json:"maxFeePerGas,omitempty"`
	GasTipCap           *hexutil.Big                 `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerBlobGas    *hexutil.Big                 `json:"maxFeePerBlobGas,omitempty"`
	Hash                common.Hash                  `json:"hash"`
	Input               hexutil.Bytes                `json:"input"`
	Nonce               hexutil.Uint64               `json:"nonce"`
	To                  *common.Address              `json:"to"`
	TransactionIndex    *hexutil.Uint64              `json:"transactionIndex"`
	Value               *hexutil.Big                 `json:"value"`
	Type                hexutil.Uint64               `json:"type"`
	Accesses            *types.AccessList            `json:"accessList,omitempty"`
	ChainID             *hexutil.Big                 `json:"chainId,omitempty"`
	BlobVersionedHashes []common.Hash                `json:"blobVersionedHashes,omitempty"`
	AuthorizationList   []types.SetCodeAuthorization `json:"authorizationList,omitempty"`
	V                   *hexutil.Big                 `json:"v"`
	R                   *hexutil.Big                 `json:"r"`
	S                   *hexutil.Big                 `json:"s"`
	YParity             *hexutil.Uint64              `json:"yParity,omitempty"`

	// deposit-tx only
	SourceHash *common.Hash `json:"sourceHash,omitempty"`
	Mint       *hexutil.Big `json:"mint,omitempty"`
	IsSystemTx *bool        `json:"isSystemTx,omitempty"`
	// deposit-tx post-Canyon only
	DepositReceiptVersion *hexutil.Uint64 `json:"depositReceiptVersion,omitempty"`
}

// newRPCTransaction returns a transaction that will serialize to the RPC
// representation, with the given location metadata set (if available).
func newRPCTransaction(tx *types.Transaction, blockHash common.Hash, blockNumber uint64, blockTime uint64, index uint64, baseFee *big.Int, config *params.ChainConfig, receipt *types.Receipt) *RPCTransaction {
	signer := types.MakeSigner(config, new(big.Int).SetUint64(blockNumber), blockTime)
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()
	result := &RPCTransaction{
		Type:     hexutil.Uint64(tx.Type()),
		From:     from,
		Gas:      hexutil.Uint64(tx.Gas()),
		GasPrice: (*hexutil.Big)(tx.GasPrice()),
		Hash:     tx.Hash(),
		Input:    hexutil.Bytes(tx.Data()),
		Nonce:    hexutil.Uint64(tx.Nonce()),
		To:       tx.To(),
		Value:    (*hexutil.Big)(tx.Value()),
		V:        (*hexutil.Big)(v),
		R:        (*hexutil.Big)(r),
		S:        (*hexutil.Big)(s),
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = &blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		result.TransactionIndex = (*hexutil.Uint64)(&index)
	}

	switch tx.Type() {
	case types.DepositTxType:
		srcHash := tx.SourceHash()
		isSystemTx := tx.IsSystemTx()
		result.SourceHash = &srcHash
		if isSystemTx {
			// Only include IsSystemTx when true
			result.IsSystemTx = &isSystemTx
		}
		result.Mint = (*hexutil.Big)(tx.Mint())
		if receipt != nil && receipt.DepositNonce != nil {
			result.Nonce = hexutil.Uint64(*receipt.DepositNonce)
			if receipt.DepositReceiptVersion != nil {
				result.DepositReceiptVersion = new(hexutil.Uint64)
				*result.DepositReceiptVersion = hexutil.Uint64(*receipt.DepositReceiptVersion)
			}
		}
	case types.LegacyTxType:
		if v.Sign() == 0 && r.Sign() == 0 && s.Sign() == 0 { // pre-bedrock relayed tx does not have a signature
			result.ChainID = (*hexutil.Big)(new(big.Int).Set(config.ChainID))
			break
		}
		// if a legacy transaction has an EIP-155 chain id, include it explicitly
		if id := tx.ChainId(); id.Sign() != 0 {
			result.ChainID = (*hexutil.Big)(id)
		}

	case types.AccessListTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity

	case types.DynamicFeeTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		if baseFee != nil && blockHash != (common.Hash{}) {
			// price = min(gasTipCap + baseFee, gasFeeCap)
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}

	case types.BlobTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		if baseFee != nil && blockHash != (common.Hash{}) {
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}
		result.MaxFeePerBlobGas = (*hexutil.Big)(tx.BlobGasFeeCap())
		result.BlobVersionedHashes = tx.BlobHashes()

	case types.SetCodeTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		if baseFee != nil && blockHash != (common.Hash{}) {
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}
		result.AuthorizationList = tx.SetCodeAuthorizations()
	}
	return result
}

// effectiveGasPrice computes the transaction gas fee, based on the given basefee value.
//
//	price = min(gasTipCap + baseFee, gasFeeCap)
func effectiveGasPrice(tx *types.Transaction, baseFee *big.Int) *big.Int {
	fee := tx.GasTipCap()
	fee = fee.Add(fee, baseFee)
	if tx.GasFeeCapIntCmp(fee) < 0 {
		return tx.GasFeeCap()
	}
	return fee
}

// NewRPCPendingTransaction returns a pending transaction that will serialize to the RPC representation
func NewRPCPendingTransaction(tx *types.Transaction, current *types.Header, config *params.ChainConfig) *RPCTransaction {
	var (
		baseFee     *big.Int
		blockNumber = uint64(0)
		blockTime   = uint64(0)
	)
	if current != nil {
		baseFee = eip1559.CalcBaseFee(config, current, current.Time+1)
		blockNumber = current.Number.Uint64()
		blockTime = current.Time
	}
	return newRPCTransaction(tx, common.Hash{}, blockNumber, blockTime, 0, baseFee, config, nil)
}

// newRPCTransactionFromBlockIndex returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockIndex(ctx context.Context, b *types.Block, index uint64, config *params.ChainConfig, backend ReceiptGetter) *RPCTransaction {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	tx := txs[index]
	rcpt := depositTxReceipt(ctx, b.Hash(), index, backend, tx)
	return newRPCTransaction(tx, b.Hash(), b.NumberU64(), b.Time(), index, b.BaseFee(), config, rcpt)
}

type ReceiptGetter interface {
	GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error)
}

func depositTxReceipt(ctx context.Context, blockHash common.Hash, index uint64, backend ReceiptGetter, tx *types.Transaction) *types.Receipt {
	if tx.Type() != types.DepositTxType {
		return nil
	}
	receipts, err := backend.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil
	}
	if index >= uint64(len(receipts)) {
		return nil
	}
	return receipts[index]
}

// newRPCRawTransactionFromBlockIndex returns the bytes of a transaction given a block and a transaction index.
func newRPCRawTransactionFromBlockIndex(b *types.Block, index uint64) hexutil.Bytes {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	blob, _ := txs[index].MarshalBinary()
	return blob
}

// GetRowConsumptionByBlockHashes returns summed up row consumption for given blocks
func (s *BlockChainAPI) GetRowConsumptionByBlockHashes(_ context.Context, blockHashes []common.Hash) *types.RowConsumption {
	rowConsumptionMap := make(map[string]uint64)

	for _, blockHash := range blockHashes {
		blockRowConsumption := rawdb.ReadBlockRowConsumption(s.b.ChainDb(), blockHash)
		if blockRowConsumption == nil {
			log.Error("row consumption for the provided block is nil", "blockHash", blockHash.String())
			continue
		}

		subCircuitRowUsages := []types.SubCircuitRowUsage(*blockRowConsumption)
		for _, subCircuitRowUsage := range subCircuitRowUsages {
			opRowConsumption, ok := rowConsumptionMap[subCircuitRowUsage.Name]

			if ok {
				sum := opRowConsumption + subCircuitRowUsage.RowNumber
				rowConsumptionMap[subCircuitRowUsage.Name] = sum
				continue
			}

			rowConsumptionMap[subCircuitRowUsage.Name] = subCircuitRowUsage.RowNumber
		}
	}

	totalRowConsumption := make([]types.SubCircuitRowUsage, 0)
	for name, rowConsumption := range rowConsumptionMap {
		totalRowConsumption = append(totalRowConsumption, types.SubCircuitRowUsage{
			Name:      name,
			RowNumber: rowConsumption,
		})
	}

	res := types.RowConsumption(totalRowConsumption)

	return &res
}

// accessListResult returns an optional accesslist
// It's the result of the `debug_createAccessList` RPC call.
// It contains an error if the transaction itself failed.
type accessListResult struct {
	Accesslist *types.AccessList `json:"accessList"`
	Error      string            `json:"error,omitempty"`
	GasUsed    hexutil.Uint64    `json:"gasUsed"`
}

// CreateAccessList creates an EIP-2930 type AccessList for the given transaction.
// Reexec and BlockNrOrHash can be specified to create the accessList on top of a certain state.
// StateOverrides can be used to create the accessList while taking into account state changes from previous transactions.
func (api *BlockChainAPI) CreateAccessList(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, stateOverrides *override.StateOverride) (*accessListResult, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}

	header, err := headerByNumberOrHash(ctx, api.b, bNrOrHash)
	if err == nil && header != nil && api.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if api.b.HistoricalRPCService() != nil {
			var res accessListResult
			err := api.b.HistoricalRPCService().CallContext(ctx, &res, "eth_createAccessList", args, blockNrOrHash)
			if err != nil {
				return nil, fmt.Errorf("historical backend error: %w", err)
			}
			return &res, nil
		} else {
			return nil, rpc.ErrNoHistoricalFallback
		}
	}

	acl, gasUsed, vmerr, err := AccessList(ctx, api.b, bNrOrHash, args, stateOverrides)
	if err != nil {
		return nil, err
	}
	result := &accessListResult{Accesslist: &acl, GasUsed: hexutil.Uint64(gasUsed)}
	if vmerr != nil {
		result.Error = vmerr.Error()
	}
	return result, nil
}

// AccessList creates an access list for the given transaction.
// If the accesslist creation fails an error is returned.
// If the transaction itself fails, an vmErr is returned.
func AccessList(ctx context.Context, b Backend, blockNrOrHash rpc.BlockNumberOrHash, args TransactionArgs, stateOverrides *override.StateOverride) (acl types.AccessList, gasUsed uint64, vmErr error, err error) {
	// Retrieve the execution context
	db, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if db == nil || err != nil {
		return nil, 0, nil, err
	}

	// Apply state overrides immediately after StateAndHeaderByNumberOrHash.
	// If not applied here, there could be cases where user-specified overrides (e.g., nonce)
	// may conflict with default values from the database, leading to inconsistencies.
	if stateOverrides != nil {
		if err := stateOverrides.Apply(db, nil); err != nil {
			return nil, 0, nil, err
		}
	}

	// Ensure any missing fields are filled, extract the recipient and input data
	if err = args.setFeeDefaults(ctx, b, header); err != nil {
		return nil, 0, nil, err
	}
	if args.Nonce == nil {
		nonce := hexutil.Uint64(db.GetNonce(args.from()))
		args.Nonce = &nonce
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil, b.ChainConfig(), db)
	if err = args.CallDefaults(b.RPCGasCap(), blockCtx.BaseFee, b.ChainConfig().ChainID); err != nil {
		return nil, 0, nil, err
	}

	var to common.Address
	if args.To != nil {
		to = *args.To
	} else {
		to = crypto.CreateAddress(args.from(), uint64(*args.Nonce))
	}
	isPostMerge := header.Difficulty.Sign() == 0
	// Retrieve the precompiles since they don't need to be added to the access list
	precompiles := vm.ActivePrecompiles(b.ChainConfig().Rules(header.Number, isPostMerge, header.Time))

	// addressesToExclude contains sender, receiver, precompiles and valid authorizations
	addressesToExclude := map[common.Address]struct{}{args.from(): {}, to: {}}
	for _, addr := range precompiles {
		addressesToExclude[addr] = struct{}{}
	}

	// Prevent redundant operations if args contain more authorizations than EVM may handle
	maxAuthorizations := uint64(*args.Gas) / params.CallNewAccountGas
	if uint64(len(args.AuthorizationList)) > maxAuthorizations {
		return nil, 0, nil, errors.New("insufficient gas to process all authorizations")
	}

	for _, auth := range args.AuthorizationList {
		// Duplicating stateTransition.validateAuthorization() logic
		if (!auth.ChainID.IsZero() && auth.ChainID.CmpBig(b.ChainConfig().ChainID) != 0) || auth.Nonce+1 < auth.Nonce {
			continue
		}

		if authority, err := auth.Authority(); err == nil {
			addressesToExclude[authority] = struct{}{}
		}
	}

	// Create an initial tracer
	prevTracer := logger.NewAccessListTracer(nil, addressesToExclude)
	if args.AccessList != nil {
		prevTracer = logger.NewAccessListTracer(*args.AccessList, addressesToExclude)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, nil, err
		}
		// Retrieve the current access list to expand
		accessList := prevTracer.AccessList()
		log.Trace("Creating access list", "input", accessList)

		// Copy the original db so we don't modify it
		statedb := db.Copy()
		// Set the accesslist to the last al
		args.AccessList = &accessList
		msg := args.ToMessage(header.BaseFee, true, true)

		// Apply the transaction with the access list tracer
		tracer := logger.NewAccessListTracer(accessList, addressesToExclude)
		config := vm.Config{Tracer: tracer.Hooks(), NoBaseFee: true}
		evm := b.GetEVM(ctx, statedb, header, &config, nil)

		// Lower the basefee to 0 to avoid breaking EVM
		// invariants (basefee < feecap).
		if msg.GasPrice.Sign() == 0 {
			evm.Context.BaseFee = new(big.Int)
		}
		if msg.BlobGasFeeCap != nil && msg.BlobGasFeeCap.BitLen() == 0 {
			evm.Context.BlobBaseFee = new(big.Int)
		}
		res, err := core.ApplyMessage(evm, msg, new(core.GasPool).AddGas(msg.GasLimit))
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to apply transaction: %v err: %v", args.ToTransaction(types.LegacyTxType).Hash(), err)
		}
		if tracer.Equal(prevTracer) {
			return accessList, res.UsedGas, res.Err, nil
		}
		prevTracer = tracer
	}
}

// TransactionAPI exposes methods for reading and creating transaction data.
type TransactionAPI struct {
	b                     Backend
	nonceLock             *AddrLocker
	signer                types.Signer
	slsQuarantineVerifier SLSQuarantineVerifier
}

type SLSQuarantineVerifier interface {
	IsQuarantined(ctx context.Context, txHash common.Hash) (*slsapiCommon.IsQuarantinedResponse, error)
}

// NewTransactionAPI creates a new RPC service with methods for interacting with transactions.
func NewTransactionAPI(b Backend, nonceLock *AddrLocker, slsQuarantineVerifier SLSQuarantineVerifier) *TransactionAPI {
	// The signer used by the API should always be the 'latest' known one because we expect
	// signers to be backwards-compatible with old transactions.
	signer := types.LatestSigner(b.ChainConfig())
	return &TransactionAPI{
		b:                     b,
		nonceLock:             nonceLock,
		signer:                signer,
		slsQuarantineVerifier: slsQuarantineVerifier,
	}
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
func (s *TransactionAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetBlockTransactionCountByHash returns the number of transactions in the block with the given hash.
func (s *TransactionAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetTransactionByBlockNumberAndIndex returns the transaction for the given block number and index.
func (s *TransactionAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(ctx, block, uint64(index), s.b.ChainConfig(), s.b)
	}
	return nil
}

// GetTransactionByBlockHashAndIndex returns the transaction for the given block hash and index.
func (s *TransactionAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(ctx, block, uint64(index), s.b.ChainConfig(), s.b)
	}
	return nil
}

// GetRawTransactionByBlockNumberAndIndex returns the bytes of the transaction for the given block number and index.
func (s *TransactionAPI) GetRawTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockHashAndIndex returns the bytes of the transaction for the given block hash and index.
func (s *TransactionAPI) GetRawTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (s *TransactionAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	// Ask transaction pool for the nonce which includes pending transactions
	if blockNr, ok := blockNrOrHash.Number(); ok && blockNr == rpc.PendingBlockNumber {
		nonce, err := s.b.GetPoolNonce(ctx, address)
		if err != nil {
			return nil, err
		}
		return (*hexutil.Uint64)(&nonce), nil
	}
	// Resolve block number and use its state to ask for the nonce
	header, err := headerByNumberOrHash(ctx, s.b, blockNrOrHash)
	if err != nil {
		return nil, err
	}

	if s.b.ChainConfig().IsOptimismPreBedrock(header.Number) {
		if s.b.HistoricalRPCService() != nil {
			var res hexutil.Uint64
			err := s.b.HistoricalRPCService().CallContext(ctx, &res, "eth_getTransactionCount", address, blockNrOrHash)
			if err != nil {
				return nil, fmt.Errorf("historical backend error: %w", err)
			}
			return &res, nil
		} else {
			return nil, rpc.ErrNoHistoricalFallback
		}
	}

	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	nonce := state.GetNonce(address)
	return (*hexutil.Uint64)(&nonce), state.Error()
}

// GetTransactionByHash returns the transaction for the given hash
func (api *TransactionAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	// Try to return an already finalized transaction
	found, tx, blockHash, blockNumber, index := api.b.GetCanonicalTransaction(hash)

	quarantine, slsErr := api.getSLSQuarantine(ctx, hash)
	if slsErr != nil {
		return nil, slsErr
	}
	// Return the transaction as normal if quarantined
	// Quarantined txs will get an error when retrieving the receipt
	if quarantine != nil {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(quarantine.TxData); err != nil {
			return nil, err
		}
		return NewRPCPendingTransaction(&tx, api.b.CurrentHeader(), api.b.ChainConfig()), nil
	}

	if !found {
		// No finalized transaction, try to retrieve it from the pool
		if tx := api.b.GetPoolTransaction(hash); tx != nil {
			return NewRPCPendingTransaction(tx, api.b.CurrentHeader(), api.b.ChainConfig()), nil
		}
		// If also not in the pool there is a chance the tx indexer is still in progress.
		if !api.b.TxIndexDone() {
			return nil, NewTxIndexingError()
		}
		// If the transaction is not found in the pool and the indexer is done, return nil
		return nil, nil
	}
	header, err := api.b.HeaderByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	rcpt := depositTxReceipt(ctx, blockHash, index, api.b, tx)
	return newRPCTransaction(tx, blockHash, blockNumber, header.Time, index, header.BaseFee, api.b.ChainConfig(), rcpt), nil
}

// GetRawTransactionByHash returns the bytes of the transaction for the given hash.
func (api *TransactionAPI) GetRawTransactionByHash(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	found, tx, _, _, _ := api.b.GetCanonicalTransaction(hash)
	if !found {
		if tx = api.b.GetPoolTransaction(hash); tx != nil {
			return tx.MarshalBinary()
		}
		// If also not in the pool there is a chance the tx indexer is still in progress.
		if !api.b.TxIndexDone() {
			return nil, NewTxIndexingError()
		}
		// If the transaction is not found in the pool and the indexer is done, return nil
		return nil, nil
	}
	return tx.MarshalBinary()
}

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
// If the SLS quarantine verification system is enabled and the transaction is quarantined,
// an error will be returned detailing the quarantine reason and authority.
// If SLS is disabled, the function assumes the node does not interact with the SLS
// and proceeds to retrieve the transaction receipt as normal.
func (s *TransactionAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]any, error) {
	found, tx, blockHash, blockNumber, index := s.b.GetCanonicalTransaction(hash)
	if !found {
		if err := s.verifySLSQuarantine(ctx, hash); err != nil {
			return nil, err
		}
		// Make sure indexer is done.
		if !s.b.TxIndexDone() {
			return nil, NewTxIndexingError()
		}

		return nil, nil
	}
	header, err := s.b.HeaderByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	receipts, err := s.b.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if uint64(len(receipts)) <= index {
		if err := s.verifySLSQuarantine(ctx, hash); err != nil {
			return nil, err
		}

		return nil, nil
	}
	receipt := receipts[index]

	// Derive the sender.
	signer := types.MakeSigner(s.b.ChainConfig(), header.Number, header.Time)
	return marshalReceipt(receipt, blockHash, blockNumber, signer, tx, int(index), s.b.ChainConfig()), nil
}

// verifySLSQuarantine checks whether the transaction identified by the given hash is quarantined via SLS.
// Returns an error if the transaction is quarantined or if there's an issue with the SLS verification process.
// If SLS is disabled, it proceeds as though no quarantine check was performed and returns nil.
func (s *TransactionAPI) verifySLSQuarantine(ctx context.Context, hash common.Hash) error {
	// ErrSLSDisabled means that SLS is not active, so the function will proceed as
	// if no quarantine check could be performed. This allows the func to work with or without SLS.
	result, err := s.slsQuarantineVerifier.IsQuarantined(ctx, hash)
	if err != nil && errors.Is(err, slsapiCommon.ErrSLSDisabled) {
		return nil
	}
	if err != nil {
		return NewSLSError()
	}

	if result != nil && result.IsQuarantined && result.Quarantine != nil {
		return NewSLSQuarantineError(result.Quarantine.QuarantinedReason, result.Quarantine.QuarantinedBy)
	}

	return nil
}

// getSLSQuarantine gets the transaction by hash if it is quarantined.
// If SLS is disabled, it proceeds as though no quarantine check was performed and returns nil.
func (s *TransactionAPI) getSLSQuarantine(ctx context.Context, hash common.Hash) (*slsapiCommon.IsQuarantinedResponse, error) {
	// ErrSLSDisabled means that SLS is not active, so the function will proceed as
	// if no quarantine check could be performed. This allows the func to work with or without SLS.
	result, err := s.slsQuarantineVerifier.IsQuarantined(ctx, hash)
	if err != nil && errors.Is(err, slsapiCommon.ErrSLSDisabled) {
		return nil, nil
	}
	if err != nil {
		return nil, NewSLSError()
	}
	if result != nil && result.IsQuarantined && result.Quarantine != nil && result.TxData != nil {
		return result, nil
	}

	return nil, nil
}

// marshalReceipt marshals a transaction receipt into a JSON object.
func marshalReceipt(receipt *types.Receipt, blockHash common.Hash, blockNumber uint64, signer types.Signer, tx *types.Transaction, txIndex int, chainConfig *params.ChainConfig) map[string]any {
	from, _ := types.Sender(signer, tx)

	fields := map[string]any{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   tx.Hash(),
		"transactionIndex":  hexutil.Uint64(txIndex),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
		"type":              hexutil.Uint(tx.Type()),
		"effectiveGasPrice": (*hexutil.Big)(receipt.EffectiveGasPrice),
	}

	if chainConfig.Optimism != nil && !tx.IsDepositTx() {
		fields["l1GasPrice"] = (*hexutil.Big)(receipt.L1GasPrice)
		fields["l1GasUsed"] = (*hexutil.Big)(receipt.L1GasUsed)
		fields["l1Fee"] = (*hexutil.Big)(receipt.L1Fee)
		if receipt.FeeScalar != nil { // removed in Ecotone
			fields["l1FeeScalar"] = receipt.FeeScalar.String()
		}
		// Fields added in Ecotone
		if receipt.L1BlobBaseFee != nil {
			fields["l1BlobBaseFee"] = (*hexutil.Big)(receipt.L1BlobBaseFee)
		}
		if receipt.L1BaseFeeScalar != nil {
			fields["l1BaseFeeScalar"] = hexutil.Uint64(*receipt.L1BaseFeeScalar)
		}
		if receipt.L1BlobBaseFeeScalar != nil {
			fields["l1BlobBaseFeeScalar"] = hexutil.Uint64(*receipt.L1BlobBaseFeeScalar)
		}
		// Fields added in Isthmus
		if receipt.OperatorFeeScalar != nil {
			fields["operatorFeeScalar"] = hexutil.Uint64(*receipt.OperatorFeeScalar)
		}
		if receipt.OperatorFeeConstant != nil {
			fields["operatorFeeConstant"] = hexutil.Uint64(*receipt.OperatorFeeConstant)
		}

	}
	if chainConfig.Optimism != nil && tx.IsDepositTx() && receipt.DepositNonce != nil {
		fields["depositNonce"] = hexutil.Uint64(*receipt.DepositNonce)
		if receipt.DepositReceiptVersion != nil {
			fields["depositReceiptVersion"] = hexutil.Uint64(*receipt.DepositReceiptVersion)
		}
	}

	// Assign receipt status or post state.
	if len(receipt.PostState) > 0 {
		fields["root"] = hexutil.Bytes(receipt.PostState)
	} else {
		fields["status"] = hexutil.Uint(receipt.Status)
	}
	if receipt.Logs == nil {
		fields["logs"] = []*types.Log{}
	}

	if tx.Type() == types.BlobTxType {
		fields["blobGasUsed"] = hexutil.Uint64(receipt.BlobGasUsed)
		fields["blobGasPrice"] = (*hexutil.Big)(receipt.BlobGasPrice)
	}

	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields
}

// sign is a helper function that signs a transaction with the private key of the given address.
func (s *TransactionAPI) sign(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Request the wallet to sign the transaction
	return wallet.SignTx(account, tx, s.b.ChainConfig().ChainID)
}

// SubmitTransaction is a helper function that submits tx to txPool and logs a message.
func SubmitTransaction(ctx context.Context, b Backend, tx *types.Transaction) (common.Hash, error) {
	// If the transaction fee cap is already specified, ensure the
	// fee of the given transaction is _reasonable_.
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	if !b.UnprotectedAllowed() && !tx.Protected() {
		// Ensure only eip155 signed transactions are submitted if EIP155Required is set.
		return common.Hash{}, errors.New("only replay-protected (EIP-155) transactions allowed over RPC")
	}
	if err := b.SendTx(ctx, tx); err != nil {
		return common.Hash{}, err
	}
	// Print a log with full tx details for manual investigations and interventions
	head := b.CurrentBlock()
	signer := types.MakeSigner(b.ChainConfig(), head.Number, head.Time)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return common.Hash{}, err
	}

	if tx.To() == nil {
		addr := crypto.CreateAddress(from, tx.Nonce())
		log.Info("Submitted contract creation", "hash", tx.Hash().Hex(), "from", from, "nonce", tx.Nonce(), "contract", addr.Hex(), "value", tx.Value())
	} else {
		log.Info("Submitted transaction", "hash", tx.Hash().Hex(), "from", from, "nonce", tx.Nonce(), "recipient", tx.To(), "value", tx.Value())
	}
	return tx.Hash(), nil
}

// SendTransaction creates a transaction for the given argument, sign it and submit it to the
// transaction pool.
func (s *TransactionAPI) SendTransaction(ctx context.Context, args TransactionArgs) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.from()}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.from())
		defer s.nonceLock.UnlockAddr(args.from())
	}
	if args.IsEIP4844() {
		return common.Hash{}, errBlobTxNotSupported
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b, sidecarConfig{}); err != nil {
		return common.Hash{}, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.ToTransaction(types.LegacyTxType)

	signed, err := wallet.SignTx(account, tx, s.b.ChainConfig().ChainID)
	if err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, signed)
}

// FillTransaction fills the defaults (nonce, gas, gasPrice or 1559 fields)
// on a given unsigned transaction, and returns it to the caller for further
// processing (signing + broadcast).
func (s *TransactionAPI) FillTransaction(ctx context.Context, args TransactionArgs) (*SignTransactionResult, error) {
	// Set some sanity defaults and terminate on failure
	sidecarVersion := types.BlobSidecarVersion0
	if len(args.Blobs) > 0 {
		h := s.b.CurrentHeader()
		if s.b.ChainConfig().IsOsaka(h.Number, h.Time) {
			sidecarVersion = types.BlobSidecarVersion1
		}
	}
	config := sidecarConfig{
		blobSidecarAllowed: true,
		blobSidecarVersion: sidecarVersion,
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b, config); err != nil {
		return nil, err
	}
	// Assemble the transaction and obtain rlp
	tx := args.ToTransaction(types.LegacyTxType)
	// TODO(s1na): fill in blob proofs, commitments
	data, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, tx}, nil
}

// SendRawTransaction will add the signed transaction to the transaction pool.
// The sender is responsible for signing the transaction and using the correct nonce.
func (s *TransactionAPI) SendRawTransaction(ctx context.Context, input hexutil.Bytes) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(input); err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, tx)
}

// Sign calculates an ECDSA signature for:
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message).
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The account associated with addr must be unlocked.
//
// https://github.com/zircuit-labs/wiki/wiki/JSON-RPC#eth_sign
func (s *TransactionAPI) Sign(addr common.Address, data hexutil.Bytes) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Sign the requested hash with the wallet
	signature, err := wallet.SignText(account, data)
	if err == nil {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	}
	return signature, err
}

// SignTransactionResult represents a RLP encoded signed transaction.
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// SignTransaction will sign the given transaction with the from account.
// The node needs to have the private key of the account corresponding with
// the given from address and it needs to be unlocked.
func (s *TransactionAPI) SignTransaction(ctx context.Context, args TransactionArgs) (*SignTransactionResult, error) {
	if args.Gas == nil {
		return nil, errors.New("gas not specified")
	}
	if args.GasPrice == nil && (args.MaxPriorityFeePerGas == nil || args.MaxFeePerGas == nil) {
		return nil, errors.New("missing gasPrice or maxFeePerGas/maxPriorityFeePerGas")
	}
	if args.IsEIP4844() {
		return nil, errBlobTxNotSupported
	}
	if args.Nonce == nil {
		return nil, errors.New("nonce not specified")
	}

	sidecarVersion := types.BlobSidecarVersion0
	if len(args.Blobs) > 0 {
		h := s.b.CurrentHeader()
		if s.b.ChainConfig().IsOsaka(h.Number, h.Time) {
			sidecarVersion = types.BlobSidecarVersion1
		}
	}

	config := sidecarConfig{
		blobSidecarAllowed: true,
		blobSidecarVersion: sidecarVersion,
	}
	if err := args.setDefaults(ctx, s.b, config); err != nil {
		return nil, err
	}
	// Before actually sign the transaction, ensure the transaction fee is reasonable.
	tx := args.ToTransaction(types.LegacyTxType)
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), s.b.RPCTxFeeCap()); err != nil {
		return nil, err
	}
	signed, err := s.sign(args.from(), tx)
	if err != nil {
		return nil, err
	}
	data, err := signed.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// PendingTransactions returns the transactions that are in the transaction pool
// and have a from address that is one of the accounts this node manages.
func (s *TransactionAPI) PendingTransactions() ([]*RPCTransaction, error) {
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return nil, err
	}
	accounts := make(map[common.Address]struct{})
	for _, wallet := range s.b.AccountManager().Wallets() {
		for _, account := range wallet.Accounts() {
			accounts[account.Address] = struct{}{}
		}
	}
	curHeader := s.b.CurrentHeader()
	transactions := make([]*RPCTransaction, 0, len(pending))
	for _, tx := range pending {
		from, _ := types.Sender(s.signer, tx)
		if _, exists := accounts[from]; exists {
			transactions = append(transactions, NewRPCPendingTransaction(tx, curHeader, s.b.ChainConfig()))
		}
	}
	return transactions, nil
}

// Resend accepts an existing transaction and a new gas price and limit. It will remove
// the given transaction from the pool and reinsert it with the new gas price and limit.
func (s *TransactionAPI) Resend(ctx context.Context, sendArgs TransactionArgs, gasPrice *hexutil.Big, gasLimit *hexutil.Uint64) (common.Hash, error) {
	if sendArgs.Nonce == nil {
		return common.Hash{}, errors.New("missing transaction nonce in transaction spec")
	}
	if err := sendArgs.setDefaults(ctx, s.b, sidecarConfig{}); err != nil {
		return common.Hash{}, err
	}
	matchTx := sendArgs.ToTransaction(types.LegacyTxType)

	// Before replacing the old transaction, ensure the _new_ transaction fee is reasonable.
	price := matchTx.GasPrice()
	if gasPrice != nil {
		price = gasPrice.ToInt()
	}
	gas := matchTx.Gas()
	if gasLimit != nil {
		gas = uint64(*gasLimit)
	}
	if err := checkTxFee(price, gas, s.b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	// Iterate the pending list for replacement
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return common.Hash{}, err
	}
	for _, p := range pending {
		wantSigHash := s.signer.Hash(matchTx)
		pFrom, err := types.Sender(s.signer, p)
		if err == nil && pFrom == sendArgs.from() && s.signer.Hash(p) == wantSigHash {
			// Match. Re-sign and send the transaction.
			if gasPrice != nil && (*big.Int)(gasPrice).Sign() != 0 {
				sendArgs.GasPrice = gasPrice
			}
			if gasLimit != nil && *gasLimit != 0 {
				sendArgs.Gas = gasLimit
			}
			signedTx, err := s.sign(sendArgs.from(), sendArgs.ToTransaction(types.LegacyTxType))
			if err != nil {
				return common.Hash{}, err
			}
			if err = s.b.SendTx(ctx, signedTx); err != nil {
				return common.Hash{}, err
			}
			return signedTx.Hash(), nil
		}
	}
	return common.Hash{}, fmt.Errorf("transaction %#x not found", matchTx.Hash())
}

// DebugAPI is the collection of Ethereum APIs exposed over the debugging
// namespace.
type DebugAPI struct {
	b Backend
}

// NewDebugAPI creates a new instance of DebugAPI.
func NewDebugAPI(b Backend) *DebugAPI {
	return &DebugAPI{b: b}
}

// GetRawHeader retrieves the RLP encoding for a single header.
func (api *DebugAPI) GetRawHeader(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	header, _ := api.b.HeaderByHash(ctx, hash)
	if header == nil {
		return nil, fmt.Errorf("header #%d not found", hash)
	}
	return rlp.EncodeToBytes(header)
}

// GetRawBlock retrieves the RLP encoded for a single block.
func (api *DebugAPI) GetRawBlock(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	block, _ := api.b.BlockByHash(ctx, hash)
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", hash)
	}
	return rlp.EncodeToBytes(block)
}

// GetRawReceipts retrieves the binary-encoded receipts of a single block.
func (api *DebugAPI) GetRawReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	receipts, err := api.b.GetReceipts(ctx, hash)
	if err != nil {
		return nil, err
	}
	result := make([]hexutil.Bytes, len(receipts))
	for i, receipt := range receipts {
		b, err := receipt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		result[i] = b
	}
	return result, nil
}

// GetRawTransaction returns the bytes of the transaction for the given hash.
func (s *DebugAPI) GetRawTransaction(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	found, tx, _, _, _ := s.b.GetCanonicalTransaction(hash)
	if !found {
		if tx = s.b.GetPoolTransaction(hash); tx != nil {
			return tx.MarshalBinary()
		}
		// If also not in the pool there is a chance the tx indexer is still in progress.
		if !s.b.TxIndexDone() {
			return nil, NewTxIndexingError()
		}
		return nil, NewTxIndexingError()
	}
	return tx.MarshalBinary()
}

// PrintBlock retrieves a block and returns its pretty printed form.
func (api *DebugAPI) PrintBlock(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return spew.Sdump(block), nil
}

// ChaindbProperty returns leveldb properties of the key-value database.
func (api *DebugAPI) ChaindbProperty() (string, error) {
	return api.b.ChainDb().Stat()
}

// ChaindbCompact flattens the entire key-value database into a single level,
// removing all unused slots and merging all keys.
func (api *DebugAPI) ChaindbCompact() error {
	cstart := time.Now()
	for b := 0; b <= 255; b++ {
		var (
			start = []byte{byte(b)}
			end   = []byte{byte(b + 1)}
		)
		if b == 255 {
			end = nil
		}
		log.Info("Compacting database", "range", fmt.Sprintf("%#X-%#X", start, end), "elapsed", common.PrettyDuration(time.Since(cstart)))
		if err := api.b.ChainDb().Compact(start, end); err != nil {
			log.Error("Database compaction failed", "err", err)
			return err
		}
	}
	return nil
}

// SetHead rewinds the head of the blockchain to a previous block.
func (api *DebugAPI) SetHead(number hexutil.Uint64) {
	api.b.SetHead(uint64(number))
}

func (api *DebugAPI) ChainConfig() *params.ChainConfig {
	return api.b.ChainConfig()
}

// NetAPI offers network related RPC methods
type NetAPI struct {
	net            *p2p.Server
	networkVersion uint64
}

// NewNetAPI creates a new net API instance.
func NewNetAPI(net *p2p.Server, networkVersion uint64) *NetAPI {
	return &NetAPI{net, networkVersion}
}

// Listening returns an indication if the node is listening for network connections.
func (s *NetAPI) Listening() bool {
	return true // always listening
}

// PeerCount returns the number of connected peers
func (s *NetAPI) PeerCount() hexutil.Uint {
	return hexutil.Uint(s.net.PeerCount())
}

// Version returns the current ethereum protocol version.
func (s *NetAPI) Version() string {
	return fmt.Sprintf("%d", s.networkVersion)
}

// checkTxFee is an internal function used to check whether the fee of
// the given transaction is _reasonable_(under the cap).
func checkTxFee(gasPrice *big.Int, gas uint64, cap float64) error {
	// Short circuit if there is no cap for transaction fee at all.
	if cap == 0 {
		return nil
	}
	feeEth := new(big.Float).Quo(new(big.Float).SetInt(new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gas))), new(big.Float).SetInt(big.NewInt(params.Ether)))
	feeFloat, _ := feeEth.Float64()
	if feeFloat > cap {
		return fmt.Errorf("tx fee (%.2f ether) exceeds the configured cap (%.2f ether)", feeFloat, cap)
	}
	return nil
}

// toHexSlice creates a slice of hex-strings based on []byte.
func toHexSlice(b [][]byte) []string {
	r := make([]string, len(b))
	for i := range b {
		r[i] = hexutil.Encode(b[i])
	}
	return r
}
