package storage

import (
	"context"
	"sync"
	"time"

	"github.com/zircuit-labs/l2-geth-public/core/sls/model"

	"github.com/zircuit-labs/l2-geth-public/common"
)

type (
	// Memory struct provides an in-memory storage mechanism for quarantined transactions,
	// using a map to associate Ethereum transaction hashes with Quarantine objects.
	Memory struct {
		data                    map[common.Hash]*model.Quarantine
		integrityListData       map[common.Address]*model.IntegrityListEntry
		quarantineDetectorCalls map[string]*model.QuarantineDetectorCalls
		admins                  []common.Address
		transactionResults      map[string]*model.TransactionResult
		trustListData           map[common.Address]*model.TrustListEntry
		// for now, just using a single lock for all maps because this storage is only used for testing;
		// we can have more granular locks for each individual map for better performance
		mu sync.RWMutex
	}
)

// NewMemory initializes and returns a new instance of Memory storage.
func NewMemory() *Memory {
	return &Memory{
		data:                    map[common.Hash]*model.Quarantine{},
		integrityListData:       map[common.Address]*model.IntegrityListEntry{},
		admins:                  []common.Address{},
		transactionResults:      map[string]*model.TransactionResult{},
		quarantineDetectorCalls: map[string]*model.QuarantineDetectorCalls{},
		trustListData:           map[common.Address]*model.TrustListEntry{},
	}
}

// All retrieves a paginated list of all quarantined transactions stored in memory.
func (m *Memory) All(ctx context.Context, offset, limit int, from *common.Address) ([]*model.Quarantine, int, error) {
	var paginatedQuarantines []*model.Quarantine

	currentIndex := 0
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, quarantine := range m.data {
		if currentIndex >= offset && currentIndex < offset+limit {
			if from == nil || from.String() == quarantine.From {
				paginatedQuarantines = append(paginatedQuarantines, quarantine)
			}
		}

		currentIndex++

		if currentIndex >= offset+limit {
			break
		}
	}

	return paginatedQuarantines, len(m.data), nil
}

// Add inserts a new quarantined transaction into the memory storage.
func (m *Memory) Add(ctx context.Context, quarantine *model.Quarantine) error {
	tx, err := quarantine.Tx()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.data[tx.Hash()] = quarantine
	m.mu.Unlock()

	return nil
}

// Quarantined retrieves all transactions that are currently quarantined and not released.
func (m *Memory) Quarantined(ctx context.Context, from *common.Address) ([]*model.Quarantine, int, error) {
	quarantines := make([]*model.Quarantine, 0, len(m.data))
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, quarantine := range m.data {
		if quarantine.IsReleased {
			continue
		}

		if from != nil && from.String() != quarantine.From {
			continue
		}

		quarantines = append(quarantines, quarantine)
	}

	return quarantines, len(m.data), nil
}

// Release marks a quarantined transaction as released in the memory storage.
func (m *Memory) Release(ctx context.Context, txHash common.Hash, reason string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[txHash]
	if !ok {
		return false, nil
	}

	m.data[txHash].SetExpiresOn(time.Now())
	m.data[txHash].Release(reason)

	return true, nil
}

// SetExpiresOn updates the expiration time of a quarantined transaction in memory.
func (m *Memory) SetExpiresOn(ctx context.Context, txHash common.Hash, expiresOn time.Time, releaser common.Address) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[txHash]
	if !ok {
		return false, nil
	}

	m.data[txHash].SetExpiresOn(expiresOn)
	m.data[txHash].SetReleaser(releaser)
	return true, nil
}

// IsQuarantined checks if a given transaction hash corresponds to a transaction that is currently quarantined.
func (m *Memory) IsQuarantined(ctx context.Context, txHash common.Hash) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	quarantine, ok := m.data[txHash]
	if !ok {
		return false, nil
	}

	return !quarantine.IsReleased, nil
}

// PendingRelease retrieves all transactions currently in quarantine that are pending release due to their expiration.
func (m *Memory) PendingRelease(ctx context.Context, quarantineType model.QuarantineType) ([]*model.Quarantine, error) {
	var pendingReleaseQuarantines []*model.Quarantine
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, quarantine := range m.data {
		if quarantine.ShouldBeReleased() && quarantine.QuarantineType == quarantineType {
			pendingReleaseQuarantines = append(pendingReleaseQuarantines, quarantine)
		}
	}

	return pendingReleaseQuarantines, nil
}

func (m *Memory) FindByHash(ctx context.Context, txHash common.Hash) (*model.Quarantine, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	quarantine, ok := m.data[txHash]
	if !ok {
		return nil, ErrTransactionNotFound
	}

	return quarantine, nil
}

// Ping is a no-operation for memory storage but conforms to the storage interface.
func (m *Memory) Ping(ctx context.Context) error {
	return nil
}

func (m *Memory) AddIntegrityListAddresses(ctx context.Context, addresses []common.Address) error {
	entries := entriesFromAddresses(addresses)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range entries {
		m.integrityListData[common.HexToAddress(entry.Address)] = entry
	}
	return nil
}

func (m *Memory) RemoveIntegrityListAddresses(ctx context.Context, addresses []common.Address) error {
	entries := entriesFromAddresses(addresses)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range entries {
		delete(m.integrityListData, common.HexToAddress(entry.Address))
	}
	return nil
}

func (m *Memory) GetIntegrityListAddresses(ctx context.Context) ([]common.Address, error) {
	var entries []*model.IntegrityListEntry
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, entry := range m.integrityListData {
		entries = append(entries, entry)
	}
	return addressesFromEntries(entries), nil
}

func (m *Memory) AddressesInIntegrityList(ctx context.Context, addresses []common.Address) ([]common.Address, error) {
	var foundAddresses []common.Address
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, address := range addresses {
		if _, ok := m.integrityListData[address]; ok {
			foundAddresses = append(foundAddresses, address)
		}
	}
	return foundAddresses, nil
}

// LogQuarantineDetectorLog adds a new quarantine log to the memory.
func (m *Memory) LogQuarantineDetectorLog(ctx context.Context, call *model.QuarantineDetectorCalls) error {
	m.mu.Lock()
	m.quarantineDetectorCalls[call.TxHash] = call
	m.mu.Unlock()
	return nil
}

func (m *Memory) GetAdminAddresses(ctx context.Context) ([]common.Address, error) {
	return m.admins, nil
}

func (m *Memory) IsAdmin(ctx context.Context, address common.Address) (bool, error) {
	for _, admin := range m.admins {
		if admin.Cmp(address) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// AddTransactionResult adds a new transaction result to the memory storage.
func (m *Memory) AddTransactionResult(ctx context.Context, result *model.TransactionResult) error {
	m.mu.Lock()
	m.transactionResults[result.TxHash] = result
	m.mu.Unlock()
	return nil
}

// IsQuarantinedAndScanned checks if a given transaction hash corresponds to a transaction that is currently quarantined or has been scanned.
func (m *Memory) IsQuarantinedAndScanned(ctx context.Context, txHash common.Hash) (*model.TransactionResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	quarantine, quarantineFound := m.data[txHash]
	result, resultFound := m.transactionResults[txHash.String()]

	if !resultFound {
		return nil, ErrTransactionNotFound
	}

	if quarantineFound {
		result.Quarantine = quarantine
	}

	return result, nil
}

// AddressInTrustList implements Storage.
func (m *Memory) AddressInTrustList(ctx context.Context, address common.Address) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.trustListData[address]
	if !ok {
		return false, nil
	}

	return true, nil
}

// AddTrustListAddresses adds a new trusted address to the memory storage.
func (m *Memory) AddTrustListAddresses(ctx context.Context, addresses []common.Address) error {
	entries := trustListEntriesFromAddresses(addresses)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range entries {
		m.trustListData[common.HexToAddress(entry.Address)] = entry
	}
	return nil
}

// RemoveTrustListAddresses removes a trusted address from the memory storage.
func (m *Memory) RemoveTrustListAddresses(ctx context.Context, addresses []common.Address) error {
	entries := trustListEntriesFromAddresses(addresses)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range entries {
		delete(m.trustListData, common.HexToAddress(entry.Address))
	}
	return nil
}

// GetTrustListAddresses implements Storage.
func (m *Memory) GetTrustListAddresses(ctx context.Context) ([]common.Address, error) {
	var entries []*model.TrustListEntry
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, entry := range m.trustListData {
		entries = append(entries, entry)
	}
	return addressesFromTrustListEntries(entries), nil
}

// AddressesInTrustList implements Storage.
func (m *Memory) AddressesInTrustList(ctx context.Context, addresses []common.Address) ([]common.Address, error) {
	var foundAddresses []common.Address
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, address := range addresses {
		if _, ok := m.trustListData[address]; ok {
			foundAddresses = append(foundAddresses, address)
		}
	}
	return foundAddresses, nil
}
