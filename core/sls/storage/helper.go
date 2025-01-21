package storage

import (
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
)

func entriesFromAddresses(addresses []common.Address) []*model.IntegrityListEntry {
	entries := make([]*model.IntegrityListEntry, 0, len(addresses))
	for _, address := range addresses {
		entries = append(entries, &model.IntegrityListEntry{Address: address.Hex()})
	}
	return entries
}

func addressesFromEntries(entries []*model.IntegrityListEntry) []common.Address {
	addresses := make([]common.Address, 0, len(entries))
	for _, entry := range entries {
		addresses = append(addresses, common.HexToAddress(entry.Address))
	}
	return addresses
}

func trustListEntriesFromAddresses(addresses []common.Address) []*model.TrustListEntry {
	entries := make([]*model.TrustListEntry, 0, len(addresses))
	for _, address := range addresses {
		entries = append(entries, &model.TrustListEntry{Address: address.Hex()})
	}
	return entries
}

func addressesFromTrustListEntries(entries []*model.TrustListEntry) []common.Address {
	addresses := make([]common.Address, 0, len(entries))
	for _, entry := range entries {
		addresses = append(addresses, common.HexToAddress(entry.Address))
	}
	return addresses
}
