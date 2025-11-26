// Copyright 2016 The go-ethereum Authors
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

package types

import (
	"container/heap"
	"maps"
	"slices"
	"sort"
	"sync"
)

// nonceHeap is a heap.Interface implementation over 64bit unsigned integers for
// retrieving sorted transactions from the possibly gapped future queue.
type nonceHeap []uint64

func (h nonceHeap) Len() int           { return len(h) }
func (h nonceHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h nonceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *nonceHeap) Push(x any) {
	*h = append(*h, x.(uint64))
}

func (h *nonceHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = 0
	*h = old[0 : n-1]
	return x
}

// SortedMap is a nonce->transaction hash map with a heap based index to allow
// iterating over the contents in a nonce-incrementing way.
type SortedMap struct {
	items   map[uint64]*Transaction // Hash map storing the transaction data
	index   *nonceHeap              // Heap of nonces of all the stored transactions (non-strict mode)
	cache   Transactions            // Cache of the transactions already sorted
	cacheMu sync.Mutex              // Mutex covering the cache
}

// NewSortedMap creates a new nonce-sorted transaction map.
func NewSortedMap() *SortedMap {
	return &SortedMap{
		items: make(map[uint64]*Transaction),
		index: new(nonceHeap),
	}
}

// Get retrieves the current transactions associated with the given nonce.
func (m *SortedMap) Get(nonce uint64) *Transaction {
	return m.items[nonce]
}

// Len returns the number of transactions in the map.
func (m *SortedMap) Len() int {
	return len(m.items)
}

// Items retrieves a copy of the current transactions.
func (m *SortedMap) Items() map[uint64]*Transaction {
	items := make(map[uint64]*Transaction, len(m.items))
	maps.Copy(items, m.items)
	return items
}

// Put inserts a new transaction into the map, also updating the map's nonce
// index. If a transaction already exists with the same nonce, it's overwritten.
func (m *SortedMap) Put(tx *Transaction) {
	nonce := tx.Nonce()
	if m.items[nonce] == nil {
		heap.Push(m.index, nonce)
	}
	m.cacheMu.Lock()
	m.items[nonce], m.cache = tx, nil
	m.cacheMu.Unlock()
}

// Forward removes all transactions from the map with a nonce lower than the
// provided threshold. Every removed transaction is returned for any post-removal
// maintenance.
func (m *SortedMap) Forward(threshold uint64) Transactions {
	var removed Transactions

	// Pop off heap items until the threshold is reached
	for m.index.Len() > 0 && (*m.index)[0] < threshold {
		nonce := heap.Pop(m.index).(uint64)
		removed = append(removed, m.items[nonce])
		delete(m.items, nonce)
	}
	// If we had a cached order, shift the front
	m.cacheMu.Lock()
	if m.cache != nil {
		m.cache = m.cache[len(removed):]
	}
	m.cacheMu.Unlock()
	return removed
}

// Filter iterates over the list of transactions and removes all of them for which
// the specified function evaluates to true.
// Filter, as opposed to 'filter', re-initialises the heap after the operation is done.
// If you want to do several consecutive filterings, it's therefore better to first
// do a .filter(func1) followed by .Filter(func2) or reheap()
func (m *SortedMap) Filter(filter func(*Transaction) bool) Transactions {
	removed := m.FilterNoReheap(filter)
	// If transactions were removed, the heap and cache are ruined
	if len(removed) > 0 {
		m.Reheap()
	}
	return removed
}

func (m *SortedMap) Reheap() {
	*m.index = make([]uint64, 0, len(m.items))
	for nonce := range m.items {
		*m.index = append(*m.index, nonce)
	}
	heap.Init(m.index)
	m.cacheMu.Lock()
	m.cache = nil
	m.cacheMu.Unlock()
}

// FilterNoReheap is identical to Filter, but **does not** regenerate the heap. This method
// should only be used if followed immediately by a call to Filter or reheap()
func (m *SortedMap) FilterNoReheap(filter func(*Transaction) bool) Transactions {
	var removed Transactions

	// Collect all the transactions to filter out
	for nonce, tx := range m.items {
		if filter(tx) {
			removed = append(removed, tx)
			delete(m.items, nonce)
		}
	}
	if len(removed) > 0 {
		m.cacheMu.Lock()
		m.cache = nil
		m.cacheMu.Unlock()
	}
	return removed
}

// Cap places a hard limit on the number of items, returning all transactions
// exceeding that limit.
func (m *SortedMap) Cap(threshold int) Transactions {
	// Short circuit if the number of items is under the limit
	if len(m.items) <= threshold {
		return nil
	}
	// Otherwise gather and drop the highest nonce'd transactions
	var drops Transactions
	slices.Sort(*m.index)
	for size := len(m.items); size > threshold; size-- {
		drops = append(drops, m.items[(*m.index)[size-1]])
		delete(m.items, (*m.index)[size-1])
	}
	*m.index = (*m.index)[:threshold]
	// The sorted m.index slice is still a valid heap, so there is no need to
	// reheap after deleting tail items.

	// If we had a cache, shift the back
	m.cacheMu.Lock()
	if m.cache != nil {
		m.cache = m.cache[:len(m.cache)-len(drops)]
	}
	m.cacheMu.Unlock()
	return drops
}

// Remove deletes a transaction from the maintained map, returning whether the
// transaction was found.
func (m *SortedMap) Remove(nonce uint64) bool {
	// Short circuit if no transaction is present
	_, ok := m.items[nonce]
	if !ok {
		return false
	}
	// Otherwise delete the transaction and fix the heap index
	for i := range m.index.Len() {
		if (*m.index)[i] == nonce {
			heap.Remove(m.index, i)
			break
		}
	}
	delete(m.items, nonce)
	m.cacheMu.Lock()
	m.cache = nil
	m.cacheMu.Unlock()

	return true
}

// Ready retrieves a sequentially increasing list of transactions starting at the
// provided nonce that is ready for processing. The returned transactions will be
// removed from the list.
//
// Note, all transactions with nonces lower than start will also be returned to
// prevent getting into an invalid state. This is not something that should ever
// happen but better to be self correcting than failing!
func (m *SortedMap) Ready(start uint64) Transactions {
	// Short circuit if no transactions are available
	if m.index.Len() == 0 || (*m.index)[0] > start {
		return nil
	}
	// Otherwise start accumulating incremental transactions
	var ready Transactions
	for next := (*m.index)[0]; m.index.Len() > 0 && (*m.index)[0] == next; next++ {
		ready = append(ready, m.items[next])
		delete(m.items, next)
		heap.Pop(m.index)
	}
	m.cacheMu.Lock()
	m.cache = nil
	m.cacheMu.Unlock()

	return ready
}

func (m *SortedMap) flatten() Transactions {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	// If the sorting was not cached yet, create and cache it
	if m.cache == nil {
		m.cache = make(Transactions, 0, len(m.items))
		for _, tx := range m.items {
			m.cache = append(m.cache, tx)
		}
		sort.Sort(TxByNonce(m.cache))
	}
	return m.cache
}

// Flatten creates a nonce-sorted slice of transactions based on the loosely
// sorted internal representation. The result of the sorting is cached in case
// it's requested again before any modifications are made to the contents.
func (m *SortedMap) Flatten() Transactions {
	cache := m.flatten()
	// Copy the cache to prevent accidental modification
	txs := make(Transactions, len(cache))
	copy(txs, cache)
	return txs
}

// LastElement returns the last element of a flattened list, thus, the
// transaction with the highest nonce
func (m *SortedMap) LastElement() *Transaction {
	cache := m.flatten()
	return cache[len(cache)-1]
}

// FirstElement returns the first element from the heap (guaranteed to be lowest), thus, the
// transaction with the lowest nonce. Returns nil if there are no elements.
func (m *SortedMap) FirstElement() *Transaction {
	if m.Len() == 0 {
		return nil
	}
	return m.Get((*m.index)[0])
}
