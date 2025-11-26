package slsstray

import (
	"sync"
	"testing"
	"time"
)

// Mock MerkleRootGenerator for testing
type MockMerkleRootGenerator struct {
	MerkleRoot string
}

func TestMerkleRootStore_SetAndGet(t *testing.T) {
	// create a new store for testing (not using the global one)
	store := &MerkleRootStore{}

	// getMerkleRoot returns empty string when generator is nil
	result := store.GetMerkleRoot()
	if result != "" {
		t.Errorf("Expected empty string for nil generator, got %s", result)
	}

	// set generator and get merkle root
	gen := &MerkleRootGenerator{
		merkleRoot: "test-merkle-root-123",
	}
	store.SetGenerator(gen)

	result = store.GetMerkleRoot()
	if result != "test-merkle-root-123" {
		t.Errorf("Expected 'test-merkle-root-123', got %s", result)
	}

	// update generator's merkle root and verify it's reflected
	gen.merkleRoot = "updated-merkle-root-456"
	result = store.GetMerkleRoot()
	if result != "updated-merkle-root-456" {
		t.Errorf("Expected 'updated-merkle-root-456', got %s", result)
	}

	// Test 5: Set generator to nil
	store.SetGenerator(nil)
	result = store.GetMerkleRoot()
	if result != "" {
		t.Errorf("Expected empty string after setting nil generator, got %s", result)
	}
}

func TestMerkleRootStore_Concurrent_Read(t *testing.T) {
	store := &MerkleRootStore{}
	gen := &MerkleRootGenerator{
		merkleRoot: "test-merkle-root-123",
	}
	store.SetGenerator(gen)

	var wg sync.WaitGroup
	iterations := 100

	// start multiple goroutines reading
	for range 10 {
		wg.Go(func() {
			for range iterations {
				_ = store.GetMerkleRoot()
				time.Sleep(time.Microsecond)
			}
		})
	}
	// this should not panic or deadlock
	wg.Wait()
}

func TestPackageLevelFunctions(t *testing.T) {
	merkleRootStore = &MerkleRootStore{}

	result := GetMerkleRoot()
	if result != "" {
		t.Errorf("Expected empty string initially, got %s", result)
	}

	gen := &MerkleRootGenerator{
		merkleRoot: "package-level-test",
	}
	SetMerkleRootStore(gen)

	result = GetMerkleRoot()
	if result != "package-level-test" {
		t.Errorf("Expected 'package-level-test', got %s", result)
	}

	// update through generator reference
	gen.merkleRoot = "updated-package-level"
	result = GetMerkleRoot()
	if result != "updated-package-level" {
		t.Errorf("Expected 'updated-package-level', got %s", result)
	}
}
