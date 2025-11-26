package ratelimiter

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiterManager_GetRateLimiter(t *testing.T) {
	t.Parallel()

	manager := GetManager()

	config := Config{
		Key:         "test-limiter",
		LimitPerSec: 5,
		BurstPerSec: 2,
	}

	limiter1 := manager.GetRateLimiter(config)
	limiter2 := manager.GetRateLimiter(config)

	assert.Equal(t, limiter1, limiter2, "Expected same rate limiter instance for same key")
}

func TestTokenBucketRateLimiter_Wait(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      Config
		waitCalls   int
		cancelCtx   bool
		expectedErr error
	}{
		{
			name: "Single call with available token",
			config: Config{
				Key:         "test-1",
				LimitPerSec: math.MaxInt64,
				BurstPerSec: 1,
			},
			waitCalls:   1,
			cancelCtx:   false,
			expectedErr: nil,
		},
		{
			name: "Multiple calls within burst",
			config: Config{
				Key:         "test-2",
				LimitPerSec: math.MaxInt64,
				BurstPerSec: 5,
			},
			waitCalls:   5,
			cancelCtx:   false,
			expectedErr: nil,
		},
		{
			name: "Call exceeds burst, wait for token",
			config: Config{
				Key:         "test-3",
				LimitPerSec: 10,
				BurstPerSec: 1,
			},
			waitCalls:   2,
			cancelCtx:   false,
			expectedErr: nil,
		},
		{
			name: "Context cancelled before token available",
			config: Config{
				Key:         "test-4",
				LimitPerSec: 1,
				BurstPerSec: 1,
			},
			waitCalls:   2,
			cancelCtx:   true,
			expectedErr: context.Canceled,
		},
		{
			name: "Zero rate, no tokens available",
			config: Config{
				Key:         "test-5",
				LimitPerSec: 0, // Treated as unlimited in rate.Limiter
				BurstPerSec: 1,
			},
			waitCalls:   1,
			cancelCtx:   false,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			manager := GetManager()
			limiter := manager.GetRateLimiter(tt.config)

			for i := range tt.waitCalls {
				ctx := context.Background()
				if tt.cancelCtx && i == tt.waitCalls-1 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(context.Background())
					cancel()
				}

				err := limiter.Wait(ctx)
				if tt.expectedErr != nil && i == tt.waitCalls-1 {
					assert.True(t, errors.Is(err, tt.expectedErr), "expected error %v, got %v", tt.expectedErr, err)
				} else {
					assert.NoError(t, err, "expected no error, got %v", err)
				}
			}
		})
	}
}

func TestTokenBucketRateLimiter_BurstCapacity(t *testing.T) {
	t.Parallel()

	manager := GetManager()
	limiter := manager.GetRateLimiter(Config{
		Key:         "burst-test",
		LimitPerSec: 1, // 1 token per second
		BurstPerSec: 3,
	})

	// Consume burst tokens
	for range 3 {
		err := limiter.Wait(context.Background())
		assert.NoError(t, err, "Expected no error when consuming burst tokens")
	}

	start := time.Now()

	// Next call should wait for ~1 second
	err := limiter.Wait(context.Background())
	assert.NoError(t, err, "Expected no error after waiting for token")

	duration := time.Since(start)
	assert.GreaterOrEqual(t, duration, 900*time.Millisecond, "Expected approximately 1 second delay")
}

func TestTokenBucketRateLimiter_RateZero(t *testing.T) {
	t.Parallel()

	manager := GetManager()
	limiter := manager.GetRateLimiter(Config{
		Key:         "zero-rate-test",
		LimitPerSec: 0,
		BurstPerSec: 1,
	})

	err := limiter.Wait(context.Background())
	assert.NoError(t, err, "Expected no error for zero rate (unlimited requests)")
}

func TestTokenBucketRateLimiter_SequentialWait(t *testing.T) {
	t.Parallel()

	manager := GetManager()
	limiter := manager.GetRateLimiter(Config{
		Key:         "sequential-test",
		LimitPerSec: 10,
		BurstPerSec: 2,
	})

	start := time.Now()

	// First two calls should pass immediately due to burst
	err := limiter.Wait(context.Background())
	assert.NoError(t, err, "Expected no error for first call")

	err = limiter.Wait(context.Background())
	assert.NoError(t, err, "Expected no error for second call")

	// Third call should wait ~100ms
	err = limiter.Wait(context.Background())
	assert.NoError(t, err, "Expected no error after waiting")

	duration := time.Since(start)
	assert.GreaterOrEqual(t, duration, 100*time.Millisecond, "Expected approximately 100ms delay for token refill")
}

func TestRateLimiterManager_ThreadSafety(t *testing.T) {
	t.Parallel()

	manager := GetManager()

	config := Config{
		Key:         "concurrent-test",
		LimitPerSec: 5,
		BurstPerSec: 2,
	}

	limiter := manager.GetRateLimiter(config)

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			err := limiter.Wait(context.Background())
			assert.NoError(t, err, "Expected no error in concurrent access")
		})
	}
	wg.Wait()
}
