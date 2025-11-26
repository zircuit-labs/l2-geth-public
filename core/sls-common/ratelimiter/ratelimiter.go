package ratelimiter

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

type Config struct {
	Key         string
	LimitPerSec float64
	BurstPerSec int
}

type RateLimiter interface {
	Wait(ctx context.Context) error
}

type TokenBucketRateLimiter struct {
	limiter *rate.Limiter
}

func (t *TokenBucketRateLimiter) Wait(ctx context.Context) error {
	return t.limiter.Wait(ctx)
}

type Manager struct {
	mu       sync.Mutex
	limiters map[string]*TokenBucketRateLimiter
}

var (
	instance *Manager
	once     sync.Once
)

func GetManager() *Manager {
	once.Do(func() {
		instance = &Manager{
			limiters: make(map[string]*TokenBucketRateLimiter),
		}
	})
	return instance
}

// GetRateLimiter retrieves or creates a rate limiter based on the key
func (m *Manager) GetRateLimiter(config Config) *TokenBucketRateLimiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limiter, exists := m.limiters[config.Key]; exists {
		return limiter
	}

	newLimiter := &TokenBucketRateLimiter{
		limiter: rate.NewLimiter(rate.Limit(config.LimitPerSec), config.BurstPerSec),
	}
	m.limiters[config.Key] = newLimiter

	return newLimiter
}
