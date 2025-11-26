package sls

import (
	"context"
	"sync"
)

type Executor interface {
	Loop(ctx context.Context, wg *sync.WaitGroup, mu *sync.RWMutex)
	Stop()
}
