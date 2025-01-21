package slslog

import "github.com/zircuit-labs/l2-geth-public/log"

func New() log.Logger {
	return log.New("sls", true)
}

func NewWith(ctx ...interface{}) log.Logger {
	return New().With(ctx...)
}
