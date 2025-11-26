package tracing

import (
	"math/big"

	"github.com/zircuit-labs/l2-geth/common"
	_ "github.com/zircuit-labs/l2-geth/core/sls-public/tracer"
	"github.com/zircuit-labs/l2-geth/core/tracing"
	"github.com/zircuit-labs/l2-geth/core/types"
	_ "github.com/zircuit-labs/l2-geth/eth/tracers/native"
)

// MuxTracer is a tracer mux, to support running multiple tracers together
type MuxTracer struct {
	tracers []*tracing.Hooks
}

// NewMuxTracer creates a new MuxTracer with multiple tracers
func NewMuxTracer(tracers ...*tracing.Hooks) *MuxTracer {
	return &MuxTracer{tracers}
}

func (t *MuxTracer) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnTxStart: t.OnTxStart,
		OnTxEnd:   t.OnTxEnd,
		OnEnter:   t.OnEnter,
		OnExit:    t.OnExit,
		OnOpcode:  t.OnOpcode,
		OnFault:   t.OnFault,
		OnLog:     t.OnLog,
	}
}

func (t *MuxTracer) OnTxStart(vm *tracing.VMContext, tx *types.Transaction, from common.Address) {
	for _, tracer := range t.tracers {
		if tracer.OnTxStart != nil {
			tracer.OnTxStart(vm, tx, from)
		}
	}
}

func (t *MuxTracer) OnTxEnd(receipt *types.Receipt, err error) {
	for _, tracer := range t.tracers {
		if tracer.OnTxEnd != nil {
			tracer.OnTxEnd(receipt, err)
		}
	}
}

// OnEnter runs OnEnter for each tracer in the MuxTracer
func (t *MuxTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	for _, tracer := range t.tracers {
		if tracer.OnEnter != nil {
			tracer.OnEnter(depth, typ, from, to, input, gas, value)
		}
	}
}

// OnExit runs OnExit for each tracer in the MuxTracer
func (t *MuxTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	for _, tracer := range t.tracers {
		if tracer.OnExit != nil {
			tracer.OnExit(depth, output, gasUsed, err, reverted)
		}
	}
}

// OnOpcode runs OnOpcode for each tracer in the MuxTracer
func (t *MuxTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	for _, tracer := range t.tracers {
		if tracer.OnOpcode != nil {
			tracer.OnOpcode(pc, op, gas, cost, scope, rData, depth, err)
		}
	}
}

// OnFault runs OnFault for each tracer in the MuxTracer
func (t *MuxTracer) OnFault(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, depth int, err error) {
	for _, tracer := range t.tracers {
		if tracer.OnFault != nil {
			tracer.OnFault(pc, op, gas, cost, scope, depth, err)
		}
	}
}

// OnLog runs OnLog for each tracer in the MuxTracer
func (t *MuxTracer) OnLog(log *types.Log) {
	for _, tracer := range t.tracers {
		if tracer.OnLog != nil {
			tracer.OnLog(log)
		}
	}
}
