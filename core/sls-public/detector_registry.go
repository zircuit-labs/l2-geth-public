package sls

import (
	"context"
	"time"

	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
)

type DetectorRegistry struct{}

func NewDetectorRegistry(factory, db any, refreshInterval time.Duration) *DetectorRegistry {
	return &DetectorRegistry{}
}

func (dr *DetectorRegistry) Start(ctx context.Context) error {
	return nil
}

func (dr *DetectorRegistry) GetTransactionDetectors(detectorType slsCommon.DetectorType) [][]slsCommon.TransactionDetector {
	return [][]slsCommon.TransactionDetector{}
}

func (dr *DetectorRegistry) GetBlockDetectors() []slsCommon.BlockDetector {
	return []slsCommon.BlockDetector{}
}

func (dr *DetectorRegistry) Stop() {}
