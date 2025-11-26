package sls

import (
	"errors"

	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

type DetectorType int

const (
	DetectorTypeForkChoice DetectorType = iota
	DetectorTypeLegacyPool
	DetectorTypeBlock
)

const (
	DetectorTypeStringForkChoice = "forkchoice"
	DetectorTypeStringLegacyPool = "legacypool"
	DetectorTypeStringBlock      = "block"
	DetectorTypeStringUnknown    = "unknown"
)

var (
	ErrUnknownDetectorTypeString = errors.New("unknown detector type")
)

var detectorTypeToString = map[DetectorType]string{
	DetectorTypeForkChoice: DetectorTypeStringForkChoice,
	DetectorTypeLegacyPool: DetectorTypeStringLegacyPool,
	DetectorTypeBlock:      DetectorTypeStringBlock,
}

var stringToDetectorType = map[string]DetectorType{
	DetectorTypeStringForkChoice: DetectorTypeForkChoice,
	DetectorTypeStringLegacyPool: DetectorTypeLegacyPool,
	DetectorTypeStringBlock:      DetectorTypeBlock,
}

func DetectorTypeFromString(s string) (DetectorType, error) {
	if dt, ok := stringToDetectorType[s]; ok {
		return dt, nil
	}
	return 0, stacktrace.Wrap(ErrUnknownDetectorTypeString)
}

func (dt DetectorType) String() string {
	if s, ok := detectorTypeToString[dt]; ok {
		return s
	}
	return DetectorTypeStringUnknown
}
