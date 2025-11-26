package slsstray

// SLS Stray runs in two modes, where
// mode1 (sequencer mode) captures and publishes stray data (meta, snapshot, diff)
// mode2 (replica mode) consumes stray data (meta, snapshot, diff) from S3
// enableStray indicates stray mode1
// enableSLSDataSync indicates stray mode2
type StrayMode uint8

const (
	ModeUnknown   StrayMode = iota
	ModeDisabled            // both flags false
	ModeSequencer           // enableStray == true, enableSLSDataSync == false
	ModeReplica             // enableStray == false, enableSLSDataSync == true
)

func GetMode(enableStray, enableSLSDataSync bool) StrayMode {
	if enableStray && enableSLSDataSync {
		return ModeUnknown
	}
	if enableStray {
		return ModeSequencer
	}
	if enableSLSDataSync {
		return ModeReplica
	}
	return ModeDisabled
}

func (m StrayMode) String() string {
	switch m {
	case ModeDisabled:
		return "disabled"
	case ModeSequencer:
		return "sequencer"
	case ModeReplica:
		return "replica"
	default:
		return "unknown"
	}
}

func (m StrayMode) IsDisabled() bool {
	return m == ModeDisabled
}

func (m StrayMode) IsSequencer() bool {
	return m == ModeSequencer
}

func (m StrayMode) IsReplica() bool {
	return m == ModeReplica
}
