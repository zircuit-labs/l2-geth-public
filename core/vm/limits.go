package vm

// NewEVMLimiter builds a ExecutionLimiter from a limitConfig.
// Cycle-based limits take precedence over count-based limits if both are present.
func NewEVMLimiter(cfg LimitConfig) ExecutionLimiter {
	if cfg.Empty() {
		return nil
	}
	// Cycle limiter takes precedence if present.
	if cfg.Cycle != nil {
		return newCycleLimiter(cfg.Cycle)
	}
	if cfg.Count != nil {
		return newCountLimiter(cfg.Count)
	}
	return nil
}
