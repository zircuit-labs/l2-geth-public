package metrics

type Metrics interface {
	IncFallbackCounter(name string)
	IncErrorCounter()
	SetQuarantineCount(name string, count int)
}
