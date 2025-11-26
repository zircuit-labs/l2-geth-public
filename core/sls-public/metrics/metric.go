package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	metricsCommon "github.com/zircuit-labs/l2-geth/core/sls-common/metrics"
)

const (
	labelBlockName = "block_name"
)

type (
	Metrics struct {
		blockFallbackCounter   *prometheus.CounterVec
		blockErrorCounter      prometheus.Counter
		blockQuarantineCounter *prometheus.GaugeVec
	}
)

var _ metricsCommon.Metrics = (*Metrics)(nil)

func NewCollector(prom prometheus.Registerer) (*Metrics, error) {
	blockFallbackCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sls_block_fallback",
			Help: "A counter for fallback at block level.",
		},
		[]string{labelBlockName},
	)

	blockErrorCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sls_block_error",
			Help: "A counter for errors at block level.",
		},
	)
	blockQuarantineCounter := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sls_block_quarantine",
			Help: "A counter for number of quarantines at block level.",
		},
		[]string{labelBlockName},
	)

	// Register the collectors
	var err error
	if blockFallbackCounter, err = registerCollector(prom, blockFallbackCounter); err != nil {
		return nil, err
	}
	if blockErrorCounter, err = registerCollector(prom, blockErrorCounter); err != nil {
		return nil, err
	}
	if blockQuarantineCounter, err = registerCollector(prom, blockQuarantineCounter); err != nil {
		return nil, err
	}

	return &Metrics{
		blockFallbackCounter:   blockFallbackCounter,
		blockErrorCounter:      blockErrorCounter,
		blockQuarantineCounter: blockQuarantineCounter,
	}, nil
}

func (c *Metrics) IncFallbackCounter(name string) {
	c.blockFallbackCounter.With(
		prometheus.Labels{
			labelBlockName: name,
		},
	).Inc()
}

func (c *Metrics) IncErrorCounter() {
	c.blockErrorCounter.Inc()
}

func (c *Metrics) SetQuarantineCount(name string, count int) {
	c.blockQuarantineCounter.With(prometheus.Labels{
		labelBlockName: name,
	}).Set(float64(count))
}

var ErrWrongMetricType = errors.New("collector already registered with different type")

// registerCollector registers a Prometheus collector and returns the registered collector or an error
func registerCollector[T prometheus.Collector](prom prometheus.Registerer, c T) (T, error) {
	err := prom.Register(c)
	if err == nil {
		return c, nil // All good, returns the newly registered metric
	}

	var are prometheus.AlreadyRegisteredError
	if !errors.As(err, &are) {
		return c, err // Some other error
	}

	existing, ok := are.ExistingCollector.(T)
	if !ok {
		return c, ErrWrongMetricType // Collector was already registered but with a different type
	}

	return existing, nil // Already registered, return it
}
