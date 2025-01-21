package metrics

import (
	"errors"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	labelDetectorClientName         = "detector_name"
	labelDetectorMethod             = "method"
	labelDetectorResponseStatusCode = "code"
)

type Collector struct {
	detectorLatency      *prometheus.HistogramVec
	detectorCounter      *prometheus.CounterVec
	detectorErrorCounter *prometheus.CounterVec
	detectorRetries      *prometheus.GaugeVec
}

func NewCollector(prom prometheus.Registerer) (*Collector, error) {
	detectorLatency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sls_detector_latency_seconds",
		Help:    "Latency of the detector API calls",
		Buckets: prometheus.DefBuckets,
	}, []string{labelDetectorClientName, labelDetectorMethod, labelDetectorResponseStatusCode})

	detectorCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sls_detector_requests_total",
			Help: "A counter for requests from the client.",
		},
		[]string{labelDetectorResponseStatusCode, labelDetectorMethod, labelDetectorClientName},
	)

	detectorErrorCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sls_detector_error_requests",
			Help: "A counter for unsuccessful requests from the client.",
		},
		[]string{labelDetectorMethod, labelDetectorClientName},
	)

	detectorRetries := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sls_detector_retries",
			Help: "A gauge for retries from the client.",
		},
		[]string{labelDetectorClientName, labelDetectorMethod},
	)

	// Register the collectors
	var err error
	if detectorLatency, err = registerCollector(prom, detectorLatency); err != nil {
		return nil, err
	}
	if detectorCounter, err = registerCollector(prom, detectorCounter); err != nil {
		return nil, err
	}
	if detectorErrorCounter, err = registerCollector(prom, detectorErrorCounter); err != nil {
		return nil, err
	}
	if detectorRetries, err = registerCollector(prom, detectorRetries); err != nil {
		return nil, err
	}

	return &Collector{
		detectorLatency:      detectorLatency,
		detectorCounter:      detectorCounter,
		detectorErrorCounter: detectorErrorCounter,
		detectorRetries:      detectorRetries,
	}, nil
}

func (c *Collector) ObserveDetectorLatency(clientName, url string, statusCode int, startTime time.Time) {
	c.detectorLatency.With(
		prometheus.Labels{
			labelDetectorClientName:         clientName,
			labelDetectorMethod:             url,
			labelDetectorResponseStatusCode: strconv.Itoa(statusCode),
		}).Observe(time.Since(startTime).Seconds())
}

func (c *Collector) IncDetectorCounter(clientName, url string, statusCode int) {
	c.detectorCounter.With(
		prometheus.Labels{
			labelDetectorClientName:         clientName,
			labelDetectorMethod:             url,
			labelDetectorResponseStatusCode: strconv.Itoa(statusCode),
		},
	).Inc()
}

func (c *Collector) IncErrorCounter(clientName, url string) {
	c.detectorErrorCounter.With(
		prometheus.Labels{
			labelDetectorClientName: clientName,
			labelDetectorMethod:     url,
		},
	).Inc()
}

func (c *Collector) SetDetectorRetries(clientName, method string, attempt int) {
	c.detectorRetries.With(prometheus.Labels{
		labelDetectorClientName: clientName,
		labelDetectorMethod:     method,
	}).Set(float64(attempt))
}

var (
	ErrWrongMetricType = errors.New("collector already registered with different type")
)

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
