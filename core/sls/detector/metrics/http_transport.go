package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate mockgen -source http_transport.go -destination mock_http_transport.go -package metrics

type (
	HTTPCollector interface {
		ObserveDetectorLatency(clientName, url string, statusCode int, startTime time.Time)
		IncDetectorCounter(clientName, url string, statusCode int)
	}

	HTTPRoundTripper interface {
		RoundTrip(*http.Request) (*http.Response, error)
	}
)

func NewHTTPTransport(clientName string, transport HTTPRoundTripper, collector HTTPCollector) http.RoundTripper {
	return promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		start := time.Now()
		resp, err := transport.RoundTrip(r)
		if err != nil {
			return resp, err
		}

		collector.ObserveDetectorLatency(clientName, r.URL.Path, resp.StatusCode, start)
		collector.IncDetectorCounter(clientName, r.URL.Path, resp.StatusCode)

		return resp, nil
	})
}
