// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package prometheus

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/zircuit-labs/l2-geth-public/metrics"
)

var (
	typeGaugeTpl           = "# TYPE %s gauge\n"
	typeCounterTpl         = "# TYPE %s counter\n"
	typeSummaryTpl         = "# TYPE %s summary\n"
	keyValueTpl            = "%s %v\n\n"
	keyQuantileTagValueTpl = "%s {quantile=\"%s\"} %v\n"
)

// collector is a collection of byte buffers that aggregate Prometheus reports
// for different metric types.
type collector struct {
	buff *bytes.Buffer
}

// newCollector creates a new Prometheus metric aggregator.
func newCollector() *collector {
	return &collector{
		buff: &bytes.Buffer{},
	}
}

// Add adds the metric i to the collector. This method returns an error if the
// metric type is not supported/known.
func (c *collector) Add(name string, i any) error {
	switch m := i.(type) {
	case metrics.Counter:
		c.addCounter(name, m.Snapshot())
	case metrics.CounterFloat64:
		c.addCounterFloat64(name, m.Snapshot())
	case metrics.Gauge:
		c.addGauge(name, m.Snapshot())
	case metrics.GaugeFloat64:
		c.addGaugeFloat64(name, m.Snapshot())
	case metrics.GaugeInfo:
		c.addGaugeInfo(name, m.Snapshot())
	case metrics.Histogram:
		c.addHistogram(name, m.Snapshot())
	case metrics.Meter:
		c.addMeter(name, m.Snapshot())
	case metrics.Timer:
		c.addTimer(name, m.Snapshot())
	case metrics.ResettingTimer:
		c.addResettingTimer(name, m.Snapshot())
	default:
		return fmt.Errorf("unknown prometheus metric type %T", i)
	}
	return nil
}

func (c *collector) addCounter(name string, m metrics.CounterSnapshot) {
	c.writeGaugeCounter(name, m.Count())
}

func (c *collector) addCounterFloat64(name string, m metrics.CounterFloat64Snapshot) {
	c.writeGaugeCounter(name, m.Count())
}

func (c *collector) addGauge(name string, m metrics.GaugeSnapshot) {
	c.writeGaugeCounter(name, m.Value())
}

func (c *collector) addGaugeFloat64(name string, m metrics.GaugeFloat64Snapshot) {
	c.writeGaugeCounter(name, m.Value())
}

func (c *collector) addGaugeInfo(name string, m metrics.GaugeInfoSnapshot) {
	c.writeGaugeInfo(name, m.Value())
}

func (c *collector) addHistogram(name string, m metrics.HistogramSnapshot) {
	pv := []float64{0.5, 0.75, 0.95, 0.99, 0.999, 0.9999}
	ps := m.Percentiles(pv)
	c.writeSummaryCounter(name, m.Count())
	c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, mutateKey(name)))
	for i := range pv {
		c.writeSummaryPercentile(name, strconv.FormatFloat(pv[i], 'f', -1, 64), ps[i])
	}
	c.buff.WriteRune('\n')
}

func (c *collector) addMeter(name string, m metrics.MeterSnapshot) {
	c.writeGaugeCounter(name, m.Count())
}

func (c *collector) addTimer(name string, m metrics.TimerSnapshot) {
	pv := []float64{0.5, 0.75, 0.95, 0.99, 0.999, 0.9999}
	ps := m.Percentiles(pv)
	c.writeSummaryCounter(name, m.Count())
	c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, mutateKey(name)))
	for i := range pv {
		c.writeSummaryPercentile(name, strconv.FormatFloat(pv[i], 'f', -1, 64), ps[i])
	}
	c.buff.WriteRune('\n')
}

func (c *collector) addResettingTimer(name string, m metrics.ResettingTimerSnapshot) {
	if m.Count() <= 0 {
		return
	}
	ps := m.Percentiles([]float64{0.50, 0.95, 0.99})
	c.writeSummaryCounter(name, m.Count())
	c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, mutateKey(name)))
	c.writeSummaryPercentile(name, "0.50", ps[0])
	c.writeSummaryPercentile(name, "0.95", ps[1])
	c.writeSummaryPercentile(name, "0.99", ps[2])
	c.buff.WriteRune('\n')
}

func (c *collector) writeGaugeInfo(name string, value metrics.GaugeInfoValue) {
	name = mutateKey(name)
	c.buff.WriteString(fmt.Sprintf(typeGaugeTpl, name))
	c.buff.WriteString(name)
	c.buff.WriteString(" ")
	var kvs []string
	for k, v := range value {
		kvs = append(kvs, fmt.Sprintf("%v=%q", k, v))
	}
	sort.Strings(kvs)
	c.buff.WriteString(fmt.Sprintf("{%v} 1\n\n", strings.Join(kvs, ", ")))
}

func (c *collector) writeGaugeCounter(name string, value interface{}) {
	name = mutateKey(name)
	c.buff.WriteString(fmt.Sprintf(typeGaugeTpl, name))
	c.buff.WriteString(fmt.Sprintf(keyValueTpl, name, value))
}

func (c *collector) writeSummaryCounter(name string, value interface{}) {
	name = mutateKey(name + "_count")
	c.buff.WriteString(fmt.Sprintf(typeCounterTpl, name))
	c.buff.WriteString(fmt.Sprintf(keyValueTpl, name, value))
}

func (c *collector) writeSummaryPercentile(name, p string, value interface{}) {
	name = mutateKey(name)
	c.buff.WriteString(fmt.Sprintf(keyQuantileTagValueTpl, name, p, value))
}

func mutateKey(key string) string {
	return strings.ReplaceAll(key, "/", "_")
}

// addPrometheusMetric prometheus metric in prometheus exposition format and it also adds the labels to the metric
func (c *collector) addPrometheusMetric(name string, metric *io_prometheus_client.Metric) {
	name = mutateKey(name)
	labels := metric.GetLabel()
	var kvs []string
	if len(labels) > 0 {
		for _, v := range labels {
			kvs = append(kvs, fmt.Sprintf("%v=%q", v.GetName(), v.GetValue()))
		}
		sort.Strings(kvs)
	}
	switch {
	case metric.Gauge != nil:
		c.buff.WriteString(fmt.Sprintf(typeGaugeTpl, name))
		c.buff.WriteString(name)
		c.buff.WriteString(" ")
		c.buff.WriteString(fmt.Sprintf("{%v} %v\n\n", strings.Join(kvs, ", "), metric.Gauge.GetValue()))
	case metric.Counter != nil:
		c.buff.WriteString(fmt.Sprintf(typeCounterTpl, name))
		c.buff.WriteString(name)
		c.buff.WriteString(" ")
		c.buff.WriteString(fmt.Sprintf("{%v} %v\n\n", strings.Join(kvs, ", "), metric.Counter.GetValue()))
	case metric.Untyped != nil:
		c.buff.WriteString(fmt.Sprintf(typeGaugeTpl, name))
		c.buff.WriteString(name)
		c.buff.WriteString(" ")
		c.buff.WriteString(fmt.Sprintf("{%v} %v\n\n", strings.Join(kvs, ", "), metric.Untyped.GetValue()))
	case metric.Summary != nil:
		c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, name))
		c.buff.WriteString(fmt.Sprintf(keyValueTpl, name+"_count", metric.Summary.GetSampleCount()))
		c.buff.WriteString(fmt.Sprintf(keyValueTpl, name+"_sum", metric.Summary.GetSampleSum()))

		for _, quantile := range metric.Summary.Quantile {
			c.buff.WriteString(name)
			c.buff.WriteString(" ")
			temp := append([]string{}, kvs...)
			temp = append(temp, fmt.Sprintf("quantile=%q", strconv.FormatFloat(quantile.GetQuantile(), 'f', -1, 64)))
			sort.Strings(temp)
			c.buff.WriteString(fmt.Sprintf("{%v} %v\n\n", strings.Join(temp, ", "), quantile.GetValue()))
		}
	case metric.Histogram != nil:
		c.buff.WriteString(fmt.Sprintf(typeSummaryTpl, name))
		c.buff.WriteString(fmt.Sprintf(keyValueTpl, name+"_count", metric.Histogram.GetSampleCount()))
		c.buff.WriteString(fmt.Sprintf(keyValueTpl, name+"_sum", metric.Histogram.GetSampleSum()))

		for _, bucket := range metric.Histogram.Bucket {
			c.buff.WriteString(name)
			c.buff.WriteString(" ")
			temp := append([]string{}, kvs...)
			temp = append(temp, fmt.Sprintf("le=%q", strconv.FormatFloat(bucket.GetUpperBound(), 'f', -1, 64)))
			sort.Strings(temp)
			c.buff.WriteString(fmt.Sprintf("{%v} %v\n\n", strings.Join(temp, ", "), bucket.GetCumulativeCount()))
		}
	}
}
