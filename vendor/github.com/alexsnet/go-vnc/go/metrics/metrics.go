/*
The metrics package provides support for tracking various metrics.
*/
package metrics

import (
	"fmt"
	"log"
	"math"
	"net/http"
)

// TODO(alexsnet): Add the following stats:
// - MultiLevel
//   - MinuteHour
// - VariableMap
// TODO(alexsnet): Consider locking.

type Metric interface {
	// Adjust increments or decrements the metric value.
	Adjust(int64)

	// Increment increases the metric value by one.
	Increment()

	// Name returns the varz name.
	Name() string

	// Reset the metric.
	Reset()

	// Value returns the current metric value.
	Value() uint64
}

var metrics map[string]Metric

func init() {
	reset()

	http.Handle("/varz", http.HandlerFunc(Varz))
}

func add(metric Metric) error {
	if _, ok := metrics[metric.Name()]; ok {
		return fmt.Errorf("Metric %v already exists.", metric.Name())
	}
	metrics[metric.Name()] = metric
	return nil
}

func reset() {
	metrics = map[string]Metric{}
}

func Adjust(name string, val int64) {
	m, ok := metrics[name]
	if ok {
		m.Adjust(val)
	}
}

func Varz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, m := range metrics {
		fmt.Fprintf(w, "%v\n", m.Value())
	}
}

// Counter provides a simple monotonically incrementing counter.
type Counter struct {
	name string
	val  uint64
}

func NewCounter(name string) *Counter {
	c := &Counter{name: name}
	if err := add(c); err != nil {
		return nil
	}
	return c
}

func (c *Counter) Adjust(val int64) {
	log.Fatal("A Counter metric cannot be adjusted")
}

func (c *Counter) Increment() {
	c.val++
}

func (c *Counter) Name() string {
	return c.name
}

func (c *Counter) Reset() {
	c.val = 0
}

func (c *Counter) Value() uint64 {
	return c.val
}

// The Gauge type represents a non-negative integer, which may increase or
// decrease, but shall never exceed the maximum value.
type Gauge struct {
	name string
	val  uint64
}

func NewGauge(name string) *Gauge {
	g := &Gauge{name: name}
	if err := add(g); err != nil {
		return nil
	}
	return g
}

// Adjust allows one to increase or decrease a metric.
func (g *Gauge) Adjust(val int64) {
	// The value is positive.
	if val > 0 {
		if g.val == math.MaxUint64 {
			return
		}
		v := g.val + uint64(val)
		if v > g.val {
			g.val = v
			return
		}
		// The value wrapped, so set to maximum allowed value.
		g.val = math.MaxUint64
		return
	}

	// The value is negative.
	v := g.val - uint64(-val)
	if v < g.val {
		g.val = v
		return
	}
	// The value wrapped, so set to zero.
	g.val = 0
}

func (g *Gauge) Increment() {
	log.Fatal("A Gauge metric cannot be adjusted")
}

func (g *Gauge) Name() string {
	return g.name
}

func (g *Gauge) Reset() {
	g.val = 0
}

func (g *Gauge) Value() uint64 {
	return g.val
}
