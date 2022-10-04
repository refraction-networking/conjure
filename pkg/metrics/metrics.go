package metrics

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Metrics provides an interface to log operational counters
type Metrics struct {
	metricsMap map[string]int
	rwMutex    sync.RWMutex
	logger     log.FieldLogger
}

// NewMetrics creates a Metrics object using the provided logger and starts logging every provided logPeriod
func NewMetrics(logger log.FieldLogger, logPeriod time.Duration) *Metrics {
	m := &Metrics{
		logger:     logger,
		rwMutex:    sync.RWMutex{},
		metricsMap: map[string]int{},
	}

	go m.waitAndLog(logPeriod)

	return m
}

// Add increments the specified field by the specified value
func (m *Metrics) Add(name string, val int) {
	m.rwMutex.Lock()
	defer m.rwMutex.Unlock()
	m.metricsMap[name] += val
}

// log adds the fields currently inside metricsMap to the logger and logs
func (m *Metrics) log() {
	loggerWithFields := m.logger

	m.rwMutex.RLock()
	for key, val := range m.metricsMap {
		loggerWithFields = loggerWithFields.WithField(key, val)
	}
	m.rwMutex.RUnlock()

	loggerWithFields.Infof("current metrics")
}

func (m *Metrics) waitAndLog(sleepPeriod time.Duration) {
	for {
		time.Sleep(sleepPeriod)
		m.log()
	}
}
