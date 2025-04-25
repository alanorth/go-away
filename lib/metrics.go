package lib

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type stateMetrics struct {
	rules      *prometheus.CounterVec
	challenges *prometheus.CounterVec
}

func newMetrics() *stateMetrics {
	return &stateMetrics{
		rules: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "go-away_rule_results",
			Help: "The number of rule hits or misses",
		}, []string{"rule", "result"}),
		challenges: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "go-away_challenge_actions",
			Help: "The number of challenges issued, passed or explicitly failed",
		}, []string{"challenge", "action"}),
	}
}

func (metrics *stateMetrics) Rule(name, result string) {
	metrics.rules.With(prometheus.Labels{"rule": name, "result": result}).Inc()
}

func (metrics *stateMetrics) Challenge(name, action string) {
	metrics.challenges.With(prometheus.Labels{"challenge": name, "action": action}).Inc()
}
