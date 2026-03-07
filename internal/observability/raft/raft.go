package raft

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Raft-related Prometheus metrics. These are defined in a standalone package to avoid
// import cycles between cluster (Raft) and HTTP packages.

var (
	RaftApplyLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "raft_apply_latency_ms",
		Help:    "Latencia de raft.Apply en milisegundos",
		Buckets: prometheus.ExponentialBuckets(1, 2, 12),
	})

	RaftLeadershipChanges = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "raft_leadership_changes_total",
		Help: "Cambios de rol a leader",
	})

	RaftLogSizeBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "raft_log_size_bytes",
		Help: "Tamaño en bytes del archivo de log/stable (BoltDB)",
	})
)

// RegisterRaft registers the raft metrics on the given registry (or default if nil).
func RegisterRaft(reg prometheus.Registerer) error {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	if err := reg.Register(RaftApplyLatency); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			return err
		}
	}
	if err := reg.Register(RaftLeadershipChanges); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			return err
		}
	}
	if err := reg.Register(RaftLogSizeBytes); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			return err
		}
	}
	return nil
}
