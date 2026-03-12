package emailv2

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

var emailSendDurationBuckets = []float64{
	0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

type emailSeries struct {
	Provider string
	Status   string
}

var (
	emailMetricsMu sync.RWMutex

	emailSendTotal = map[emailSeries]int64{}

	emailSendDurationCount = map[emailSeries]int64{}
	emailSendDurationSum   = map[emailSeries]float64{}
	// Histogram buckets are stored as cumulative counts.
	emailSendDurationBucket = map[emailSeries][]int64{}
)

func recordEmailSendMetric(provider ProviderKind, status string, duration time.Duration) {
	series := emailSeries{
		Provider: normalizeEmailMetricProvider(provider),
		Status:   normalizeEmailMetricStatus(status),
	}

	seconds := duration.Seconds()
	if seconds < 0 {
		seconds = 0
	}

	emailMetricsMu.Lock()
	defer emailMetricsMu.Unlock()

	emailSendTotal[series]++
	emailSendDurationCount[series]++
	emailSendDurationSum[series] += seconds

	buckets := emailSendDurationBucket[series]
	if buckets == nil {
		buckets = make([]int64, len(emailSendDurationBuckets))
		emailSendDurationBucket[series] = buckets
	}
	for i, le := range emailSendDurationBuckets {
		if seconds <= le {
			buckets[i]++
		}
	}
}

// WritePrometheusEmailMetrics appends email provider metrics in Prometheus text format.
func WritePrometheusEmailMetrics(w io.Writer) {
	totals, counts, sums, buckets := snapshotEmailMetrics()
	series := make([]emailSeries, 0, len(totals))
	for s := range totals {
		series = append(series, s)
	}
	sort.Slice(series, func(i, j int) bool {
		if series[i].Provider == series[j].Provider {
			return series[i].Status < series[j].Status
		}
		return series[i].Provider < series[j].Provider
	})

	fmt.Fprintln(w)
	fmt.Fprintln(w, "# HELP email_send_total Total emails sent grouped by provider and status.")
	fmt.Fprintln(w, "# TYPE email_send_total counter")
	for _, s := range series {
		fmt.Fprintf(
			w,
			"email_send_total{provider=%q,status=%q} %d\n",
			sanitizePromLabel(s.Provider),
			sanitizePromLabel(s.Status),
			totals[s],
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "# HELP email_send_duration_seconds Email send duration grouped by provider and status.")
	fmt.Fprintln(w, "# TYPE email_send_duration_seconds histogram")
	for _, s := range series {
		bs := buckets[s]
		if bs == nil {
			bs = make([]int64, len(emailSendDurationBuckets))
		}
		for i, le := range emailSendDurationBuckets {
			fmt.Fprintf(
				w,
				"email_send_duration_seconds_bucket{provider=%q,status=%q,le=%q} %d\n",
				sanitizePromLabel(s.Provider),
				sanitizePromLabel(s.Status),
				formatPromFloat(le),
				bs[i],
			)
		}
		fmt.Fprintf(
			w,
			"email_send_duration_seconds_bucket{provider=%q,status=%q,le=\"+Inf\"} %d\n",
			sanitizePromLabel(s.Provider),
			sanitizePromLabel(s.Status),
			counts[s],
		)
		fmt.Fprintf(
			w,
			"email_send_duration_seconds_sum{provider=%q,status=%q} %s\n",
			sanitizePromLabel(s.Provider),
			sanitizePromLabel(s.Status),
			formatPromFloat(sums[s]),
		)
		fmt.Fprintf(
			w,
			"email_send_duration_seconds_count{provider=%q,status=%q} %d\n",
			sanitizePromLabel(s.Provider),
			sanitizePromLabel(s.Status),
			counts[s],
		)
	}
}

func snapshotEmailMetrics() (
	map[emailSeries]int64,
	map[emailSeries]int64,
	map[emailSeries]float64,
	map[emailSeries][]int64,
) {
	emailMetricsMu.RLock()
	defer emailMetricsMu.RUnlock()

	totals := make(map[emailSeries]int64, len(emailSendTotal))
	for k, v := range emailSendTotal {
		totals[k] = v
	}
	counts := make(map[emailSeries]int64, len(emailSendDurationCount))
	for k, v := range emailSendDurationCount {
		counts[k] = v
	}
	sums := make(map[emailSeries]float64, len(emailSendDurationSum))
	for k, v := range emailSendDurationSum {
		sums[k] = v
	}
	buckets := make(map[emailSeries][]int64, len(emailSendDurationBucket))
	for k, v := range emailSendDurationBucket {
		cloned := make([]int64, len(v))
		copy(cloned, v)
		buckets[k] = cloned
	}
	return totals, counts, sums, buckets
}

func normalizeEmailMetricProvider(provider ProviderKind) string {
	p := strings.TrimSpace(strings.ToLower(string(provider)))
	if p == "" {
		return "unknown"
	}
	return p
}

func normalizeEmailMetricStatus(status string) string {
	s := strings.TrimSpace(strings.ToLower(status))
	if s == "" {
		return "unknown"
	}
	return s
}

func sanitizePromLabel(v string) string {
	return strings.ReplaceAll(v, `"`, `\"`)
}

func formatPromFloat(v float64) string {
	// Keep a stable compact format in exposition output.
	s := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", v), "0"), ".")
	if s == "" || s == "-0" {
		return "0"
	}
	return s
}

func resetEmailMetricsForTests() {
	emailMetricsMu.Lock()
	defer emailMetricsMu.Unlock()

	emailSendTotal = map[emailSeries]int64{}
	emailSendDurationCount = map[emailSeries]int64{}
	emailSendDurationSum = map[emailSeries]float64{}
	emailSendDurationBucket = map[emailSeries][]int64{}
}
