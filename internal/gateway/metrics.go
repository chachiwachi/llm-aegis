package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// metrics expone contadores en formato de texto de Prometheus sin dependencias.
type metrics struct {
	mu       sync.Mutex
	counters map[string]float64
	help     map[string]string
}

func newMetrics() *metrics {
	return &metrics{
		counters: map[string]float64{},
		help: map[string]string{
			"aegis_requests_total":        "Peticiones procesadas por ruta y acción.",
			"aegis_findings_total":        "Hallazgos del motor por dirección y categoría.",
			"aegis_scan_seconds_sum":      "Tiempo total de análisis en el motor.",
			"aegis_scan_seconds_count":    "Número de análisis en el motor.",
			"aegis_upstream_errors_total": "Errores al contactar con el proveedor.",
		},
	}
}

func (m *metrics) add(name string, v float64, labels ...string) {
	key := name
	if len(labels) > 0 {
		parts := make([]string, 0, len(labels)/2)
		for i := 0; i+1 < len(labels); i += 2 {
			parts = append(parts, fmt.Sprintf("%s=%q", labels[i], labels[i+1]))
		}
		key += "{" + strings.Join(parts, ",") + "}"
	}
	m.mu.Lock()
	m.counters[key] += v
	m.mu.Unlock()
}

func (m *metrics) observeScan(d time.Duration) {
	m.add("aegis_scan_seconds_sum", d.Seconds())
	m.add("aegis_scan_seconds_count", 1)
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.counters))
	for k := range m.counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	written := map[string]bool{}
	for _, k := range keys {
		name, _, _ := strings.Cut(k, "{")
		if !written[name] {
			written[name] = true
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, m.help[name], name)
		}
		fmt.Fprintf(&b, "%s %g\n", k, m.counters[k])
	}
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}
