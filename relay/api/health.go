package api

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// HealthStatus represents the health check response
type HealthStatus struct {
	Status    string    `json:"status"`    // "healthy" | "unhealthy" | "ready" | "not_ready"
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Uptime    string    `json:"uptime,omitempty"`
}

// HealthChecker manages service health and readiness state
type HealthChecker struct {
	startTime time.Time
	ready     atomic.Bool // Readiness flag
	version   string
}

// NewHealthChecker creates a new HealthChecker instance
func NewHealthChecker(version string) *HealthChecker {
	hc := &HealthChecker{
		startTime: time.Now(),
		version:   version,
	}
	hc.ready.Store(false) // Not ready until IPAM/ACL initialized
	return hc
}

// SetReady marks the service as ready (or not ready) to accept traffic
func (hc *HealthChecker) SetReady(ready bool) {
	hc.ready.Store(ready)
}

// LivenessHandler handles liveness probe requests
// Returns 200 OK if the process is alive (always succeeds)
func (hc *HealthChecker) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	status := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   hc.version,
		Uptime:    time.Since(hc.startTime).String(),
	}

	json.NewEncoder(w).Encode(status)
}

// ReadinessHandler handles readiness probe requests
// Returns 200 OK only when IPAM/ACL are fully initialized
func (hc *HealthChecker) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !hc.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(HealthStatus{
			Status:    "not_ready",
			Timestamp: time.Now(),
			Version:   hc.version,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthStatus{
		Status:    "ready",
		Timestamp: time.Now(),
		Version:   hc.version,
		Uptime:    time.Since(hc.startTime).String(),
	})
}
