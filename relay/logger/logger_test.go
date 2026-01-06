package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestLogger_Levels(t *testing.T) {
	testCases := []struct {
		name        string
		loggerLevel slog.Level
		logLevel    slog.Level
		shouldLog   bool
	}{
		{"debug-logs-debug", slog.LevelDebug, slog.LevelDebug, true},
		{"debug-logs-info", slog.LevelDebug, slog.LevelInfo, true},
		{"info-skips-debug", slog.LevelInfo, slog.LevelDebug, false},
		{"info-logs-info", slog.LevelInfo, slog.LevelInfo, true},
		{"warn-skips-info", slog.LevelWarn, slog.LevelInfo, false},
		{"error-logs-error", slog.LevelError, slog.LevelError, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(&buf, tc.loggerLevel)

			switch tc.logLevel {
			case slog.LevelDebug:
				logger.Debug("test message")
			case slog.LevelInfo:
				logger.Info("test message")
			case slog.LevelWarn:
				logger.Warn("test message")
			case slog.LevelError:
				logger.Error("test message")
			}

			logged := buf.Len() > 0
			if logged != tc.shouldLog {
				t.Errorf("Expected shouldLog=%v, got logged=%v", tc.shouldLog, logged)
			}
		})
	}
}

func TestLogger_StructuredOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)

	logger.Info("IP allocated",
		slog.String("component", "IPAM"),
		slog.String("client_id", "client-1"),
		slog.String("virtual_ip", "10.100.0.2"),
	)

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if entry["level"] != "INFO" {
		t.Errorf("Expected level INFO, got %v", entry["level"])
	}
	if entry["component"] != "IPAM" {
		t.Errorf("Expected component IPAM, got %v", entry["component"])
	}
	if entry["msg"] != "IP allocated" {
		t.Errorf("Expected message 'IP allocated', got %v", entry["msg"])
	}
	if entry["client_id"] != "client-1" {
		t.Errorf("Expected client_id=client-1, got %v", entry["client_id"])
	}
}

func TestWithComponent(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)
	ipamLogger := WithComponent(logger, "IPAM")

	ipamLogger.Info("Session created", slog.String("session_id", "abc123"))

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if entry["component"] != "IPAM" {
		t.Errorf("Expected component IPAM, got %v", entry["component"])
	}
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)

	const numGoroutines = 10
	const messagesPerGoroutine = 100

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < messagesPerGoroutine; j++ {
				logger.Info("Goroutine message",
					slog.String("component", "TEST"),
					slog.Int("goroutine_id", id),
					slog.Int("message_num", j),
				)
			}
			done <- true
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	lines := strings.Split(buf.String(), "\n")
	// Should have numGoroutines * messagesPerGoroutine valid JSON lines
	// (plus one empty line at the end)
	validLines := 0
	for _, line := range lines {
		if line != "" {
			var entry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &entry); err == nil {
				validLines++
			}
		}
	}

	expected := numGoroutines * messagesPerGoroutine
	if validLines != expected {
		t.Errorf("Expected %d valid log lines, got %d", expected, validLines)
	}
}
