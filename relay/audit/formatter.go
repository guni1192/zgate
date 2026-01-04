package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

// Formatter formats audit events for output.
type Formatter interface {
	Format(event *AuditEvent) ([]byte, error)
}

// JSONFormatter formats events as JSON (production default).
type JSONFormatter struct {
	Pretty bool
}

func (f *JSONFormatter) Format(event *AuditEvent) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(event, "", "  ")
	}
	return json.Marshal(event)
}

// TextFormatter formats events as human-readable text.
type TextFormatter struct {
	TimeFormat string
}

func (f *TextFormatter) Format(event *AuditEvent) ([]byte, error) {
	timeFormat := f.TimeFormat
	if timeFormat == "" {
		timeFormat = time.RFC3339
	}

	output := fmt.Sprintf("[%s] [%s] [%s] %s",
		event.Timestamp.Format(timeFormat),
		event.Level,
		event.EventType,
		event.Message,
	)

	if event.ClientID != "" {
		output += fmt.Sprintf(" client_id=%s", event.ClientID)
	}
	if event.DestIP != "" {
		output += fmt.Sprintf(" dest_ip=%s", event.DestIP)
	}
	if event.Action != "" {
		output += fmt.Sprintf(" action=%s", event.Action)
	}
	if event.RuleID != "" {
		output += fmt.Sprintf(" rule_id=%s", event.RuleID)
	}
	if event.Reason != "" {
		output += fmt.Sprintf(" reason=%q", event.Reason)
	}

	return []byte(output), nil
}
