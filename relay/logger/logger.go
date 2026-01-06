package logger

import (
	"io"
	"log/slog"
	"os"
)

// New creates a new structured logger using slog with JSON output.
// Level options: slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError
func New(output io.Writer, level slog.Level) *slog.Logger {
	if output == nil {
		output = os.Stdout
	}

	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(handler)
}

// WithComponent creates a logger with a component attribute.
func WithComponent(logger *slog.Logger, component string) *slog.Logger {
	return logger.With(slog.String("component", component))
}
