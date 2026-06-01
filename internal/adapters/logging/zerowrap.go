package logging

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bnema/zerowrap"
)

const AppName = "gtkls-bitwarden-client"

// LogFileFormat is the format used for the file-backed log output.
type LogFileFormat string

const (
	LogFileFormatJSON    LogFileFormat = "json"
	LogFileFormatConsole LogFileFormat = "console"
)

// LogMeta describes the resolved logger configuration for startup diagnostics
// and tests. Path is the full file path used by the zerowrap file logger.
type LogMeta struct {
	Path       string
	Level      string
	FileFormat LogFileFormat
	Console    bool
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
}

const (
	defaultLogLevel   = "info"
	defaultLogFormat  = LogFileFormatJSON
	defaultMaxSizeMB  = 100
	defaultMaxBackups = 3
	defaultMaxAgeDays = 28
	envLogLevel       = "GTKLSBW_LOG_LEVEL"
	envLogFormat      = "GTKLSBW_LOG_FORMAT"
	envLogConsole     = "GTKLSBW_LOG_CONSOLE"
	envLogPath        = "GTKLSBW_LOG_PATH"
	envLogMaxSizeMB   = "GTKLSBW_LOG_MAX_SIZE_MB"
	envLogMaxBackups  = "GTKLSBW_LOG_MAX_BACKUPS"
	envLogMaxAgeDays  = "GTKLSBW_LOG_MAX_AGE_DAYS"
)

// NewContextFromEnv creates the application zerowrap file logger from GTKLSBW_LOG_*
// environment variables and attaches it to ctx with zerowrap.WithCtx.
//
// Defaults are file-only JSON logging at info level using zerowrap's
// app-managed single-file path for AppName. The returned cleanup function must
// be called by the process owner to close the rotating file writer.
func NewContextFromEnv(ctx context.Context, version string) (context.Context, func(), LogMeta, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	meta, fileCfg, err := logConfigFromEnv()
	if err != nil {
		return ctx, func() {}, meta, err
	}

	if meta.Path != "" {
		if err := os.MkdirAll(filepath.Dir(meta.Path), 0o750); err != nil {
			return ctx, func() {}, meta, fmt.Errorf("create log directory: %w", err)
		}
	}

	consoleOutput := io.Writer(io.Discard)
	if meta.Console {
		consoleOutput = os.Stderr
	}

	log, cleanup, err := zerowrap.NewWithFile(
		zerowrap.Config{
			Level:  meta.Level,
			Format: "console",
			Output: consoleOutput,
		},
		fileCfg,
	)
	if err != nil {
		return ctx, func() {}, meta, err
	}

	ctx = zerowrap.WithCtx(ctx, log)
	fields := map[string]any{zerowrap.FieldService: AppName}
	if version != "" {
		fields[zerowrap.FieldVersion] = version
	}
	ctx = zerowrap.CtxWithFields(ctx, fields)

	return ctx, cleanup, meta, nil
}

func logConfigFromEnv() (LogMeta, zerowrap.FileConfig, error) {
	level, err := parseLogLevel(os.Getenv(envLogLevel))
	if err != nil {
		return LogMeta{}, zerowrap.FileConfig{}, err
	}

	format, err := parseLogFileFormat(os.Getenv(envLogFormat))
	if err != nil {
		return LogMeta{}, zerowrap.FileConfig{}, err
	}

	console, err := parseOptionalBool(envLogConsole, false)
	if err != nil {
		return LogMeta{}, zerowrap.FileConfig{}, err
	}

	maxSize, err := parsePositiveIntEnv(envLogMaxSizeMB, defaultMaxSizeMB)
	if err != nil {
		return LogMeta{}, zerowrap.FileConfig{}, err
	}
	maxBackups, err := parsePositiveIntEnv(envLogMaxBackups, defaultMaxBackups)
	if err != nil {
		return LogMeta{}, zerowrap.FileConfig{}, err
	}
	maxAge, err := parsePositiveIntEnv(envLogMaxAgeDays, defaultMaxAgeDays)
	if err != nil {
		return LogMeta{}, zerowrap.FileConfig{}, err
	}

	fileCfg := zerowrap.FileConfig{
		Enabled:    true,
		AppName:    AppName,
		Name:       AppName,
		Mode:       zerowrap.FileModeSingle,
		FileFormat: zerowrap.FileFormat(format),
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
	}
	if path := os.Getenv(envLogPath); path != "" {
		fileCfg.Path = path
	}

	path, err := zerowrap.ResolveLogPath(fileCfg)
	if err != nil {
		return LogMeta{}, zerowrap.FileConfig{}, fmt.Errorf("resolve log path: %w", err)
	}

	meta := LogMeta{
		Path:       path,
		Level:      level,
		FileFormat: format,
		Console:    console,
		MaxSizeMB:  maxSize,
		MaxBackups: maxBackups,
		MaxAgeDays: maxAge,
	}

	return meta, fileCfg, nil
}

func parseLogLevel(value string) (string, error) {
	level := strings.ToLower(strings.TrimSpace(value))
	if level == "" {
		return defaultLogLevel, nil
	}
	switch level {
	case "trace", "debug", "info", "warn", "error", "fatal", "panic", "disabled":
		return level, nil
	case "warning":
		return "warn", nil
	default:
		return "", fmt.Errorf("%s must be one of trace, debug, info, warn, warning, error, fatal, panic, disabled: %q", envLogLevel, value)
	}
}

func parseLogFileFormat(value string) (LogFileFormat, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	if format == "" {
		return defaultLogFormat, nil
	}
	switch LogFileFormat(format) {
	case LogFileFormatJSON, LogFileFormatConsole:
		return LogFileFormat(format), nil
	default:
		return "", fmt.Errorf("%s must be json or console: %q", envLogFormat, value)
	}
}

func parseOptionalBool(name string, defaultValue bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", name, err)
	}
	return parsed, nil
}

func parsePositiveIntEnv(name string, defaultValue int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a positive integer: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer: %d", name, parsed)
	}
	return parsed, nil
}
