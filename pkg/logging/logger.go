package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// InitZapLogger initializes a zap logger with the specified log level
func InitZapLogger(logLevel string) *zap.Logger {
	var level zapcore.Level
	switch logLevel {
	case "trace", "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "silent":
		level = zapcore.FatalLevel // Essentially silent for our use case
	default:
		level = zapcore.InfoLevel
	}

	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(level)
	config.Development = false
	config.DisableCaller = true
	config.DisableStacktrace = true
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder

	logger, _ := config.Build()
	return logger
}
