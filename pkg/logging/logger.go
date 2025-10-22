package logging

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// InitLogger configures the global gologger based on log level string
// Supports: trace, debug, info, warn, error, silent
func InitLogger(logLevel string) {
	var level levels.Level
	switch logLevel {
	case "trace", "debug":
		level = levels.LevelDebug
	case "info":
		level = levels.LevelInfo
	case "warn":
		level = levels.LevelWarning
	case "error":
		level = levels.LevelError
	case "silent":
		level = levels.LevelSilent
	default:
		level = levels.LevelInfo
	}

	gologger.DefaultLogger.SetMaxLevel(level)
}

// GetLogger returns the configured gologger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
