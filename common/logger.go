package common

import (
	"go.uber.org/zap"
)

// NewLogger returns a new logger
func NewLogger(debugMode bool, logFilePath string) (*zap.SugaredLogger, error) {
	var conf zap.Config
	if debugMode {
		conf = zap.NewDevelopmentConfig()
	} else {
		conf = zap.NewProductionConfig()
	}

	if logFilePath != "" {
		conf.OutputPaths = []string{
			logFilePath,
			"stdout",
		}
	}

	conf.DisableStacktrace = true

	var logger, err = conf.Build()
	if err != nil {
		return nil, err
	}

	return logger.Sugar(), nil
}

// NewNopLogger returns a new nop logger
func NewNopLogger() *zap.SugaredLogger {
	return zap.NewNop().Sugar()
}
