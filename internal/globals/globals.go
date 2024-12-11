package globals

import (
	"doorkeeper/api/v1alpha2"

	"go.uber.org/zap"
)

var (
// Application = ApplicationT{}
)

// ExecutionContext TODO
type ApplicationT struct {
	Logger   zap.SugaredLogger
	LogLevel string

	Config v1alpha2.DoorkeeperConfigT
}

// SetLogger TODO
// func SetLogger(logLevel string, disableTrace bool) (err error) {
// 	parsedLogLevel, err := zap.ParseAtomicLevel(logLevel)
// 	if err != nil {
// 		return err
// 	}

// 	// Initialize the logger
// 	loggerConfig := zap.NewProductionConfig()
// 	if disableTrace {
// 		loggerConfig.DisableStacktrace = true
// 		loggerConfig.DisableCaller = true
// 	}

// 	loggerConfig.EncoderConfig.TimeKey = "timestamp"
// 	loggerConfig.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
// 	loggerConfig.Level.SetLevel(parsedLogLevel.Level())

// 	// Configure the logger
// 	logger, err := loggerConfig.Build()
// 	if err != nil {
// 		return err
// 	}

// 	Application.Logger = *logger.Sugar()
// 	return nil
// }

// func GetDefaultLogFields() map[string]any {
// 	return map[string]any{
// 		"request_id":   "none",
// 		"request":      utils.DefaultRequestStruct(),
// 		"response":     utils.DefaultResponseStruct(),
// 		"current_auth": "none",
// 		"error":        "none",
// 	}
// }
