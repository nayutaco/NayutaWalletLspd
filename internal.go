package main

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/nayutaco/NayutaHub2Lspd/rpc"
)

func (s *internal) SetLogLevel(ctx context.Context, in *rpc.LogLevelRequest) (*rpc.LogLevelReply, error) {
	log.Infof("SetLogLevel: %d", in.Level)

	var level string
	switch in.Level {
	case rpc.LogLevelRequest_LOGLEVEL_ERROR:
		level = "error"
	case rpc.LogLevelRequest_LOGLEVEL_WARN:
		level = "warn"
	case rpc.LogLevelRequest_LOGLEVEL_INFO:
		level = "info"
	case rpc.LogLevelRequest_LOGLEVEL_DEBUG:
		level = "debug"
	case rpc.LogLevelRequest_LOGLEVEL_TRACE:
		level = "trace"
	default:
		return nil, fmt.Errorf("loglevel: invalid value: %v", in.Level)
	}
	log.Infof("SetLogLevel: %s", level)
	logLevel, err := convLoglevel(level)
	if err != nil {
		return nil, fmt.Errorf("loglevel: %v", err)
	}
	log.SetLevel(logLevel)
	log.Error("log.Error")
	log.Warn("log.Warn")
	log.Info("log.Info")
	log.Debug("log.Debug")
	log.Trace("log.Trace")

	return &rpc.LogLevelReply{}, nil
}
