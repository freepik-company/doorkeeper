// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"doorkeeper/internal/doorkeeper"
	"doorkeeper/internal/logger"
	"doorkeeper/internal/utils"
)

var (
	logLevelFlag = flag.String("log-level", "info", "Verbosity level for logs")
	configFlag   = flag.String("config", "doorkeeper.yaml", "Path to the config file")
)

func main() {
	flag.Parse()

	extLogger := logger.NewLogger(logger.GetLevel(*logLevelFlag))
	logFields := utils.GetDefaultLogFields()

	/////////////////////////////
	// EXECUTION FLOW RELATED
	/////////////////////////////

	s, err := doorkeeper.NewDoorkeeper(*configFlag)
	if err != nil {
		logFields.Set(utils.LogFieldKeyError, err.Error())
		extLogger.Fatal("fail in http server creation", logFields)
	}

	go s.Run()
	defer s.Stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
