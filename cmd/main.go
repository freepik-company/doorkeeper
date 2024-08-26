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
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"log"

	"doorkeeper/internal/httpserver"
	"doorkeeper/internal/globals"
)

var (
	httpPortFlag = flag.String("port", "8000", "HTTP server port")
	logLevelFlag = flag.String("log-level", "info", "Verbosity level for logs")
	disableTraceFlag = flag.Bool("disable-trace", true, "Disable showing traces in logs")
)

func main() {
	flag.Parse()

	// Init the logger and store the level into the context
	globals.Application.LogLevel = *logLevelFlag

	err := globals.SetLogger(*logLevelFlag, *disableTraceFlag)
	if err != nil {
		log.Fatal(err)
	}

	/////////////////////////////
	// EXECUTION FLOW RELATED
	/////////////////////////////

	s := httpserver.NewHttpServer()
	go s.Run(fmt.Sprintf(":%s", *httpPortFlag))
	defer s.Stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

