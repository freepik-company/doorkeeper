package httpserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"time"

	//
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"doorkeeper/internal/logger"
	"doorkeeper/internal/utils"
)

const (
	resultHeader   = "x-ext-authz-check-result"
	receivedHeader = "x-ext-authz-check-received"

	resultAllowed    = "allowed"
	resultDenied     = "denied"
	resultDeniedBody = "Unauthorized"
)

var (
	urlEncodeRegex = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

type HttpServer struct {
	server *http.Server

	config v1alpha2.DoorkeeperConfigT
	log    logger.LoggerT
}

func NewHttpServer(filepath string) (server *HttpServer, err error) {
	server = &HttpServer{}
	server.config, err = config.ParseConfigFile(filepath)
	if err != nil {
		return server, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleRequest)
	server.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%s", server.config.Address, server.config.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	level := logger.GetLevel(server.config.LogLevel)
	commonFields := map[string]any{
		"service": "doorkeeper",
		"serve":   fmt.Sprintf("%s:%s", server.config.Address, server.config.Port),
	}
	server.log = logger.NewLogger(context.Background(), level, commonFields)
	return server, err
}

func (s *HttpServer) handleRequest(response http.ResponseWriter, request *http.Request) {
	// globals.Application.Logger.Infof(
	// 	"handle request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}",
	// 	globals.Application.Config.Auth.Type,
	// 	request.Host,
	// 	request.URL.Path,
	// 	request.URL.RawQuery,
	// 	request.Header,
	// )
	logFields := utils.GetDefaultLogFields()
	logFields["request"] = utils.RequestStruct(request)
	s.log.Info("handle request", logFields)

	valid := false

	var err error
	defer func() {
		if err != nil || !valid {
			// globals.Application.Logger.Errorf(
			// 	"denied request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}: %s",
			// 	globals.Application.Config.Auth.Type,
			// 	request.Host,
			// 	request.URL.Path,
			// 	request.URL.RawQuery,
			// 	request.Header,
			// 	err.Error(),
			// )
			response.Header().Set(resultHeader, resultDenied)
			response.WriteHeader(http.StatusForbidden)
			_, _ = response.Write([]byte(resultDeniedBody))
		}
	}()

	s.applyModifiers(request)

	//
	body, err := io.ReadAll(request.Body)
	if err != nil {
		logFields["error"] = err.Error()
		s.log.Error("unable to read request body", logFields)
		return
	}

	//
	receivedContent := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, returnIfNotTooLong(string(body)))
	response.Header().Set(receivedHeader, receivedContent)

	authResults := []bool{}
	for _, authv := range s.config.Auths {
		valid, err := checkAuthorization(request, authv)
		if err != nil {
			logFields["error"] = err.Error()
			s.log.Error("unable to check authorization", logFields)
			err = nil
			continue
		}
		authResults = append(authResults, valid)
	}

	if slices.Contains(authResults, false) {
		return
	}

	response.Header().Set(resultHeader, resultAllowed)
	response.WriteHeader(http.StatusOK)
	err = nil
}

func (s *HttpServer) Run() {
	logFields := utils.GetDefaultLogFields()

	s.log.Info("starting HTTP server", logFields)
	err := s.server.ListenAndServe()
	if err != nil {
		logFields["error"] = err.Error()
		s.log.Error("server failed", logFields)
	}
}

func (s *HttpServer) Stop() {
	logFields := utils.GetDefaultLogFields()

	err := s.server.Close()
	if err != nil {
		logFields["error"] = err.Error()
		s.log.Error("HTTP server close with error", logFields)
		return
	}

	s.log.Info("HTTP server close", logFields)
}
