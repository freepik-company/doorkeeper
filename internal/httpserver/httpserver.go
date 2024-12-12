package httpserver

import (
	"context"
	"fmt"
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

	resultAllowed     = "allowed"
	resultAllowedBody = "Authorized"

	resultDenied     = "denied"
	resultDeniedBody = "Unauthorized"
)

var (
	urlEncodeRegex = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

type HttpServer struct {
	config v1alpha2.DoorkeeperConfigT
	log    logger.LoggerT

	server *http.Server
	auths  map[string]*v1alpha2.AuthorizationConfigT
}

func NewHttpServer(filepath string) (server *HttpServer, err error) {
	server = &HttpServer{}
	server.config, err = config.ParseConfigFile(filepath)
	if err != nil {
		return server, err
	}

	server.auths = make(map[string]*v1alpha2.AuthorizationConfigT)
	for authi, authv := range server.config.Auths {
		server.auths[authv.Name] = &server.config.Auths[authi]
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleRequest)
	mux.HandleFunc("/healthz", getHealthz)
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

func getHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *HttpServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	logFields := utils.GetDefaultLogFields()
	utils.SetLogField(logFields, utils.LogFieldKeyRequestID, utils.RequestID(r))

	requestStruct := utils.RequestStruct(r)
	utils.SetLogField(logFields, utils.LogFieldKeyRequest, requestStruct)

	responseStruct := utils.NewResponseStruct(http.StatusForbidden, make(http.Header), resultDeniedBody)
	responseStruct.Headers.Set(resultHeader, resultDenied)
	responseStruct.Headers.Set(receivedHeader, fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", requestStruct.Method, requestStruct.Host, requestStruct.Path, requestStruct.Headers, requestStruct.Body))

	s.log.Info("handle request", logFields)

	defer func() {
		n, err := sendResponse(w, responseStruct)
		utils.SetLogField(logFields, utils.LogFieldKeyResponseBytes, n)
		if err != nil {
			utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
			s.log.Error("error in send response", logFields)
			return
		}

		s.log.Error("success in handle request", logFields)
	}()

	s.applyModifiers(r)
	responseStruct.Request = utils.RequestStruct(r)

	authResults := []bool{}
	for _, authv := range s.config.Auths {
		valid, err := checkAuthorization(r, authv)
		if err != nil {
			utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
			s.log.Error("unable to check authorization", logFields)
			err = nil
			continue
		}
		authResults = append(authResults, valid)
	}

	if slices.Contains(authResults, false) {
		return
	}

	//
	responseStruct.Code = http.StatusOK
	responseStruct.Headers.Set(resultHeader, resultAllowed)
	responseStruct.Body = resultAllowedBody
	responseStruct.Length = len(resultAllowedBody)
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
