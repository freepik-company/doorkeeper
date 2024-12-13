package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	//
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"doorkeeper/internal/logger"
	"doorkeeper/internal/utils"
)

const (
// resultHeader   = "x-ext-authz-check-result"
// receivedHeader = "x-ext-authz-check-received"

// resultAllowed     = "allowed"
// resultAllowedBody = "Authorized"

// resultDenied     = "denied"
// resultDeniedBody = "Unauthorized"
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
	var err error = nil

	logFields := utils.GetDefaultLogFields()
	utils.SetLogField(logFields, utils.LogFieldKeyRequestID, utils.RequestID(r))
	utils.SetLogField(logFields, utils.LogFieldKeyRequest, utils.RequestStruct(r))

	// Set denied response values
	responseStruct := utils.NewResponseStruct(s.config.Response.Denied.StatusCode, nil, s.config.Response.Denied.Body)
	for hk, hv := range s.config.Response.Denied.Headers {
		responseStruct.Headers.Set(hk, hv)
	}

	s.log.Info("handle request", logFields)

	defer func() {
		if err != nil {
			// Set error response values
			responseStruct.Code = http.StatusInternalServerError
			responseStruct.Body = fmt.Sprintf("%d %s", responseStruct.Code, http.StatusText(responseStruct.Code))
			responseStruct.Length = len(responseStruct.Body)
		}

		utils.SetLogField(logFields, utils.LogFieldKeyResponse, responseStruct)

		n, err := sendResponse(w, responseStruct)
		utils.SetLogField(logFields, utils.LogFieldKeyResponseBytes, n)
		if err != nil {
			utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
			s.log.Error("error in send response", logFields)
			return
		}

		s.log.Info("success in handle request", logFields)
	}()

	s.applyModifiers(r)
	responseStruct.Request = utils.RequestStruct(r)

	for _, reqv := range s.config.RequestAuthReq {
		utils.SetLogField(logFields, utils.LogFieldKeyRequirement, reqv.Name)

		reqResults := []bool{}
		valid := false
		for _, authn := range reqv.Authorizations {
			utils.SetLogField(logFields, utils.LogFieldKeyAuthorization, authn)

			valid, err = checkAuthorization(r, s.auths[authn])
			if err != nil {
				utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
				s.log.Error("unable to check authorization", logFields)
				return
			}
			utils.SetLogField(logFields, utils.LogFieldKeyAuthorizationResult, strconv.FormatBool(valid))

			s.log.Debug("success in check authorization", logFields)
			reqResults = append(reqResults, valid)
		}
		utils.SetLogField(logFields, utils.LogFieldKeyAuthorization, utils.LogFieldValueDefaultStr)
		utils.SetLogField(logFields, utils.LogFieldKeyAuthorizationResult, utils.LogFieldValueDefaultStr)

		switch reqv.Type {
		case config.ConfigTypeValueRequirementALL:
			{
				if slices.Contains(reqResults, false) {
					s.log.Info("denied request", logFields)
					return
				}
			}
		case config.ConfigTypeValueRequirementANY:
			{
				if !slices.Contains(reqResults, true) {
					s.log.Info("denied request", logFields)
					return
				}
			}
		}
	}
	utils.SetLogField(logFields, utils.LogFieldKeyRequirement, utils.LogFieldValueDefaultStr)

	// Set allowed response values
	responseStruct.Code = s.config.Response.Allowed.StatusCode
	responseStruct.Body = s.config.Response.Allowed.Body
	responseStruct.Length = len(s.config.Response.Allowed.Body)
	for hk, hv := range s.config.Response.Allowed.Headers {
		responseStruct.Headers.Set(hk, hv)
	}

	s.log.Info("allowed request", logFields)
}

func (s *HttpServer) Run() {
	logFields := utils.GetDefaultLogFields()

	s.log.Info("starting HTTP server", logFields)
	err := s.server.ListenAndServe()
	if err != nil {
		utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
		s.log.Error("server failed", logFields)
	}
}

func (s *HttpServer) Stop() {
	logFields := utils.GetDefaultLogFields()

	err := s.server.Close()
	if err != nil {
		utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
		s.log.Error("HTTP server close with error", logFields)
		return
	}

	s.log.Info("HTTP server close", logFields)
}
