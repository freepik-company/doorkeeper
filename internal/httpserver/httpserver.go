package httpserver

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	//
	"doorkeeper/internal/hmac"
	"doorkeeper/internal/globals"
)

const (
	resultHeader   = "x-ext-authz-check-result"
	receivedHeader = "x-ext-authz-check-received"

	resultAllowed = "allowed"
	resultDenied  = "denied"
	resultDeniedBody = "Unauthorized"
)

var (
	
	//
	authorizationParamType = os.Getenv("DOORKEEPER_AUTHORIZATION_PARAM_TYPE")
	authorizationParamName = os.Getenv("DOORKEEPER_AUTHORIZATION_PARAM_NAME")
	authorizationType = os.Getenv("DOORKEEPER_AUTHORIZATION_TYPE")
	
	//
	hmacEncryptionKey = os.Getenv("DOORKEEPER_HMAC_ENCRYPTION_KEY")
	hmacEncryptionArgotithm = os.Getenv("DOORKEEPER_HMAC_ENCRYPTION_ALGORITHM")
	hmacType = os.Getenv("DOORKEEPER_HMAC_TYPE")
)

type HttpServer struct {
	*http.Server
}

func NewHttpServer() *HttpServer {
	if authorizationParamType == "" || authorizationParamName == "" || authorizationType == "" {
		globals.Application.Logger.Fatal("environment variables fot authorization must be setted")
	}

	if authorizationType == "hmac" && 
	(hmacEncryptionKey == "" || hmacEncryptionArgotithm == "" || hmacType == "") {
		globals.Application.Logger.Fatal("environment variables for 'hmac' authorization type must be setted")
	}
	
	return &HttpServer{}
}

func (s *HttpServer) handleRequest(response http.ResponseWriter, request *http.Request) {
	globals.Application.Logger.Infof(
		"handle request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}", 
		authorizationType,
		request.Host,
		request.URL.Path, 
		request.URL.RawQuery,
		request.Header,
	)
	
	var err error
	defer func(){
		if err != nil {
			globals.Application.Logger.Errorf(
				"denied request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}: %s", 
				authorizationType,
				request.Host,
				request.URL.Path, 
				request.URL.RawQuery,
				request.Header,
				err.Error(),
			)
			response.Header().Set(resultHeader, resultDenied)
			response.WriteHeader(http.StatusForbidden)
			_, _ = response.Write([]byte(resultDeniedBody))
		}
	}()

	//
	body, err := io.ReadAll(request.Body)
	if err != nil {
		globals.Application.Logger.Errorf("unable to read request body: %s", err.Error())
		return
	}
	
	//
	receivedContent := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, returnIfNotTooLong(string(body)))
	response.Header().Set(receivedHeader, receivedContent)

	token := request.URL.Query().Get(authorizationParamName)
	if authorizationParamType == "header" {
		token = request.Header.Get(authorizationParamName)
	}

	var valid bool
	if authorizationType == "hmac" {
		pathParts := strings.Split(request.URL.Path, "?")

		if hmacType == "url" {
			valid, err = hmac.ValidateTokenUrl(token, hmacEncryptionKey, hmacEncryptionArgotithm, pathParts[0])
			if err != nil {
				err = fmt.Errorf("unable to validate token in request: %s", err.Error())
				return
			}
		}
	}
	
	if !valid {
		err = fmt.Errorf("invalid token in request")		
		return 
	}
	
	globals.Application.Logger.Infof(
		"allowed request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}", 
		authorizationType,
		request.Host, 
		request.URL.Path, 
		request.URL.RawQuery,
		request.Header,
	)

	response.Header().Set(resultHeader, resultAllowed)
	response.WriteHeader(http.StatusOK)
	err = nil
}

func (s *HttpServer) Run(httpAddr string) {
	defer func() {
		globals.Application.Logger.Infof("Stopped HTTP server")
	}()

	// Create the webserver to serve the requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	globals.Application.Logger.Infof("Starting HTTP server on %s", httpAddr)

	err := http.ListenAndServe(httpAddr, mux)
	if err != nil {
		globals.Application.Logger.Errorf("Server failed. Reason: %s", err.Error())
	}
}

func (s *HttpServer) Stop() {
	globals.Application.Logger.Infof("HTTP server stopped: %v", s.Close())
}
