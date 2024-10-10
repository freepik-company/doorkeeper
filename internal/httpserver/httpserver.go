package httpserver

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	//
	"doorkeeper/internal/globals"
	"doorkeeper/internal/hmac"
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
	*http.Server
}

func NewHttpServer() (server *HttpServer) {
	if globals.Application.Config.Auth.Param.Type == "" || globals.Application.Config.Auth.Param.Name == "" ||
		globals.Application.Config.Auth.Type == "" {

		globals.Application.Logger.Fatal("environment variables fot authorization must be setted")
	}

	if globals.Application.Config.Auth.Type == "hmac" &&
		(globals.Application.Config.Hmac.EncryptionKey == "" ||
			globals.Application.Config.Hmac.EncryptionAlgorithm == "" ||
			globals.Application.Config.Hmac.Type == "") {
		globals.Application.Logger.Fatal("environment variables for 'hmac' authorization type must be setted")
	}

	for index, mod := range globals.Application.Config.Modifiers {
		if mod.Type == "path" {
			globals.Application.Config.Modifiers[index].Path.CompiledRegex = regexp.MustCompile(mod.Path.Pattern)
		}
	}

	return server
}

func (s *HttpServer) handleRequest(response http.ResponseWriter, request *http.Request) {
	globals.Application.Logger.Infof(
		"handle request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}",
		globals.Application.Config.Auth.Type,
		request.Host,
		request.URL.Path,
		request.URL.RawQuery,
		request.Header,
	)

	var err error
	defer func() {
		if err != nil {
			globals.Application.Logger.Errorf(
				"denied request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}: %s",
				globals.Application.Config.Auth.Type,
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

	for _, modifier := range globals.Application.Config.Modifiers {
		switch modifier.Type {
		case "path":
			request.URL.Path = modifier.Path.CompiledRegex.ReplaceAllString(request.URL.Path, modifier.Path.Replace)

		case "header":
			// TODO
		}
	}

	//
	body, err := io.ReadAll(request.Body)
	if err != nil {
		globals.Application.Logger.Errorf("unable to read request body: %s", err.Error())
		return
	}

	//
	receivedContent := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, returnIfNotTooLong(string(body)))
	response.Header().Set(receivedHeader, receivedContent)

	token := request.URL.Query().Get(globals.Application.Config.Auth.Param.Name)
	if globals.Application.Config.Auth.Param.Type == "header" {
		token = request.Header.Get(globals.Application.Config.Auth.Param.Name)
	}

	var valid bool
	var generatedHmac, receivedHmac string
	if globals.Application.Config.Auth.Type == "hmac" {
		path := strings.Split(request.URL.Path, "?")[0]

		if globals.Application.Config.Hmac.Type == "url" {
			if globals.Application.Config.Hmac.Url.EarlyEncode {
				path = url.PathEscape(path)

				if globals.Application.Config.Hmac.Url.LowerEncode {
					path = urlEncodeRegex.ReplaceAllStringFunc(path, func(match string) string {
						return strings.ToLower(match)
					})
				}
			}

			//
			valid, generatedHmac, receivedHmac, err = hmac.ValidateTokenUrl(token, globals.Application.Config.Hmac.EncryptionKey,
				globals.Application.Config.Hmac.EncryptionAlgorithm, path)
			if err != nil {
				err = fmt.Errorf("unable to validate token in request: %s", err.Error())
				return
			}
		}
	}

	if !valid {
		err = fmt.Errorf("invalid token in request {generatedHMAC:'%s', receivedHMAC:'%s'}", generatedHmac, receivedHmac)
		return
	}

	globals.Application.Logger.Infof(
		"allowed request {authorizationType '%s', host: '%s', path: '%s', query: %s, headers '%v'}",
		globals.Application.Config.Auth.Type,
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
