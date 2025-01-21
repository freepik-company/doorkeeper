package doorkeeper

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	//

	"doorkeeper/internal/authorizations"
	"doorkeeper/internal/config"
	"doorkeeper/internal/logger"
	"doorkeeper/internal/modifiers"
	"doorkeeper/internal/utils"
)

type DoorkeeperT struct {
	log logger.LoggerT

	server *http.Server

	mods         []modifiers.ModifierI
	auths        map[string]authorizations.AuthI
	requirements []requirementT

	allowed       responseT
	denied        responseT
	internalError responseT
}

type requirementT struct {
	Name           string
	Type           string
	Authorizations []string
}

type responseT struct {
	Code    int         `json:"code"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"`
}

func NewDoorkeeper(filepath string) (d *DoorkeeperT, err error) {
	d = &DoorkeeperT{}
	cfg, err := config.ParseConfigFile(filepath)
	if err != nil {
		return d, err
	}

	for _, modv := range cfg.Modifiers {
		mod, err := modifiers.GetModifier(modv)
		if err != nil {
			return d, err
		}

		d.mods = append(d.mods, mod)
	}

	// Set responses
	d.allowed = newResponse(cfg.Response.Allowed.StatusCode, cfg.Response.Allowed.Headers, []byte(cfg.Response.Allowed.Body))
	d.denied = newResponse(cfg.Response.Denied.StatusCode, cfg.Response.Denied.Headers, []byte(cfg.Response.Denied.Body))
	d.internalError = newResponse(
		http.StatusInternalServerError,
		map[string]string{},
		[]byte(fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))),
	)

	// Set auth
	d.auths = make(map[string]authorizations.AuthI)
	for _, authv := range cfg.Auths {
		d.auths[authv.Name], err = authorizations.GetAuthorization(authv)
		if err != nil {
			return d, err
		}
	}

	for _, rv := range cfg.RequestAuthReq {
		req := requirementT{
			Name: rv.Name,
			Type: rv.Type,
		}
		req.Authorizations = append(req.Authorizations, rv.Authorizations...)

		d.requirements = append(d.requirements, req)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleRequest)
	mux.HandleFunc("/healthz", getHealthz)
	d.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Address, cfg.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	d.log = logger.NewLogger(logger.GetLevel(cfg.LogLevel))
	return d, err
}

func getHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (d *DoorkeeperT) handleRequest(w http.ResponseWriter, r *http.Request) {
	logFields := utils.GetDefaultLogFields()
	logFields.Set(utils.LogFieldKeyRequestID, utils.RequestID(r))

	// Set default denied response values
	var err error = nil
	var response responseT = d.denied

	defer func() {
		if err != nil {
			// Set error response values
			response = d.internalError
		}

		logFields.Set(utils.LogFieldKeyResponse, response)

		n, err := sendResponse(w, response)
		if err != nil {
			logFields.Set(utils.LogFieldKeyError, fmt.Sprintf("only %d bytes were delivered: %s", n, err.Error()))
			d.log.Error("error in send response", logFields)
			return
		}
	}()

	logFields.Set(utils.LogFieldKeyRequest, utils.RequestLogStruct(r))

	// Apply modifiers to the request
	for modi := range d.mods {
		d.mods[modi].Apply(r)
	}

	logFields.Set(utils.LogFieldKeyRequestMod, utils.RequestLogStruct(r))
	d.log.Info("handle request", logFields)
	logFields.Del(utils.LogFieldKeyRequest)

	for _, reqv := range d.requirements {
		logFields.Set(utils.LogFieldKeyRequirement, reqv.Name)

		reqResults := []bool{}
		for _, authn := range reqv.Authorizations {
			logFields.Set(utils.LogFieldKeyAuthorization, authn)

			err = d.auths[authn].Check(r)
			if err != nil {
				logFields.Set(utils.LogFieldKeyError, err.Error())
				d.log.Debug("error in authorization check", logFields)
				logFields.Del(utils.LogFieldKeyError)

				reqResults = append(reqResults, false)
				err = nil
				continue
			}

			d.log.Debug("success in authorization check", logFields)
			reqResults = append(reqResults, true)
		}
		logFields.Del(utils.LogFieldKeyAuthorization)
		logFields.Del(utils.LogFieldKeyRequirement)

		invalid := slices.Contains(reqResults, false) // result with ConfigTypeValueRequirementALL type by default
		if reqv.Type == config.ConfigTypeValueRequirementANY {
			invalid = !slices.Contains(reqResults, true)
		}

		if invalid {
			logFields.Set(utils.LogFieldKeyResponse, response)
			d.log.Info("denied request", logFields)
			return
		}
	}
	logFields.Del(utils.LogFieldKeyRequirement)

	// Set allowed response values
	response = d.allowed

	logFields.Set(utils.LogFieldKeyResponse, response)
	d.log.Info("allowed request", logFields)
}

func (d *DoorkeeperT) Run() {
	logFields := utils.GetDefaultLogFields()

	d.log.Info("starting HTTP server", logFields)
	err := d.server.ListenAndServe()
	if err != nil {
		logFields.Set(utils.LogFieldKeyError, err.Error())
		d.log.Error("server failed", logFields)
	}
}

func (d *DoorkeeperT) Stop() {
	logFields := utils.GetDefaultLogFields()

	err := d.server.Close()
	if err != nil {
		logFields.Set(utils.LogFieldKeyError, err.Error())
		d.log.Error("HTTP server close with error", logFields)
		return
	}

	d.log.Info("HTTP server close", logFields)
}
