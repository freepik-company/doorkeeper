package doorkeeper

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	//
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"doorkeeper/internal/logger"
	"doorkeeper/internal/modifiers"
	"doorkeeper/internal/utils"
)

var (
	urlEncodeRegex = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

type DoorkeeperT struct {
	config v1alpha2.DoorkeeperConfigT
	log    logger.LoggerT

	server *http.Server
	mods   []modifiers.ModifierI
	auths  map[string]*v1alpha2.AuthorizationConfigT
}

func NewDoorkeeper(filepath string) (d *DoorkeeperT, err error) {
	d = &DoorkeeperT{}
	d.config, err = config.ParseConfigFile(filepath)
	if err != nil {
		return d, err
	}

	for _, modv := range d.config.Modifiers {
		mod, err := modifiers.GetModifier(modv)
		if err != nil {
			return d, err
		}

		d.mods = append(d.mods, mod)
		// switch modv.Type {
		// case config.ConfigModifierTypePATH:
		// 	{
		// 		d.config.Modifiers[modi].Path.CompiledRegex = regexp.MustCompile(modv.Path.Pattern)
		// 	}
		// case config.ConfigModifierTypeHEADER:
		// 	{
		// 		d.config.Modifiers[modi].Header.CompiledRegex = regexp.MustCompile(modv.Header.Pattern)
		// 	}
		// }
	}

	for authi, authv := range d.config.Auths {
		switch authv.Type {
		case config.ConfigAuthTypeHMAC:
		case config.ConfigAuthTypeIPLIST:
			{
				_, d.config.Auths[authi].IpList.CidrCompiled, err = net.ParseCIDR(authv.IpList.Cidr)
				if err != nil {
					return d, err
				}

				for _, tnv := range authv.IpList.TrustedNetworks {
					var cidr *net.IPNet
					_, cidr, err = net.ParseCIDR(tnv)
					if err != nil {
						return d, err
					}
					d.config.Auths[authi].IpList.TrustedNetworksCompiled = append(d.config.Auths[authi].IpList.TrustedNetworksCompiled, cidr)
				}
			}
		case config.ConfigAuthTypeMATCH:
			{
				d.config.Auths[authi].Match.CompiledRegex = regexp.MustCompile(authv.Match.Pattern)
			}
		}
	}

	d.auths = make(map[string]*v1alpha2.AuthorizationConfigT)
	for authi, authv := range d.config.Auths {
		d.auths[authv.Name] = &d.config.Auths[authi]
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleRequest)
	mux.HandleFunc("/healthz", getHealthz)
	d.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%s", d.config.Address, d.config.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	level := logger.GetLevel(d.config.LogLevel)
	commonFields := map[string]any{
		"service": "doorkeeper",
		"serve":   fmt.Sprintf("%s:%s", d.config.Address, d.config.Port),
	}
	d.log = logger.NewLogger(context.Background(), level, commonFields)
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
	var err error = nil

	logFields := utils.GetDefaultLogFields()
	utils.SetLogField(logFields, utils.LogFieldKeyRequestID, utils.RequestID(r))
	utils.SetLogField(logFields, utils.LogFieldKeyRequest, utils.RequestStruct(r))

	// Set denied response values
	responseStruct := utils.NewResponseStruct(d.config.Response.Denied.StatusCode, nil, d.config.Response.Denied.Body)
	for hk, hv := range d.config.Response.Denied.Headers {
		responseStruct.Headers.Set(hk, hv)
	}

	d.log.Info("handle request", logFields)

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
			d.log.Error("error in send response", logFields)
			return
		}

		d.log.Info("success in handle request", logFields)
	}()

	// Apply modifiers to the request
	for modi := range d.mods {
		d.mods[modi].Apply(r)
	}
	// d.applyModifiers(r)
	responseStruct.Request = utils.RequestStruct(r)

	for _, reqv := range d.config.RequestAuthReq {
		utils.SetLogField(logFields, utils.LogFieldKeyRequirement, reqv.Name)

		reqResults := []bool{}
		valid := false
		for _, authn := range reqv.Authorizations {
			utils.SetLogField(logFields, utils.LogFieldKeyAuthorization, authn)

			valid, err = checkAuthorization(r, d.auths[authn])
			if err != nil {
				utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
				valid = false
				err = nil
			}
			utils.SetLogField(logFields, utils.LogFieldKeyAuthorizationResult, strconv.FormatBool(valid))

			d.log.Debug("check authorization result", logFields)
			reqResults = append(reqResults, valid)
			utils.SetLogField(logFields, utils.LogFieldKeyError, utils.LogFieldValueDefaultStr)
		}
		utils.SetLogField(logFields, utils.LogFieldKeyAuthorization, utils.LogFieldValueDefaultStr)
		utils.SetLogField(logFields, utils.LogFieldKeyAuthorizationResult, utils.LogFieldValueDefaultStr)

		switch reqv.Type {
		case config.ConfigTypeValueRequirementALL:
			{
				if slices.Contains(reqResults, false) {
					d.log.Info("denied request", logFields)
					return
				}
			}
		case config.ConfigTypeValueRequirementANY:
			{
				if !slices.Contains(reqResults, true) {
					d.log.Info("denied request", logFields)
					return
				}
			}
		}
	}
	utils.SetLogField(logFields, utils.LogFieldKeyRequirement, utils.LogFieldValueDefaultStr)

	// Set allowed response values
	responseStruct.Code = d.config.Response.Allowed.StatusCode
	responseStruct.Body = d.config.Response.Allowed.Body
	responseStruct.Length = len(d.config.Response.Allowed.Body)
	for hk, hv := range d.config.Response.Allowed.Headers {
		responseStruct.Headers.Set(hk, hv)
	}

	d.log.Info("allowed request", logFields)
}

func (d *DoorkeeperT) Run() {
	logFields := utils.GetDefaultLogFields()

	d.log.Info("starting HTTP server", logFields)
	err := d.server.ListenAndServe()
	if err != nil {
		utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
		d.log.Error("server failed", logFields)
	}
}

func (d *DoorkeeperT) Stop() {
	logFields := utils.GetDefaultLogFields()

	err := d.server.Close()
	if err != nil {
		utils.SetLogField(logFields, utils.LogFieldKeyError, err.Error())
		d.log.Error("HTTP server close with error", logFields)
		return
	}

	d.log.Info("HTTP server close", logFields)
}
