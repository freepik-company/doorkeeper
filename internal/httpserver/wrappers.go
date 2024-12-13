package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"doorkeeper/internal/hmac"
	"doorkeeper/internal/utils"
)

func sendResponse(w http.ResponseWriter, resp utils.ResponseT) (n int, err error) {
	for hk, hvs := range resp.Headers {
		for _, hv := range hvs {
			w.Header().Add(hk, hv)
		}
	}

	if resp.Body != "" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(resp.Length))

		w.WriteHeader(resp.Code)
		n, err = w.Write([]byte(resp.Body))
	}

	return n, err
}

func (s *HttpServer) applyModifiers(r *http.Request) {
	for _, modv := range s.config.Modifiers {
		switch modv.Type {
		case config.ConfigTypeValueModifierPATH:
			r.URL.Path = modv.Path.CompiledRegex.ReplaceAllString(r.URL.Path, modv.Path.Replace)

		case config.ConfigTypeValueModifierHEADER:
			// TODO
		}
	}
}

func checkAuthorization(r *http.Request, auth *v1alpha2.AuthorizationConfigT) (valid bool, err error) {
	paramToCheck := r.URL.Query().Get(auth.Param.Name)
	if auth.Param.Type == config.ConfigTypeValueAuthParamHEADER {
		paramToCheck = r.Header.Get(auth.Param.Name)
	}

	switch auth.Type {
	case config.ConfigTypeValueAuthHMAC:
		{
			path := strings.Split(r.URL.Path, "?")[0]
			if auth.Hmac.Type == config.ConfigTypeValueAuthHmacURL {
				if auth.Hmac.Url.EarlyEncode {
					path = url.PathEscape(path)

					if auth.Hmac.Url.LowerEncode {
						path = urlEncodeRegex.ReplaceAllStringFunc(path, func(match string) string {
							return strings.ToLower(match)
						})
					}
				}

				//
				var generatedHmac, receivedHmac string
				valid, generatedHmac, receivedHmac, err = hmac.ValidateTokenUrl(paramToCheck, auth.Hmac.EncryptionKey, auth.Hmac.EncryptionAlgorithm, path)
				if err != nil {
					err = fmt.Errorf("unable to validate token in request: %s", err.Error())
					return valid, err
				}
				_ = generatedHmac
				_ = receivedHmac
			}
		}
	}

	return valid, err
}
