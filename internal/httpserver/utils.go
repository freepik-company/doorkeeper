package httpserver

import (
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/hmac"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (s *HttpServer) applyModifiers(r *http.Request) {
	for _, modv := range s.config.Modifiers {
		switch modv.Type {
		case "Path":
			r.URL.Path = modv.Path.CompiledRegex.ReplaceAllString(r.URL.Path, modv.Path.Replace)

		case "Header":
			// TODO
		}
	}
}

func checkAuthorization(r *http.Request, auth v1alpha2.AuthorizationConfigT) (valid bool, err error) {
	paramToCheck := r.URL.Query().Get(auth.Param.Name)
	if auth.Param.Type == "Header" {
		paramToCheck = r.Header.Get(auth.Param.Name)
	}

	switch auth.Type {
	case "HMAC":
		{
			path := strings.Split(r.URL.Path, "?")[0]
			if auth.Hmac.Type == "URL" {
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
	// var generatedHmac, receivedHmac string
	// if globals.Application.Config.Auth.Type == "hmac" {
	// 	path := strings.Split(request.URL.Path, "?")[0]

	// 	if globals.Application.Config.Hmac.Type == "url" {
	// 		if globals.Application.Config.Hmac.Url.EarlyEncode {
	// 			path = url.PathEscape(path)

	// 			if globals.Application.Config.Hmac.Url.LowerEncode {
	// 				path = urlEncodeRegex.ReplaceAllStringFunc(path, func(match string) string {
	// 					return strings.ToLower(match)
	// 				})
	// 			}
	// 		}

	// 		//
	// 		valid, generatedHmac, receivedHmac, err = hmac.ValidateTokenUrl(token, globals.Application.Config.Hmac.EncryptionKey,
	// 			globals.Application.Config.Hmac.EncryptionAlgorithm, path)
	// 		if err != nil {
	// 			err = fmt.Errorf("unable to validate token in request: %s", err.Error())
	// 			return
	// 		}
	// 	}
	// }

	// if !valid {
	// 	err = fmt.Errorf("invalid token in request {generatedHMAC:'%s', receivedHMAC:'%s'}", generatedHmac, receivedHmac)
	// 	return
	// }
	return valid, err
}
