package doorkeeper

import (
	"fmt"
	"net"
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

// func (d *DoorkeeperT) applyModifiers(r *http.Request) {
// 	for _, modv := range d.config.Modifiers {
// 		switch modv.Type {
// 		case config.ConfigModifierTypePATH:
// 			r.URL.Path = modv.Path.CompiledRegex.ReplaceAllString(r.URL.Path, modv.Path.Replace)

// 		case config.ConfigModifierTypeHEADER:
// 			headerVal := modv.Header.CompiledRegex.ReplaceAllString(r.Header.Get(modv.Header.Name), modv.Header.Replace)
// 			r.Header.Set(modv.Header.Name, headerVal)
// 		}
// 	}
// }

func checkAuthorization(r *http.Request, auth *v1alpha2.AuthorizationConfigT) (valid bool, err error) {
	paramToCheck := r.URL.Query().Get(auth.Param.Name)
	if auth.Param.Type == config.ConfigAuthParamTypeHEADER {
		paramToCheck = r.Header.Get(auth.Param.Name)
	}

	if paramToCheck == "" {
		err = fmt.Errorf("empty param to check in request")
		return valid, err
	}

	switch auth.Type {
	case config.ConfigAuthTypeHMAC:
		{
			valueToCheck := ""
			if auth.Hmac.Type == config.ConfigAuthHmacTypeURL {
				switch auth.Hmac.Url.From {
				case config.ConfigAuthHmacUrlFromPATH:
					valueToCheck = strings.Split(r.URL.Path, "?")[0]
				case config.ConfigAuthHmacUrlFromHEADER:
					valueToCheck = r.Header.Get(auth.Hmac.Url.Name)
				}

				if auth.Hmac.Url.EarlyEncode {
					valueToCheck = url.PathEscape(valueToCheck)

					if auth.Hmac.Url.LowerEncode {
						valueToCheck = urlEncodeRegex.ReplaceAllStringFunc(valueToCheck, func(match string) string {
							return strings.ToLower(match)
						})
					}
				}

				//
				var generatedHmac, receivedHmac string
				valid, generatedHmac, receivedHmac, err = hmac.ValidateTokenUrl(paramToCheck, auth.Hmac.EncryptionKey, auth.Hmac.EncryptionAlgorithm, valueToCheck, auth.Hmac.MandatoryFields)
				if err != nil {
					err = fmt.Errorf("unable to validate hmac sign in request: %s", err.Error())
					return valid, err
				}
				_ = generatedHmac
				_ = receivedHmac
			}
		}
	case config.ConfigAuthTypeIPLIST:
		{
			iplist := strings.Split(paramToCheck, auth.IpList.Separator)

			// filter trusted networks
			filteredIpList := []net.IP{}
			for _, ipv := range iplist {
				trimipv := strings.TrimSpace(ipv)
				currentIP := net.ParseIP(trimipv)
				if currentIP == nil {
					err = fmt.Errorf("invalid ip '%s' in list recieved", trimipv)
					return valid, err
				}

				found := false
				for _, tnv := range auth.IpList.TrustedNetworksCompiled {
					if tnv.Contains(currentIP) {
						found = true
						break
					}
				}

				if !found {
					filteredIpList = append(filteredIpList, currentIP)
				}
			}

			// check filtered ip list

			if len(filteredIpList) != 1 {
				err = fmt.Errorf("to mutch ips in list after filter trusted networks %v", filteredIpList)
				return valid, err
			}

			valid = auth.IpList.CidrCompiled.Contains(filteredIpList[0])
			if auth.IpList.Reverse {
				valid = !valid
			}
		}
	case config.ConfigAuthTypeMATCH:
		{
			valid = auth.Match.CompiledRegex.MatchString(paramToCheck)
			if auth.Match.Reverse {
				valid = !valid
			}
		}
	}

	return valid, err
}
