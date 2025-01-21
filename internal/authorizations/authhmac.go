package authorizations

import (
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"doorkeeper/internal/hmac"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	urlEncodeRegex = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

type HmacT struct {
	paramType string
	paramName string

	hmacType            string
	hmacMandatoryFields []string

	hmacEncryptionKey       string
	hmacEncryptionAlgorithm string

	hmacUrlFrom        string
	hmacUrlName        string
	hmacUrlEarlyEncode bool
	hmacUrlLowerEncode bool
}

func NewHmac(cfg v1alpha2.AuthorizationConfigT) (h *HmacT, err error) {
	h = &HmacT{
		paramType: cfg.Param.Type,
		paramName: cfg.Param.Name,

		hmacType:            cfg.Hmac.Type,
		hmacMandatoryFields: cfg.Hmac.MandatoryFields,

		hmacEncryptionKey:       cfg.Hmac.EncryptionKey,
		hmacEncryptionAlgorithm: cfg.Hmac.EncryptionAlgorithm,

		hmacUrlFrom:        cfg.Hmac.Url.From,
		hmacUrlName:        cfg.Hmac.Url.Name,
		hmacUrlEarlyEncode: cfg.Hmac.Url.EarlyEncode,
		hmacUrlLowerEncode: cfg.Hmac.Url.LowerEncode,
	}
	return h, err
}

func (a *HmacT) Check(r *http.Request) (err error) {
	// get params

	paramToCheck := r.URL.Query().Get(a.paramName)
	if a.paramType == config.ConfigAuthParamTypeHEADER {
		paramToCheck = r.Header.Get(a.paramName)
	}

	if paramToCheck == "" {
		err = fmt.Errorf("empty %s param '%s' in request", a.paramType, a.paramName)
		return err
	}

	// check

	switch a.hmacType {
	case config.ConfigAuthHmacTypeURL:
		{
			err = a.checkUrlType(r, paramToCheck)
		}
	default:
		{
			err = fmt.Errorf("unsupported hmac type")
		}
	}

	return err
}

func (a *HmacT) checkUrlType(r *http.Request, paramToCheck string) (err error) {
	urlValue := strings.Split(r.URL.Path, "?")[0]
	if a.hmacUrlFrom == config.ConfigAuthHmacUrlFromHEADER {
		urlValue = r.Header.Get(a.hmacUrlName)
	}

	if urlValue == "" {
		return fmt.Errorf("unable to get url value { from: '%s', name: '%s' }", a.hmacUrlFrom, a.hmacUrlName)
	}

	if a.hmacUrlEarlyEncode {
		urlValue = url.PathEscape(urlValue)

		if a.hmacUrlLowerEncode {
			urlValue = urlEncodeRegex.ReplaceAllStringFunc(urlValue, func(match string) string {
				return strings.ToLower(match)
			})
		}
	}

	//
	var generatedHmac, receivedHmac string
	generatedHmac, receivedHmac, err = hmac.ValidateTokenUrl(paramToCheck, a.hmacEncryptionKey, a.hmacEncryptionAlgorithm, urlValue, a.hmacMandatoryFields)
	_ = generatedHmac
	_ = receivedHmac

	return err
}
