package utils

import (
	"crypto/md5"
	"doorkeeper/internal/logger"
	"encoding/hex"
	"fmt"
	"net/http"
)

const (
	LogFieldKeyService       = "service"
	LogFieldKeyRequestID     = "requestID"
	LogFieldKeyRequest       = "request"
	LogFieldKeyRequestMod    = "requestMod"
	LogFieldKeyResponse      = "response"
	LogFieldKeyAuthorization = "authorization"
	LogFieldKeyRequirement   = "requirement"
	LogFieldKeyError         = "error"

	LogFieldValueService = "doorkeeper"
)

type RequestLogT struct {
	Method      string      `json:"method"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	QueryParams string      `json:"queryParams"`
	Headers     http.Header `json:"headers"`
}

func RequestID(r *http.Request) string {
	headers := "{"
	for hk, hvs := range r.Header {
		headers += "(" + hk + fmt.Sprintf("%v", hvs) + ")"

	}
	headers += "}"

	reqStr := fmt.Sprintf("{method: '%s', host: '%s', path: '%s/%s', headers: '%s'}", r.Method, r.Host, r.URL.Path, r.URL.RawQuery, headers)
	md5Hash := md5.New()
	_, err := md5Hash.Write([]byte(reqStr))
	if err != nil {
		return "UnableGetRequestID"
	}

	return hex.EncodeToString(md5Hash.Sum(nil))
}

func RequestLogStruct(r *http.Request) (req RequestLogT) {
	req.Method = r.Method
	req.Host = r.Host
	req.Path = r.URL.Path
	req.QueryParams = r.URL.RawQuery
	req.Headers = make(http.Header)
	for hk, hvs := range r.Header {
		for _, hv := range hvs {
			req.Headers.Add(hk, hv)
		}
	}

	return req
}

func GetDefaultLogFields() logger.ExtraFieldsT {
	return map[string]any{
		LogFieldKeyService: LogFieldValueService,
	}
}
