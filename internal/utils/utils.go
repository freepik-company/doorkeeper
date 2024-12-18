package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

const (
	LogFieldKeyRequestID           = "requestID"
	LogFieldKeyRequest             = "request"
	LogFieldKeyResponse            = "response"
	LogFieldKeyResponseBytes       = "responseBytes"
	LogFieldKeyAuthorization       = "authorization"
	LogFieldKeyAuthorizationResult = "authorizationResult"
	LogFieldKeyRequirement         = "requirement"
	LogFieldKeyError               = "error"

	LogFieldValueDefaultStr = "none"
	LogFieldValueDefaultInt = 0
)

type RequestT struct {
	Method      string      `json:"method"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	QueryParams string      `json:"queryParams"`
	Headers     http.Header `json:"headers"`
	Body        string      `json:"body"`
}

type ResponseT struct {
	Code    int         `json:"code"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
	Length  int         `json:"length"`
	Request RequestT    `json:"request"`
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

func RequestStruct(r *http.Request) (req RequestT) {
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		req.Body = err.Error()
		return req
	}

	if len(body) > 60000 {
		req.Body = "<too-long>"
	}

	return req
}

func ResponseStruct(r *http.Response) (res ResponseT) {
	res.Body = r.Status
	res.Length = len(r.Status)
	res.Code = r.StatusCode
	res.Headers = make(http.Header)
	for hk, hvs := range r.Header {
		for _, hv := range hvs {
			res.Headers.Add(hk, hv)
		}
	}

	res.Request = RequestStruct(r.Request)

	return res
}

func DefaultRequestStruct() (req RequestT) {
	req.Method = LogFieldValueDefaultStr
	req.Host = LogFieldValueDefaultStr
	req.Path = LogFieldValueDefaultStr
	req.QueryParams = LogFieldValueDefaultStr
	req.Headers = make(http.Header)
	req.Body = LogFieldValueDefaultStr
	return req
}

func DefaultResponseStruct() (res ResponseT) {
	res.Code = 0
	res.Body = LogFieldValueDefaultStr
	res.Headers = make(http.Header)
	res.Request = DefaultRequestStruct()
	return res
}

func NewResponseStruct(statusCode int, headers http.Header, body string) (res ResponseT) {
	if headers == nil {
		headers = make(http.Header)
	}

	res.Code = statusCode
	res.Headers = headers
	res.Body = body
	res.Length = len(body)
	return res
}

func GetDefaultLogFields() map[string]any {
	return map[string]any{
		LogFieldKeyRequestID:           LogFieldValueDefaultStr,
		LogFieldKeyRequest:             DefaultRequestStruct(),
		LogFieldKeyResponse:            DefaultResponseStruct(),
		LogFieldKeyResponseBytes:       LogFieldValueDefaultInt,
		LogFieldKeyAuthorization:       LogFieldValueDefaultStr,
		LogFieldKeyAuthorizationResult: LogFieldValueDefaultStr,
		LogFieldKeyRequirement:         LogFieldValueDefaultStr,
		LogFieldKeyError:               LogFieldValueDefaultStr,
	}
}

func SetLogField(logFields map[string]any, key string, value any) {
	if _, ok := logFields[key]; ok {
		logFields[key] = value
	}
}
