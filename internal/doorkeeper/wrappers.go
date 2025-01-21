package doorkeeper

import (
	"net/http"
	"strconv"
)

func newResponse(code int, headers map[string]string, body []byte) (resp responseT) {
	resp.Code = code

	resp.Headers = make(http.Header)
	for k, v := range headers {
		resp.Headers.Set(k, v)
	}

	if body != nil {
		resp.Headers.Set("Content-Type", "text/plain")
		resp.Headers.Set("Content-Length", strconv.Itoa(len(body)))

		resp.Body = body
	}
	return resp
}

func sendResponse(w http.ResponseWriter, resp responseT) (n int, err error) {
	for hk, hvs := range resp.Headers {
		for _, hv := range hvs {
			w.Header().Add(hk, hv)
		}
	}

	w.WriteHeader(resp.Code)

	if resp.Body != nil {
		n, err = w.Write([]byte(resp.Body))
	}

	return n, err
}
