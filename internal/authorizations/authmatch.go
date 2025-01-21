package authorizations

import (
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"fmt"
	"net/http"
	"regexp"
)

type MatchT struct {
	paramType string
	paramName string

	reverse       bool
	compiledRegex *regexp.Regexp
}

func NewMatch(cfg v1alpha2.AuthorizationConfigT) (h *MatchT, err error) {
	h = &MatchT{
		paramType: cfg.Param.Type,
		paramName: cfg.Param.Name,
		reverse:   cfg.Match.Reverse,
	}

	h.compiledRegex = regexp.MustCompile(cfg.Match.Pattern)

	return h, err
}

func (a *MatchT) Check(r *http.Request) (err error) {
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

	valid := a.compiledRegex.MatchString(paramToCheck)
	if a.reverse {
		valid = !valid
	}

	if !valid {
		err = fmt.Errorf("invalid match in request")
	}

	return err
}
