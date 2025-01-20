package modifiers

import (
	"net/http"
	"regexp"

	"doorkeeper/api/v1alpha2"
)

type PathT struct {
	replace       string
	compiledRegex *regexp.Regexp
}

func NewPath(cfg v1alpha2.ModifierConfigT) (p *PathT, err error) {
	p = &PathT{
		replace:       cfg.Path.Replace,
		compiledRegex: regexp.MustCompile(cfg.Path.Pattern),
	}

	return p, err
}

func (m *PathT) Apply(r *http.Request) error {
	r.URL.Path = m.compiledRegex.ReplaceAllString(r.URL.Path, m.replace)
	return nil
}
