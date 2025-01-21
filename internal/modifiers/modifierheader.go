package modifiers

import (
	"net/http"
	"regexp"

	"doorkeeper/api/v1alpha2"
)

type HeaderT struct {
	name          string
	replace       string
	compiledRegex *regexp.Regexp
}

func NewHeader(cfg v1alpha2.ModifierConfigT) (h *HeaderT, err error) {
	h = &HeaderT{
		name:          cfg.Header.Name,
		replace:       cfg.Header.Replace,
		compiledRegex: regexp.MustCompile(cfg.Header.Pattern),
	}
	return h, err
}

func (m *HeaderT) Apply(r *http.Request) {
	r.Header.Set(m.name, m.compiledRegex.ReplaceAllString(r.Header.Get(m.name), m.replace))
}
