package modifiers

import (
	"fmt"
	"net/http"

	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
)

type ModifierI interface {
	Apply(r *http.Request)
}

func GetModifier(cfg v1alpha2.ModifierConfigT) (ModifierI, error) {
	switch cfg.Type {
	case config.ConfigModifierTypePATH:
		{
			return NewPath(cfg)
		}
	case config.ConfigModifierTypeHEADER:
		{
			return NewHeader(cfg)
		}
	}

	return nil, fmt.Errorf("unsupported modifier type")
}
