package authorizations

import (
	"fmt"
	"net/http"

	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
)

type AuthI interface {
	Check(*http.Request) error
}

func GetAuthorization(cfg v1alpha2.AuthorizationConfigT) (AuthI, error) {
	switch cfg.Type {
	case config.ConfigAuthTypeHMAC:
		{
			return NewHmac(cfg)
		}
	case config.ConfigAuthTypeIPLIST:
		{
			return NewIPList(cfg)
		}
	case config.ConfigAuthTypeMATCH:
		{
			return NewMatch(cfg)
		}
	}

	return nil, fmt.Errorf("unsupported authorization type")
}
