package authorizations

import (
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"fmt"
)

type AuthI interface {
}

func GetAuthorization(cfg v1alpha2.AuthorizationConfigT) (AuthI, error) {
	switch cfg.Type {
	case config.ConfigAuthTypeHMAC:
		{
		}
	case config.ConfigAuthTypeIPLIST:
		{
		}
	case config.ConfigAuthTypeMATCH:
		{
		}
	}

	return nil, fmt.Errorf("unsupported authorization type")
}
