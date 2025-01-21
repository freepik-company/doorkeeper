package authorizations

import (
	"doorkeeper/api/v1alpha2"
	"doorkeeper/internal/config"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type IPListT struct {
	paramType string
	paramName string

	separator               string
	reverse                 bool
	cidrCompiled            *net.IPNet
	trustedNetworksCompiled []*net.IPNet
}

func NewIPList(cfg v1alpha2.AuthorizationConfigT) (i *IPListT, err error) {
	i = &IPListT{
		paramType: cfg.Param.Type,
		paramName: cfg.Param.Name,
		separator: cfg.IpList.Separator,
		reverse:   cfg.IpList.Reverse,
	}
	_, i.cidrCompiled, err = net.ParseCIDR(cfg.IpList.Cidr)
	if err != nil {
		return i, err
	}

	for _, tnv := range cfg.IpList.TrustedNetworks {
		var cidr *net.IPNet
		_, cidr, err = net.ParseCIDR(tnv)
		if err != nil {
			return i, err
		}
		i.trustedNetworksCompiled = append(i.trustedNetworksCompiled, cidr)
	}

	return i, err
}

func (a *IPListT) Check(r *http.Request) (err error) {
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

	iplist := strings.Split(paramToCheck, a.separator)

	// filter trusted networks
	filteredIpList := []net.IP{}
	for _, ipv := range iplist {
		trimipv := strings.TrimSpace(ipv)
		currentIP := net.ParseIP(trimipv)
		if currentIP == nil {
			err = fmt.Errorf("invalid ip '%s' in list recieved", trimipv)
			return err
		}

		found := false
		for _, tnv := range a.trustedNetworksCompiled {
			if tnv.Contains(currentIP) {
				found = true
				break
			}
		}

		if !found {
			filteredIpList = append(filteredIpList, currentIP)
		}
	}

	// check filtered ip list

	if len(filteredIpList) != 1 {
		err = fmt.Errorf("to mutch ips in list after filter trusted networks %v", filteredIpList)
		return err
	}

	valid := a.cidrCompiled.Contains(filteredIpList[0])
	if a.reverse {
		valid = !valid
	}

	if !valid {
		err = fmt.Errorf("invalid ip in request")
	}

	return err
}
