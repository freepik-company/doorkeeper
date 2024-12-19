/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha2

import (
	"net"
	"regexp"
)

type DoorkeeperConfigT struct {
	LogLevel       string                 `yaml:"logLevel"`
	Address        string                 `yaml:"address"`
	Port           string                 `yaml:"port"`
	Modifiers      []ModifierConfigT      `yaml:"modifiers"`
	Auths          []AuthorizationConfigT `yaml:"authorizations"`
	RequestAuthReq []RequestAuthReqT      `yaml:"requestAuthRequirements"`
	Response       ResponseConfigT        `yaml:"response"`
}

//--------------------------------
// Modifiers
//--------------------------------

type ModifierConfigT struct {
	Type string              `yaml:"type"` // values: Path
	Path ModifierPathConfigT `yaml:"path"`
}

type ModifierPathConfigT struct {
	Pattern string `yaml:"pattern"`
	Replace string `yaml:"replace"`

	// Carry stuff
	CompiledRegex *regexp.Regexp
}

//--------------------------------
// Authorization
//--------------------------------

type AuthorizationConfigT struct {
	Name  string           `yaml:"name"`
	Type  string           `yaml:"type"` // values: HMAC|CIDR
	Param AuthParamConfigT `yaml:"param"`

	Hmac   HmacConfigT   `yaml:"hmac"`
	IpList IpListConfigT `yaml:"ipList"`
	Match  MatchConfigT  `yaml:"match"`
}

type AuthParamConfigT struct {
	Type string `yaml:"type"` // values: Header|Query
	Name string `yaml:"name"` // values: :host|:authority|<header-name>
}

// HMAC

type HmacConfigT struct {
	Type                string `yaml:"type"` // values: URL
	EncryptionKey       string `yaml:"encryptionKey"`
	EncryptionAlgorithm string `yaml:"encryptionAlgorithm"`

	//
	MandatoryFields []string       `yaml:"mandatoryFields,omitempty"`
	Url             HmacUrlConfigT `yaml:"url,omitempty"`
}

type HmacUrlConfigT struct {
	EarlyEncode bool `yaml:"earlyEncode,omitempty"`
	LowerEncode bool `yaml:"lowerEncode,omitempty"`
}

// IPLIST

type IpListConfigT struct {
	Separator       string   `yaml:"separator"`
	Reverse         bool     `yaml:"reverse"`
	Cidr            string   `yaml:"cidr"`
	TrustedNetworks []string `yaml:"trustedNetworks"`

	// Carry stuff
	CidrCompiled            *net.IPNet
	TrustedNetworksCompiled []*net.IPNet
}

// MATCH

type MatchConfigT struct {
	Reverse bool   `yaml:"reverse"`
	Pattern string `yaml:"pattern"`

	// Carry stuff
	CompiledRegex *regexp.Regexp
}

//--------------------------------
// RequestAuthRequirement
//--------------------------------

type RequestAuthReqT struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"` // values: all|any
	Authorizations []string `yaml:"authorizations"`
}

// --------------------------------
// Response
// --------------------------------

type ResponseConfigT struct {
	Denied  ResponseT `yaml:"denied"`
	Allowed ResponseT `yaml:"allowed"`
}

type ResponseT struct {
	StatusCode int               `yaml:"statusCode"`
	Headers    map[string]string `yaml:"headers"`
	Body       string            `yaml:"body"`
}
