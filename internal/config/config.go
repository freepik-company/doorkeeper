package config

import (
	"fmt"
	"os"
	"regexp"
	"slices"

	"doorkeeper/api/v1alpha2"

	"gopkg.in/yaml.v3"
)

const (
	// Modifiers types

	ConfigTypeValueModifierPATH   = "Path"
	ConfigTypeValueModifierHEADER = "Header"

	// Authorizations types

	ConfigTypeValueAuthHMAC   = "HMAC"
	ConfigTypeValueAuthIPLIST = "IPLIST"

	ConfigTypeValueAuthParamHEADER = "Header"
	ConfigTypeValueAuthParamQUERY  = "Query"

	ConfigTypeValueAuthHmacURL = "URL"

	ConfigTypeValueAuthHmacAlgorithmMD5    = "md5"
	ConfigTypeValueAuthHmacAlgorithmSHA1   = "sha1"
	ConfigTypeValueAuthHmacAlgorithmSHA256 = "sha256"
	ConfigTypeValueAuthHmacAlgorithmSHA512 = "sha512"

	// Requirements types

	ConfigTypeValueRequirementALL = "all"
	ConfigTypeValueRequirementANY = "any"
)

func expandEnv(input []byte) []byte {
	re := regexp.MustCompile(`\${ENV:([A-Za-z_][A-Za-z0-9_]*)}\$`)
	result := re.ReplaceAllFunc(input, func(match []byte) []byte {
		key := re.FindSubmatch(match)[1]
		if value, exists := os.LookupEnv(string(key)); exists {
			return []byte(value)
		}
		return match
	})

	return result
}

// checkConfig TODO
func checkConfig(config v1alpha2.DoorkeeperConfigT) error {
	//------------------------------
	// Modifiers
	//------------------------------

	modTypes := []string{ConfigTypeValueModifierPATH}
	for _, modv := range config.Modifiers {
		if !slices.Contains(modTypes, modv.Type) {
			return fmt.Errorf("modifier type must be one of %v", modTypes)
		}

		switch modv.Type {
		case "Path":
			{
				if modv.Path.Pattern == "" {
					return fmt.Errorf("pattern in path modifier must be set")
				}
			}
		}
	}

	//------------------------------
	// Authorizations
	//------------------------------

	if len(config.Auths) <= 0 {
		return fmt.Errorf("no authorizations defined")
	}

	authTypes := []string{ConfigTypeValueAuthHMAC, ConfigTypeValueAuthIPLIST}
	authParamTypes := []string{ConfigTypeValueAuthParamHEADER, ConfigTypeValueAuthParamQUERY}
	for _, authv := range config.Auths {
		// check auth basic fields
		if authv.Name == "" {
			return fmt.Errorf("authorization name must be set")
		}

		if !slices.Contains(authTypes, authv.Type) {
			return fmt.Errorf("authorization type must be one of %v", authTypes)
		}

		// check auth param fields
		if authv.Param.Name == "" {
			return fmt.Errorf("param name in authorization must be set")
		}

		if !slices.Contains(authParamTypes, authv.Param.Type) {
			return fmt.Errorf("param type in authorizations must be one of %v", authParamTypes)
		}

		// check specific types param fields
		switch authv.Type {
		case ConfigTypeValueAuthHMAC:
			{
				authHmacTypes := []string{ConfigTypeValueAuthHmacURL}
				if !slices.Contains(authHmacTypes, authv.Hmac.Type) {
					return fmt.Errorf("hmac type in authorizations must be one of %v", authHmacTypes)
				}

				encryptionAlgorithms := []string{ConfigTypeValueAuthHmacAlgorithmMD5, ConfigTypeValueAuthHmacAlgorithmSHA1, ConfigTypeValueAuthHmacAlgorithmSHA256, ConfigTypeValueAuthHmacAlgorithmSHA512}
				if !slices.Contains(encryptionAlgorithms, authv.Hmac.EncryptionAlgorithm) {
					return fmt.Errorf("hmac encryption algorithm in authorizations must be one of %v", encryptionAlgorithms)
				}

				if authv.Hmac.EncryptionKey == "" {
					return fmt.Errorf("encription key in hmac authorizations must be set")
				}
			}
		case ConfigTypeValueAuthIPLIST:
			{
				if authv.IpList.Cidr == "" {
					return fmt.Errorf("cidr field in ip list authorizations must be set")
				}
			}
		}
	}

	//------------------------------
	// RequestAuthRequirements
	//------------------------------

	if len(config.RequestAuthReq) <= 0 {
		return fmt.Errorf("no request auth requirements defined")
	}

	reqTypes := []string{ConfigTypeValueRequirementALL, ConfigTypeValueRequirementANY}
	for _, reqv := range config.RequestAuthReq {
		if !slices.Contains(reqTypes, reqv.Type) {
			return fmt.Errorf("request auth requirement type must be one of %v", reqTypes)
		}

		if len(reqv.Authorizations) <= 0 {
			return fmt.Errorf("no authorizations in request auth requirements")
		}

		for _, authn := range reqv.Authorizations {
			found := false
			for _, authv := range config.Auths {
				if authv.Name == authn {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("specified authorization name in request auth requirement not found in authorization list")
			}
		}
	}

	//------------------------------
	// Response
	//------------------------------

	if (config.Response.Denied.StatusCode < 100 || config.Response.Denied.StatusCode > 599) ||
		(config.Response.Allowed.StatusCode < 100 || config.Response.Allowed.StatusCode > 599) {
		return fmt.Errorf("status code fields in response config field must be set with valid status codes (from 100 to 599)")
	}

	return nil
}

// ParseConfigFile TODO
func ParseConfigFile(filepath string) (config v1alpha2.DoorkeeperConfigT, err error) {
	var fileBytes []byte
	fileBytes, err = os.ReadFile(filepath)
	if err != nil {
		return config, err
	}

	fileBytes = expandEnv(fileBytes)

	// config, err = Unmarshal(fileBytes)
	err = yaml.Unmarshal(fileBytes, &config)
	if err != nil {
		return config, err
	}

	err = checkConfig(config)

	return config, err
}
