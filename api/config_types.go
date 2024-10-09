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

package api

import "regexp"

type DoorkeeperConfigT struct {
	Auth      AuthorizationConfigT `yaml:"authorization"`
	Hmac      HmacConfigT          `yaml:"hmac"`
	Modifiers []ModifierConfigT    `yaml:"modifiers"`
}

type AuthorizationConfigT struct {
	Type  string           `yaml:"type"`
	Param AuthParamConfigT `yaml:"param"`
}

type AuthParamConfigT struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}

type HmacConfigT struct {
	Type                string `yaml:"type"`
	EncryptionKey       string `yaml:"encryptionKey"`
	EncryptionAlgorithm string `yaml:"encryptionAlgorithm"`
}

type ModifierConfigT struct {
	Type string              `yaml:"type"`
	Path ModifierPathConfigT `yaml:"path"`
}

type ModifierPathConfigT struct {
	Pattern string `yaml:"pattern"`
	Replace string `yaml:"replace"`

	// Carry stuff
	CompiledRegex *regexp.Regexp
}
