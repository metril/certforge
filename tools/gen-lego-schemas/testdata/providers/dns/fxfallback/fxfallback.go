package fxfallback

import (
	"strings"

	"github.com/go-acme/lego/v4/platform/config/env"
)

const (
	envNamespace = "FXFALLBACK_"

	EnvEmail        = envNamespace + "EMAIL"
	EnvAPIKey       = envNamespace + "API_KEY"
	EnvDNSAPIToken  = envNamespace + "DNS_API_TOKEN"
	EnvZoneAPIToken = envNamespace + "ZONE_API_TOKEN"
)

const (
	altEnvNamespace = "FB_"

	altEnvEmail = altEnvNamespace + "API_EMAIL"
)

func altEnvName(v string) string {
	return strings.ReplaceAll(v, envNamespace, altEnvNamespace)
}

func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.GetWithFallback(
		[]string{EnvEmail, altEnvEmail},
		[]string{EnvAPIKey, altEnvName(EnvAPIKey)},
	)
	if err != nil {
		values, err = env.GetWithFallback(
			[]string{EnvDNSAPIToken, altEnvName(EnvDNSAPIToken)},
			[]string{EnvZoneAPIToken, altEnvName(EnvZoneAPIToken), EnvDNSAPIToken, altEnvName(EnvDNSAPIToken)},
		)
	}
	_ = values
	return nil, err
}
