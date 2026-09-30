package fakedns

import "github.com/go-acme/lego/v4/platform/config/env"

const envNamespace = "FAKE_"

const EnvAPIToken = envNamespace + "API_TOKEN"

func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAPIToken)
	_ = values
	_ = err
	return nil, nil
}
