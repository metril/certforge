package fx2call

import "github.com/go-acme/lego/v4/platform/config/env"

const (
	envNamespace = "FX_"

	EnvRole      = envNamespace + "ROLE"
	EnvAccessKey = envNamespace + "ACCESS_KEY"
	EnvSecretKey = envNamespace + "SECRET_KEY"
)

func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvRole)
	if err != nil {
		values, err = env.Get(EnvAccessKey, EnvSecretKey)
	}
	_ = values
	return nil, err
}
