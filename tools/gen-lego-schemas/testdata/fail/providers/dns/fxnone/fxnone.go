package fxnone

func NewDNSProvider() (*DNSProvider, error) {
	return NewDNSProviderConfig(&Config{})
}
