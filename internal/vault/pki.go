package vault

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// SignRequest is the input to PKISign: a PEM CSR plus the names and TTL
// Vault should sign into the leaf.
type SignRequest struct {
	CSR         string
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	TTL         string
}

// SignResponse is Vault's signed leaf plus its issuing chain. CAChain
// excludes the leaf itself, matching Vault 1.18's PKI sign response.
type SignResponse struct {
	Certificate  string
	IssuingCA    string
	CAChain      []string
	SerialNumber string
}

type pkiSignResponse struct {
	Data struct {
		Certificate  string   `json:"certificate"`
		IssuingCA    string   `json:"issuing_ca"`
		CAChain      []string `json:"ca_chain"`
		SerialNumber string   `json:"serial_number"`
	} `json:"data"`
}

// PKISign signs req.CSR under mount's role, returning the leaf and its
// issuing chain. A TTL above the role's max_ttl is capped by Vault, not an
// error.
func (c *Client) PKISign(ctx context.Context, mount, role string, req SignRequest) (SignResponse, error) {
	body := map[string]any{
		"csr":         req.CSR,
		"common_name": req.CommonName,
		"format":      "pem",
	}
	if len(req.DNSNames) > 0 {
		body["alt_names"] = strings.Join(req.DNSNames, ",")
	}
	if len(req.IPAddresses) > 0 {
		ips := make([]string, len(req.IPAddresses))
		for i, ip := range req.IPAddresses {
			ips[i] = ip.String()
		}
		body["ip_sans"] = strings.Join(ips, ",")
	}
	if req.TTL != "" {
		body["ttl"] = req.TTL
	}

	var resp pkiSignResponse
	path := fmt.Sprintf("/v1/%s/sign/%s", escapePath(mount), escapeSegment(role))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp, requestOpts{}); err != nil {
		return SignResponse{}, c.Redact(err)
	}
	return SignResponse{
		Certificate:  resp.Data.Certificate,
		IssuingCA:    resp.Data.IssuingCA,
		CAChain:      resp.Data.CAChain,
		SerialNumber: resp.Data.SerialNumber,
	}, nil
}

// PKIRevoke revokes a certificate previously issued under mount by its
// serial number, passed through exactly as given (colon-separated hex,
// e.g. as returned by PKISign) — never reformatted.
func (c *Client) PKIRevoke(ctx context.Context, mount, serial string) error {
	body := map[string]string{"serial_number": serial}
	path := fmt.Sprintf("/v1/%s/revoke", escapePath(mount))
	return c.Redact(c.doJSON(ctx, http.MethodPost, path, body, nil, requestOpts{}))
}

// PKIReadCA returns mount's current CA certificate (PEM).
func (c *Client) PKIReadCA(ctx context.Context, mount string) (string, error) {
	var resp struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	path := fmt.Sprintf("/v1/%s/cert/ca", escapePath(mount))
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp, requestOpts{}); err != nil {
		return "", c.Redact(err)
	}
	return resp.Data.Certificate, nil
}
