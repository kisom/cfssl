package roots

import (
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/kisom/cfssl/api/client"
	"github.com/kisom/cfssl/helpers"
	"github.com/kisom/cfssl/info"
)

// This package contains CFSSL integration.

// NewCFSSL produces a new CFSSL root.
func NewCFSSL(metadata map[string]string) ([]*x509.Certificate, error) {
	host, ok := metadata["host"]
	if !ok {
		return nil, errors.New("transport: CFSSL root provider requires a host")
	}

	label := metadata["label"]
	profile := metadata["profile"]

	srv := client.NewServer(host)
	data, err := json.Marshal(info.Req{Label: label, Profile: profile})
	if err != nil {
		return nil, err
	}

	resp, err := srv.Info(data)
	if err != nil {
		return nil, err
	}

	return helpers.ParseCertificatesPEM([]byte(resp.Certificate))
}
