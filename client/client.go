package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	ijson "github.com/foxboron/ssh-tpm-ca-authority/internal/json"
	"golang.org/x/crypto/ssh"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/google/go-tpm/tpm2/transport"
)

type ChallengeResponse struct {
	Secret []byte
}

type SignedCertResponse struct {
	ImportableKey []byte
	SignedSSHCert []byte
}

type AttestClient struct {
	url string
	c   *http.Client
}

func NewClient(url string) *AttestClient {
	return &AttestClient{
		url: url,
		c:   new(http.Client),
	}
}

func (a *AttestClient) GetAttestURL() string {
	return fmt.Sprintf("%s/%s", a.url, "attest")
}

func (a *AttestClient) GetSubmitURL() string {
	return fmt.Sprintf("%s/%s", a.url, "submit")
}

func (a *AttestClient) GetKey(rwc transport.TPMCloser) (*keyfile.TPMKey, *ssh.Certificate, error) {
	ap, err := attest.NewAttestationParameters(rwc)
	if err != nil {
		return nil, nil, err
	}
	defer keyfile.FlushHandle(rwc, ap.Handle.Handle)

	b, err := json.Marshal(ap)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("POST", a.GetAttestURL(), bytes.NewBuffer(b))
	if err != nil {
		return nil, nil, err
	}

	resp, err := a.c.Do(req)
	if err != nil {
		return nil, nil, err
	}

	ch, err := ijson.Decode[*attest.EncryptedCredential](resp.Body)
	if err != nil {
		return nil, nil, err
	}

	secret, err := ap.GetSecret(rwc, ch)
	if err != nil {
		return nil, nil, err
	}

	b, err = json.Marshal(ChallengeResponse{
		Secret: secret,
	})
	if err != nil {
		return nil, nil, err
	}

	req, err = http.NewRequest("POST", a.GetSubmitURL(), bytes.NewBuffer(b))
	if err != nil {
		return nil, nil, err
	}

	resp, err = a.c.Do(req)
	if err != nil {
		return nil, nil, err
	}

	sshkey, err := ijson.Decode[*SignedCertResponse](resp.Body)
	if err != nil {
		return nil, nil, err
	}
	k, err := keyfile.Decode(sshkey.ImportableKey)
	if err != nil {
		return nil, nil, err
	}

	pubkey, err := ssh.ParsePublicKey(sshkey.SignedSSHCert)
	if err != nil {
		return nil, nil, err
	}

	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return nil, nil, fmt.Errorf("failed parsing ssh certificate")
	}
	return k, cert, err
}
