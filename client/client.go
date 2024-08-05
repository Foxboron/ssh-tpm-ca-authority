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
	tpmoidc "github.com/foxboron/ssh-tpm-ca-authority/oidc"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type ChallengeResponse struct {
	Secret []byte
	Jwt    string
}

type SignedCertResponse struct {
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

func (a *AttestClient) GetKey(rwc transport.TPMCloser, user, host string) (*keyfile.TPMKey, *ssh.Certificate, error) {
	userkey, rsp, err := keyfile.NewLoadableKeyWithResponse(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		return nil, nil, err
	}
	sshca, err := a.GetCASignedKey(rwc, userkey, rsp, user, host)
	return userkey, sshca, err
}

func (a *AttestClient) GetCASignedKey(rwc transport.TPMCloser, clientkey *keyfile.TPMKey, rsp *tpm2.CreateResponse, user, host string) (*ssh.Certificate, error) {
	ap, err := attest.NewAttestationParameters(rwc, clientkey, rsp)
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(rwc, ap.Handle.Handle)

	ap.Host = host
	ap.User = user

	b, err := json.Marshal(ap)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", a.GetAttestURL(), bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("failed building attest request: %v", err)
	}

	resp, err := a.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed doing attest: %v", err)
	}

	ch, err := ijson.Decode[*attest.EncryptedCredential](resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed decording json encryptedcredential: %v", err)
	}

	secret, err := ap.GetSecret(rwc, ch)
	if err != nil {
		return nil, fmt.Errorf("failed getting secret: %v", err)
	}

	jwt, err := tpmoidc.RunOIDCFlow(ch.OIDC, string(ch.Nonce))
	if err != nil {
		return nil, fmt.Errorf("filed producing jwt: %v", err)
	}

	b, err = json.Marshal(ChallengeResponse{
		Secret: secret,
		Jwt:    jwt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed marshalling challenge response: %v", err)
	}

	req, err = http.NewRequest("POST", a.GetSubmitURL(), bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	resp, err = a.c.Do(req)
	if err != nil {
		return nil, err
	}

	sshkey, err := ijson.Decode[*SignedCertResponse](resp.Body)
	if err != nil {
		return nil, err
	}

	pubkey, err := ssh.ParsePublicKey(sshkey.SignedSSHCert)
	if err != nil {
		return nil, err
	}

	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("failed parsing ssh certificate")
	}
	return cert, err
}
