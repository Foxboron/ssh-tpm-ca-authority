package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	ssim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

func encode[T any](w http.ResponseWriter, status int, v T) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func decode[T any](r *http.Response) (T, error) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return v, fmt.Errorf("decode json: %w", err)
	}
	return v, nil
}

// TPM represents a connection to a TPM simulator.
type TPM struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// OpenSimulator starts and opens a TPM simulator.
func OpenSimulator() (transport.TPMCloser, error) {
	sim, err := ssim.GetWithFixedSeedInsecure(1234)
	if err != nil {
		return nil, err
	}
	return &TPM{
		transport: sim,
	}, nil
}

// Close implements the TPM interface.
func (t *TPM) Close() error {
	return t.transport.Close()
}

type ChallengeResponse struct {
	Secret []byte
}

type SignedCertResponse struct {
	ImportableKey []byte
	SignedSSHCert []byte
}

func main() {

	attestUrl := "http://127.0.0.1:8080/attest"
	submitUrl := "http://127.0.0.1:8080/submit"

	rwc, err := OpenSimulator()
	if err != nil {
		log.Fatal(err)
	}
	defer rwc.Close()

	var c http.Client

	ap, err := attest.NewAttestationParameters(rwc)
	if err != nil {
		log.Fatal(err)
	}
	defer keyfile.FlushHandle(rwc, ap.Handle.Handle)

	b, err := json.Marshal(ap)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("POST", attestUrl, bytes.NewBuffer(b))
	if err != nil {
		log.Fatal(err)
	}

	resp, err := c.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	ch, err := decode[*attest.EncryptedCredential](resp)
	if err != nil {
		log.Fatal(err)
	}

	secret, err := ap.GetSecret(rwc, ch)
	if err != nil {
		log.Fatal(err)
	}

	b, err = json.Marshal(ChallengeResponse{
		Secret: secret,
	})
	if err != nil {
		log.Fatal(err)
	}

	req, err = http.NewRequest("POST", submitUrl, bytes.NewBuffer(b))
	if err != nil {
		log.Fatal(err)
	}

	resp, err = c.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	sshkey, err := decode[*SignedCertResponse](resp)
	if err != nil {
		log.Fatal(err)
	}

	kk, err := keyfile.Decode(sshkey.ImportableKey)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := kk.Signer(rwc, []byte(nil), []byte(nil))
	if err != nil {
		log.Fatal(err)
	}

	h := crypto.SHA256.New()
	h.Write([]byte("heyho"))
	b = h.Sum(nil)

	sig, err := signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := kk.Verify(crypto.SHA256, b[:], sig)
	if !ok || err != nil {
		log.Fatal(err)
	}
}
