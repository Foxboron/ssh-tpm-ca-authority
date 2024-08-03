package main

import (
	"crypto"
	"fmt"
	"io"
	"log"

	ssim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	"github.com/foxboron/ssh-tpm-ca-authority/client"
)

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

	rwc, err := OpenSimulator()
	if err != nil {
		log.Fatal(err)
	}
	defer rwc.Close()

	c := client.NewClient("http://127.0.0.1:8080")
	kk, _, err := c.GetKey(rwc, "", "")
	if err != nil {
		log.Fatal(err)
	}

	signer, err := kk.Signer(rwc, []byte(nil), []byte(nil))
	if err != nil {
		log.Fatal(err)
	}

	h := crypto.SHA256.New()
	h.Write([]byte("heyho"))
	b := h.Sum(nil)

	sig, err := signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := kk.Verify(crypto.SHA256, b[:], sig)
	if !ok || err != nil {
		log.Fatal(err)
	}
}
