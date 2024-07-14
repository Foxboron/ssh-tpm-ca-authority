package main

import (
	"crypto"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/foxboron/ssh-tpm-ca-authority/client"
	"github.com/foxboron/ssh-tpm-ca-authority/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	ssim "github.com/google/go-tpm-tools/simulator"
)

// TPM represents a connection to a TPM simulator.
type TPM struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPM) Close() error {
	return t.transport.Close()
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

func TestMain(t *testing.T) {
	rwc, err := OpenSimulator()
	if err != nil {
		log.Fatal(err)
	}
	defer rwc.Close()

	ekHandle, _, err := attest.ReadEKCert(rwc)
	if err != nil {
		t.Fatalf("message")
	}
	ekName := fmt.Sprintf("%x", ekHandle.Name.Buffer)
	// Flush EK as we don't need it after this
	keyfile.FlushHandle(rwc, ekHandle)

	// Create CA
	ca, err := keyfile.NewLoadableKey(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatalf("message")
	}

	as := server.NewTPMAttestServer(
		rwc, []string{ekName}, ca,
	)

	ts := httptest.NewServer(as.Handlers())
	defer ts.Close()
	c := client.NewClient(ts.URL)
	k, cert, err := c.GetKey(rwc, "test.local")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if cert.Type() != "ecdsa-sha2-nistp256-cert-v01@openssh.com" {
		t.Fatalf("not the correct cert type")
	}

	h := crypto.SHA256.New()
	h.Write([]byte("heyho"))
	b := h.Sum(nil)

	signer, err := k.Signer(rwc, []byte(nil), []byte(nil))
	if err != nil {
		t.Fatalf("failed creating signer")
	}

	sig, err := signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("failed TPM2_Sign")
	}

	ok, err := k.Verify(crypto.SHA256, b[:], sig)
	if !ok || err != nil {
		t.Fatalf("failed signing hash")
	}
}
