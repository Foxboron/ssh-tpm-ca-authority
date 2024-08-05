package main

import (
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
	// Flush EK as we don't need it after this
	keyfile.FlushHandle(rwc, ekHandle)

	// Create CA
	ca, err := keyfile.NewLoadableKey(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatalf("message")
	}

	as := server.NewTPMAttestServer(
		rwc,
		&server.Config{
			Hosts: []*server.HostConf{
				{
					Host:   "test.local",
					CaFile: &server.UnmarshalTPMkey{ca},
					Users: []*server.UsersConf{
						{
							User: "fox",
							EK:   fmt.Sprintf("%x", ekHandle.Name.Buffer),
						},
					},
				},
			},
		},
	)

	ts := httptest.NewServer(as.Handlers())
	defer ts.Close()
	c := client.NewClient(ts.URL)

	userkey, rsp, err := keyfile.NewLoadableKeyWithResponse(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatalf("message")
	}

	cert, err := c.GetCASignedKey(rwc, userkey, rsp, "fox", "test.local")
	if err != nil {
		t.Errorf("failed getting ca signed key: %v", err)
	}

	if cert.Type() != "ecdsa-sha2-nistp256-cert-v01@openssh.com" {
		t.Fatalf("not the correct cert type")
	}
}
