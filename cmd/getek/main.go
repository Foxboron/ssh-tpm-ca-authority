package main

import (
	"fmt"
	"log"

	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/google/go-tpm/tpm2/transport"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
)

func main() {
	rwc, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}

	ekHandle, _, err := attest.ReadEKCert(rwc)
	if err != nil {
		log.Fatal(err)
	}
	keyfile.FlushHandle(rwc, ekHandle)

	fmt.Printf("%x\n", ekHandle.Name.Buffer)
}
