package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"slices"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-ca-authority/client"
	ijson "github.com/foxboron/ssh-tpm-ca-authority/internal/json"
	"golang.org/x/crypto/ssh"

	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMAttestServer struct {
	rwc   transport.TPMCloser
	eks   []string
	state *sync.Map
	ca    *keyfile.TPMKey
}

func (t *TPMAttestServer) Handlers() *http.ServeMux {
	var mux http.ServeMux
	mux.HandleFunc("/attest", t.attestHandler)
	mux.HandleFunc("/submit", t.submitHandler)
	return &mux
}

func (t *TPMAttestServer) attestHandler(w http.ResponseWriter, r *http.Request) {
	params, err := ijson.Decode[*attest.AttestationParameters](r.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	name, err := tpm2.ObjectName(params.EK)
	if err != nil {
		log.Fatal(err)
		return
	}

	if !slices.Contains(t.eks, fmt.Sprintf("%x", name.Buffer)) {
		return
	}

	ok, err := params.VerifyAKCreation()
	if err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "failed checking AK creation: %v", err)
		return
	}

	if !ok {
		fmt.Fprintf(w, "AK creation doesn't validate")
		return
	}

	challenge := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)

	ch, err := params.CreateChallenge(challenge)
	if err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't create challenge")
		return
	}

	if err := ijson.Encode(w, 200, ch); err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't return challenge")
		return
	}

	t.state.Store(string(challenge), tpm2.Marshal(params.SRK.Public))
}

func (t *TPMAttestServer) submitHandler(w http.ResponseWriter, r *http.Request) {
	cr, err := ijson.Decode[*client.ChallengeResponse](r.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	val, ok := t.state.Load(string(cr.Secret))
	if !ok {
		fmt.Println(err)
		return
	}
	ek, err := tpm2.Unmarshal[tpm2.TPMTPublic](val.([]byte))
	if err != nil {
		log.Fatal(err)
	}

	cakey := key.SSHTPMKey{t.ca}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	clientkey, err := keyfile.NewImportablekey(ek, *pk, keyfile.WithParent(tpm2.TPMRHEndorsement))
	if err != nil {
		log.Fatalf("can't create newloadablekey")
	}

	clientSSHKey := key.SSHTPMKey{clientkey}
	clientsshkey, err := clientSSHKey.SSHPublicKey()
	if err != nil {
		log.Fatalf("can't create sshpublickey")
	}
	certificate := ssh.Certificate{
		Key:             clientsshkey,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"fox"},
		KeyId:           "TPM Key",
		ValidAfter:      0,
		ValidBefore:     math.MaxUint64,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	casigner, err := cakey.Signer(t.rwc, []byte(nil), []byte(nil))
	if err != nil {
		log.Fatalf("can't get signer fn")
	}
	signer, err := ssh.NewSignerFromSigner(casigner)
	if err != nil {
		log.Fatalf("can't get new signer")
	}
	mas, err := ssh.NewSignerWithAlgorithms(signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		log.Fatalf("can't sign")
	}

	if err := certificate.SignCert(rand.Reader, mas); err != nil {
		log.Fatal(err)
	}

	rsp := &client.SignedCertResponse{
		ImportableKey: clientkey.Bytes(),
		SignedSSHCert: certificate.Marshal(),
	}

	if err := ijson.Encode(w, 200, rsp); err != nil {
		fmt.Fprintf(w, "can't return signed response: %v", err)
		return
	}
}

func NewTPMAttestServer(rwc transport.TPMCloser, eks []string, ca *keyfile.TPMKey) *TPMAttestServer {
	return &TPMAttestServer{
		rwc:   rwc,
		eks:   eks,
		ca:    ca,
		state: new(sync.Map),
	}
}
