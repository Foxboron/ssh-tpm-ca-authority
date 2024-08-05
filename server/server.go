package server

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-ca-authority/client"
	ijson "github.com/foxboron/ssh-tpm-ca-authority/internal/json"
	"github.com/foxboron/ssh-tpm-ca-authority/oidc"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/ssh"

	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type MapState struct {
	Host      string
	User      string
	EK        string
	SSHPubkey *tpm2.TPMTPublic
	Nonce     string
}

type TPMAttestServer struct {
	rwc    transport.TPMCloser
	config *Config
	state  *sync.Map
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

	hconf, ok := t.config.HasHost(params.Host)
	if !ok {
		return
	}

	userek := fmt.Sprintf("%x", name.Buffer)

	user, ok := hconf.GetUser(params.User, userek)
	if !ok {
		fmt.Println("invalid user")
		fmt.Fprintf(w, "invalid user")
		return
	}

	ok, err = params.AK.VerifyCreation(true)
	if err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "failed checking AK creation: %v", err)
		return
	}

	if !ok {
		fmt.Fprintf(w, "AK creation doesn't validate")
		return
	}

	ok, err = params.Verify()
	if err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "failed checking signature over ssh pubkey creation: %v", err)
		return
	}
	if !ok {
		fmt.Fprintf(w, "signature over ssh key isn't valid")
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

	ch.OIDC = user.OIDCConnector
	ch.Nonce = ksuid.New().String()

	if err := ijson.Encode(w, 200, ch); err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't return challenge")
		return
	}

	v := &MapState{
		Host:      params.Host,
		User:      params.User,
		EK:        userek,
		SSHPubkey: params.TPMBoundKey.Public,
		Nonce:     ch.Nonce,
	}
	t.state.Store(string(challenge), v)
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

	state := val.(*MapState)

	h, ok := t.config.HasHost(state.Host)
	if !ok {
		return
	}

	userconf, ok := h.GetUser(state.User, state.EK)
	if !ok {
		return
	}

	ok, err = oidc.VerifyUserAndJWT(userconf.OIDCConnector, userconf.Email, string(state.Nonce), cr.Jwt)
	if err != nil {
		log.Fatal(err)
		return
	}

	if !ok {
		fmt.Println("failed auth")
		return
	}

	cakey := key.SSHTPMKey{TPMKey: h.CaFile.TPMKey}

	after := time.Now()

	before := after.Add(time.Minute * 5)

	// Create the SSH key from the tpm2.TPMTPublic we got and attested
	eccKey, err := attest.GetECDSAFromTPMTPublic(state.SSHPubkey)
	if err != nil {
		log.Fatal(err)
	}
	boundsshkey, err := ssh.NewPublicKey(eccKey)
	if err != nil {
		log.Fatal(err)
	}

	certificate := ssh.Certificate{
		Key:             boundsshkey,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{state.User},
		KeyId:           "TPM Key",
		ValidAfter:      uint64(after.Unix()),
		ValidBefore:     uint64(before.Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	slog.Info("issued SSH certificate", slog.String("user", state.User))

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
		SignedSSHCert: certificate.Marshal(),
	}

	if err := ijson.Encode(w, 200, rsp); err != nil {
		fmt.Fprintf(w, "can't return signed response: %v", err)
		return
	}
}

func NewTPMAttestServer(rwc transport.TPMCloser, config *Config) *TPMAttestServer {
	return &TPMAttestServer{
		rwc:    rwc,
		config: config,
		state:  new(sync.Map),
	}
}
