package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/crypto/ssh"
)

var (
	caFile = "id_ecdsa.tpm"

	// These are eks we trust
	eks = []string{
		"000b502e5556de80baa022194b49e2cd67bd3aebdd8201d89ef88bfbe380b3cc9098",
	}
	// We keep track of our challenges here
	// Probably not good enough, but POC quality
	// Key is ekName+challenge
	state sync.Map
)

func encode[T any](w http.ResponseWriter, status int, v T) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func decode[T any](r *http.Request) (T, error) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return v, fmt.Errorf("decode json: %w", err)
	}
	return v, nil
}

func attestHandler(w http.ResponseWriter, r *http.Request) {
	params, err := decode[*attest.AttestationParameters](r)
	if err != nil {
		fmt.Println(err)
		return
	}

	name, err := tpm2.ObjectName(params.EK)
	if err != nil {
		log.Fatal(err)
		return
	}

	if !slices.Contains(eks, fmt.Sprintf("%x", name.Buffer)) {
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

	if err := encode(w, 200, ch); err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't return challenge")
		return
	}

	state.Store(string(challenge), tpm2.Marshal(params.SRK.Public))
}

type ChallengeResponse struct {
	Secret []byte
}

type SignedCertResponse struct {
	ImportableKey []byte
	SignedSSHCert []byte
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	cr, err := decode[*ChallengeResponse](r)
	if err != nil {
		fmt.Println(err)
		return
	}

	val, ok := state.Load(string(cr.Secret))
	if !ok {
		fmt.Println(err)
		return
	}
	ek, err := tpm2.Unmarshal[tpm2.TPMTPublic](val.([]byte))
	if err != nil {
		log.Fatal(err)
	}

	b, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}

	tpmkey, err := keyfile.Decode(b)
	if err != nil {
		log.Fatal(err)
	}

	cakey := key.SSHTPMKey{tpmkey}

	rwc, err := simulator.OpenSimulator()
	if err != nil {
		log.Fatal(err)
	}
	defer rwc.Close()

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	clientkey, err := keyfile.NewImportablekey(ek, *pk, keyfile.WithParent(tpm2.TPMRHEndorsement))
	if err != nil {
		log.Fatalf("can't create newloadablekey")
	}

	client := key.SSHTPMKey{clientkey}
	clientsshkey, err := client.SSHPublicKey()
	if err != nil {
		log.Fatalf("can't create sshpublickey")
	}
	certificate := ssh.Certificate{
		Key:      clientsshkey,
		CertType: ssh.UserCert,
	}

	casigner, err := cakey.Signer(rwc, []byte(nil), []byte(nil))
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

	rsp := &SignedCertResponse{
		ImportableKey: clientkey.Bytes(),
		SignedSSHCert: certificate.Marshal(),
	}

	if err := encode(w, 200, rsp); err != nil {
		fmt.Fprintf(w, "can't return signed response: %v", err)
		return
	}
}

func mkHandlers() *http.ServeMux {
	var mux http.ServeMux
	mux.HandleFunc("/attest", attestHandler)
	mux.HandleFunc("/submit", submitHandler)
	return &mux
}

func run(ctx context.Context) error {
	srv := &http.Server{
		Addr:    ":8080",
		Handler: mkHandlers(),
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}
	<-idleConnsClosed
	return nil
}

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
