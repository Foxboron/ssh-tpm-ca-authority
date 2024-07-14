package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-ca-authority/server"
	"github.com/google/go-tpm/tpm2/transport"
)

var (
	caFile = "id_ecdsa.tpm"

	// These are eks we trust
	eks = []string{
		"000b502e5556de80baa022194b49e2cd67bd3aebdd8201d89ef88bfbe380b3cc9098",
	}
)

func run(ctx context.Context, rwc transport.TPMCloser, ek []string, ca *keyfile.TPMKey) error {
	as := server.NewTPMAttestServer(
		rwc, ek, ca,
	)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: as.Handlers(),
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
	rwc, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}

	b, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}

	ca, err := keyfile.Decode(b)
	if err != nil {
		log.Fatal(err)
	}

	if err := run(ctx, rwc, eks, ca); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
