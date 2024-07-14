package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/foxboron/ssh-tpm-ca-authority/server"
	"github.com/google/go-tpm/tpm2/transport"
)

const usage = `Usage:
    ssh-tpm-ca-authority [FLAGS]

Options:
    --config PATH        File location of config.yaml

Example:
    $ ssh-tpm-ca-authority --config config.yaml`

func run(ctx context.Context, rwc transport.TPMCloser, config *server.Config) error {

	as := server.NewTPMAttestServer(
		rwc, config,
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
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		configPath string
	)
	flag.StringVar(&configPath, "config", "config.yaml", "config path")
	flag.Parse()

	b, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}

	config, err := server.NewConfig(b)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	rwc, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}

	if err := run(ctx, rwc, config); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
