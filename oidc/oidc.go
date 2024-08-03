package oidc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/browser"
	"github.com/segmentio/ksuid"

	"github.com/sigstore/sigstore/pkg/oauth"
	"github.com/sigstore/sigstore/pkg/oauth/oidc"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

type cid struct {
	ConnectorId string `json:"connector_id"`
	UserId      string `json:"user_id"`
}

type claims struct {
	Email           string `json:"email"`
	Verified        bool   `json:"email_verified"`
	Subject         string `json:"sub"`
	FederatedClaims cid    `json:"federated_claims"`
}

func startRedirectListener(state, htmlPage, redirectURL string, codeCh chan string, errCh chan error) (*http.Server, *url.URL, error) {
	var listener net.Listener
	var urlListener *url.URL
	var err error

	if redirectURL == "" {
		listener, err = net.Listen("tcp", "localhost:0") // ":0" == OS picks
		if err != nil {
			return nil, nil, err
		}

		addr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			return nil, nil, fmt.Errorf("listener addr is not TCPAddr")
		}

		urlListener = &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("localhost:%d", addr.Port),
			Path:   "/auth/callback",
		}
	} else {
		urlListener, err = url.Parse(redirectURL)
		if err != nil {
			return nil, nil, err
		}
		listener, err = net.Listen("tcp", urlListener.Host)
		if err != nil {
			return nil, nil, err
		}
	}

	m := http.NewServeMux()
	s := &http.Server{
		Addr:    urlListener.Host,
		Handler: m,

		// an arbitrary reasonable value to fix gosec lint error
		ReadHeaderTimeout: 2 * time.Second,
	}

	m.HandleFunc(urlListener.Path, func(w http.ResponseWriter, r *http.Request) {
		// even though these are fetched from the FormValue method,
		// these are supplied as query parameters
		if r.FormValue("state") != state {
			errCh <- errors.New("invalid state token")
			return
		}
		codeCh <- r.FormValue("code")
		fmt.Fprint(w, htmlPage)
	})

	go func() {
		if err := s.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	return s, urlListener, nil
}

func getCode(codeCh chan string, errCh chan error) (string, error) {
	select {
	case code := <-codeCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-time.After(120 * time.Second):
		return "", errors.New("timeout")
	}
}

func RunOIDCFlow(connector, nonce string) (string, error) {
	issuer := "https://oauth2.sigstore.dev/auth"
	provider, err := coreoidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return "", nil
	}

	cfg := oauth2.Config{
		ClientID:     "sigstore",
		ClientSecret: "",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{coreoidc.ScopeOpenID, "email"},
	}

	stateToken := ksuid.New().String()

	codeCh := make(chan string)
	errCh := make(chan error)

	// get html success page with configured autoclose and autocloseTimeout settings
	htmlPage, err := oauth.GetInteractiveSuccessHTML(true, 6)
	if err != nil {
		return "", nil
	}

	// starts listener using the redirect_uri, otherwise starts on ephemeral port
	redirectServer, redirectURL, err := startRedirectListener(
		stateToken,
		htmlPage,
		cfg.RedirectURL,
		codeCh,
		errCh,
	)
	if err != nil {
		close(codeCh)
		close(errCh)
		return "", nil
	}
	defer func() {
		go func() {
			_ = redirectServer.Shutdown(context.Background())
			close(codeCh)
			close(errCh)
		}()
	}()

	pkce, err := oidc.NewPKCE(provider)
	if err != nil {
		return "", nil
	}

	opts := append(pkce.AuthURLOpts(), oauth2.AccessTypeOnline, coreoidc.Nonce(nonce),
		oauthflow.ConnectorIDOpt(connector))

	cfg.RedirectURL = redirectURL.String()
	authCodeURL := cfg.AuthCodeURL(stateToken, opts...)

	browser.OpenURL(authCodeURL)

	code, err := getCode(codeCh, errCh)
	if err != nil {
		return "", err
	}

	t, err := cfg.Exchange(context.Background(), code, append(pkce.TokenURLOpts(), coreoidc.Nonce(nonce))...)
	if err != nil {
		return "", err
	}

	unverifiedIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("did not get id_token")
	}

	verifier := provider.Verifier(&coreoidc.Config{ClientID: "sigstore"})
	_, err = verifier.Verify(context.Background(), unverifiedIDToken)
	if err != nil {
		return "", err
	}
	return unverifiedIDToken, nil
}

func VerifyUserAndJWT(connector string, email string, nonce string, jwt string) (bool, error) {
	issuer := "https://oauth2.sigstore.dev/auth"
	provider, err := coreoidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return false, err
	}

	verifier := provider.Verifier(&coreoidc.Config{ClientID: "sigstore"})
	l, err := verifier.Verify(context.Background(), jwt)
	if err != nil {
		return false, err
	}

	var c claims
	l.Claims(&c)

	if c.Email == email && c.FederatedClaims.ConnectorId == connector {
		return true, nil
	}
	return false, err
}
