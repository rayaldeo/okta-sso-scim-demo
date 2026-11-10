// Command server runs the Okta SSO + SCIM demo app.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/auth"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/config"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/web"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	var opts web.Options
	if cfg.OIDCEnabled() {
		// Fail fast: a typo in OIDC_ISSUER should stop startup, not surface
		// as a broken login later.
		opts.OIDC, err = auth.NewOIDC(auth.OIDCConfig{
			Issuer:       cfg.OIDCIssuer,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL(),
			Scopes:       cfg.OIDCScopes,
		})
		if err != nil {
			return err
		}
		log.Info("oidc ready", "issuer", cfg.OIDCIssuer, "redirect_uri", cfg.OIDCRedirectURL())
	}

	if cfg.SAMLEnabled() {
		key, cert, err := auth.LoadSAMLKeyPair(cfg.SAMLKeyFile, cfg.SAMLCertFile)
		if err != nil {
			return err
		}
		md, err := auth.FetchIDPMetadata(context.Background(), cfg.SAMLIdPMetadataURL)
		if err != nil {
			return err
		}
		opts.SAML, err = auth.NewSAML(auth.SAMLConfig{
			EntityID: cfg.SAMLEntityID(), ACSURL: cfg.SAMLACSURL(), SLOURL: cfg.SAMLSLOURL(),
			Key: key, Certificate: cert, IDPMetadata: md, Store: st,
		})
		if err != nil {
			return err
		}
		log.Info("saml ready", "idp", md.EntityID, "entity_id", cfg.SAMLEntityID(), "acs", cfg.SAMLACSURL())
	}

	srv, err := web.New(cfg, st, log, opts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go purgeExpiredSessions(ctx, st, log)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL.String(),
			"oidc", cfg.OIDCEnabled(), "saml", cfg.SAMLEnabled(), "scim", cfg.SCIMEnabled())
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

func purgeExpiredSessions(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := st.DeleteExpiredSessions(ctx); err != nil {
				log.Error("purge sessions", "err", err)
			} else if n > 0 {
				log.Info("purged expired sessions", "count", n)
			}
		}
	}
}
