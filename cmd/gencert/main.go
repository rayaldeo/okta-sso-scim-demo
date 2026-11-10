// Command gencert creates the SAML service provider's signing key and a
// self-signed certificate. The app signs SAML LogoutRequests with the key;
// Okta verifies them with the certificate you upload to the SAML app.
//
//	go run ./cmd/gencert              # writes certs/sp.key and certs/sp.crt
//	go run ./cmd/gencert -out other/  # somewhere else
//
// Existing files are never overwritten. Both are gitignored.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := flag.String("out", "certs", "directory to write sp.key and sp.crt into")
	cn := flag.String("cn", "okta-sso-scim-demo SP", "certificate common name")
	years := flag.Int("years", 2, "certificate validity in years")
	flag.Parse()

	if err := run(*out, *cn, *years); err != nil {
		fmt.Fprintln(os.Stderr, "gencert:", err)
		os.Exit(1)
	}
}

func run(dir, cn string, years int) error {
	keyPath, certPath := filepath.Join(dir, "sp.key"), filepath.Join(dir, "sp.crt")
	for _, p := range []string{keyPath, certPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists; delete it first to rotate the key", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(years, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (keep private) and %s (upload to Okta)\n", keyPath, certPath)
	return nil
}

func mustPKCS8(key *rsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return b
}
