// Package tlspin handles servers reachable by IP with a self-signed
// certificate: the client trusts exactly one public key (a pin) instead
// of a certificate authority. The pin format is curl's
// --pinnedpubkey "sha256//<base64 SHA-256 of the SubjectPublicKeyInfo>",
// so the installer one-liner and the agent check the same value.
package tlspin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const prefix = "sha256//"

// Pin returns the pin of a certificate's public key.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return prefix + base64.StdEncoding.EncodeToString(sum[:])
}

// Valid reports whether s is a well-formed pin.
func Valid(s string) bool {
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s[len(prefix):])
	return err == nil && len(b) == sha256.Size
}

// ClientConfig returns a TLS config that accepts the server only if its
// certificate carries the pinned key. Names and CAs are not checked: the
// pin is the trust anchor.
func ClientConfig(pin string) (*tls.Config, error) {
	if !Valid(pin) {
		return nil, fmt.Errorf("invalid TLS pin %q (expected sha256//<base64>)", pin)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls pin: server sent no certificate")
			}
			got := Pin(cs.PeerCertificates[0])
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return fmt.Errorf("tls pin mismatch: server key is %s", got)
			}
			return nil
		},
	}, nil
}

// PinFromFile reads a PEM certificate file and returns the pin of its
// first certificate.
func PinFromFile(certFile string) (string, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s: no PEM certificate", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", certFile, err)
	}
	return Pin(cert), nil
}

// SelfSigned returns cert.pem and key.pem in dir, creating a self-signed
// certificate for the given hosts (IPs or names) if none exists yet. An
// existing certificate is kept, so its pin stays stable.
func SelfSigned(dir string, hosts []string) (certFile, keyFile string, err error) {
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return certFile, keyFile, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "netcrawl-server"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range append(hosts, "127.0.0.1", "localhost") {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", err
	}
	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// IsSelfSigned reports whether the first certificate in a PEM file signs
// itself (and therefore needs a pin rather than a CA).
func IsSelfSigned(certFile string) (bool, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, fmt.Errorf("%s: no PEM certificate", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	// CheckSignatureFrom would demand a CA certificate; a self-signed
	// leaf is not one, so check the signature directly.
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false, nil
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil, nil
}
