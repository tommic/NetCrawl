package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSelfSignedAndPin(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := SelfSigned(dir, []string{"192.168.1.5", "netcrawl.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(keyFile); info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
	pin, err := PinFromFile(certFile)
	if err != nil || !Valid(pin) {
		t.Fatalf("pin %q, %v", pin, err)
	}
	if self, err := IsSelfSigned(certFile); err != nil || !self {
		t.Fatalf("IsSelfSigned = %v, %v", self, err)
	}
	// A second call keeps the certificate (stable pin).
	if _, _, err := SelfSigned(dir, nil); err != nil {
		t.Fatal(err)
	}
	if again, _ := PinFromFile(filepath.Join(dir, "cert.pem")); again != pin {
		t.Fatal("pin changed")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	get := func(p string) error {
		cfg, err := ClientConfig(p)
		if err != nil {
			return err
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := c.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(pin); err != nil {
		t.Fatalf("right pin: %v", err)
	}
	other, _, _ := SelfSigned(t.TempDir(), nil)
	wrong, _ := PinFromFile(other)
	if err := get(wrong); err == nil {
		t.Fatal("wrong pin accepted")
	}
	if _, err := ClientConfig("sha256//abc"); err == nil {
		t.Fatal("invalid pin accepted")
	}
}

func TestIsSelfSignedCAIssued(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "netcrawl.example.org"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "c.pem")
	if err := writePEM(f, "CERTIFICATE", leafDER, 0o644); err != nil {
		t.Fatal(err)
	}
	if self, err := IsSelfSigned(f); err != nil || self {
		t.Fatalf("CA-issued leaf: self-signed = %v, %v", self, err)
	}
}
