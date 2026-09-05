package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestProbeTLS(t *testing.T) {
	cert := selfSignedCert(t, "router.local", "MyRouter CA")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// tls.Listen only performs the server-side handshake lazily on
			// first Read/Write, so force it before closing.
			go func(c net.Conn) {
				_ = c.(*tls.Conn).Handshake()
				time.Sleep(100 * time.Millisecond)
				c.Close()
			}(c)
		}
	}()

	addr, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	info, ok := probeTLS(context.Background(), addr, port, time.Second)
	if !ok {
		t.Fatal("expected probeTLS to succeed")
	}
	if info.TLSSubject != "router.local" {
		t.Errorf("TLSSubject = %q, want %q", info.TLSSubject, "router.local")
	}
	if info.TLSIssuer != "MyRouter CA" {
		t.Errorf("TLSIssuer = %q, want %q", info.TLSIssuer, "MyRouter CA")
	}
	if info.TLSNotAfter == "" {
		t.Error("TLSNotAfter is empty")
	}
}

func TestProbeHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestWebUI/1.0")
		fmt.Fprint(w, "<html><head><title>NAS Login Page</title></head><body>hi</body></html>")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, mux)

	addr, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	info, ok := probeHTTP(context.Background(), addr, port, time.Second)
	if !ok {
		t.Fatal("expected probeHTTP to succeed")
	}
	if info.HTTPServer != "TestWebUI/1.0" {
		t.Errorf("HTTPServer = %q, want %q", info.HTTPServer, "TestWebUI/1.0")
	}
	if info.HTTPTitle != "NAS Login Page" {
		t.Errorf("HTTPTitle = %q, want %q", info.HTTPTitle, "NAS Login Page")
	}
}

func TestProbeBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			go func(c net.Conn) { time.Sleep(200 * time.Millisecond); c.Close() }(c)
		}
	}()

	addr, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	info, ok := probeBanner(context.Background(), addr, port, time.Second)
	if !ok {
		t.Fatal("expected probeBanner to succeed")
	}
	if info.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("Banner = %q, want %q", info.Banner, "SSH-2.0-OpenSSH_9.6")
	}
}

func TestRelevant(t *testing.T) {
	for _, port := range []int{443, 8443, 80, 8080, 22, 21, 25} {
		if !Relevant(port) {
			t.Errorf("Relevant(%d) = false, want true", port)
		}
	}
	if Relevant(3306) {
		t.Error("Relevant(3306) = true, want false")
	}
}

// selfSignedCert builds a two-level chain (a self-signed CA plus a leaf
// certificate it signs) so the resulting leaf has a Subject different from
// its Issuer, the way a certificate from an internal or vendor CA would.
func selfSignedCert(t *testing.T, cn, issuer string) tls.Certificate {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuer},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
}
