package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestSigningStringFormat(t *testing.T) {
	got := SigningString("POST", "/api/v1/crawler/jobs/j1/result", "lab-1", "j1", 1700000000, "abc", []byte("{}"))
	want := strings.Join([]string{
		"NETCRAWL-HMAC-SHA256-V1", "POST", "/api/v1/crawler/jobs/j1/result", "lab-1", "j1", "1700000000", "abc",
		"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", // sha256("{}")
	}, "\n")
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestSignVerify(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s := SigningString("GET", PathJob, "lab-1", "", time.Now().Unix(), "n", nil)
	sig := Sign(key, s)
	if !Verify(key, s, sig) {
		t.Error("valid signature rejected")
	}
	if Verify(key, s+"x", sig) {
		t.Error("signature over different string accepted")
	}
	other, _ := NewKey()
	if Verify(other, s, sig) {
		t.Error("signature with other key accepted")
	}
	if Verify(key, s, "zz") || Verify(key, s, "") {
		t.Error("malformed signature accepted")
	}
	// Any change to the body changes the signing string.
	if SigningString("POST", "/p", "c", "j", 1, "n", []byte("a")) == SigningString("POST", "/p", "c", "j", 1, "n", []byte("b")) {
		t.Error("body must be part of the signing string")
	}
}

func TestKeyEncoding(t *testing.T) {
	k, _ := NewKey()
	got, err := DecodeKey(" " + EncodeKey(k) + "\n")
	if err != nil || string(got) != string(k) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := DecodeKey("c2hvcnQ"); err == nil {
		t.Error("short key accepted")
	}
	if _, err := DecodeKey("not base64!"); err == nil {
		t.Error("invalid encoding accepted")
	}
}

func TestParseTimestamp(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, tt := range []struct {
		in string
		ok bool
	}{
		{"1700000000", true},
		{"1700000299", true},
		{"1699999701", true},
		{"1700000301", false},
		{"1699999699", false},
		{"abc", false},
		{"", false},
	} {
		_, err := ParseTimestamp(tt.in, now)
		if (err == nil) != tt.ok {
			t.Errorf("ParseTimestamp(%q) err = %v, want ok=%v", tt.in, err, tt.ok)
		}
	}
}

func TestValidators(t *testing.T) {
	for id, want := range map[string]bool{"lab-1": true, "a": true, "pi.kitchen_2": true, "": false, "-x": false, "Lab": false, "a b": false, strings.Repeat("a", 65): false} {
		if ValidCrawlerID(id) != want {
			t.Errorf("ValidCrawlerID(%q) != %v", id, want)
		}
	}
	n, _ := NewNonce()
	for nonce, want := range map[string]bool{n: true, "short": false, strings.Repeat("a", 129): false, "0123456789abcdef/": false} {
		if ValidNonce(nonce) != want {
			t.Errorf("ValidNonce(%q) != %v", nonce, want)
		}
	}
	id, _ := NewID()
	if len(id) != 36 || id[14] != '4' || !ValidJobID(id) {
		t.Errorf("NewID = %q, want UUIDv4", id)
	}
	for _, bad := range []string{"", "../admin/jobs", strings.ToUpper(id), id + "0", strings.Replace(id, "-", "x", 1)} {
		if ValidJobID(bad) {
			t.Errorf("ValidJobID(%q) = true", bad)
		}
	}
}
