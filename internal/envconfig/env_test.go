package envconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := "# comment\n\nNC_TEST_A=one\nNC_TEST_B = \"two\"\nNC_TEST_C='three'\nNC_TEST_KEEP=from-file\ninvalid line\n=novalue\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"NC_TEST_A", "NC_TEST_B", "NC_TEST_C"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("NC_TEST_KEEP", "from-env")

	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"NC_TEST_A": "one", "NC_TEST_B": "two", "NC_TEST_C": "three", "NC_TEST_KEEP": "from-env"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestLoadMissingFileIsNoError(t *testing.T) {
	if err := Load(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Errorf("missing .env must not be an error: %v", err)
	}
}

func TestGet(t *testing.T) {
	t.Setenv("NC_TEST_GET", "")
	if got := Get("NC_TEST_GET", "fallback"); got != "fallback" {
		t.Errorf("empty value: got %q, want fallback", got)
	}
	t.Setenv("NC_TEST_GET", "set")
	if got := Get("NC_TEST_GET", "fallback"); got != "set" {
		t.Errorf("got %q, want set", got)
	}
}
