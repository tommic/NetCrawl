package ports

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestResolvePresets(t *testing.T) {
	got, err := Resolve("tiny", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{22, 80, 443}; !reflect.DeepEqual(got, want) {
		t.Errorf("tiny = %v, want %v", got, want)
	}
	all, err := Resolve("all", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 65535 || all[0] != 1 || all[len(all)-1] != 65535 {
		t.Errorf("all: got %d ports (%d..%d)", len(all), all[0], all[len(all)-1])
	}
	for _, p := range []string{"", "custom"} {
		got, err := Resolve(p, nil)
		if err != nil || len(got) != 0 {
			t.Errorf("Resolve(%q, nil) = %v, %v; want empty", p, got, err)
		}
	}
}

func TestResolveCustomAndRanges(t *testing.T) {
	got, err := Resolve("tiny", []Spec{"8080", "22", "9000-9003", " 7 ", "9002-9004"})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{7, 22, 80, 443, 8080, 9000, 9001, 9002, 9003, 9004}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveErrors(t *testing.T) {
	tests := []struct {
		preset string
		custom []Spec
		want   string
	}{
		{"comon", nil, "unknown port preset"},
		{"tiny", []Spec{"0"}, "out of range"},
		{"tiny", []Spec{"65536"}, "out of range"},
		{"tiny", []Spec{"http"}, "not a number"},
		{"tiny", []Spec{"9010-9000"}, "start is greater than end"},
		{"tiny", []Spec{"9000-"}, "invalid port range"},
		{"tiny", []Spec{"80.5"}, "not a number"},
	}
	for _, tt := range tests {
		_, err := Resolve(tt.preset, tt.custom)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Resolve(%q, %v) error = %v, want it to contain %q", tt.preset, tt.custom, err, tt.want)
		}
	}
}

func TestSpecUnmarshal(t *testing.T) {
	var specs []Spec
	if err := json.Unmarshal([]byte(`[8000, "8080", "9000-9010"]`), &specs); err != nil {
		t.Fatal(err)
	}
	if want := []Spec{"8000", "8080", "9000-9010"}; !reflect.DeepEqual(specs, want) {
		t.Errorf("got %v, want %v", specs, want)
	}
	if err := json.Unmarshal([]byte(`[true]`), &specs); err == nil {
		t.Error("expected error for boolean port entry")
	}
}

func TestPresetsListed(t *testing.T) {
	names := strings.Join(Presets(), ",")
	for _, want := range []string{"all", "common", "custom", "database", "tiny", "web"} {
		if !strings.Contains(names, want) {
			t.Errorf("Presets() = %s, missing %s", names, want)
		}
	}
}
