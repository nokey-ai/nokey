package env

import (
	"strings"
	"testing"
)

func TestFilterSecrets_NoFilter(t *testing.T) {
	all := map[string]string{"A": "1", "B": "2", "C": "3"}
	got, err := FilterSecrets(all, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

func TestFilterSecrets_Only(t *testing.T) {
	all := map[string]string{"A": "1", "B": "2", "C": "3"}
	got, err := FilterSecrets(all, "A,C", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	if got["A"] != "1" || got["C"] != "3" {
		t.Errorf("got = %v, want A and C", got)
	}
}

func TestFilterSecrets_OnlyNotFound(t *testing.T) {
	all := map[string]string{"A": "1"}
	_, err := FilterSecrets(all, "NONEXISTENT", "")
	if err == nil || !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("expected 'secret not found' error, got: %v", err)
	}
}

func TestFilterSecrets_Except(t *testing.T) {
	all := map[string]string{"A": "1", "B": "2", "C": "3"}
	got, err := FilterSecrets(all, "", "B")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	if _, ok := got["B"]; ok {
		t.Error("B should be excluded")
	}
}

func TestFilterSecrets_BothOnlyAndExcept(t *testing.T) {
	_, err := FilterSecrets(nil, "A", "B")
	if err == nil || !strings.Contains(err.Error(), "cannot use both") {
		t.Errorf("expected 'cannot use both' error, got: %v", err)
	}
}

func TestFilterNames_NoFilter(t *testing.T) {
	got, err := FilterNames([]string{"A", "B", "C"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

func TestFilterNames_Only(t *testing.T) {
	got, err := FilterNames([]string{"A", "B", "C"}, "A,C", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "A" || got[1] != "C" {
		t.Errorf("got = %v, want [A C]", got)
	}
}

func TestFilterNames_OnlyNotFound(t *testing.T) {
	_, err := FilterNames([]string{"A"}, "NOPE", "")
	if err == nil || !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("expected 'secret not found' error, got: %v", err)
	}
}

func TestFilterNames_Except(t *testing.T) {
	got, err := FilterNames([]string{"A", "B", "C"}, "", "B")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	for _, n := range got {
		if n == "B" {
			t.Error("B should be excluded")
		}
	}
}

func TestFilterNames_BothOnlyAndExcept(t *testing.T) {
	_, err := FilterNames(nil, "A", "B")
	if err == nil || !strings.Contains(err.Error(), "cannot use both") {
		t.Errorf("expected 'cannot use both' error, got: %v", err)
	}
}

func TestParseCommaSeparated(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"A", []string{"A"}},
		{"A,B,C", []string{"A", "B", "C"}},
		{" A , B , C ", []string{"A", "B", "C"}},
		{"A,,B", []string{"A", "B"}},
	}

	for _, tt := range tests {
		got := ParseCommaSeparated(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("ParseCommaSeparated(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ParseCommaSeparated(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}
