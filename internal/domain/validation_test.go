package domain

import "testing"

func TestValidateMD5(t *testing.T) {
	tests := []struct {
		md5   string
		valid bool
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", true},
		{"D41D8CD98F00B204E9800998ECF8427E", true},
		{"123", false},
		{"", false},
		{"z41d8cd98f00b204e9800998ecf8427e", false},
	}

	for _, tt := range tests {
		if got := ValidateMD5(tt.md5); got != tt.valid {
			t.Errorf("ValidateMD5(%q) = %v, want %v",
				tt.md5, got, tt.valid)
		}
	}
}

func TestThreatValidate(t *testing.T) {
	threat := Threat{
		MD5:  "D41D8CD98F00B204E9800998ECF8427E",
		Name: " Trojan.Win32.Generic ",
	}

	if err := threat.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if threat.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("MD5 was not normalized")
	}

	if threat.Name != "Trojan.Win32.Generic" {
		t.Errorf("name was not trimmed")
	}

	if threat.ThreatType != ThreatTypeOther {
		t.Errorf("unexpected threat type: %s", threat.ThreatType)
	}

	if threat.Severity != SeverityMedium {
		t.Errorf("unexpected severity: %s", threat.Severity)
	}
}

func TestThreatValidateInvalidName(t *testing.T) {
	threat := Threat{
		MD5:  "d41d8cd98f00b204e9800998ecf8427e",
		Name: "   ",
	}

	if err := threat.Validate(); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName, got %v", err)
	}
}
