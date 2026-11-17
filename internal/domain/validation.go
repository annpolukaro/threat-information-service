package domain

import (
	"errors"
	"regexp"
	"strings"
)

var md5Regex = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

var (
	ErrInvalidMD5        = errors.New("invalid md5")
	ErrInvalidName       = errors.New("invalid name")
	ErrInvalidThreatType = errors.New("invalid threat type")
	ErrInvalidSeverity   = errors.New("invalid severity")
)

func ValidateMD5(md5 string) bool {
	return md5Regex.MatchString(md5)
}

func (t *Threat) Validate() error {
	if !ValidateMD5(t.MD5) {
		return ErrInvalidMD5
	}

	t.Name = strings.TrimSpace(t.Name)

	if t.Name == "" || len(t.Name) > 255 {
		return ErrInvalidName
	}

	if t.ThreatType == "" {
		t.ThreatType = ThreatTypeOther
	}

	switch t.ThreatType {
	case ThreatTypeTrojan, ThreatTypeVirus, ThreatTypeWorm,
		ThreatTypeRansomware, ThreatTypeSpyware, ThreatTypeOther:
	default:
		return ErrInvalidThreatType
	}

	if t.Severity == "" {
		t.Severity = SeverityMedium
	}

	switch t.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return ErrInvalidSeverity
	}

	t.MD5 = strings.ToLower(t.MD5)

	return nil
}
