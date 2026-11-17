package domain

import "time"

type ThreatType string

const (
	ThreatTypeTrojan     ThreatType = "trojan"
	ThreatTypeVirus      ThreatType = "virus"
	ThreatTypeWorm       ThreatType = "worm"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeSpyware    ThreatType = "spyware"
	ThreatTypeOther      ThreatType = "other"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Threat struct {
	MD5         string
	Name        string
	Description string
	ThreatType  ThreatType
	Severity    Severity
	FirstSeenAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
