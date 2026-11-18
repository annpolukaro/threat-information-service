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
	MD5         string     `json:"md5"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ThreatType  ThreatType `json:"threat_type"`
	Severity    Severity   `json:"severity"`
	FirstSeenAt *time.Time `json:"first_seen_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}
