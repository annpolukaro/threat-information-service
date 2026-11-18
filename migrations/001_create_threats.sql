
CREATE TABLE IF NOT EXISTS threats (
    md5 VARCHAR(32) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    threat_type VARCHAR(50) NOT NULL DEFAULT 'other',
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    first_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT threats_md5_format CHECK (
        md5 ~ '^[0-9a-f]{32}$'
    ),

    CONSTRAINT threats_type_check CHECK (
        threat_type IN (
            'trojan',
            'virus',
            'worm',
            'ransomware',
            'spyware',
            'other'
        )
    ),

    CONSTRAINT threats_severity_check CHECK (
        severity IN (
            'low',
            'medium',
            'high',
            'critical'
        )
    )
);
