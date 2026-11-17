
CREATE TABLE threats (
    md5 CHAR(32) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    threat_type VARCHAR(32) NOT NULL DEFAULT 'other',
    severity VARCHAR(16) NOT NULL DEFAULT 'medium',
    first_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_md5
        CHECK (md5 ~ '^[0-9a-f]{32}$'),

    CONSTRAINT valid_name
        CHECK (length(btrim(name)) > 0),

    CONSTRAINT valid_threat_type
        CHECK (threat_type IN (
            'trojan', 'virus', 'worm',
            'ransomware', 'spyware', 'other'
        )),

    CONSTRAINT valid_severity
        CHECK (severity IN (
            'low', 'medium', 'high', 'critical'
        ))
);
