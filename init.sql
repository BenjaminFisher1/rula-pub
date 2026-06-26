-- Initializes DB on first run

CREATE TABLE IF NOT EXISTS risky_users (
    id TEXT PRIMARY KEY,
    user_principal_name VARCHAR(255) NOT NULL, --encrypted 
    user_display_name VARCHAR(255), --encrypted
    
    -- Risk attributes
    risk_level VARCHAR(20),
    risk_state VARCHAR(20),
    risk_detail VARCHAR(50),
    risk_last_updated_datetime TIMESTAMPTZ,
    
    -- User status
    is_deleted BOOLEAN DEFAULT FALSE,
    is_processing BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risky_users_upn ON risky_users(user_principal_name);
CREATE INDEX IF NOT EXISTS idx_risky_users_risk_level ON risky_users(risk_level);
CREATE INDEX IF NOT EXISTS idx_risky_users_risk_state ON risky_users(risk_state);
CREATE INDEX IF NOT EXISTS idx_risky_users_risk_detail ON risky_users(risk_detail);
CREATE INDEX IF NOT EXISTS idx_risky_users_updated ON risky_users(updated_at DESC);



CREATE TABLE IF NOT EXISTS risky_events (
    event_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES risky_users(id) ON DELETE CASCADE,
    user_principal_name VARCHAR(255), --encrypted
    
    -- Event details
    activity VARCHAR(50),
    activity_datetime TIMESTAMPTZ,
    detected_datetime TIMESTAMPTZ,
    last_updated_datetime TIMESTAMPTZ,
    
    -- Risk information
    risk_type VARCHAR(50),
    risk_level VARCHAR(20),
    risk_state VARCHAR(20),
    risk_detail VARCHAR(50),
    
    -- Location & context
    ip_address inet, --masked
    location_city VARCHAR(100),
    location_state VARCHAR(100),
    location_country_code VARCHAR(10),
    user_agent TEXT, 
    
    -- Additional info
    additional_info JSONB,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_user_id ON risky_events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_user_upn ON risky_events(user_principal_name);
CREATE INDEX IF NOT EXISTS idx_events_activity_datetime ON risky_events(activity_datetime DESC);
CREATE INDEX IF NOT EXISTS idx_events_detected_datetime ON risky_events(detected_datetime DESC);
CREATE INDEX IF NOT EXISTS idx_events_risk_type ON risky_events(risk_type);
CREATE INDEX IF NOT EXISTS idx_events_risk_level ON risky_events(risk_level);
CREATE INDEX IF NOT EXISTS idx_events_ip ON risky_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_events_country ON risky_events(location_country_code);
CREATE INDEX IF NOT EXISTS idx_events_additional_info ON risky_events USING GIN (additional_info);



CREATE TABLE IF NOT EXISTS fetch_runs (
    fetch_id SERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    users_synced INTEGER,
    events_synced INTEGER,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_fetch_runs_started ON fetch_runs(started_at DESC);




CREATE TABLE IF NOT EXISTS user_risk_tags (
    tag_id SERIAL PRIMARY KEY,
    user_id TEXT REFERENCES risky_users(id),
    tag_name VARCHAR(100),              -- item such as 'impossible_travel'
    severity VARCHAR(20),               -- critical, high, medium, low
    pattern_data JSONB,                 -- Details about what triggered this tag
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_risk_tags_user_id ON user_risk_tags(user_id);
CREATE INDEX IF NOT EXISTS idx_user_risk_tags_severity ON user_risk_tags(severity);

-- custom risk assessments (computed from tags)
CREATE TABLE IF NOT EXISTS custom_risk_assessments (
    assessment_id SERIAL PRIMARY KEY,
    user_id TEXT REFERENCES risky_users(id),
    custom_risk_level VARCHAR(20),      -- critical, high, etc
    custom_risk_score INTEGER,          -- 0-100
    active_tags JSONB,                  -- Summary of active tags
    assessed_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(user_id, assessed_at)
);

CREATE INDEX IF NOT EXISTS idx_custom_risk_user ON custom_risk_assessments(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_risk_level ON custom_risk_assessments(custom_risk_level, assessed_at DESC);