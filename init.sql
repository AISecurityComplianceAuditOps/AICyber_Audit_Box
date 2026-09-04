-- ShakthiDB Initialization Script
-- This creates the schema required for the AICyberAuditBox application

-- 1. Create audit_findings table with all fields matched to SQLAlchemy model in app.py
CREATE TABLE IF NOT EXISTS audit_findings (
    id SERIAL PRIMARY KEY,
    use_case_sl INTEGER,
    use_case_name VARCHAR(300),
    severity VARCHAR(50),
    control VARCHAR(200),
    finding TEXT,
    recommendation TEXT,
    status VARCHAR(50) DEFAULT 'Open',
    comment TEXT DEFAULT '',
    source_files TEXT DEFAULT 'All uploaded documents',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Create chat_messages table to store chat conversations
CREATE TABLE IF NOT EXISTS chat_messages (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100),
    session_title VARCHAR(300),
    role VARCHAR(50),
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

