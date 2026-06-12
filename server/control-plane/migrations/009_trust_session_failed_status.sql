-- Allow trust_sessions to record non-minting attestation outcomes so the
-- dashboard can report attestation failures. A 'failed' row never validates
-- proofs (empty session_secret, immediate expiry); it exists purely for stats.

ALTER TABLE trust_sessions DROP CONSTRAINT IF EXISTS trust_sessions_status_check;
ALTER TABLE trust_sessions
    ADD CONSTRAINT trust_sessions_status_check
    CHECK (status IN ('active', 'revoked', 'failed'));

-- Stats are grouped by status over an issued_at window per tenant.
CREATE INDEX IF NOT EXISTS idx_trust_sessions_tenant_issued
    ON trust_sessions (tenant_id, issued_at);
