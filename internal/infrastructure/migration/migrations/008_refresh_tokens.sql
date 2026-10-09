-- +goose Up
-- Refresh tokens emitidos (um registro por jti). O token nunca é persistido.
-- Rotação: cada refresh revoga o jti usado (revoked_reason='rotated', replaced_by)
-- e emite outro. Reuso de um jti já rotacionado revoga toda a família do usuário.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id             UUID PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    expires_at     TIMESTAMP NOT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMP,
    revoked_reason VARCHAR(32),
    replaced_by    UUID
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_app ON refresh_tokens(user_id, application_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- +goose Down
DROP TABLE IF EXISTS refresh_tokens;
