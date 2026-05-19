-- V2: refresh_tokens table
CREATE TABLE refresh_tokens (
    id          VARCHAR(36)   NOT NULL PRIMARY KEY,
    token       VARCHAR(2048) NOT NULL,
    user_id     VARCHAR(36)   NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expiry_date TIMESTAMPTZ   NOT NULL,
    revoked     BOOLEAN       NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_refresh_tokens_token   ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

