-- The hash of each agent's allowlist, as its last hello reported it (ADR 0024).

ALTER TABLE agent_presence
    ADD COLUMN allowlist_sha256 bytea CHECK (octet_length(allowlist_sha256) = 32);
