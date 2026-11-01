-- Foundations for M1, as described in docs/data-model.md. File contents,
-- plaintext credentials, and private keys are never stored. File names live only
-- in delivery_files, so they can be deleted without touching evidence.

CREATE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TABLE workspaces (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    name       text NOT NULL UNIQUE CHECK (name ~ '^[A-Za-z0-9._-]{1,128}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    name         text NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,128}$'),
    status       text NOT NULL CHECK (status IN ('pending_approval', 'approved', 'revoked')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE enrollment_tokens (
    token_sha256 bytea PRIMARY KEY CHECK (octet_length(token_sha256) = 32),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    agent_name   text NOT NULL CHECK (agent_name ~ '^[A-Za-z0-9._-]{1,128}$'),
    agent_id     uuid REFERENCES agents (id),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CHECK ((used_at IS NULL) = (agent_id IS NULL))
);

CREATE INDEX enrollment_tokens_workspace_id ON enrollment_tokens (workspace_id);
CREATE INDEX enrollment_tokens_agent_id ON enrollment_tokens (agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX enrollment_tokens_expiry ON enrollment_tokens (expires_at) WHERE used_at IS NULL;

-- Append-only. Exact bytes, because a signature covers exact bytes.
CREATE TABLE signed_statements (
    id           bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    payload_type text NOT NULL CHECK (char_length(payload_type) <= 128),
    envelope     bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_identities (
    id                    uuid PRIMARY KEY DEFAULT uuidv7(),
    agent_id              uuid NOT NULL REFERENCES agents (id),
    ed25519_public_key    bytea NOT NULL CHECK (octet_length(ed25519_public_key) = 32),
    mldsa65_public_key    bytea NOT NULL CHECK (octet_length(mldsa65_public_key) = 1952),
    encryption_recipient  text NOT NULL CHECK (char_length(encryption_recipient) <= 4096),
    identity_statement_id bytea REFERENCES signed_statements (id),
    not_after             timestamptz,
    revoked_at            timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    CHECK ((identity_statement_id IS NULL) = (not_after IS NULL))
);

CREATE INDEX agent_identities_agent_id ON agent_identities (agent_id);
CREATE INDEX agent_identities_statement ON agent_identities (identity_statement_id)
    WHERE identity_statement_id IS NOT NULL;
CREATE UNIQUE INDEX agent_identities_one_active ON agent_identities (agent_id)
    WHERE revoked_at IS NULL;

-- Kept apart so that heartbeats don't rewrite rows holding keys.
CREATE TABLE agent_presence (
    agent_id      uuid PRIMARY KEY REFERENCES agents (id),
    agent_version text CHECK (char_length(agent_version) <= 64),
    last_seen_at  timestamptz NOT NULL DEFAULT now()
) WITH (fillfactor = 70);

CREATE TABLE runs (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    -- Both stay empty for manual M1 runs. flow_id gains a foreign key in M2.
    flow_id      uuid,
    flow_version integer CHECK (flow_version >= 1),
    status       text NOT NULL CHECK (status IN (
        'pending', 'running', 'succeeded', 'partial_failure', 'failed', 'cancelled'
    )),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK ((flow_id IS NULL) = (flow_version IS NULL))
);

CREATE INDEX runs_workspace_page ON runs (workspace_id, id DESC);
CREATE INDEX runs_active ON runs (status)
    WHERE status IN ('pending', 'running');
CREATE TRIGGER runs_updated_at BEFORE UPDATE ON runs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE deliveries (
    id                    uuid PRIMARY KEY DEFAULT uuidv7(),
    run_id                uuid NOT NULL REFERENCES runs (id),
    source_agent_id       uuid NOT NULL REFERENCES agents (id),
    destination_agent_id  uuid NOT NULL REFERENCES agents (id),
    size_bytes            bigint CHECK (size_bytes >= 0),
    sealed_sha256         bytea CHECK (octet_length(sealed_sha256) = 32),
    status                text NOT NULL CHECK (status IN (
        'pending', 'claimed', 'transferring', 'verifying', 'retry_wait', 'succeeded', 'failed', 'cancelled'
    )),
    evidence              text NOT NULL DEFAULT 'none' CHECK (evidence IN ('none', 'source_only', 'verified')),
    error_code            text CHECK (error_code ~ '^[a-z0-9_]{1,64}$'),
    manifest_statement_id bytea REFERENCES signed_statements (id),
    receipt_statement_id  bytea REFERENCES signed_statements (id),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK (source_agent_id <> destination_agent_id),
    -- Evidence must match the statements actually held.
    CHECK (evidence <> 'source_only' OR (manifest_statement_id IS NOT NULL AND sealed_sha256 IS NOT NULL)),
    CHECK (evidence <> 'verified' OR (
        manifest_statement_id IS NOT NULL AND receipt_statement_id IS NOT NULL AND sealed_sha256 IS NOT NULL
    )),
    CHECK (status <> 'succeeded' OR evidence = 'verified')
);

CREATE INDEX deliveries_run_id ON deliveries (run_id);
CREATE INDEX deliveries_source_agent_id ON deliveries (source_agent_id);
CREATE INDEX deliveries_destination_agent_id ON deliveries (destination_agent_id);
CREATE INDEX deliveries_manifest ON deliveries (manifest_statement_id) WHERE manifest_statement_id IS NOT NULL;
CREATE INDEX deliveries_receipt ON deliveries (receipt_statement_id) WHERE receipt_statement_id IS NOT NULL;
CREATE INDEX deliveries_active ON deliveries (status, id)
    WHERE status IN ('pending', 'claimed', 'transferring', 'verifying', 'retry_wait');
CREATE TRIGGER deliveries_updated_at BEFORE UPDATE ON deliveries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Deletable on its own, because a file name can be personal data.
CREATE TABLE delivery_files (
    delivery_id uuid PRIMARY KEY REFERENCES deliveries (id) ON DELETE CASCADE,
    file_name   text NOT NULL CHECK (char_length(file_name) BETWEEN 1 AND 1024)
);
