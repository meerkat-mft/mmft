-- Flows and their versions, as described in docs/data-model.md and ADR 0022.
-- A version's payload is kept as exact bytes, because an approval signs exact
-- bytes. Versions are never edited: each saved draft takes the next number.

CREATE TABLE flows (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    name         text NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,128}$'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE flow_versions (
    flow_id               uuid NOT NULL REFERENCES flows (id),
    version               integer NOT NULL CHECK (version >= 1),
    payload               bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_sha256        bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    status                text NOT NULL CHECK (status IN ('draft', 'approved', 'superseded')),
    -- The approval as received: the statement, its signers' certificates, and
    -- the root key that issued them (ADR 0023). The statement is also kept in
    -- signed_statements.
    approval              bytea,
    approval_statement_id bytea REFERENCES signed_statements (id),
    approved_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (flow_id, version),
    CHECK ((approval IS NULL) = (approval_statement_id IS NULL)),
    CHECK ((approval IS NULL) = (approved_at IS NULL)),
    CHECK (status <> 'approved' OR approval IS NOT NULL)
);

-- At most one approved version per flow.
CREATE UNIQUE INDEX flow_versions_one_approved ON flow_versions (flow_id) WHERE status = 'approved';
CREATE INDEX flow_versions_approval ON flow_versions (approval_statement_id)
    WHERE approval_statement_id IS NOT NULL;

-- Manual runs keep both columns empty, and a foreign key with an empty column
-- isn't checked.
ALTER TABLE runs ADD CONSTRAINT runs_flow_version_fkey
    FOREIGN KEY (flow_id, flow_version) REFERENCES flow_versions (flow_id, version);
CREATE INDEX runs_flow ON runs (flow_id, flow_version) WHERE flow_id IS NOT NULL;
