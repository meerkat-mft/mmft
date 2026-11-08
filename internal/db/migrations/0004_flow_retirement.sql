-- Flow retirement, as described in docs/data-model.md and ADR 0025. A retired
-- flow keeps its versions, but takes no new drafts or approvals. The
-- retirement is kept as received, and its statement in signed_statements.

ALTER TABLE flows
    ADD COLUMN retirement              bytea,
    ADD COLUMN retirement_statement_id bytea REFERENCES signed_statements (id),
    ADD COLUMN retired_at              timestamptz,
    ADD CONSTRAINT flows_retirement_complete CHECK (
        (retirement IS NULL) = (retirement_statement_id IS NULL) AND (retirement IS NULL) = (retired_at IS NULL)
    );

CREATE INDEX flows_retirement ON flows (retirement_statement_id) WHERE retirement_statement_id IS NOT NULL;
