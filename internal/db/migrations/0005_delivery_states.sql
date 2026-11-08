-- Delivery states and leases, as described in docs/data-model.md and ADR 0026.
-- The database itself rejects a status change that isn't listed, so no code
-- path can skip a state or revive a finished delivery, and it records every
-- change of a delivery's status.

-- The allowed status changes. A later migration adds rows, for example for
-- retries, rather than editing these.
CREATE TABLE delivery_status_transitions (
    from_status text NOT NULL,
    to_status   text NOT NULL,
    PRIMARY KEY (from_status, to_status)
);

INSERT INTO delivery_status_transitions (from_status, to_status) VALUES
    ('pending', 'claimed'),
    ('claimed', 'transferring'),
    ('transferring', 'verifying'),
    ('verifying', 'succeeded'),
    ('pending', 'failed'),
    ('claimed', 'failed'),
    ('transferring', 'failed'),
    ('verifying', 'failed');

CREATE TABLE run_status_transitions (
    from_status text NOT NULL,
    to_status   text NOT NULL,
    PRIMARY KEY (from_status, to_status)
);

INSERT INTO run_status_transitions (from_status, to_status) VALUES
    ('pending', 'running'),
    ('pending', 'failed'),
    ('running', 'succeeded'),
    ('running', 'partial_failure'),
    ('running', 'failed');

-- A failure always says why.
ALTER TABLE deliveries ADD CONSTRAINT deliveries_failed_has_code
    CHECK (status <> 'failed' OR error_code IS NOT NULL);

CREATE FUNCTION check_delivery_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'a delivery must start pending, not %', NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.status IS DISTINCT FROM OLD.status AND NOT EXISTS (
        SELECT 1 FROM delivery_status_transitions
        WHERE from_status = OLD.status AND to_status = NEW.status
    ) THEN
        RAISE EXCEPTION 'a delivery can''t go from % to %', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER deliveries_check_status BEFORE INSERT OR UPDATE OF status ON deliveries
    FOR EACH ROW EXECUTE FUNCTION check_delivery_status();

-- A run starts pending, changes only as listed, and can't end while one of its
-- deliveries is still active.
CREATE FUNCTION check_run_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'a run must start pending, not %', NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM run_status_transitions
        WHERE from_status = OLD.status AND to_status = NEW.status
    ) THEN
        RAISE EXCEPTION 'a run can''t go from % to %', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status NOT IN ('pending', 'running') AND EXISTS (
        SELECT 1 FROM deliveries
        WHERE run_id = NEW.id AND status IN ('pending', 'claimed', 'transferring', 'verifying', 'retry_wait')
    ) THEN
        RAISE EXCEPTION 'a run can''t end while a delivery is active'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER runs_check_status BEFORE INSERT OR UPDATE OF status ON runs
    FOR EACH ROW EXECUTE FUNCTION check_run_status();

-- One row per status change, written by the trigger below, so no change goes
-- unrecorded. Never edited. It holds no file name. Agents' signed audit
-- events (ADR 0014) come on top of this.
CREATE TABLE delivery_events (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    delivery_id uuid NOT NULL REFERENCES deliveries (id),
    from_status text,
    to_status   text NOT NULL,
    error_code  text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX delivery_events_delivery_id ON delivery_events (delivery_id);

CREATE FUNCTION record_delivery_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO delivery_events (delivery_id, to_status) VALUES (NEW.id, NEW.status);
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO delivery_events (delivery_id, from_status, to_status, error_code)
            VALUES (NEW.id, OLD.status, NEW.status, NEW.error_code);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER deliveries_record_event AFTER INSERT OR UPDATE OF status ON deliveries
    FOR EACH ROW EXECUTE FUNCTION record_delivery_event();

CREATE FUNCTION reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER delivery_events_append_only BEFORE UPDATE OR DELETE ON delivery_events
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER delivery_events_no_truncate BEFORE TRUNCATE ON delivery_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_change();

-- One row per offer of one side of a delivery. Its ID is the work ID. The row
-- is granted when the agent claims it, extended by each accepted update, and
-- ended once. A retry gets a new row, so a claim from an earlier attempt can
-- never act. Kept apart from deliveries so that extending a lease doesn't
-- rewrite the delivery row.
CREATE TABLE delivery_leases (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    delivery_id uuid NOT NULL REFERENCES deliveries (id),
    side        text NOT NULL CHECK (side IN ('send', 'receive')),
    agent_id    uuid NOT NULL REFERENCES agents (id),
    offered_at  timestamptz NOT NULL,
    granted_at  timestamptz,
    expires_at  timestamptz,
    ended_at    timestamptz,
    end_reason  text CHECK (end_reason IN ('released', 'expired', 'delivery_ended')),
    CHECK ((granted_at IS NULL) = (expires_at IS NULL)),
    CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
    CHECK (end_reason <> 'expired' OR granted_at IS NOT NULL)
) WITH (fillfactor = 70);

CREATE INDEX delivery_leases_delivery_id ON delivery_leases (delivery_id);
CREATE INDEX delivery_leases_agent_id ON delivery_leases (agent_id);
-- At most one open lease for each side of a delivery.
CREATE UNIQUE INDEX delivery_leases_one_open ON delivery_leases (delivery_id, side) WHERE ended_at IS NULL;
-- The sweep finds expired leases through this.
CREATE INDEX delivery_leases_expiry ON delivery_leases (expires_at)
    WHERE ended_at IS NULL AND granted_at IS NOT NULL;
