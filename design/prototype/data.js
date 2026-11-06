// Fake data for the console prototypes. It uses the real statuses, evidence
// levels, and error codes from the data model, and no real company names.
// Every screen lists the API calls it would need, and whether each is built,
// specified in api/openapi.yaml, or missing.
window.MMFT_DATA = {
  workspace: "finance",

  flow: {
    id: "0190f4a2-6c1e-7a3b-9d10-3f2a1c9e7b40",
    name: "invoices-daily",
    version: 4,
    status: "approved",
    approvals: [
      { by: "sam.lee", at: "2026-11-04 16:12" },
      { by: "ana.ruiz", at: "2026-11-04 16:40" },
    ],
    draft: { version: 5, change: "Adds a path for credit notes to the archive agent", waitingFor: 2 },
    tree: {
      trigger: { kind: "Schedule", detail: "Every day at 06:00, Europe/Amsterdam" },
      source: { kind: "Source", agent: "finance-export-01", detail: "/exports/invoices", match: "*.csv, *.pdf" },
      rules: [
        {
          when: 'file.name.endsWith(".pdf")',
          label: "PDF invoices",
          destinations: [{ kind: "Destination", agent: "ledger-in-02", detail: "/inbound/invoices" }],
          outcome: { kind: "Outcome", detail: "Archive the source file" },
        },
        {
          when: 'file.name.endsWith(".csv") && file.size < 50MB',
          label: "CSV batches",
          destinations: [
            { kind: "Destination", agent: "ledger-in-02", detail: "/inbound/batches" },
            { kind: "Destination", agent: "archive-03", detail: "/vault/batches" },
          ],
          failure: { kind: "On failure", detail: "Notify the integrations on-call" },
        },
      ],
      unmatched: "Files matching no rule stay in place and raise an alert",
    },
    api: [
      ["GET /flows/{flow_id}", "specified"],
      ["GET /flows/{flow_id}/versions/{version}", "specified"],
      ["GET /flows/{flow_id}/versions/{version}/approval", "specified"],
      ["GET /agents/{agent_id}", "built"],
    ],
  },

  run: {
    id: "0190f9c3-2b7d-7e01-8c44-91d0a6f2e113",
    flow: "invoices-daily",
    version: 4,
    trigger: "Schedule, 06:00",
    started: "2026-11-06 06:00:02",
    ended: "2026-11-06 06:03:41",
    status: "partial_failure",
    counts: { succeeded: 9, retry_wait: 1, failed: 2 },
    deliveries: [
      { id: "d01", file: "INV-2026-11-0412.pdf", from: "finance-export-01", to: "ledger-in-02", size: "184 KB", status: "succeeded", evidence: "verified" },
      { id: "d02", file: "INV-2026-11-0413.pdf", from: "finance-export-01", to: "ledger-in-02", size: "201 KB", status: "succeeded", evidence: "verified" },
      { id: "d03", file: "batch-0611-a.csv", from: "finance-export-01", to: "ledger-in-02", size: "12.4 MB", status: "succeeded", evidence: "verified" },
      { id: "d04", file: "batch-0611-a.csv", from: "finance-export-01", to: "archive-03", size: "12.4 MB", status: "failed", evidence: "source_only", error: "hash_mismatch" },
      { id: "d05", file: "batch-0611-b.csv", from: "finance-export-01", to: "ledger-in-02", size: "9.8 MB", status: "succeeded", evidence: "verified" },
      { id: "d06", file: "batch-0611-b.csv", from: "finance-export-01", to: "archive-03", size: "9.8 MB", status: "retry_wait", evidence: "source_only", error: "relay_failed", retry: "Next attempt 06:08, 2 of 5" },
      { id: "d07", file: "INV-2026-11-0414.pdf", from: "finance-export-01", to: "ledger-in-02", size: "176 KB", status: "failed", evidence: "none", error: "destination_exists" },
      { id: "d08", file: "INV-2026-11-0415.pdf", from: "finance-export-01", to: "ledger-in-02", size: "190 KB", status: "succeeded", evidence: "verified" },
      { id: "d09", file: null, from: "finance-export-01", to: "ledger-in-02", size: "222 KB", status: "succeeded", evidence: "verified" },
      { id: "d10", file: "INV-2026-11-0417.pdf", from: "finance-export-01", to: "ledger-in-02", size: "168 KB", status: "succeeded", evidence: "verified" },
      { id: "d11", file: "INV-2026-11-0418.pdf", from: "finance-export-01", to: "ledger-in-02", size: "205 KB", status: "succeeded", evidence: "verified" },
      { id: "d12", file: "INV-2026-11-0419.pdf", from: "finance-export-01", to: "ledger-in-02", size: "199 KB", status: "succeeded", evidence: "verified" },
    ],
    api: [
      ["GET /runs/{run_id}", "built"],
      ["GET /runs?workspace=&flow=", "missing"],
      ["GET /runs/{run_id}/deliveries?status=", "missing"],
    ],
  },

  audit: {
    delivery: "0190f9c3-41aa-7c55-b0e2-7d61c0a4f9d8",
    file: "batch-0611-b.csv",
    from: "finance-export-01",
    to: "ledger-in-02",
    sealedSha256: "9f2c4e81b07d3a65c2f1e04b98d7a3c6e15f0b2d4a8c9e7f3b1d6a0c5e2f4b81",
    sealedSize: "9,804,712 bytes",
    status: "succeeded",
    evidence: "verified",
    events: [
      { at: "06:00:02.114", actor: "orchestrator", what: "Run started by the 06:00 schedule", kind: "info" },
      { at: "06:00:02.390", actor: "finance-export-01", what: "Claimed the work, lease 120 s", kind: "info" },
      { at: "06:00:03.902", actor: "finance-export-01", what: "Sealed the file to ledger-in-02's verified key", kind: "info" },
      { at: "06:00:03.918", actor: "finance-export-01", what: "Signed the delivery manifest", kind: "signed", statement: "manifest", id: "4e1a…b7c2" },
      { at: "06:00:04.006", actor: "relay", what: "Paired both sides; forwarding sealed bytes only", kind: "info" },
      { at: "06:00:05.441", actor: "relay", what: "Connection dropped at 6,291,456 bytes", kind: "warn" },
      { at: "06:00:06.517", actor: "ledger-in-02", what: "Resumed from 6,291,456 bytes", kind: "info" },
      { at: "06:00:07.803", actor: "ledger-in-02", what: "Hash matches the signed manifest; decrypted", kind: "info" },
      { at: "06:00:07.811", actor: "ledger-in-02", what: "Placed the file without replacing anything", kind: "info" },
      { at: "06:00:07.826", actor: "ledger-in-02", what: "Signed the delivery receipt", kind: "signed", statement: "receipt", id: "c93d…10fa" },
      { at: "06:00:07.950", actor: "orchestrator", what: "Both statements verified; delivery succeeded", kind: "ok" },
      { at: "06:05:00.000", actor: "orchestrator", what: "Included in audit checkpoint 1,482", kind: "signed", statement: "checkpoint", id: "77b0…e4d1" },
    ],
    api: [
      ["GET /deliveries/{delivery_id}", "missing"],
      ["GET /deliveries/{delivery_id}/events", "missing"],
      ["GET /audit/checkpoints", "specified"],
    ],
  },
};
