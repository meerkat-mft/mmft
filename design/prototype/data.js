// Fake data for the prototype. It uses the real statuses, evidence levels,
// and error codes from the data model, and no real company names. File names
// and agent names are untrusted text and are only ever rendered as text.
window.MMFT = {
  workspace: "finance",
  workspaces: ["finance", "logistics", "hr-payroll"],
  connections: { orchestrator: "connected", relay: "connected" },
  alerts: 2,

  agents: [
    { id: "a1", name: "finance-export-01", status: "approved", version: "0.4.0", seen: "12 s ago", host: "Linux", expires: "2027-02-04", fingerprint: "7c41e0a9 5b2d18f3 c09e6a71 2f4d8b60" },
    { id: "a2", name: "ledger-in-02", status: "approved", version: "0.4.0", seen: "8 s ago", host: "Linux", expires: "2027-02-04", fingerprint: "1e9b4c27 a8f03d56 7b21c9e4 d06f3a18" },
    { id: "a3", name: "archive-03", status: "approved", version: "0.3.2", seen: "4 min ago", host: "Linux", expires: "2026-12-01", fingerprint: "b3d07a1f 64e2c95b 0a8f71d3 e5c94b26" },
    { id: "a4", name: "payroll-sftp-04", status: "pending", version: "0.4.0", seen: "1 min ago", host: "Linux", expires: null, fingerprint: "58a1f6c0 2d9e47b3 a1c08e5f 7b64d92a" },
  ],

  flows: [
    {
      id: "f1", name: "invoices-daily", version: 4, status: "approved", lastRun: "partial_failure",
      approvals: [{ by: "sam.lee", at: "2026-11-04 16:12" }, { by: "ana.ruiz", at: "2026-11-04 16:40" }],
      draft: { version: 5, change: "Adds a path for credit notes to the archive agent", have: 1, need: 2, approvedBy: ["sam.lee"] },
      tree: {
        trigger: { kind: "Schedule", title: "Every day at 06:00", detail: "Europe/Amsterdam" },
        source: { kind: "Source", title: "finance-export-01", detail: "/exports/invoices", match: "*.csv, *.pdf" },
        paths: [
          {
            label: "PDF invoices", when: 'file.name.endsWith(".pdf")',
            destinations: [{ title: "ledger-in-02", detail: "/inbound/invoices" }],
            outcome: "Archive the source file",
          },
          {
            label: "CSV batches", when: 'file.name.endsWith(".csv") && file.size < 50MB',
            destinations: [{ title: "ledger-in-02", detail: "/inbound/batches" }, { title: "archive-03", detail: "/vault/batches" }],
            failure: "Notify the integrations on-call",
          },
        ],
        unmatched: "Files that match no path stay in place and raise an alert.",
      },
    },
    { id: "f2", name: "payroll-weekly", version: 7, status: "approved", lastRun: "running", approvals: [{ by: "ana.ruiz", at: "2026-10-28 09:02" }, { by: "jo.berg", at: "2026-10-28 09:30" }] },
    { id: "f3", name: "bank-statements", version: 2, status: "approved", lastRun: "failed", approvals: [{ by: "sam.lee", at: "2026-10-12 11:20" }, { by: "jo.berg", at: "2026-10-12 12:05" }] },
    { id: "f4", name: "customs-export", version: 1, status: "draft", lastRun: null, approvals: [], draft: { version: 1, change: "First version", have: 0, need: 2, approvedBy: [] } },
  ],

  runs: [
    {
      id: "0190f9c3-2b7d-7e01", flow: "f1", version: 4, trigger: "Schedule, 06:00", started: "06:00:02", date: "2026-11-07", duration: "3 min 39 s", status: "partial_failure",
      deliveries: [
        { id: "d04", file: "batch-0611-a.csv", from: "finance-export-01", to: "archive-03", size: "12.4 MB", status: "failed", evidence: "source_only", error: "hash_mismatch", next: "The sealed file changed on the way. Run it again." },
        { id: "d06", file: "batch-0611-b.csv", from: "finance-export-01", to: "archive-03", size: "9.8 MB", status: "retry_wait", evidence: "source_only", error: "relay_failed", next: "Next attempt in 4 s, attempt 2 of 5", live: true },
        { id: "d07", file: "INV-2026-11-0414.pdf", from: "finance-export-01", to: "ledger-in-02", size: "176 KB", status: "failed", evidence: "none", error: "destination_exists", next: "A file with this name is already in the inbox." },
        { id: "d01", file: "INV-2026-11-0412.pdf", from: "finance-export-01", to: "ledger-in-02", size: "184 KB", status: "succeeded", evidence: "verified" },
        { id: "d02", file: "INV-2026-11-0413.pdf", from: "finance-export-01", to: "ledger-in-02", size: "201 KB", status: "succeeded", evidence: "verified" },
        { id: "d03", file: "batch-0611-a.csv", from: "finance-export-01", to: "ledger-in-02", size: "12.4 MB", status: "succeeded", evidence: "verified" },
        { id: "d05", file: "batch-0611-b.csv", from: "finance-export-01", to: "ledger-in-02", size: "9.8 MB", status: "succeeded", evidence: "verified" },
        { id: "d08", file: "INV-2026-11-0415.pdf", from: "finance-export-01", to: "ledger-in-02", size: "190 KB", status: "succeeded", evidence: "verified" },
        { id: "d09", file: null, from: "finance-export-01", to: "ledger-in-02", size: "222 KB", status: "succeeded", evidence: "verified" },
        { id: "d10", file: "INV-2026-11-0417.pdf", from: "finance-export-01", to: "ledger-in-02", size: "168 KB", status: "succeeded", evidence: "verified" },
        { id: "d11", file: "INV-2026-11-0418.pdf", from: "finance-export-01", to: "ledger-in-02", size: "205 KB", status: "succeeded", evidence: "verified" },
        { id: "d12", file: "INV-2026-11-0419.pdf", from: "finance-export-01", to: "ledger-in-02", size: "199 KB", status: "succeeded", evidence: "verified" },
      ],
    },
    {
      id: "0190f9b1-77c2-7a10", flow: "f2", version: 7, trigger: "Schedule, Friday 05:30", started: "05:30:00", date: "2026-11-07", duration: "running", status: "running", progress: 0.42,
      deliveries: [
        { id: "p1", file: "payslips-2026-45.zip", from: "hr-export-01", to: "payroll-sftp-04", size: "48.2 MB", status: "transferring", evidence: "source_only", progress: 0.42 },
        { id: "p2", file: "summary-2026-45.pdf", from: "hr-export-01", to: "payroll-sftp-04", size: "1.1 MB", status: "succeeded", evidence: "verified" },
      ],
    },
    {
      id: "0190f6a0-1c3e-7b44", flow: "f3", version: 2, trigger: "Manual, by sam.lee", started: "16:41:13", date: "2026-11-06", duration: "18 s", status: "failed",
      deliveries: [{ id: "b1", file: "statement-2026-11-06.mt940", from: "bank-in-05", to: "ledger-in-02", size: "88 KB", status: "failed", evidence: "none", error: "peer_identity_invalid", next: "The destination's identity didn't verify. Check its approval." }],
    },
    {
      id: "0190f5e2-9a01-7c02", flow: "f1", version: 4, trigger: "Schedule, 06:00", started: "06:00:01", date: "2026-11-06", duration: "2 min 51 s", status: "succeeded",
      deliveries: [{ id: "y1", file: "INV-2026-11-0401.pdf", from: "finance-export-01", to: "ledger-in-02", size: "180 KB", status: "succeeded", evidence: "verified" }],
    },
    {
      id: "0190f4d7-3b88-7d19", flow: "f1", version: 4, trigger: "Schedule, 06:00", started: "06:00:02", date: "2026-11-05", duration: "3 min 02 s", status: "succeeded",
      deliveries: [{ id: "z1", file: "INV-2026-11-0390.pdf", from: "finance-export-01", to: "ledger-in-02", size: "171 KB", status: "succeeded", evidence: "verified" }],
    },
  ],

  // The audit trail of one delivery, used by the delivery panel.
  timeline: [
    { at: "06:00:02.390", actor: "finance-export-01", what: "Claimed the work, lease 120 s" },
    { at: "06:00:03.902", actor: "finance-export-01", what: "Sealed the file to archive-03's verified key" },
    { at: "06:00:03.918", actor: "finance-export-01", what: "Signed the delivery manifest", statement: "4e1a…b7c2" },
    { at: "06:00:04.006", actor: "relay", what: "Paired both sides, forwarding sealed bytes only" },
    { at: "06:00:05.441", actor: "relay", what: "Connection dropped at 6,291,456 bytes", warn: true },
  ],
};
