# Meerkat MFT

Meerkat MFT orchestrates system-to-system file movement between sources and destinations that the customer owns.

## Language

### Platform parts

**Meerkat stack**:
The complete set of Meerkat services deployed for one organization.
_Avoid_: Platform instance, server

**Orchestrator**:
The service that holds configuration and audit records and decides what moves and when. It never reads file contents.
_Avoid_: Core, server, manager

**Relay**:
The service that forwards encrypted file data between agents that have no direct path to each other.
_Avoid_: Gateway, proxy, worker

**Agent**:
The software installed once on each system to move files on the orchestrator's instructions. Write "transfer agent" where the short form could be unclear.
_Avoid_: Worker, client, node, mover

**Bundled agent**:
An agent shipped inside the Meerkat stack, used to reach systems that have no agent of their own.
_Avoid_: Built-in worker

**Console**:
The web interface administrators use to build flows and monitor the system through the API. It cannot approve flows or receive credentials.
_Avoid_: Admin UI, dashboard, portal

**CLI**:
The signed command-line tool for working with the orchestrator through its API, and the only place to approve flows and enter credentials.

**API**:
The public REST interface that exposes every orchestrator capability to the console, the CLI, and third-party tools.

### Connecting to systems

**Connector**:
The capability that lets an agent read from or write to one kind of system, such as local files, SFTP, or Azure Blob.
_Avoid_: Adapter, plugin, integration

**Local files connector**:
The connector for files on the system where the agent is installed.
_Avoid_: Agent connector

**Endpoint**:
A specific customer-owned location that a connector reaches, such as one SFTP server or one storage container.
_Avoid_: Target, connection

**Credential**:
A secret an agent uses to access an endpoint, managed centrally but readable only by the agents it is sealed to.
_Avoid_: Secret, login

### Defining file movement

**Flow**:
A versioned definition of what happens to files, drawn as a tree of cards.
_Avoid_: Data flow, job, pipeline, workflow

**Flow version**:
One immutable, signed revision of a flow.
_Avoid_: Revision, draft

**Approval**:
An administrator's signature on a flow version, made in the CLI, without which agents will not run it.
_Avoid_: Publish, sign-off

**Card**:
One element on the flow canvas, such as a trigger, source, condition, or destination.
_Avoid_: Node, block, step

**Canvas**:
The visual workspace where a flow's cards are placed and connected.
_Avoid_: Worktable, designer, editor

**Trigger**:
The card that starts a flow: a schedule, a file arrival, or an API call.
_Avoid_: Event

**Source**:
The card naming where a flow picks up files.
_Avoid_: Origin, input

**Selection rule**:
The rule that decides which files at a source a flow picks up.
_Avoid_: Filter, file mask

**Condition**:
A card that sends each file down one branch, based on the file's metadata.
_Avoid_: Filter, route, decision

**Path**:
One route through a flow from its source to a destination, including any failure branch.
_Avoid_: Route, branch line

**Destination**:
The card naming where a flow delivers files.
_Avoid_: Target, sink, output

**Outcome**:
A card that acts after delivery, such as notifying someone or archiving the source file.
_Avoid_: Post-processing, finalizer

### Executing file movement

**Run**:
One execution of a flow version, started by one trigger firing, which may contain many files.
_Avoid_: Job, execution, instance

**Delivery**:
One file going to one destination within a run, with its own retries and result.
_Avoid_: Transfer, transmission

**Signed statement**:
A DSSE envelope holding one signed Meerkat object, such as a flow version or delivery manifest.
_Avoid_: Signed blob, attestation

**Delivery receipt**:
The destination agent's signed statement of what it received and the result.
_Avoid_: Ack, confirmation

**Audit batch**:
An agent's signed statement covering a run of its audit events.
_Avoid_: Log bundle

**Sealed file**:
A file encrypted for one destination agent, used for one delivery.
_Avoid_: Ciphertext file, encrypted blob

**Delivery manifest**:
The source agent's signed statement of what a sealed file is and which delivery it belongs to.
_Avoid_: Envelope, metadata file

**Lease**:
An agent's temporary claim on work, which expires if the agent stops responding.
_Avoid_: Lock, reservation

**Partial failure**:
The result of a run where some deliveries succeeded and others failed.
_Avoid_: Mixed result

### Trust and evidence

**Trust root**:
The offline, customer-held key from which all trust in agents and signatures derives.
_Avoid_: Master key, root secret

**Administrator key**:
A key held in one administrator's CLI, certified by the trust root, that approves flows and signs agent identities and automation keys.
_Avoid_: Signing key, user key

**Automation key**:
A limited key held by a deployment pipeline that signs agent identities in one workspace and cannot approve flows.
_Avoid_: Service key, CI key

**Agent identity**:
The signed record binding an agent to its public keys, which other parties verify back to the trust root.
_Avoid_: Agent certificate, agent ID

**Connection certificate**:
A short-lived certificate that lets a component connect, and proves nothing about end-to-end trust.
_Avoid_: Agent certificate, mTLS key

**Enrollment**:
The process that admits a new agent to the Meerkat stack.
_Avoid_: Registration, onboarding, pairing

**Agent allowlist**:
The locally held list of paths and destinations an agent may use, which the orchestrator cannot change.
_Avoid_: Agent policy, permissions

**Audit event**:
A tamper-evident record of an action on a file or on configuration.
_Avoid_: Log entry, activity

**Audit checkpoint**:
A signed export that proves the audit trail existed unchanged at a point in time.
_Avoid_: Snapshot, backup

### People and organization

**Workspace**:
A grouping of flows and agents, such as a business unit or environment, within one Meerkat stack.
_Avoid_: Tenant, project, organization

**Administrator**:
A person who configures agents, flows, and users.
_Avoid_: Admin user, superuser

**Operator**:
A person who monitors runs and acts on failures.
_Avoid_: Support user

**Auditor**:
A person with read-only access to records and evidence.
_Avoid_: Viewer, reviewer

**Partner**:
An external organization that exchanges files with the customer.
_Avoid_: Client, vendor, third party
