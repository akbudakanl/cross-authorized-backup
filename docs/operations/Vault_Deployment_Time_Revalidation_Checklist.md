# VAULT — DEPLOYMENT-TIME REVALIDATION CHECKLIST

**Document type:** pre-deployment revalidation gate  
**Architecture freeze reference date:** 2026-07-15  
**Applies to:** the authoritative Vault core guide and its optional extensions  
**Purpose:** verify external product/platform assumptions after the project has been shelved for weeks or months

---

## 0. Why this file exists

The Vault architecture can remain logically valid while Tailscale, Headscale, AWS,
restic, RHEL, OCI, Podman, Caddy, or their APIs change.

Treat the core guide as an **architecture freeze, not a version freeze**.

Before deploying after a long shelving period:

1. Revalidate every item in this document against current **official primary sources**.
2. Run the specified local and real-network tests.
3. Classify every finding as:

```text
NO CHANGE
LOCAL PATCH
SECURITY REVIEW REQUIRED
ARCHITECTURE REDESIGN REQUIRED
```

Do not redesign the system merely because a new version exists.

Do not silently substitute a new product feature because it appears newer or faster.

A change is justified only when:

```text
a documented assumption is no longer true
OR
a security boundary can be made materially narrower without losing required behavior
OR
the real deployment environment invalidates a transport/capacity/session assumption
```

---

# 1. Core Transport Principle: No Operator-Managed Public Relay Listener

The operator's explicit transport preference is:

> Do not intentionally expose a Vault application, backup, DERP, STUN, or Peer Relay
> listener to the campus/local network or the public Internet merely to improve transfer
> performance.

The core baseline therefore does **not** enable:

```text
UDP/40000 Peer Relay listener
TCP/443 self-hosted DERP listener
UDP/3478 self-hosted DERP/STUN listener
rest-server on a primary device
Caddy backup listener on a primary device
Vault SSH listener on a primary device
```

Primary devices remain source-only.

The existing local inbound controls remain core:

```text
Fedora:
  tailscale set --shields-up=true
  tailscale set --ssh=false

Android:
  Allow incoming connections = OFF
```

Tailnet grants must also contain no PC↔Phone Vault data-plane receiver path.

---

## 1.1 Direct, Peer Relay, and DERP are three different transport types

Do not use the word "relay" generically when reviewing this architecture.

### Direct

```text
primary device
    ↕ encrypted WireGuard/Tailscale traffic
target peer
```

Tailscale attempts NAT traversal automatically.

A permanent router port-forward is **not a universal prerequisite** for Tailscale direct
connectivity.

CGNAT, hard NAT, symmetric/unpredictable NAT behavior, restrictive Wi-Fi, or UDP policy
can still prevent direct connectivity.

Therefore:

```text
"port forwarding is impossible"
```

does not by itself prove:

```text
"Tailscale direct connectivity is mathematically impossible"
```

For this project, however, the real networks are expected to be hostile to direct
connectivity:

```text
campus Wi-Fi
mobile data
RHEL home network
strict CGNAT observations
no usable IPv6
previous WireGuard/direct-path failure observations
```

The deployment-time source of truth is still an empirical connection-path test.

### Peer Relay

A Peer Relay is a **tailnet device explicitly configured to act as a relay**.

It is not created automatically by Tailscale-hosted infrastructure.

A Peer Relay requires, at minimum:

```text
a supported Tailscale device
explicit relay configuration
a selected UDP relay port
a grant permitting relay use
the UDP relay port to be accessible to participating devices
```

The Vault Peer Relay extension currently uses:

```text
UDP/40000
```

That port number is an extension choice/example. It is **not** the normal direct
Tailscale port and is **not** required for Tailscale-hosted DERP.

### Tailscale-hosted DERP

If a direct connection cannot be established and no usable Peer Relay is configured,
Tailscale falls back to a DERP relay.

In the core Vault baseline:

```text
direct, if NAT traversal actually succeeds
        ↓
Tailscale-hosted DERP
```

There is no intermediate Peer Relay because the core deployment does not configure
one.

**Important wording:**

```text
Tailscale-hosted servers do not "become our Peer Relay".
They provide DERP relay infrastructure.
Peer Relay is a separately configured tailnet-device capability.
```

---

## 1.2 Current Peer Relay policy

Current operator decision:

```text
public UDP/40000 relay listener is not acceptable
```

Therefore:

```text
Vault_Extension_Peer_Relay_Performance...
    = DISABLED BY POLICY
```

Keep the extension as a future trade-off document only.

Do not apply it automatically because DERP is slower.

If DERP performance is insufficient:

```text
1. measure the real bottleneck
2. validate the signed one-hour session assumption
3. distinguish daily delta from first-seed transfer
4. reassess transport/session architecture
5. enable Peer Relay only after an explicit policy reversal accepting the UDP listener
```

A performance problem is not permission to silently open UDP/40000.

---

## 1.3 Deployment-time transport test

Run from the real campus network and, where relevant, mobile data.

```bash
tailscale status
tailscale ping <expected-vault-peer>
tailscale netcheck
```

Record:

```text
date/time
device
physical network
Tailscale client version
target peer
connection type shown by tailscale status/ping
DERP region, if relayed
median transfer throughput
slow representative throughput
reconnects/path changes
```

Expected core result:

```text
Peer Relay is not configured.
```

If path output shows:

```text
peer-relay(...)
```

stop and investigate.

That result means the deployed tailnet has relay configuration/capability that is not
part of the core baseline.

If the real path is consistently:

```text
DERP
```

record DERP as the observed deployment transport.

Do not modify the guide to claim "forced DERP-only" unless Tailscale officially
documents a supported production mechanism that enforces that behavior on every required
client platform.

The core project may **expect** DERP because of real network behavior without
claiming that the Tailscale client was configured into a vendor-supported DERP-only
mode.

---

## 1.4 What "no open port" means in this project

Use precise wording.

The core security objective is:

```text
no operator-managed public Vault application/backup/relay service on the primary devices
no Peer Relay UDP/40000 listener
no self-hosted DERP/STUN listener
primary Tailnet inbound disabled
no unauthenticated Vault service exposed to campus peers
```

Do not make the stronger technical claim:

```text
the operating system has literally no UDP socket bound anywhere
```

unless that has been separately verified and is a deliberate requirement.

Tailscale can use UDP sockets for encrypted direct-connectivity attempts and NAT
traversal.

If the operator later requires literal zero Tailscale UDP listeners/bindings on the
physical interface, classify the change as:

```text
ARCHITECTURE REDESIGN REQUIRED
```

Do not invent an Android firewall workaround and describe it as a supported Tailscale
security mode.

---

# 2. Critical Assumption: The Vault Session Ceiling Is One Hour

## 2.1 Baseline assumption

The core architecture assumes one signed global Vault session ceiling:

```text
60 minutes
```

This is not a convenience timeout.

It is a shared security parameter enforced by several independent components.

The baseline threat model accepts the following residual risk:

> Malware already participating in a legitimately authorized session can try to use the
> currently authorized **incomplete-backup** window until successful-completion
> containment or the signed hard deadline.

For S3, the one-hour ceiling is the final fallback rather than the intended normal
post-success lifetime: snapshot creation plus later repository-lock removal should cause
exact-role session revocation and a clean-opposite signed peer close. The one-hour ceiling
still bounds incomplete/no-snapshot sessions and containment-path failure.

A longer session therefore increases residual exposure.

---

## 2.2 First-seed transfer and daily-delta transfer must be measured separately

Do not use a first 40 GB seed as the only benchmark for the normal daily workflow.

Record two workload classes:

```text
A. INITIAL SEED / LARGE RECOVERY-SCALE TRANSFER
B. REPRESENTATIVE DAILY DELTA
```

The production one-hour security window is primarily justified by the routine daily
ceremony.

Decision:

```text
daily delta comfortably finishes inside one hour
but initial seed exceeds one hour
    → do not automatically lengthen every production session
    → review a separately bounded bootstrap/seed procedure

daily delta itself approaches or exceeds one hour
    → perform full session-duration architecture review
```

A separate bootstrap procedure would be a new security path and therefore requires:

```text
SECURITY REVIEW REQUIRED
```

Do not create a hidden "temporary 4-hour mode" in a shell script.

---

## 2.3 Deployment-time one-hour performance gate

For both PC and Phone, run representative daily-delta tests on the real restrictive
network.

Record:

```text
device
network
connection type: direct / DERP
representative unique data added
restic total elapsed time
S3 elapsed time
RHEL elapsed time
retries/reconnects
DONE success/failure
session_expires_at
remaining safety margin
```

Decision:

```text
Representative daily deltas finish comfortably inside 60 minutes
    → KEEP ONE HOUR

Representative daily deltas approach or exceed 60 minutes
    → STOP
    → perform Sections 2.4 through 2.8
```

"Comfortably" must include an operator-selected margin for normal throughput variance and
restic retries.

Do not treat a 59-minute successful run as proof that a 60-minute hard ceiling is
operationally safe.

---

## 2.4 Do not change one `3600`

The one-hour limit is embedded in multiple independent enforcement points.

Search the authoritative core guide/source tree for:

```bash
grep -RInE \
  'time\.Hour|3600|3_600_000|59min50s|one-hour|one hour|one-hour session|sessionLifetime|session_expires_at|RuntimeMaxSec' \
  .
```

At minimum, review the following.

### A. VPS coordinator lifetime

Core Go coordinator:

```go
sessionLifetime = time.Hour
```

Review all code paths involving:

```text
proposedDeadline(...)
sessionDeadline
sessionExpiresAt
persisted session state
restoreSessionState(...)
sessionOpenLocked(...)
EXPIRED state
expiryPending
cross-VPS payload validation
proxy authorization
```

A VPS restart must not extend an existing persisted deadline.

### B. AWS Lambda signed-deadline validation

The core S3 gate validates that:

```text
session_expires_at - issued_at <= 3_600_000 milliseconds
```

Update consistently if the Vault session ceiling changes.

Do **not** automatically enlarge:

```text
proofLifetime
90-second downstream proof lifetime ceiling
clock-skew allowance
```

Those are separate freshness/anti-replay controls.

### C. AWS backup-role maximum session duration

Core roles use:

```bash
--max-session-duration 3600
```

Review both:

```text
Vault-PC-S3-BackupRole
Vault-Phone-S3-BackupRole
```

### D. AWS Lambda STS request duration

Core S3 gate requests:

```javascript
DurationSeconds: 3600
```

Preserve:

```text
daily slot consume
        ↓
exactly one AssumeRole SDK attempt
        ↓
clear success or fail closed
```

Do not add an STS refresh loop.

Do not allow the client to call Lambda again because the first credential expired.

Do not delete the daily slot to "fix" a long transfer.

### E. RHEL gate maximum signed session validation

The local RHEL gate currently rejects a signed session deadline that exceeds the
one-hour model.

Preserve:

```text
both Ed25519 signatures
exact target
proof freshness
Europe/Istanbul calendar date
daily local slot
slot consumed before timer/backend start
same-ceremony idempotency only while backend is active
```

### F. RHEL transient hard-stop timer

The gate schedules a systemd stop relative to signed `session_expires_at`.

Preserve:

```text
hard stop begins before signed deadline
TimeoutStopSec remains bounded
KillMode=control-group
SendSIGKILL=yes
backend process group is dead by the signed ceiling
```

The current ten-second pre-deadline stop offset is coupled to the bounded stop timing.

If teardown timing changes, review the offset explicitly.

### G. RHEL service fallback RuntimeMaxSec

Both append-only backend services currently use:

```ini
RuntimeMaxSec=59min50s
```

Review both:

```text
vault-rhel-pc-rest-server.service
vault-rhel-phone-rest-server.service
```

The fallback must not extend past the intended signed session ceiling after accounting
for bounded teardown.

### H. S3 proxy/admission expiry behavior

Search and review:

```text
sessionExpiresAt
sessionDeadline
sessionLifetime
EXPIRED
expiryPending
drain
s3FinalDrain
```

Verify:

```text
new work is denied after the signed deadline
an existing TCP connection does not renew the Vault session
connection activity does not slide/extend session_expires_at
local S3 DONE is only cooperative cleanup; successful S3 completion is contained by
  AWS-side completion revocation plus exact-session signed peer close
RHEL DONE remains only an authenticated early-close signal; the RHEL hard-stop timer is
  the RHEL security boundary
```

### I. Documentation and threat model

Update every claim containing:

```text
one-hour STS
signed one-hour Vault session deadline
one-hour bounded window
one-hour session ceiling
60-minute window
```

Do not leave the threat model claiming a one-hour residual window when code permits a
longer one.

### J. Peer Relay extension threshold

The Peer Relay performance extension currently asks whether DERP can complete a
representative transfer inside the signed one-hour ceiling.

If the signed ceiling changes, update that decision threshold.

---

## 2.5 CRITICAL AWS constraint: current S3 credential path is capped by role chaining

The core AWS path is conceptually:

```text
AWS Lambda service
    ↓ provides temporary credentials for Lambda execution role
Lambda execution role credentials
    ↓ sts:AssumeRole
device-specific S3 backup role
    ↓
returned STS credentials to the device workflow
```

AWS defines using credentials from one role to assume another role as **role chaining**.

AWS currently limits a role-chained AWS CLI/API role session to:

```text
maximum 1 hour
```

A `DurationSeconds` value greater than one hour fails for a chained `AssumeRole`
operation, regardless of a larger maximum session duration configured on the target role.

Therefore:

> Under the current core Lambda-execution-role → backup-role `AssumeRole` design,
> increasing `3600` to `7200` is not a valid two-hour S3 migration.

Treat any required S3 session longer than one hour as:

```text
ARCHITECTURE REDESIGN REQUIRED
```

unless AWS changes the relevant role-chaining rule before deployment.

Revalidate the current AWS STS and IAM documentation at deployment time.

### Required >1-hour design review questions

If routine daily S3 transfers need more than one hour:

```text
[ ] Is the one-hour bottleneck specifically S3, RHEL, or total sequential workflow time?
[ ] Can transfer ordering/concurrency be changed without weakening dual-device authorization?
[ ] Can the daily delta be reduced by changing backup scheduling rather than session duration?
[ ] Is the problem only the initial seed?
[ ] Can the initial seed use a separately reviewed bootstrap ceremony?
[ ] Has AWS changed the role-chaining one-hour rule?
[ ] Is there a non-chained federation mechanism that preserves the dual-VPS proof gate?
[ ] Can a different AWS-side broker issue a longer session without creating a renewable malware credential path?
[ ] Would decoupling S3 and RHEL signed deadlines preserve the intended threat model?
```

Do not implement credential refresh until the following question has a written answer:

> What independently prevents malware on one already-authorized endpoint from refreshing
> credentials repeatedly and converting a bounded session into an effectively renewable
> session?

---

## 2.6 Session-duration migration acceptance tests

For any session-ceiling change, repeat at least:

```text
signed deadline over configured maximum → rejected
expired session proof → rejected
proof freshness remains short
backend hard-stops by signed ceiling
RuntimeMaxSec fallback closes backend
proxy rejects post-deadline admission
daily slot does not permit a second STS mint
replayed old proof cannot open a new session
VPS restart does not extend persisted deadline
RHEL gate restart does not cancel an already-scheduled systemd hard stop
suppressed local S3 DONE cannot veto close after successful completion evidence
suppressed RHEL DONE cannot extend the signed RHEL deadline
long-lived TCP activity cannot slide the deadline
```

For S3 specifically:

```text
STS credential Expiration is recorded
own MFA without opposite live s3 phase cannot create a fresh dual-signed issuance proof
new S3 requests fail after credential expiry
no application code automatically obtains a second credential
ambiguous AssumeRole result does not trigger a second AssumeRole attempt
snapshot creation alone does not revoke the session
snapshot creation followed by a later matching lock removal drives OPEN -> REVOKING -> REVOKED
old-session S3 requests fail after AWS completion revocation propagates, before original
  credential Expiration in the normal successful-completion path
exact-session REVOKED status authorizes only signed close-only peer admission shutdown
```

---

## 2.7 Session-duration classification

A coordinated RHEL/Vault ceiling increase that preserves one fixed, non-renewable,
signed deadline is:

```text
SECURITY REVIEW REQUIRED
```

A design that refreshes STS credentials, extends `session_expires_at` while active, or
permits repeated AWS issuance in the same day is:

```text
ARCHITECTURE REDESIGN REQUIRED
```

---

# 3. Headscale Tailnet Lock Revalidation

Question:

> Has Headscale added real Tailnet Lock support or an equivalent cryptographic
> control-plane membership-integrity mechanism?

Revalidate against:

```text
Headscale latest stable release page
Headscale stable changelog/release notes
Headscale official documentation
Headscale Tailnet Lock feature-tracking issue
minimum supported Tailscale client version
Headscale/Tailscale client compatibility notes
```

Do not treat the following as equivalent to Tailnet Lock:

```text
device approval
pre-auth key expiry
manual node registration
ACLs
grants
Headscale host hardening
two Headscale instances
database backups
admin API restrictions
policy tests
```

These may reduce other risks.

They do not by themselves prove that a compromised coordination plane cannot distribute
an unsigned rogue node that locked peers accept.

## 3.1 Pass criteria for reconsidering Headscale

```text
[ ] official Headscale stable release documents the feature
[ ] cryptographic node-signature/membership semantics are documented
[ ] required Tailscale clients interoperate with it
[ ] signer initialization is understood
[ ] signing-key compromise/revocation is understood
[ ] disaster recovery is documented
[ ] rogue control-plane node-insertion negative test is defined
[ ] two-compartment threat-model delta is written
```

Only then reassess:

```text
Tailscale + Tailnet Lock
vs.
two independent Headscale control planes
```

### Evidence snapshot — 2026-07-15

Observed from the Headscale upstream project at the architecture freeze date:

```text
latest stable release: v0.29.2
v0.29.2 release date observed: 2026-07-01
Tailnet Lock feature request: issue #1307
issue #1307 status: OPEN
issue label: tailscale-feature-gap
v0.29.2 release notes reviewed: no Tailnet Lock implementation identified
```

Current result:

```text
NO CHANGE
Keep Tailscale + Tailnet Lock as core.
```

Recheck at deployment time.

---

# 4. Tailscale Exact-Device Expiry Scope Revalidation

Question:

> Can the exact device-expiry operation now be authorized without broad
> `devices:core` write scope?

The core expiry helper uses the Tailscale API operation:

```text
POST /api/v2/device/:deviceID/expire
```

At deployment time, open the current official Tailscale Trust Credentials scope table
and locate the exact endpoint.

## 4.1 Desired improvement

If Tailscale introduces an expiry-only or otherwise materially narrower scope:

```text
[ ] create a new per-tailnet WIF trust credential
[ ] grant only the narrow scope
[ ] preserve exact OIDC issuer
[ ] preserve exact workload subject
[ ] preserve exact custom-claim constraints
[ ] preserve exact Tailnet ID
[ ] preserve exact expected NodeID in the root helper
[ ] positive-test expiry of the intended primary
[ ] negative-test expiry of the opposite/other device
[ ] verify configuration-audit actor attribution
[ ] revoke the old devices:core credential
[ ] update VaultAuditWatch allowlists
[ ] update the threat model
```

After successful migration, do not retain `devices:core` "for rollback convenience"
without a documented break-glass reason.

### Evidence snapshot — 2026-07-15

The official Tailscale Trust Credentials scope table currently places:

```text
POST /api/v2/device/:deviceID/expire
```

under:

```text
devices:core
```

The same write scope also includes device lifecycle/property operations such as:

```text
DELETE device
authorize device
change device IP
change name
change key
change tags
```

Current result:

```text
NO CHANGE
The core devices:core residual-risk statement remains valid.
```

Recheck at deployment time.

---

# 5. Tailscale Workload Identity Federation Revalidation

Revalidate that Tailscale Workload Identity Federation still provides:

```text
OIDC token exchange
short-lived Tailscale API tokens
issuer validation
audience validation
subject matching
optional custom-claim matching
configured API scopes
federated credential revocation
```

For each Vault tailnet, verify the expiry workload cannot authenticate as the opposite
compartment.

Negative tests:

```text
vault-pc workload token → PC tailnet expiry credential: PASS
vault-pc workload token → Phone tailnet expiry credential: DENY

vault-phone workload token → Phone tailnet expiry credential: PASS
vault-phone workload token → PC tailnet expiry credential: DENY

wrong subject → DENY
wrong audience → DENY
expired OIDC token → DENY
wrong custom claim → DENY, where custom claims are configured
```

Any newly available narrowing mechanism can be considered a:

```text
LOCAL PATCH
```

only after the cross-compartment negative tests pass.

A feature that changes Tailnet Lock signing or membership semantics is:

```text
SECURITY REVIEW REQUIRED
```

---

# 6. Tailscale Configuration Audit Revalidation

Revalidate:

```text
configuration audit-log API endpoint
logs:configuration:read scope
event naming for node creation
node login/re-authentication
node expiry
node deletion
Tailnet Lock changes
trust credential changes
API-token/federated-token events
documented log availability/retention behavior
```

Update `VaultAuditWatch` only after capturing fresh sample events from both tailnets.

Preserve:

```text
five-minute overlapping polls
independent PC and Phone health state
default-deny mutation classifier
exact expected expiry actor
exact expected NodeID
DETECTION BLIND after repeated polling failure
recovery INFO event
```

If Tailscale adds an official push/stream mechanism that materially reduces detection
latency:

```text
SECURITY REVIEW REQUIRED
```

Do not replace the polling detector until:

```text
delivery failure is observable
reconnect/cursor semantics are understood
duplicate event handling is safe
event loss is testable
the detector-blind alarm remains meaningful
```

---

# 7. Tailscale Client and Headscale Compatibility Revalidation

Before installation, record:

```text
Fedora Tailscale version
Android Tailscale version
vault-pc Tailscale version
vault-phone Tailscale version
RHEL-PC namespace Tailscale version
RHEL-Phone namespace Tailscale version
Headscale version, only if the extension is selected
```

For the core Tailscale deployment:

```text
[ ] Tailnet Lock supported by every required client
[ ] tailscale lock status works on Linux infrastructure signers
[ ] Android remains a locked peer, not a required signing node
[ ] Shields Up behavior is unchanged
[ ] Android Allow incoming connections behavior is unchanged
[ ] exact-device expiry API behavior is unchanged
[ ] connection-path output still distinguishes direct / peer-relay / DERP
```

For the Headscale extension:

```text
[ ] current Headscale release minimum Tailscale client version is recorded
[ ] every deployed client meets it
[ ] grants/ACL syntax is validated against that exact Headscale release
[ ] public DERP map configuration remains supported
[ ] exact local node-expiry command syntax is revalidated
```

Do not use config examples from Headscale `main` while installing an older stable release.

### Evidence snapshot — 2026-07-15

Headscale v0.29.x release notes observed:

```text
minimum supported Tailscale client version: v1.80.0
v0.29.0 added grants support including application capabilities such as peer relay
```

This does not add Tailnet Lock.

---

# 8. restic Cold Storage / S3 Glacier Deep Archive Revalidation

Question:

> Has restic's Glacier / Glacier Deep Archive support matured enough to change the
> Vault cold-restore design?

Revalidate the current stable restic documentation and stable release notes.

Check:

```text
latest stable restic version
cold-storage maturity label
whether RESTIC_FEATURES=s3-restore is still required
whether s3.enable-restore is still required
s3.restore-days behavior
s3.restore-timeout behavior/default
supported S3 storage classes
metadata storage-class behavior
known-working restic commands
breaking-change warnings
Deep Archive restore caveats
```

## 8.1 Core rule

Do not treat successful cold upload/copy as proof of restore capability.

Before relying on real Deep Archive recovery:

```text
[ ] select a disposable representative encrypted subset
[ ] record restic version
[ ] record AWS storage class
[ ] record feature flags
[ ] record S3 backend options
[ ] perform the documented restore path
[ ] record archive retrieval delay
[ ] record restic elapsed time
[ ] record restore tier
[ ] record AWS cost
[ ] verify restored plaintext against expected source/hash
```

## 8.2 Maturity decision

If official stable restic documentation still calls the feature experimental or early
alpha:

```text
NO CHANGE
KEEP SEPARATE COLD-RESTORE DRILL
```

If official stable documentation promotes it to stable:

```text
SECURITY REVIEW REQUIRED
```

Review whether the dedicated MFA-protected restore permission path and canary drill
should change.

Feature maturity alone is not a reason to remove recovery testing.

### Evidence snapshot — 2026-07-15

Observed stable restic state:

```text
latest stable release: 0.19.1
0.19.1 release date: 2026-07-05
cold-storage support: experimental
maturity wording: early alpha
feature flag: RESTIC_FEATURES=s3-restore
restore option: s3.enable-restore=1
example restore-days: 7
example restore-timeout: 24h
known-working commands listed: backup, copy, prune, restore
Glacier/Deep Archive metadata is kept in Standard class
documented restore wait can be very long
```

Current result:

```text
NO CHANGE
Keep S3 cold restore as a separate tested recovery procedure.
```

---

# 9. AWS Lambda Runtime Revalidation

The core guide currently creates the two S3 gates with:

```text
nodejs22.x
```

Before deployment:

```text
[ ] confirm nodejs22.x is still supported in the selected AWS region
[ ] record AWS deprecation date
[ ] check whether a newer supported Node.js runtime is now preferable
[ ] rebuild the ZIP from the core source
[ ] reinstall exact dependencies from package-lock.json
[ ] run node --check index.mjs
[ ] record package-lock.json SHA-256
[ ] record deployment ZIP SHA-256
[ ] deploy/test gate semantics
```

Record exact versions:

```text
Node.js Lambda runtime
@aws-sdk/client-dynamodb
@aws-sdk/client-sts
npm
package-lock.json hash
deployment ZIP hash
```

Preserve:

```text
crypto.verify Ed25519 semantics
timestamp validation
Europe/Istanbul date behavior
conditional DynamoDB PutItem
one total STS SDK attempt
error classification
credential field validation
```

Runtime migration classification:

```text
supported runtime replacement; no security-semantic change
    → LOCAL PATCH

SDK/runtime changes retry, crypto, timestamp, credentials, or error semantics
    → SECURITY REVIEW REQUIRED
```

### Evidence snapshot — 2026-07-15

AWS official Lambda runtime documentation currently lists:

```text
nodejs22.x
OS: Amazon Linux 2023
deprecation date: 2027-04-30
block new function creation: 2027-06-01
block function update: 2027-07-01
```

AWS also documents:

```text
nodejs24.x
```

as a supported runtime.

Current result:

```text
NO IMMEDIATE BLOCKER
nodejs22.x remains supported at the freeze date.
```

Do not migrate to Node.js 24 solely because it exists.

Test first.

AWS currently recommends packaging the SDK clients used by the function rather than
depending only on the runtime-included SDK.

The core ZIP already follows that direction.

---

# 10. AWS STS / IAM Revalidation

Revalidate current official documentation for:

```text
AssumeRole DurationSeconds
role maximum session duration
role-chaining maximum
session policy behavior
SourceIp condition semantics
temporary credential expiration
AWS SDK retry configuration
IAM Identity Center session behavior
```

## 10.1 Mandatory role-chaining check

Before considering any session over one hour, answer:

```text
Does AWS still cap chained AssumeRole sessions at one hour?
```

At the 2026-07-15 freeze date:

```text
YES
```

This is a blocking architectural constraint for the current Lambda-role → backup-role
issuance path.

## 10.2 STS retry invariant

Revalidate the selected AWS SDK version's retry configuration.

The gate must still make:

```text
one total AssumeRole attempt
```

Do not confuse this with data-plane retries.

Allowed:

```text
restic/S3 retries using the same successfully issued STS credential
```

Forbidden:

```text
second AssumeRole because result was ambiguous
credential refresh loop
second Lambda issuance after credential expiry
deleting today's daily slot
```

Add an automated test that records the number of STS `AssumeRole` calls for an injected
ambiguous/failing case.

Expected:

```text
1
```

---

## 10.3 Successful-completion revocation and peer-close revalidation

The core 2026-07-16 S3 close path depends on several external/lifecycle assumptions
that must be revalidated together. Check current official AWS documentation and the
reviewed restic source for the deployed version.

AWS assumptions to revalidate:

```text
IAM still supports revoking older role sessions with an inline deny conditioned on
  aws:TokenIssueTime
policy changes can affect active temporary role credentials after propagation
S3 notification filters still support snapshots/ ObjectCreated and locks/ ObjectRemoved
S3 notification delivery remains at-least-once and may be duplicate/out-of-order
S3 LIST/GET namespace visibility used by reconciliation remains strongly consistent
Lambda/EventBridge can still invoke the two device-specific revokers as configured
put-bucket-notification-configuration replacement semantics are understood
Node.js runtime selected by the guide is still supported
```

Restic lifecycle assumption to revalidate against the **exact deployed restic source**:

```text
backup still holds the append lock through the backup command lifecycle
snapshot repository save still occurs after tree/blob backup work
normal command unwind releases/removes the repository lock after snapshot save
```

Do not infer this ordering from a filename convention alone. If a future restic version
changes the lock/snapshot lifecycle so that `snapshots/` creation followed by later
`locks/` removal no longer represents successful command completion, classify:

```text
SECURITY REVIEW REQUIRED
```

and redesign the completion signal before upgrading production.

Re-run these tests with synthetic data:

```text
own SSO/MFA + opposite primary absent -> no dual proof, no STS issuance
snapshot-created event alone -> state remains OPEN
lock-removal event before snapshot -> no premature revoke
snapshot + later lock removal -> OPEN -> REVOKING -> REVOKED
first completion_revoke_cutoff remains immutable under duplicate/out-of-order replay
old STS through approved VPS -> AccessDenied after IAM propagation before original Expiration
status query wrong session_expires_at -> ABSENT_OR_SESSION_MISMATCH
exact opposite REVOKED -> clean primary can request signed CLOSE_PEER
wrong-deadline/expired CLOSE -> rejected
valid repeated CLOSE -> idempotent; never reopens admission
completion revoker cannot mutate opposite backup role or list opposite bucket
backup-role permissions boundary remains attached and caps broad inline Allow tests
five-minute reconciliation cannot revoke an older slot after a newer same-device issuance
```

Also record observed latency separately for:

```text
snapshot/lock S3 event delivery
completion Lambda execution
status poll observation
CLOSE_PEER acknowledgement / proxy admission close
IAM revocation-policy propagation
```

Do not promise zero-millisecond revocation. The architectural claim is that a compromised
target endpoint cannot **veto** containment after independently observed successful S3
completion, while the signed one-hour deadline remains the final ceiling if completion
never occurs or the containment path fails.


# 11. S3 Glacier Deep Archive / Lifecycle Revalidation

Revalidate current AWS documentation for:

```text
Glacier Deep Archive minimum storage duration
retrieval tiers
restore request duration semantics
temporary restored-copy availability
lifecycle transition constraints
versioning behavior
Object Lock, if ever proposed
multipart upload behavior
pricing in the selected region
```

Do not hard-code cost assumptions from the architecture-freeze date.

The core security model must still distinguish:

```text
backup authorization
cold-storage lifecycle
restore authorization
restore cost
restore delay
```

If AWS changes Deep Archive restore semantics, update:

```text
recovery drill
cost worksheet
expected restore delay
MFA restore procedure
restic restore-timeout guidance
```

Do not grant the routine backup role broad restore or destructive lifecycle permissions
merely because the cold-storage workflow becomes easier.

---

# 12. RHEL 9 Revalidation

The core guide is a RHEL 9 guide.

Before deployment, check:

```text
current active RHEL 9 minor
RHEL 9 lifecycle/support status
security errata
current Podman/container-tools stream
current Go toolchain provided/selected
OpenSSH behavior relevant to FIDO-backed SSH
firewalld behavior
SELinux Enforcing state
systemd version
```

Do not automatically migrate to RHEL 10 merely because RHEL 10 exists.

RHEL 10 migration is:

```text
SECURITY REVIEW REQUIRED
```

because the core guide was reviewed against RHEL 9 service, package, and platform
assumptions.

### Evidence snapshot — 2026-07-15

Red Hat official release-date documentation currently lists:

```text
RHEL 9.8 GA: 2026-05-19
```

The core guide's "current active RHEL 9 minor = 9.8" wording remains correct at the
freeze date.

RHEL 9.8 is also listed as an eligible even-numbered minor in Red Hat's current extended
life-cycle model.

Current result:

```text
NO CHANGE
Use the current active RHEL 9 minor when deploying.
```

Do not permanently pin 9.8 merely because this checklist mentions it.

---

# 13. OCI Free Tier / RHEL BYOI-BYOI Revalidation

Before importing the RHEL image:

```text
[ ] identify exact OCI shape
[ ] identify exact CPU architecture
[ ] download matching RHEL 9 KVM guest image
[ ] verify image filename/hash
[ ] check Red Hat Ecosystem Catalog for current OCI certification/support
[ ] check Oracle's current RHEL custom-image instructions
[ ] check current OCI custom-image requirements
[ ] check current shape compatibility
[ ] check current networking launch-mode warnings
```

Architecture mapping to revalidate:

```text
VM.Standard.E2.1.Micro → x86_64
VM.Standard.A1.Flex    → aarch64
```

Do not infer Red Hat vendor support merely from:

```text
the image boots
+
the architecture matches
```

Oracle's current custom Linux image documentation explicitly directs RHEL users to
review the Red Hat Ecosystem Catalog for supported RHEL versions and Compute shapes.

At deployment, record:

```text
OCI shape
architecture
RHEL image filename
RHEL image SHA-256
RHEL release
Red Hat catalog support/certification result
Oracle custom-image documentation revision date
launch mode
networking mode
```

### Evidence snapshot — 2026-07-15

Oracle's current RHEL custom-image procedure documents:

```text
RHEL KVM guest image
QCOW2
Paravirtualized launch mode
supported image/shape compatibility review
default RHEL custom-image user: cloud-user
```

OCI also currently warns against hardware-assisted SR-IOV networking for custom images
on VM.Standard.A1.Flex because of possible performance problems and rare data corruption.

Recheck this warning immediately before an A1 deployment.

---

# 14. Tailscale Package and Repository Revalidation on RHEL

Before using the core install commands:

```text
[ ] open current official Tailscale Linux/RHEL installation documentation
[ ] confirm supported RHEL major version
[ ] confirm repository URL/installation method
[ ] verify package signature/repository configuration
[ ] record installed Tailscale version
[ ] check Tailscale changelog for Tailnet Lock, Peer Relay, Shields Up, node-expiry, and systemd changes
```

After installation:

```bash
tailscale version
systemctl cat tailscaled
systemctl status tailscaled
tailscale netcheck
```

On RHEL with two network-namespace instances, verify the exact custom sockets and state
directories still work with the installed Tailscale version.

Do not assume an old manually written `tailscaled` command line remains valid forever.

---

# 15. Podman and rest-server Revalidation

Revalidate:

```text
Podman version
rootless networking behavior
SELinux bind-mount labeling behavior
--read-only
--cap-drop=all
--security-opt=no-new-privileges
--memory
--pids-limit
port-publish behavior to link-local addresses
container image digest
rest-server release
append-only semantics
private-repos behavior
htpasswd behavior
```

The core guide should not deploy a floating image tag without recording the tested
digest/version.

Run:

```bash
podman version
podman image inspect localhost/vault-rest-server:0.14.0
systemd-analyze verify \
  /etc/systemd/system/vault-rhel-pc-rest-server.service \
  /etc/systemd/system/vault-rhel-phone-rest-server.service
```

Negative tests:

```text
PC container cannot mount Phone repo
Phone container cannot mount PC repo
neither container can mount maintenance credentials
container is not privileged
SELinux label disablement is absent
backend binds only intended link-local address
backend is disabled at boot
gate alone starts the backend
```

A rest-server change that modifies append-only or destructive-request behavior is:

```text
SECURITY REVIEW REQUIRED
```

---

# 16. Caddy Revalidation

Revalidate current Caddy syntax and behavior for:

```text
listener binding
TLS configuration
reverse_proxy
transport keepalive behavior
request method/path matching
header handling
timeouts
systemd service behavior
```

The RHEL watchdog/gate architecture depends on observing the internal backend rather than
mistaking reverse-proxy keepalive for active client work.

Verify:

```text
Caddy listener only on intended Tailscale namespace address
gate paths route only to local gate listener
restic protocol allowlist routes only to matching backend
PC listener cannot route to Phone backend
Phone listener cannot route to PC backend
no public 0.0.0.0 backup listener
```

A Caddy version upgrade that changes reverse-proxy connection reuse or health behavior
requires regression testing of the hard-stop and activity logic.

---

# 17. systemd Hard-Stop Revalidation

Record:

```bash
systemctl --version
systemd-analyze verify <all Vault units>
systemd-analyze security <reviewed Vault units>
```

Revalidate semantics of:

```text
RuntimeMaxSec
TimeoutStopSec
KillMode=control-group
SendSIGKILL=yes
systemd-run --on-active=
transient timers/services
ReadWritePaths
ReadOnlyPaths
ProtectSystem
ProtectHome
NoNewPrivileges
```

Security priority order:

```text
signed hard deadline works
daily slots work
repository isolation works
exact-device expiry works
    ↓
then optimize systemd exposure score
```

A lower `systemd-analyze security` number does not compensate for a broken hard-stop.

---

# 18. Firewalld and OCI Network Revalidation

Revalidate:

```text
firewalld version
active zone
default target
runtime/permanent parity
rich-rule syntax
source-specific rules
OCI NSG/security-list rules
public listeners
```

For the core no-Peer-Relay baseline, confirm:

```text
no UDP/40000 allow rule
no self-hosted DERP TCP/443 listener rule
no self-hosted DERP/STUN UDP/3478 rule
```

Do not confuse ordinary outbound HTTPS to Tailscale-hosted DERP/control infrastructure
with a public inbound listener on the VPS.

For each host:

```bash
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --list-all
sudo firewall-cmd --list-rich-rules
sudo ss -lntup
```

Compare `ss` output against the architecture listener worksheet.

Every unexpected wildcard listener is a deployment blocker until explained.

---

# 19. AWS IAM Identity Center / MFA Revalidation

Revalidate:

```text
IAM Identity Center profile behavior
browser login flow
MFA enforcement at the configured identity provider
PC and Phone gate-invocation permission sets
session caching behavior
AWS CLI v2 SSO token cache behavior
logout behavior
profile isolation
Lambda invoke permissions
```

Required invariant:

```text
PC SSO role:
  invoke only PC issuance gate plus shared read-only completion-status Lambda
  no S3/DynamoDB/IAM data or mutation permission
  no sts:AssumeRole to backup role

Phone SSO role:
  invoke only Phone issuance gate plus shared read-only completion-status Lambda
  no S3/DynamoDB/IAM data or mutation permission
  no sts:AssumeRole to backup role
```

A cached SSO session must not be confused with the Vault's one-hour STS backup
credential.

Record which layer enforces MFA and exactly when reauthentication occurs.

If the IdP no longer guarantees the intended per-session MFA ceremony:

```text
ARCHITECTURE REDESIGN REQUIRED
```

until an equivalent independent ceremony is restored.

> **[OPTIONAL UPGRADE — YubiKey / FIDO2]** Default MFA for both AWS IAM Identity
> Center and Authelia/Tailscale is TOTP. TOTP carries 1-in-1,000,000 theoretical
> predictability per window and is phishing-susceptible. When a FIDO2 hardware security
> key becomes available, upgrade in this priority order:
> 1. AWS root / recovery admin account MFA (break-glass path, single-approver)
> 2. AWS IAM Identity Center Vault user MFA (daily ceremony path)
> 3. Authelia/Tailscale OIDC MFA (network access layer)
>
> Note: the daily backup ceremony is already protected by dual-VPS Ed25519 signatures
> regardless of MFA method. The recovery path (priority 1) benefits most from
> a FIDO2 upgrade because it lacks that dual-signature protection.

---

# 20. DynamoDB Daily-Slot Revalidation

Revalidate:

```text
table name
partition-key schema
conditional PutItem behavior
Lambda permissions
DynamoDB Streams configuration
EventBridge/Lambda detector path
Istanbul calendar-date calculation
midnight rollover behavior
```

Negative tests:

```text
same device/day second issuance → DENY
PC slot does not consume Phone slot
Phone slot does not consume PC slot
failed SSO/MFA before Lambda invocation → slot absent
invalid dual signature → slot absent
valid proof reaches fail-closed issuance path → slot consumed before AssumeRole
AssumeRole failure/ambiguity → slot remains consumed
primary device cannot delete slot
support script does not delete today's slot
```

Any move from "consume before one-attempt credential creation" to "consume after
credential success" is:

```text
SECURITY REVIEW REQUIRED
```

because ambiguity semantics change.

---

# 21. AWS Source-IP / Exact S3 Host Revalidation

Before deployment, record the real observed public egress IP from each VPS.

Do not assume the inbound instance address is the actual S3 egress identity.

Verify:

```text
vault-pc observed IPv4
vault-phone observed IPv4
PC backup-role aws:SourceIp /32
Phone backup-role aws:SourceIp /32
PC exact S3 hostname
Phone exact S3 hostname
current S3 regional endpoint behavior
```

The core S3 proxy must still allow only the reviewed exact hostname and TCP/443.

If the selected AWS SDK/restic behavior starts requiring additional AWS hosts:

```text
STOP
```

Determine whether the extra host is required for:

```text
S3 data plane
AWS authentication
STS
telemetry
redirect handling
```

Do not broaden VPS egress to arbitrary AWS domains without a written reason and threat
model update.

---

# 22. Tailnet Lock Revalidation

For both tailnets:

```bash
tailscale lock status
```

Record:

```text
Tailnet Lock enabled
trusted signing-node TLKs
locked-out nodes
expected primary node
expected VPS node
expected RHEL namespace node
```

Verify disablement-secret custody.

Do not copy disablement secrets onto:

```text
PC routine Vault data path
Phone routine Vault data path
vault-pc
vault-phone
RHEL backup receiver
AWS Lambda environment
```

Revalidate current official Tailnet Lock recovery/revocation procedures.

If a signing node is compromised, use the current documented key-revocation procedure;
do not improvise by merely deleting the node in the admin console and assuming all old
signatures are harmless.

---

# 23. Detection-Plane Revalidation

Before production, inject and observe:

```text
DynamoDB slot consume
expected exact-device expiry
unexpected device mutation
new node
Tailnet Lock mutation
Tailscale audit poll failure
audit poll recovery
Lambda error
unexpected STS caller
AWS root activity test path, where safely testable
budget alarm test path
```

Record:

```text
event time
source system
detector receipt time
notification time
classifier result
expected actor
expected NodeID
```

The detector remains a detection layer, not an authorization factor.

If the detector fails, Vault authorization must not silently become broader.

---

# 24. Version and Hash Freeze After Successful Acceptance

After all deployment-time tests pass, create a deployment manifest containing:

```text
date
core guide SHA-256
threat model SHA-256
detection/custody guide SHA-256
enabled extension SHA-256 values
RHEL version
kernel version
systemd version
Podman version
Caddy version
Tailscale versions
restic version
rest-server image digest
Go version used to build Vault daemons
Vault daemon binary SHA-256 values
Lambda runtime
Lambda ZIP SHA-256
package-lock.json SHA-256
AWS SDK package versions
Headscale version, if enabled
OCI shape and architecture
RHEL imported-image SHA-256
```

Do not call a later deployment "the same reviewed Vault" after changing one of these
without recording the delta.

---

# 25. Final Go / No-Go Worksheet

Complete before production.

```text
TRANSPORT
[ ] Peer Relay is not configured.
[ ] UDP/40000 is not open.
[ ] No self-hosted DERP/STUN listener exists.
[ ] Real campus path has been measured.
[ ] Observed direct/DERP path is recorded.
[ ] No unexpected peer-relay path appears.
[ ] Primary inbound Tailnet connections remain disabled.

SESSION
[ ] Representative daily PC delta fits the signed one-hour ceiling with margin.
[ ] Representative daily Phone delta fits the signed one-hour ceiling with margin.
[ ] Initial-seed timing is recorded separately.
[ ] No hidden session-duration override exists.
[ ] AWS role-chaining one-hour rule has been revalidated.
[ ] No credential refresh loop exists.

TAILSCALE / HEADSCALE
[ ] Headscale Tailnet Lock status has been rechecked.
[ ] Tailscale devices:core expiry scope has been rechecked.
[ ] WIF issuer/subject/audience/custom-claim rules pass negative tests.
[ ] Tailnet Lock is enabled in both core tailnets.
[ ] Exact expected primary NodeIDs are recorded.

RESTIC / COLD STORAGE
[ ] Current stable restic version is recorded.
[ ] Cold-storage maturity status is rechecked.
[ ] Current s3-restore flags/options are recorded.
[ ] Deep Archive canary recovery has been completed or formally scheduled before reliance.

AWS
[ ] Lambda runtime is supported.
[ ] Lambda runtime deprecation date is recorded.
[ ] SDK dependencies are explicitly packaged and recorded.
[ ] Exactly one STS AssumeRole attempt is proven.
[ ] Own MFA without opposite live s3 phase cannot produce fresh STS issuance.
[ ] Snapshot + later lock-removal completion lifecycle is revalidated against exact deployed restic source.
[ ] S3 notification duplicate/out-of-order behavior and reconciliation assumptions are revalidated.
[ ] AWSRevokeOlderSessions / aws:TokenIssueTime semantics are revalidated.
[ ] Backup-role permissions boundaries remain attached and tested.
[ ] Old STS is denied after successful-completion revocation propagation before original Expiration.
[ ] Exact-session status and signed CLOSE_PEER tests pass; wrong-session close fails closed.
[ ] Daily-slot fail-closed behavior is proven.
[ ] SourceIp /32 policies match observed VPS egress.
[ ] Exact S3 host proxy behavior is proven.

RHEL / OCI
[ ] Current active RHEL 9 minor is recorded.
[ ] Exact OCI shape/architecture is recorded.
[ ] Red Hat OCI support/certification status is recorded.
[ ] RHEL custom-image import procedure is current.
[ ] SELinux is Enforcing.
[ ] Unexpected wildcard listeners are absent.
[ ] RHEL PC/Phone backend isolation passes.
[ ] Hard-stop timers pass crash/restart tests.

DETECTION
[ ] AuditWatch sees expected expiry events.
[ ] Unexpected mutations alert.
[ ] DETECTION BLIND test passes.
[ ] STS caller validation passes.
[ ] Daily-slot alerting passes.

DOCUMENT CONTROL
[ ] Core guide and enabled extension hashes are recorded.
[ ] Threat model matches deployed session duration.
[ ] No obsolete guide is being used as a second source of truth.
```

Decision:

```text
all required boxes pass
    → GO

one or more security assumptions are unverified
    → NO-GO

a vendor feature/API changed but the same invariant can be restored with a bounded patch
    → LOCAL PATCH or SECURITY REVIEW REQUIRED

routine daily backup needs S3 credentials longer than one hour under the current
Lambda-role → backup-role AssumeRole chain
    → ARCHITECTURE REDESIGN REQUIRED
```

---

# Appendix A — 2026-07-15 Evidence Snapshot

This appendix records the state observed when this checklist was created.

It is **not** a substitute for deployment-time revalidation.

```text
Tailscale transport:
  direct attempted first
  configured Peer Relay used if direct fails and relay is available
  DERP used when direct fails and no usable Peer Relay is available
  Peer Relay requires explicit relay-device configuration and an accessible UDP port
  core Vault Peer Relay extension uses UDP/40000
  core baseline does not configure Peer Relay

Headscale:
  latest stable observed: v0.29.2
  Tailnet Lock feature request #1307: open
  feature-gap label present
  no Tailnet Lock implementation identified in v0.29.2 release notes

Tailscale API scopes:
  POST /api/v2/device/:deviceID/expire remains under devices:core
  devices:core also covers broader device lifecycle/property operations

restic:
  latest stable observed: 0.19.1
  Glacier/Deep Archive restore support remains experimental / early alpha
  RESTIC_FEATURES=s3-restore documented
  s3.enable-restore documented
  known-working cold commands listed: backup, copy, prune, restore

AWS Lambda:
  nodejs22.x supported
  nodejs22.x deprecation currently listed as 2027-04-30
  nodejs24.x also supported
  AWS recommends packaging required AWS SDK clients in the deployment package

AWS STS/IAM:
  role chaining limits chained AssumeRole API/CLI sessions to one hour
  DurationSeconds > 3600 fails for role chaining
  current Vault Lambda execution-role → backup-role AssumeRole path must be treated as
  a one-hour S3 credential architecture

RHEL:
  RHEL 9.8 GA observed: 2026-05-19
  RHEL 9.8 is the current active RHEL 9 minor at the freeze date

OCI:
  Oracle RHEL custom-image guidance currently specifies RHEL KVM guest image
  QCOW2
  Paravirtualized launch mode
  supported shape compatibility review
  default RHEL custom-image user cloud-user
  current OCI documentation warns against SR-IOV for custom A1 images
```

---

# Appendix B — Official Primary Sources to Recheck

Use current versions of these official pages/projects.

```text
Tailscale:
  https://tailscale.com/docs/reference/connection-types
  https://tailscale.com/docs/reference/device-connectivity
  https://tailscale.com/docs/features/peer-relay
  https://tailscale.com/docs/reference/faq/firewall-ports
  https://tailscale.com/docs/reference/trust-credentials
  https://tailscale.com/docs/features/workload-identity-federation
  https://tailscale.com/docs/features/tailnet-lock
  https://tailscale.com/docs/concepts/tailnet-lock-whitepaper
  https://tailscale.com/docs/features/logging/audit-logging

Headscale:
  https://github.com/juanfont/headscale/releases
  https://github.com/juanfont/headscale/issues/1307
  https://headscale.net/

restic:
  https://github.com/restic/restic/releases
  https://restic.readthedocs.io/en/stable/faq.html
  https://restic.readthedocs.io/en/stable/

AWS:
  https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage-assume.html
  https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
  https://docs.aws.amazon.com/lambda/latest/dg/lambda-nodejs.html
  https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html

Red Hat:
  https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates
  https://access.redhat.com/support/policy/updates/errata
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/

Oracle Cloud:
  https://docs.oracle.com/iaas/Content/Compute/Tasks/importingcustomimagelinux.htm
  https://docs.oracle.com/iaas/Content/Compute/References/bringyourownimage.htm
  https://docs.oracle.com/iaas/Content/Compute/known-issues.htm
  https://docs.oracle.com/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
```

---

# Appendix C — Rule for Future AI/Operator Review

When reviewing the Vault months later, do not ask only:

```text
"What is the newest version?"
```

Ask:

```text
Which core security assumptions depended on external product behavior?
Which of those behaviors changed?
Did a broader credential scope become narrower?
Did a previously missing cryptographic control become available?
Did an experimental recovery feature become stable?
Did a runtime enter deprecation?
Did a transport path change?
Did the one-hour session assumption still fit the real daily workload?
Did AWS change the role-chaining duration constraint?
Can a new feature reduce trust without adding a new public listener?
```

The goal is not to modernize the Vault for its own sake.

The goal is to preserve or improve the exact security invariants with the smallest
reviewable change.
