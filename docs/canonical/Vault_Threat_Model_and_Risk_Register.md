# THE VAULT — THREAT MODEL AND RISK REGISTER
================================================================================

## 1. Purpose and authority

This file is independent from the installation guide. It defines what the Vault is
trying to protect, the compromise assumptions that are allowed during reasoning, the
security invariants that must remain true, and the residual risks that the operator
accepts.

The canonical implementation is:

```text
Vault_Zero_Trust_Master_Guide_CANONICAL_TAILSCALE_OUTBOUND_ONLY_NO_PRUNE.md
```

The mandatory post-install production-entry profile is:

```text
Vault_Post_Install_Detection_and_Credential_Custody.md
```

It adds an independent AWS-side detection plane and credential-custody assumptions; it
does not change the backup topology. Production claims in this threat model assume that
its acceptance tests have passed.

Optional changes are not permitted to silently rewrite this file. Every extension plan
contains a threat-model delta. Apply that delta when the extension is enabled and undo
or supersede it when the extension is removed.

## 2. Baseline architecture under review

```text
PC plaintext source
  ├── S3 PC bucket through vault-pc fixed egress
  └── RHEL PC repository through RHEL-PC compartment

Phone plaintext source
  ├── S3 Phone bucket through vault-phone fixed egress
  └── RHEL Phone repository through RHEL-Phone compartment

vault-pc <---- dedicated wg-cross ----> vault-phone
      \                                 /
       \---- canonical dual signatures-/

PC tailnet
  PC + vault-pc + RHEL-PC instance

Phone tailnet
  Phone + vault-phone + RHEL-Phone instance
```

Baseline control plane: two independent Tailscale tailnets with Tailnet Lock.
Baseline relay: direct when possible, Tailscale-managed DERP fallback.
Baseline primary topology: outbound-only; no PC↔Phone Vault receiver.
Baseline retention: keep all snapshots; no forget/prune.

## 3. Assets

### A1 — Primary plaintext

The current working data on PC and Phone. Loss, unauthorized read, or unauthorized
exfiltration is high impact.

### A2 — Restic repository passwords

PC and Phone repository passwords permit decryption of their corresponding repositories.
The baseline RHEL host does not store them.

### A3 — VPS Vault Ed25519 signing private keys

`vault-pc` and `vault-phone` each hold one independent signing key. A valid fresh AWS or
RHEL authorization proof requires both signatures on the same canonical payload.

### A4 — Device phase tokens

The PC and Phone each hold one independent 256-bit phase token. Each owning VPS stores
only its SHA-256 verifier.

### A5 — AWS issuance and containment state

DynamoDB daily-slot records, Lambda gate code/configuration, IAM roles, S3 bucket
policies, versioning, fixed `aws:SourceIp` conditions, budget alert/action, and
CloudTrail/EventBridge alerting.

### A6 — Tailscale membership trust state

Tailnet Lock key authority state, trusted signer keys, disablement secrets, exact
primary NodeIDs/IPs, and the root-owned per-tailnet OAuth expiry credential.

### A7 — RHEL ciphertext repositories and local gate state

The PC/Phone repository bytes, per-repository capacity boundaries, consumed daily-slot
files, active backend timers, Caddy/TLS configuration, and the two VPS public signing
keys.

### A8 — Independent detection and break-glass state

The `VaultDetectionState` table, DynamoDB slot stream, `VaultSlotWatch`,
`VaultAuditWatch`, `VaultStsWatch`, EventBridge/Scheduler rules, SNS security topic,
CloudTrail management-event evidence, pinned Tailscale actor/Node IDs, WIF client
IDs/audiences, and detector-health state. Break-glass records also include AWS root
recovery material, Tailscale Tailnet Lock disablement secrets, VPS-provider recovery
records, and SSH host-key fingerprints. These records must remain outside the routine
Vault working-data path.

## 4. Trust and compromise assumptions

The primary design assumption is **single-compromise resistance**, not omnipotent
adversary resistance.

The following are treated as plausible individually:

```text
one primary endpoint compromised
one Vault VPS fully root-compromised
one Tailscale coordination-plane compromise
one VPS relay/egress path compromised
RHEL root compromise
one short-lived STS credential stolen
one phase token stolen from its owning primary
network denial/interference
```

The following combinations are outside the main guarantee and are residual/high-severity
multi-boundary risks:

```text
both Vault VPS signing private keys compromised
both primary endpoints compromised at the same time
one primary + opposite Vault VPS compromised during a matching live ceremony
AWS administrator/account control compromised
RHEL root + source repository password compromise
Tailnet Lock trusted signer compromise plus a second authorization-boundary compromise
```

The MFA factor protecting a primary's high-value cloud identity is assumed not to be
simultaneously available to malware on that same primary. Prefer phishing-resistant
FIDO/passkey factors. If software TOTP is used, the documented cross-device layout keeps
the PC identity seed only on Phone and the Phone identity seed only on PC, with no
same-endpoint synchronized seed backup. AWS root and break-glass administrator factors
use separate custody rules.

## 5. Security invariants

### I-01 — Separate primary compartments

PC and Phone are not members of the same tailnet. Each primary can reach only its own
VPS Vault listeners and own RHEL listener. No direct PC↔Phone Vault data path exists in
the baseline.

### I-02 — Local inbound prohibition

Fedora keeps Tailscale Shields Up. Android keeps Allow incoming connections disabled.
Neither primary runs a Vault receiver service in the baseline.

### I-03 — Two independent Vault signatures

AWS S3 issuance and RHEL backend opening require valid `vault-pc` and `vault-phone`
Ed25519 signatures over the exact same canonical fresh payload.

### I-04 — One daily issuance/opening slot per device/repository

PC S3, Phone S3, RHEL-PC, and RHEL-Phone have separate calendar-day slots. The date is
computed in `Europe/Istanbul`. There is no reset API; the date is part of the slot key.

### I-05 — Slot before credential/backend creation

AWS Lambda consumes the device/day slot before its single `AssumeRole` attempt. RHEL
consumes the repository/day slot before starting the matching backend.

### I-06 — Credential issuance is non-retryable; data plane is retryable

After daily-slot consumption, an ambiguous AWS issuance result is fail-closed and is
not retried. A successfully returned STS credential may be reused for bounded restic/S3
operation retries until expiry. RHEL data-plane retries reuse the already-open backend
window; they do not create a new RHEL ceremony.

### I-07 — Endpoint `DONE` is not a security factor

`DONE` may close a window early. Suppressing it cannot move the persisted signed hard
one-hour session deadline. RHEL uses a systemd-managed stop timer based on the signed
deadline. VPS coordinators independently queue own-primary expiry at deadline.

### I-08 — S3 device isolation

PC and Phone use different buckets, backup roles, Lambda gates, and daily slots. A PC
backup credential cannot access the Phone bucket and vice versa. Bucket-side explicit
denies protect against an accidentally broadened identity policy.

### I-09 — Fixed egress source identity

Routine S3 backup actions are allowed only when requests leave from the matching Vault
VPS stable public egress `/32`. A stolen STS credential from an ordinary attacker IP
must fail the `aws:SourceIp` condition.

### I-10 — RHEL local authorization

RHEL does not trust `OPEN` text from either VPS. It verifies both signatures locally and
starts only the target-specific backend.

### I-11 — RHEL keyless baseline

RHEL stores neither source repository password in the baseline. RHEL is a ciphertext
receiver, not a decryption-capable maintenance node.

### I-12 — Per-repository capacity isolation

PC repository growth must not automatically exhaust the Phone repository allocation and
vice versa. Per-repository quota/allocation limits are required in addition to global
filesystem monitoring.

### I-13 — Cold S3 is not routine maintenance storage

Glacier Deep Archive receives backup data. Routine `check --read-data-subset`, PAR2,
forget, and prune are not run against cold S3. Cold recovery is validated through a
separate archive-restore drill.

### I-14 — No-prune baseline

No routine `forget` or `prune` capability exists. The 85% RHEL hard guard is an
architecture migration trigger, not permission for an ad-hoc cleanup command.

### I-15 — Independent detection plane and detector-health visibility

Production operation requires the post-install detection profile. Tailscale configuration
audit reading uses AWS-to-Tailscale workload identity federation and only
`logs:configuration:read`; no persistent Tailscale audit secret exists in Lambda. Daily
slot inserts alert through DynamoDB Streams. STS `AssumeRole` for either backup role is
validated against the exact corresponding gate execution role. Audit polling blind state
is itself a CRITICAL alert condition. Detection state cannot grant AWS/RHEL backup
authority.

### I-16 — Break-glass and admin credentials do not collapse both VPS compartments

AWS root access keys do not exist. AWS root/Tailnet Lock disablement/provider recovery
records are outside the routine Vault data path. `vault-pc` and `vault-phone` do not share
one ordinary software SSH private key. Tailscale `devices:core` credentials are distinct
and confined to their owning VPS; the audit watcher uses a separate read-only WIF
identity. Cross-VPS Ed25519 private signing keys are never co-located.

## 6. Threat register

### T-01 — PC endpoint malware

**Scenario:** malware reads PC plaintext, PC phase token, or active process credentials.

**Controls:** Phone-VPS signature required; PC S3 daily slot; PC-only bucket/role; fixed
PC VPS egress `/32`; one-hour STS; hard session deadline; RHEL-PC daily slot; PC repo
quota; Phone repository not reachable with PC role.

**Residual:** during a legitimately authorized joint session, malware can use the PC's
own already-authorized capability until the hard deadline. It can also read/exfiltrate
PC plaintext through non-Vault channels if the endpoint OS itself permits them. Vault
is not a general endpoint DLP product.

**Status:** mitigated, residual high-value endpoint risk accepted.

### T-02 — Phone endpoint malware

Symmetric to T-01.

### T-03 — One Vault VPS root compromise

**Scenario:** attacker gets one coordinator, one Vault signing private key, one Tailnet
Lock signer state, one exact S3 egress IP, and the root-owned Tailscale expiry credential
for that one tailnet.

**Controls:** opposite Vault VPS signature remains unavailable; AWS and RHEL verify both
signatures; separate buckets/roles/tailnets; opposite VPS not reachable through
`wg-cross` except the narrow cross-sign protocol.

**Residual:** attacker can cause DoS in its own compartment, abuse its own approved
source IP within whatever credentials it obtains, manipulate one tailnet signer, or
interfere with legitimate proof timing. A matching compromise of the other signing
boundary breaks I-03.

**Status:** core design target; single VPS compromise must not independently open AWS or RHEL.

### T-04 — Tailscale coordination-plane compromise

**Scenario:** control plane attempts to insert a rogue node or distribute malicious
membership state.

**Controls:** Tailnet Lock requires trusted signing keys for nodes accepted by locked
peers. Two independent tailnets limit policy/control blast radius. Primary inbound is
locally disabled. AWS/RHEL use independent Vault signatures.

**Residual:** denial of service, withheld network state, or policy changes that deny
connectivity remain possible. Tailnet Lock does not protect a compromised trusted
signing node.

**Status:** membership insertion risk mitigated by Tailnet Lock.

### T-05 — Tailnet Lock signing-node compromise

**Scenario:** one trusted infrastructure signer is compromised and signs an attacker
node in its own tailnet.

**Controls:** Tailnet Lock is not used as the Vault dual authorization factor; AWS/RHEL
still require both Vault VPS signatures. Tailnets remain separate. Local primary inbound
blocking and narrow services reduce direct exploit paths.

**Residual:** membership integrity in that one tailnet is weakened. A single physical
RHEL root compromise can expose both RHEL Tailscale instance state/signing keys; this is
a shared membership-recovery trust boundary.

**Status:** residual; review signer placement after any RHEL trust-model change.

### T-06 — Tailscale `devices:core` expiry credential compromise

**Scenario:** root-owned OAuth client secret on one VPS is stolen. `devices:core` is
broader than expire-only and can access multiple device management mutation endpoints.

**Controls:** separate credential per tailnet; no `all`, policy, auth-key, DNS, route,
user, or Tailnet Lock scopes; root-only files; exact-device helper has fixed endpoint
and verb; exact NodeID/IP/hostname/tailnet checks; persistent partial state; ambiguous
API result does not retry.

**Residual:** a thief who directly uses the OAuth secret is not constrained by the local
helper code. Scope breadth is an accepted weakness of the current Tailscale API model.

**Status:** meaningful residual; Headscale extension removes this credential at the cost
of the Tailnet Lock membership guarantee.

### T-07 — Stolen STS credential

**Scenario:** malware copies a successful PC or Phone STS credential from process memory.

**Controls:** one-hour credential lifetime; matching bucket only; matching role only;
fixed Vault VPS `aws:SourceIp`; daily reissuance slot; budget containment.

**Residual:** credential can be used inside the already-authorized egress path/window if
attacker also controls or reaches the matching VPS path. Ordinary logout does not revoke
an already-issued STS credential.

**Status:** bounded, not eliminated.

### T-08 — Repeated STS minting after VPS/auth bypass

**Scenario:** attacker bypasses VPS ceremony logic and repeatedly asks for new one-hour
sessions.

**Controls:** AWS-native DynamoDB daily slot; Lambda verification; slot consumed before
one AssumeRole attempt; CLI retry explicitly disabled.

**Residual:** two calendar-day boundary sessions can occur close together around
midnight. Each device has its own slot. Detection/containment latency still matters.

**Status:** hard rate limit implemented.

### T-09 — AWS cost/API request abuse

**Scenario:** attacker produces excessive object/request operations rather than only
large files.

**Controls:** daily issuance rate; hard STS expiry; fixed source IP; example configurable
USD 2 monthly budget; email; automatic deny attached to both backup roles.

**Residual:** AWS billing/budget data is delayed and budget actions are not real-time
hard caps. Costs can exceed the threshold before containment applies.

**Status:** mitigated by prevention + delayed containment + detection.

### T-10 — Daily slot consumed before legitimate operator session

**Scenario:** attacker obtains a valid dual proof and consumes a device/repository slot
before the operator.

**Controls:** anomaly is visible because the legitimate later ceremony is denied;
CloudTrail/Lambda logs and RHEL state record the slot; alerting and investigation are
required.

**Residual:** availability loss for that day. Security intentionally prefers a burned
slot to ambiguous duplicate issuance.

**Status:** accepted fail-closed behavior.

### T-11 — Endpoint suppresses `DONE`

**Scenario:** malware keeps its control socket or transfer active and never sends DONE.

**Controls:** persisted signed one-hour session deadline; VPS admissions expire;
S3 proxy bounded drain; RHEL systemd hard-stop timer; exact own-primary expiry intent.

**Residual:** attacker can retain the legitimate window until the hard deadline.

**Status:** bounded by design.

### T-12 — Restricted Wi-Fi blocks UDP/WireGuard direct path

**Scenario:** campus/dorm network drops UDP.

**Controls:** managed DERP fallback; Vault authorization is independent of path type.

**Residual:** throughput/latency degradation. If HTTPS/backend/DERP paths are also
blocked, backup is unavailable and fails closed.

**Status:** resilience risk, not authorization bypass.

### T-13 — RHEL root compromise

**Scenario:** attacker controls the physical RHEL OS.

**Controls:** baseline source repository passwords absent; repository bytes encrypted;
per-repository services/users/namespaces/quotas; AWS copy remains independent.

**Residual:** ciphertext theft, deletion/corruption, local TLS/htpasswd compromise,
capacity manipulation, and both RHEL Tailnet Lock signer states can be lost. If prune
extension is enabled, RHEL becomes decryption-capable and this risk materially worsens.

**Status:** keyless baseline limits confidentiality impact.

### T-14 — RHEL capacity exhaustion by one source

**Scenario:** compromised PC appends junk to its own repository and triggers global disk
pressure.

**Controls:** PC and Phone allocations/quotas are independent; local repository guard;
70/80/85 monitoring; 85% hard stop.

**Residual:** filesystem metadata/log/Podman shared-space exhaustion remains a global
host concern; keep OS reserve and global monitor.

**Status:** compartment blast radius reduced.

### T-15 — Deep Archive copy cannot be recovered when needed

**Scenario:** backup success is mistaken for proven restore capability; restic cold
storage behavior or AWS restore process changes.

**Controls:** separate MFA-protected restore permission path; scheduled canary recovery
drill; record restic version, restore tier, time, and cost; no routine cold subset check
claim.

**Residual:** archive service delay and evolving experimental client behavior.

**Status:** must be operationally tested.

### T-16 — No-prune capacity growth

**Scenario:** keep-all history reaches the RHEL storage ceiling.

**Controls:** `data_added_packed` and physical-growth logs; 90-day slope; 70/80 warnings;
85% hard ingestion stop; documented retention migration extension.

**Residual:** sudden large unique churn can reach the trigger earlier than forecast.

**Status:** deferred complexity by design.

### T-17 — Supply-chain/configuration drift

**Scenario:** package upgrade, manual edit, or generated-guide drift weakens an invariant.

**Controls:** one canonical guide; separate extensions; pinned/recorded versions where
security-sensitive; build/vet/syntax checks; hashes after acceptance; day-zero negative
tests; extension-specific rollback instructions.

**Residual:** operator may skip tests or copy commands from obsolete drafts.

**Status:** procedural risk; old 16-guide matrix is non-authoritative.

### T-18 — Detection-plane blindness

**Scenario:** EventBridge Scheduler, AWS outbound identity federation, Tailscale WIF, the
configuration-log API, or `VaultAuditWatch` fails and privileged mutation becomes less
visible.

**Controls:** five-minute overlapping polls; independent PC/Phone health counters; two
consecutive failures produce `DETECTION BLIND`; Lambda `Errors` alarm; scheduler failure
monitoring; recovery INFO; audit event fingerprints retained separately.

**Residual:** Tailscale documents no maximum audit-log inclusion delay, only that events
appear within seconds in practice. AWS administrator compromise can disable the detection
plane.

**Status:** detector failure is surfaced, but detection is not an authorization factor.

### T-19 — Break-glass/admin credential compromise collapses compartments

**Scenario:** a shared software SSH key, provider-owner account, AWS root credential,
Tailnet Lock disablement secret, or co-located VPS signing keys gives one compromise a
path across both security compartments.

**Controls:** no AWS root access keys; multiple FIDO root MFA devices; offline separated
break-glass store; separate VPS provider accounts/providers where practical; separate
FIDO-backed or compartment-specific SSH credentials; exact SSH host-key fingerprints;
separate `devices:core` credentials; cross-signing private keys never co-located.

**Residual:** one shared provider owner account or one physical FIDO token holding both
SSH credentials remains an explicitly documented shared failure domain if the operator
chooses the pragmatic lower-cost layout.

**Status:** custody architecture is part of the production security model.

## 7. Detection and containment layers

```text
PREVENTION
  Tailnet Lock
  two tailnets
  two Vault signatures
  daily AWS/RHEL slots
  one-attempt STS issuance
  fixed S3 source IP
  separate buckets/roles
  RHEL local proof verification
  per-repo capacity isolation

BOUNDED WINDOW
  one-hour STS
  signed one-hour Vault session deadline
  S3 proxy drain
  RHEL systemd hard-stop

DELAYED CONTAINMENT
  AWS Budget automatic deny

DETECTION
  failed IAM Identity Center credential verification email
  DynamoDB Streams alert on every S3 daily-slot consume
  five-minute Tailscale configuration-audit polling through read-only WIF
  default-deny mutation classifier with exact expiry actor/NodeID pinning
  DETECTION BLIND alarm after repeated audit-poll failure
  CloudTrail/EventBridge exact STS gate-role -> backup-role caller validation
  Lambda Errors and scheduler failure alarms
  AWS root-activity alert
  budget email
  RHEL gate/capacity logs
  optional local canary/audit tripwire; not authoritative against VPS root
  operator success markers
```

Do not describe delayed budget containment as a real-time cost cap. Do not describe
Tailscale device expiry as revocation of an already-issued AWS STS credential.

## 8. Extension delta protocol

When enabling an extension:

1. Copy its `Threat-model delta` section into the change log below.
2. Mark any baseline invariant it intentionally weakens as `modified` rather than
   pretending the invariant still holds.
3. Add new assets, trusted components, credentials, and data paths.
4. Add at least one negative acceptance test for the new boundary.
5. Record whether rollback restores the old security property or whether data/history
   changes are irreversible.

### Change log

```text
2026-07-15 | BASELINE | Canonical Tailscale + Tailnet Lock + Tailscale-hosted DERP,
           |          | outbound-only, keyless RHEL, no-prune.
2026-07-15 | DETECT   | Mandatory AWS-side SlotWatch/AuditWatch/StsWatch and credential
           |          | custody profile added before production sign-off.
```

## 9. Security decision summary

The Vault is not based on one magical control. The core strategy is to ensure that a
single plausible compromise loses only one compartment and encounters an independent
server-side boundary before it can create a fresh S3 or RHEL authorization window.

The most important baseline guarantees are:

```text
one compromised endpoint != two VPS signatures
one compromised VPS      != two VPS signatures
control-plane compromise != unsigned membership (Tailnet Lock)
one stolen STS            != unlimited reissuance
endpoint DONE suppression != unlimited window
one junk repository       != automatic loss of the other repository quota
RHEL root compromise      != repository decryption in the keyless baseline
```

Any future change that invalidates one of these equations is a threat-model change, not
a routine configuration edit.

## APPENDIX H — SYSTEMD/PODMAN CONFINEMENT DELTA (CANONICAL PRODUCTION BASELINE)

The canonical production baseline includes the master guide's
`PART 2A: PRODUCTION SERVICE CONFINEMENT — SYSTEMD AND PODMAN HARDENING`.

### H-A1 — Additional security objective

A compromised Vault-owned service process should have only the filesystem, network
family, capabilities, devices, and writable state required by that exact service.
Container compromise should additionally meet the rootless Podman, SELinux, read-only
root filesystem, all-capabilities-dropped, and no-new-privileges boundaries before
reaching the host user's authority.

### H-I1 — Single-source primary invariant

The Fedora Vault workflow exposes `~/Vault_PC_Ciphertext` as its only backup source and
binds that source read-only inside the systemd mount namespace. The workflow must not
crawl or bind the ordinary home tree. Android/Termux continues to pass only
`~/Vault_Phone_Ciphertext` to `restic backup`.

### H-I2 — Service confinement is defense in depth, not a new authorization factor

systemd sandboxing and Podman confinement do not replace cross-VPS dual signatures,
daily slots, Tailnet Lock, fixed S3 egress, repository quotas, or the signed hard
deadline. A sandbox failure alone must not create a valid fresh S3/RHEL authorization
proof.

### H-I3 — RHEL container separation

The PC rootless rest-server container may bind only the PC repository and PC htpasswd.
The Phone container may bind only the Phone repository and Phone htpasswd. Neither may
bind the maintenance credential directory or the opposite repository.

### H-I4 — No privileged-container escape hatch

The canonical baseline prohibits `--privileged`, SELinux label disablement, unconfined
seccomp as a troubleshooting shortcut, and broad host filesystem bind mounts for Vault
containers.

### H-R1 — Residual same-user endpoint risk

A Fedora malware process already running outside the confined Vault unit with the
desktop user's own permissions is not retroactively sandboxed by the Vault service
unit. It may access files the user can access. The hardening reduces compromise blast
radius of the Vault process tree; it is not an EDR boundary against arbitrary
same-user malware.

### H-R2 — Runtime compatibility risk

Over-hardening a network-privileged or container-supervising service can break expiry,
namespace creation, hard-stop scheduling, or backend supervision. Therefore generic
empty capability sets and speculative syscall allowlists are not applied to
`tailscaled`, WireGuard/netns infrastructure, or the Podman-launching outer unit without
version-specific testing. The negative acceptance matrix is a security invariant.

### H-R3 — Hardening regression severity

A change that causes the signed hard-stop timer, exact-device expiry, daily-slot
enforcement, or repository isolation to fail is classified as HIGH severity even if
`systemd-analyze security` reports a numerically lower exposure score.

## APPENDIX P — RHEL 9 BYOL/BYOI VPS PLATFORM DELTA

The canonical `vault-pc` and `vault-phone` hosts are RHEL 9 BYOL/BYOI systems on OCI
Free Tier. The current active RHEL 9 minor is used; this revision was normalized against
RHEL 9.8.

### P-I1 — Architecture-match invariant

An OCI `VM.Standard.E2.1.Micro` deployment uses an `x86_64` RHEL image. An
`VM.Standard.A1.Flex` deployment uses an `aarch64` RHEL image. Imported-image
architecture and selected shape must match. A shape-architecture change is a rebuild and
acceptance-test event, not a transparent resize.

### P-I2 — RHEL content and SELinux invariant

Both VPSs receive authentic supported RHEL 9 content under the operator's BYOL
entitlements and remain SELinux Enforcing. RHEL registration/subscription secrets are
not placed in public cloud-init metadata.

### P-I3 — Custom Vault native services use dedicated identities and systemd confinement

`vault-device-coordinator` runs as `vaultcoord`; `vault-s3-proxy` runs as `vaultproxy`.
DAC ownership/mode separation and effective systemd sandboxing are production
invariants. The exact-device expiry helper remains a separately modeled root-owned
privileged helper.

The canonical baseline does **not** claim dedicated SELinux MAC domains for the custom
native Go daemons. RHEL SELinux remains Enforcing, but custom policy development is
outside the required operator skill set for this design.

### P-R1 — BYOI supply/commissioning risk

A malformed, stale, incorrectly labeled, or architecture-mismatched imported image can
invalidate firewall, SELinux, update, or boot assumptions before Vault is installed.
Controls: record image origin/hash, verify architecture, verify RHEL release and
repositories, verify SELinux Enforcing after valid labeling/reboot, update before Vault
installation, and preserve provider-console recovery until SSH/firewall tests pass.

### P-R2 — Native custom-daemon MAC confinement is not claimed

The coordinator and S3 proxy may run in the targeted policy's ordinary unconfined
service domain. Therefore a service-level exploit is constrained by its dedicated Unix
identity, DAC permissions, capability removal, `NoNewPrivileges`, and systemd sandbox;
this baseline does not add an independent custom SELinux MAC boundary around those two
native daemons.

This is an explicit residual limitation, not an accidental undocumented gap. The design
avoids locally generated `sepolicy`/`audit2allow` modules because an incorrectly reviewed
allow rule can silently overgrant a security-sensitive service. Standard RHEL and
Podman/container SELinux policy remains active.

### P-R3 — Full root compromise statement is unchanged

Dedicated users, DAC separation, and systemd sandboxing make a service-level exploit
less likely to immediately read another Vault service's secrets. They do **not** change
T-03: a proven full root compromise of one VPS is still conservatively modeled as loss
of that compartment's signing key, Tailnet Lock signer state, expiry credential,
coordinator, and approved S3 egress identity.
