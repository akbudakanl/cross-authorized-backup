# THE VAULT: ZERO TRUST MASTER GUIDE — CANONICAL BASELINE
# OUTBOUND-ONLY • NO-PRUNE • TAILSCALE + TAILNET LOCK • TAILSCALE-HOSTED DERP • RHEL 9 VPS HOSTS
================================================================================

## PART 1: ARCHITECTURE, PRIMARY-DEVICE HARDENING, AND BACKUP DESTINATIONS
================================================================================

> **Canonical baseline.** This is the one master installation guide. It is deliberately
> written for a reader starting from zero: install order, files, commands, complete
> services, complete helper code, day-zero tests, failure behavior, recovery, and daily
> operator steps are documented here. Do not use the old 16-guide matrix as a second
> source of truth.
>
> **Canonical server-platform decision.** `vault-pc`, `vault-phone`, and the backup
> receiver are RHEL 9 systems with SELinux Enforcing. The two OCI Free Tier VPSs use the
> operator's Red Hat subscriptions in a BYOL/BYOI model. Use the current active RHEL 9
> minor release; at the time of this revision that is RHEL 9.8. Do not permanently pin
> an older minor merely to preserve this guide's screenshots or package versions.
>
> OCI Always Free may be either AMD `VM.Standard.E2.1.Micro` (`x86_64`) or Ampere
> `VM.Standard.A1.Flex` (`aarch64`). The imported RHEL image architecture must match the
> selected shape. RHEL 10 is not the canonical VPS baseline because its x86 baseline is
> stricter and this project prefers one RHEL 9 common denominator across older hardware
> and OCI Free Tier. A later RHEL 10 migration requires a fresh compatibility review.
>
> **Read `Vault_Threat_Model_and_Risk_Register.md` first.** Every security claim in this
> guide is scoped to that threat model. Optional architecture changes are supplied as
> reversible extension plans:
>
> * `Vault_Extension_Mutual_Backup.md`
> * `Vault_Extension_Capacity_Triggered_Prune_and_Maintenance.md`
> * `Vault_Extension_Headscale_Control_Plane.md`
> * `Vault_Extension_Peer_Relay_Performance.md`
>
> Each extension has four mandatory parts: prerequisites, install/migration, removal or
> rollback, and the exact threat-model changes that must be recorded.
>
> **After this master guide and all day-zero correctness tests, but before production,
> apply `Vault_Post_Install_Detection_and_Credential_Custody.md`.** That file is not an
> optional topology extension. It adds the independent AWS-side detection plane and the
> break-glass/admin/runtime credential-custody standard assumed by the production threat
> model.

### Why Tailscale is the canonical control plane

The baseline uses **two independent Tailscale tailnets with Tailnet Lock enabled** and
Tailscale-hosted DERP as the relay fallback. The security reason is specific: Tailnet
Lock lets trusted nodes sign/verify node keys, so compromise of the coordination plane
alone cannot insert an unsigned rogue node that locked peers accept. Headscale does not
currently implement this property. The Headscale alternative is still documented
because its local exact-node expiry path is architecturally narrower than Tailscale's
current `devices:core` API scope.

The baseline therefore chooses:

```text
Tailscale advantage:
  Tailnet Lock protects membership integrity
  Tailscale-hosted DERP removes public relay listeners from our VPSs

accepted Tailscale disadvantage:
  server-side exact device expiry currently requires devices:core
  devices:core is broader than expire-only
  one root-owned exact-device helper per tailnet is a compensating control
```

This is not a claim that Tailscale removes every control-plane risk. A malicious or
compromised coordination plane can still cause denial of service or withhold useful
network state. Tailnet Lock also cannot save a tailnet after a trusted signing node or
its signing key is compromised. The Vault's own PC-VPS/Phone-VPS Ed25519 signatures
remain the authorization factors for AWS and RHEL.

### Baseline transport decision

Peer Relay is **not enabled by default**. The baseline path is:

```text
direct WireGuard/UDP when the network permits it
        ↓ if direct is unavailable
Tailscale-hosted DERP over the normal Tailscale fallback path
```

A restrictive Wi-Fi network that blocks UDP should degrade to DERP rather than bypass
Vault controls. If DERP performance is measured and cannot reliably complete a normal
backup delta inside the hard session window, apply `Vault_Extension_Peer_Relay_Performance.md`.
Do not add public UDP/40000 merely because Peer Relay is theoretically faster.

### Baseline retention and topology decisions

```text
PRIMARY DEVICES:
  outbound-only source clients
  no PC↔Phone Vault data-plane receiver
  incoming Tailnet connections disabled locally

RHEL:
  two isolated network namespaces
  two independent Tailscale instances
  two independent Caddy listeners/backends/users
  keyless ciphertext receiver in the baseline
  per-repository capacity isolation

S3:
  two buckets
  two backup roles
  two daily issuance slots
  one STS issuance attempt per device/calendar-day
  same issued credential may retry S3 data-plane work only while backup is incomplete
  successful restic completion is inferred AWS-side from snapshot creation followed
    by repository-lock removal, then the matching role session is revoked
  the clean opposite primary closes the completed device's VPS S3 admission after
    AWS reports the exact shared session as REVOKED
  one-hour signed deadline remains the final fail-closed ceiling
  Glacier Deep Archive pack data; no routine read-data-subset against cold S3

RETENTION:
  keep all snapshots
  no forget/prune
  70/80/85 capacity policy
  85% is a hard ingestion stop and migration trigger
```

## HOW THE SESSION ACTUALLY WORKS — READ BEFORE INSTALLING

The easiest way to misunderstand this system is to attribute its security to “the VPN
closes when backup finishes.” That is only one cleanup layer. The actual guarantees are
server-side and independent of a cooperative endpoint.

### PC S3 ceremony

```text
1. PC is a signed member of the PC Tailnet Lock tailnet.
2. Phone is a signed member of the Phone Tailnet Lock tailnet.
3. PC authenticates to its own Tailscale identity when its prior device key has been
   server-side expired; the configured identity provider must require MFA.
4. Phone does the symmetric authentication in its own tailnet.
5. PC presents its device-specific phase token to vault-pc.
6. Phone presents its independent phase token to vault-phone.
7. The two VPS coordinators create one canonical S3_PC payload.
8. vault-pc signs it with the PC-VPS Ed25519 private key.
9. vault-phone signs the exact same payload with the Phone-VPS Ed25519 private key.
10. PC performs AWS IAM Identity Center SSO/MFA and invokes only the PC Lambda gate.
11. Lambda verifies both VPS signatures and exact payload semantics.
12. Lambda atomically consumes S3#PC#YYYY-MM-DD in DynamoDB.
13. Only after the slot is consumed does Lambda call AssumeRole once.
14. The returned one-hour STS credential reaches only the PC process.
15. Restic sends only through the exact-host proxy on vault-pc.
16. S3 accepts the backup-role data path only from vault-pc's fixed public egress /32.
17. Network/S3 operation retries reuse the same STS credential; the issuance helper
   never invokes Lambda a second time after an ambiguous outcome.
18. A successful restic backup creates a new repository snapshot and then releases its
   repository lock. S3 notifications feed both operations to the device-specific
   completion revoker; duplicate or out-of-order events are processed idempotently.
19. After the revoker has observed a snapshot followed by lock removal for the exact
   issued window, it stores one immutable revocation cutoff and installs the
   `AWSRevokeOlderSessions` deny on the matching backup role.
20. Each primary keeps its MFA-backed SSO session only long enough to poll a read-only
   completion-status Lambda for the opposite device and the exact shared
   `session_expires_at`.
21. When AWS reports the opposite device `REVOKED`, the clean primary authenticates to
   its own coordinator and requests a close-only `CLOSE_PEER s3`. Its VPS signs a
   short-lived close payload over `wg-cross`; the opposite VPS verifies the VPS
   signature and exact shared session deadline, then closes only its local S3 proxy
   admission.
22. Local `DONE s3`, peer close, AWS role-session revocation, and the signed one-hour
   deadline are ordered containment layers. No endpoint can use `DONE` to open or extend
   a session, and suppressing `DONE` does not preserve the S3 path after a successful
   backup has been independently observed.
```

Phone S3 is symmetric and uses a different Lambda, daily slot, role, bucket, VPS egress
IP, and repository password.

**A failed AWS SSO/MFA login does not consume the daily slot.** The failed-login alert
may fire, but Lambda has not reached the conditional DynamoDB write. The slot is consumed
only after both VPS proofs validate and the issuance gate enters its fail-closed
credential-creation path.

### Why a single compromised endpoint is not enough

A PC compromise can expose the PC phase token and can control PC-side local actions. It
cannot create the Phone-VPS signature. A Phone compromise is symmetric. **MFA alone is
therefore not sufficient to start a fresh S3 transfer:** the opposite primary must also
have a live authenticated `s3` phase so that the opposite VPS will sign the same fresh
payload. Do not turn either phase helper into an always-on daemon or pre-authorize the
absent primary.

During a legitimate joint session malware on one endpoint may share the
already-authorized window while the backup is incomplete. After a successful restic
completion has been independently observed in S3, the completion revoker cuts off the
old role session and the clean opposite primary receives read-only AWS completion state
and closes the completed endpoint's VPS S3 admission with a fresh peer-VPS-signed
close-only message. The one-hour hard deadline, separate daily slot, fixed egress IP,
bucket isolation, and per-repository RHEL capacity boundary remain final containment
layers. The design does not claim that an endpoint already authorized for its own
repository becomes harmless during the short active window.

### Why a single compromised VPS is not enough

A full root compromise of `vault-pc` exposes the PC-VPS signing key, PC coordinator,
PC S3 egress IP, and PC Tailnet Lock signer state. It still does not expose the
Phone-VPS Ed25519 signing key. AWS PC issuance and RHEL-PC opening require both Vault
VPS signatures on the same fresh payload. The Phone-VPS is the independent second
approval boundary.

### RHEL ceremony

RHEL does not trust a VPS text response such as `OPEN rhel`. The source device obtains a
fresh dual-signed `RHEL_PC` or `RHEL_PHONE` proof. The RHEL host verifies both public-key
signatures locally, validates target/date/nonce/freshness and the shared signed hard
session deadline, atomically consumes the repository-specific daily slot, arms a
systemd-managed hard-stop timer, and starts only the matching backend.

```text
RHEL_PC proof   -> PC backend only -> PC repository only -> PC quota only
RHEL_PHONE proof-> Phone backend only -> Phone repository only -> Phone quota only
```

`DONE rhel` is an authenticated early-close signal. It is not a security factor. The
hard stop does not depend on endpoint cooperation, quiet traffic, a VPS watchdog poll,
or successful primary-node expiry.

### Restricted Wi-Fi behavior

If the current Wi-Fi blocks direct WireGuard UDP:

```text
direct path fails
        ↓
Tailscale Tailscale-hosted DERP carries encrypted WireGuard packets over its relay path
        ↓
Vault authorization is unchanged
```

If the network also blocks the Tailscale control/backend/DERP HTTPS paths, the session
fails closed. There is no “connect directly to S3 without the VPS” fallback and no
“temporarily expose RHEL publicly” fallback.

## INSTALLATION ORDER — DO NOT IMPROVISE THE DEPENDENCY GRAPH

1. Read and customize the threat model.
2. Prepare the PC, Phone, password manager, MFA factors, RHEL host, and two VPSs; final break-glass/admin custody is completed by the post-install security guide.
3. Reserve one stable AWS-egress public IPv4 for each VPS and record the actual observed egress IP.
4. Build `wg-cross`, generate independent Vault VPS Ed25519 signing keys, and generate device phase tokens.
5. Create two separate Tailscale tailnets and enroll only the three expected nodes in each.
6. Enable Tailnet Lock in both tailnets and store disablement secrets offline.
7. Apply explicit deny-by-default tailnet grants and local primary-device inbound blocking.
8. Deploy the two Vault coordinators and prove that neither side can obtain a proof alone.
9. Deploy the two exact-host S3 proxies.
10. Configure the exact-device Tailscale expiry helper in each tailnet and prove fail-closed behavior.
11. Build the AWS buckets, roles, Lambda gates, DynamoDB daily slots, failed-login alerts, and budget containment.
12. Build RHEL namespaces, two tailscaled instances, two TLS/Caddy paths, two rootless backends, quotas, and the local dual-signature gate.
13. Install the complete PC and Termux daily workflows.
14. Initialize S3 and RHEL repositories through the real gates; never initialize by bypassing them.
15. Run every day-zero negative test before storing irreplaceable data.
16. Apply `PART 2A: PRODUCTION SERVICE CONFINEMENT — SYSTEMD AND PODMAN HARDENING` and pass its negative tests.
17. Apply `Vault_Post_Install_Detection_and_Credential_Custody.md` and pass its negative/health tests.
18. Record baseline capacity and begin normal operation.

## DEFINITION OF DONE

```text
[ ] Exactly two VPSs exist: vault-pc and vault-phone; both are RHEL 9 BYOL/BYOI hosts with SELinux Enforcing.
[ ] PC and Phone are in separate Tailnet Lock tailnets.
[ ] Each tailnet contains only primary + own VPS + own RHEL instance.
[ ] Tailnet Lock status is verified from the Linux infrastructure signers.
[ ] Android is a locked peer, not a signing node.
[ ] Primary inbound Tailnet connections are disabled locally.
[ ] No PC↔Phone Vault data-plane grant or receiver exists.
[ ] Each VPS has a different Ed25519 signing private key.
[ ] One VPS alone cannot produce a valid dual-signed S3/RHEL proof.
[ ] PC and Phone use different S3 buckets, roles, Lambda gates, and daily slots.
[ ] SSO gate-invoke roles cannot call S3 or AssumeRole directly.
[ ] Lambda consumes the slot before one non-retried AssumeRole attempt.
[ ] AWS CLI invocation helper pins AWS_MAX_ATTEMPTS=1.
[ ] Same issued STS credential may retry only while completion state is not REVOKED and the signed deadline remains open.
[ ] Each bucket sends snapshot-created and lock-removed events only to its own completion revoker.
[ ] Completion revocation requires snapshot evidence plus subsequent lock-removal evidence for the exact issued window.
[ ] First completion revoke cutoff is immutable; duplicate/out-of-order S3 events are idempotent.
[ ] Each backup role has an exact-bucket/fixed-egress permissions boundary before the revoker receives iam:PutRolePolicy.
[ ] Completion status is read-only and bound to exact calendar_date + session_expires_at.
[ ] A clean opposite primary can issue only close-only peer S3 containment; it cannot open, extend, or mint authority.
[ ] Budget threshold is explicitly operator-configurable; example default is USD 2/month.
[ ] Threshold action sends email and attaches automatic deny to both backup roles.
[ ] RHEL verifies both VPS signatures locally.
[ ] RHEL PC and Phone backends are separate users/services/listeners/repository trees.
[ ] RHEL repositories have independent capacity allocations/quotas.
[ ] 85% hard guard stops only the affected repository ingestion path where possible.
[ ] RHEL stores no source repository password in the baseline.
[ ] No routine forget or prune path exists.
[ ] Routine keyed content-read verification runs against hot RHEL, not Deep Archive S3.
[ ] S3 cold restore has a separate tested recovery drill.
[ ] Suppressing local DONE cannot preserve S3 admission after independently observed successful completion and peer close.
[ ] Suppressing DONE cannot extend the signed hard session deadline.
[ ] Exact own-primary Tailscale expiry ambiguity fails closed and blocks the next ceremony.
[ ] Tailscale-hosted DERP works on the real restrictive network when direct UDP does not.
[ ] The mandatory systemd/Podman service-confinement stage has been applied and its negative tests pass.
[ ] Both VPS custom Go daemons run as dedicated non-root users with reviewed DAC permissions and effective systemd sandboxing.
[ ] The mandatory post-install detection/custody guide has been applied.
[ ] Daily-slot stream alerting, Tailscale AuditWatch WIF, STS caller validation, and detector-blind alarms pass their tests.
[ ] AuditWatch stores no persistent Tailscale audit secret and has only logs:configuration:read.
[ ] AWS root has no access keys; break-glass/root/Tailnet Lock recovery secrets are outside the routine Vault data path.
[ ] vault-pc and vault-phone do not share one ordinary software SSH private key.
```

## How This Works — Core Principles

The computer and phone are **source-only backup clients**. Neither primary device runs
Vault Caddy, rest-server, WebDAV, SSH, or any other Vault receiver service. Neither
accepts Tailnet inbound connections during the backup workflow.

Each source independently sends its own plaintext data to two destinations:

```text
PC plaintext
  ├── restic → AWS S3 PC repository      (off-site)
  └── restic → RHEL /pc repository       (on-premises independent backup)

Phone plaintext
  ├── restic → AWS S3 phone repository   (off-site)
  └── restic → RHEL /phone repository    (on-premises independent backup)
```

There is deliberately **no** PC→Phone or Phone→PC backup flow. Removing the flow
eliminates the direct cross-device Caddy/rest-server attack edge rather than merely
reducing the amount of time it is open.

### Primary-device inbound prohibition

On the Fedora computer, the Tailscale session runs with Shields Up:

```bash
tailscale set --shields-up=true
tailscale set --ssh=false
```

On Android, open the Tailscale app and keep **Allow incoming connections** disabled.
The device can still initiate outbound Tailnet connections while refusing inbound
Tailnet connections.

This is defense in depth. The Tailscale grant policy also contains no PC→Phone,
Phone→PC, vault-pc→Phone, or vault-phone→PC application-data grant. The local client-side
inbound block remains valuable even if the control-plane policy is accidentally
broadened.

### Cross-VPS dual-device authorization

The former shared Control VPS latch is removed. The PC and phone now belong to two
separate security compartments and each primary device authenticates only to its own
VPS:

```text
PC    → vault-pc VPS
Phone → vault-phone VPS
```

Each VPS stores only its own device phase-token verifier and its own Ed25519 signing
private key. The two VPSs are joined by a dedicated point-to-point `wg-cross` tunnel.
When the PC requests an `s3` or `rhel` ceremony, `vault-pc` creates a fresh canonical
payload and signs it. `vault-phone` signs the **same bytes** only while the phone has a
live authenticated socket in the same phase. The reverse rule applies to phone
ceremonies.

The resulting proof bundle contains:

```text
canonical ceremony payload
+ PC-VPS Ed25519 signature
+ Phone-VPS Ed25519 signature
```

AWS Lambda and the local RHEL gate verify both signatures themselves. A VPS is not
trusted to report that the other VPS approved the ceremony. Therefore compromise of
one VPS, one phase token, one primary endpoint, or one relay host does not by itself
create a valid two-signature authorization proof under the stated single-compromise
threat model.

A few seconds of manual skew are expected. The local coordinator waits up to 10 minutes
for the opposite device to join the same phase. Once a proof has been issued, a brief
control-socket loss alone does not revoke an already-issued STS credential or an
already-open RHEL backend. Before successful S3 completion revocation, transient
S3 data-plane retries may reuse the same credential; after the exact slot reaches
`REVOKED`, old-session reuse is intentionally denied. RHEL retries remain possible while
the same bounded backend window is open. The AWS and RHEL daily slots prevent a second
issuance/opening ceremony.

If single-device backup later becomes legitimate, redesign the proof policy. Do not
simulate the absent device, copy its phase token, or copy a VPS signing private key.

### S3 completion revocation and cross-device close are security factors; local `DONE` is not

A compromised primary endpoint can suppress its own `DONE` message after a legitimate
ceremony has already opened. Therefore **no S3 security guarantee in this generation
assumes that malware will cooperate with local `DONE`**.

The S3 close path is asymmetric by design:

```text
OPEN:
  local live s3 phase
  AND opposite live s3 phase
  AND PC-VPS signature
  AND Phone-VPS signature
  AND device-specific SSO/MFA
  AND unused device/day slot

CLOSE AFTER SUCCESS:
  local DONE may close own proxy immediately
  AND AWS independently observes:
        new snapshots/<id>
        followed by repository locks/<id> removal
      inside the exact issued session window
  AND AWS revokes role sessions older than one immutable cutoff
  AND clean opposite primary polls read-only completion state
  AND clean opposite primary requests CLOSE_PEER s3
  AND opposite VPS verifies peer-VPS signature + exact shared deadline
  OR signed one-hour hard deadline expires
```

Restic saves the snapshot only after its backup tree/blob work has completed. The
ordinary backup command holds an append lock and releases that lock when the command
unwinds. The completion revoker therefore does **not** revoke on `snapshots/` creation
alone. It records snapshot evidence and lock-removal evidence for the same issued
window, tolerates duplicate or out-of-order S3 notifications, and transitions the slot
to `REVOKED` only when both have been observed in the safe order. A periodic
reconciliation invocation checks the strongly consistent S3 namespace for the same
condition if a notification is delayed or missed.

The revocation Lambda writes the matching backup role's inline
`AWSRevokeOlderSessions` deny with:

```text
aws:TokenIssueTime < completion_revoke_cutoff
```

The first stored cutoff is immutable and reused for duplicate events. Future daily
sessions issue after that cutoff and are not denied merely because the old revocation
policy remains attached. Because IAM policy changes are not instantaneous, the Vault
does not rely on IAM propagation as its only immediate close mechanism.

Both daily workflows preserve their MFA-backed SSO session through a short S3 completion
barrier. Each device asks the read-only `Vault-S3-Completion-Status` Lambda only about
the opposite role and the exact `calendar_date + session_expires_at` decoded from its
own dual-signed proof. When AWS reports that exact opposite slot as `REVOKED`, the clean
device sends:

```text
CLOSE_PEER s3 <own phase token>
```

to **its own** coordinator. The caller cannot select an arbitrary target. Its coordinator
derives the opposite role, signs a fresh close-only payload with its own VPS Ed25519 key,
and sends it across `wg-cross`. The receiving VPS accepts `CLOSE` only from the exact
peer WireGuard IP, verifies the peer VPS signature, checks a <=90-second freshness
window, requires `target_role == its own role`, and requires the signed
`session_expires_at` to equal the currently active shared deadline. It then closes only
its local S3 phase/proxy admission.

`CLOSE_PEER` has no proof-issuance, STS, RHEL-open, deadline-extension, or slot-reset
authority. A compromised primary may abuse its own close token to close the opposite
S3 path early and cause denial of service; under the single-compromise threat model
that fail-safe close authority is preferable to giving one compromised endpoint a veto
over containment.

This changes the intended S3 residual risk:

```text
OLD residual:
  malware can suppress DONE and use the already-issued STS/proxy path until one hour

CURRENT residual:
  malware can share the legitimate incomplete-backup window
  successful completion -> AWS completion observation -> peer close / IAM revocation
  S3 event/status/close propagation is not zero-millisecond
  if a successful snapshot is never created, the backup never completed and the
    signed one-hour deadline remains the final ceiling
```

`DONE rhel` remains an authenticated early-close/cleanup trigger rather than a security
factor. RHEL has no equivalent S3 repository-event completion plane; its locally
verified dual-signed proof and systemd-managed hard-stop timer remain the security
boundary.

At the hard session deadline, each VPS independently denies new proof/admission use and
atomically queues expiry of **its own** primary Tailnet node. This hard-expiry path does
not depend on `DONE`, S3 event delivery, IAM propagation, or successful peer close.

### Secret placement

Each primary device stores only routine secrets needed to back up **its own** data:

| File | Purpose |
|---|---|
| `~/.config/vault-secrets/own_restic_pw` | The source device own restic repository password |
| `~/.config/vault-secrets/rhel_htpasswd` | Client credential for that source dedicated RHEL listener |
| `~/.config/vault-secrets/oracle_phase_token` | Historical filename retained for compatibility; unique token used only with that device own VPS coordinator |

Directory mode is `700`; secret file mode is `600`.

AWS uses browser-authenticated IAM Identity Center / SSO. The PC and phone use different
one-hour routine permission sets and profiles. Those SSO roles have **no S3, DynamoDB,
IAM, or `sts:AssumeRole` permission**. Each may invoke only its device-specific Lambda
issuance gate plus the shared read-only `Vault-S3-Completion-Status` Lambda. The issuance
gate returns one-hour STS credentials for the corresponding S3 backup role after the
cross-VPS proof and daily slot checks succeed. The status Lambda returns only exact-session
completion state. The scripts hold STS credentials in process memory/environment only and
unset them immediately after their S3 backup command succeeds.

The PC never stores the phone restic password, phone phase token, or Phone-VPS private
signing key. The phone never stores the PC equivalents. Both VPS public signing keys are
copied to AWS Lambda and RHEL because public keys are not secrets; private signing keys
remain on their owning VPS only.

---


### Two-compartment VPS infrastructure invariant — **2 VPS required**

The canonical baseline uses two independent security compartments:

```text
vault-pc
    member/signing node in PC Tailscale tailnet
    PC Vault device coordinator
    PC Vault Ed25519 signing private key
    PC exact-host S3 CONNECT proxy
    PC stable AWS-approved public egress IPv4
    PC exact-device Tailscale expiry helper

vault-phone
    member/signing node in Phone Tailscale tailnet
    Phone Vault device coordinator
    Phone Vault Ed25519 signing private key
    Phone exact-host S3 CONNECT proxy
    Phone stable AWS-approved public egress IPv4
    Phone exact-device Tailscale expiry helper

vault-pc <-> dedicated wg-cross <-> vault-phone
```

The primary devices never join the same tailnet. RHEL runs two isolated `tailscaled`
instances in separate Linux network namespaces, one per tailnet. The VPS public IPv4
addresses are not public backup listeners; they are stable outbound identities for the
S3 `aws:SourceIp` policy and endpoints for the narrow VPS-to-VPS WireGuard link.

Tailscale-hosted DERP is the default relay fallback. The baseline opens no public
Peer Relay UDP/40000 and runs no self-hosted DERP listener on either Vault VPS.

A single VPS root compromise is modeled conservatively as loss of that compartment's
Vault signing key, coordinator, Tailnet Lock signer key, and approved S3 egress IP. It
does not provide the opposite Vault VPS Ed25519 key. Cross-VPS proofs therefore remain
mandatory even with Tailnet Lock enabled.

## Security Model

```text
Threat priority:
  T1/T2 — one compromised primary endpoint
  VPS-C — one fully compromised compartment VPS

Security objective:
  one device or one VPS must not independently create a fresh S3 STS session or open
  a fresh RHEL repository backend.

PC
  inbound PC-tailnet: DENY (Shields Up)
  local Vault listener: NONE
  source key: PC own_restic_pw only
       │
       ├── PC VPS local phase token
       ├── PC SSO/MFA role → invoke PC Lambda gate only
       ├── PC VPS exact-host S3 proxy → PC bucket only
       └── RHEL PC listener → PC backend only

Phone
  inbound Phone-tailnet: DENY (Allow incoming OFF)
  local Vault listener: NONE
  source key: Phone own_restic_pw only
       │
       ├── Phone VPS local phase token
       ├── Phone SSO/MFA role → invoke Phone Lambda gate only
       ├── Phone VPS exact-host S3 proxy → Phone bucket only
       └── RHEL Phone listener → Phone backend only

Fresh S3 authorization:
  valid PC-VPS signature
  AND valid Phone-VPS signature
  AND device-specific SSO/MFA caller permission
  AND device/day DynamoDB slot is absent

Fresh RHEL authorization:
  valid PC-VPS signature
  AND valid Phone-VPS signature
  AND repository/day local slot is absent
```

Direct Tailscale transport and Tailscale-hosted DERP are transport mechanisms only. Managed
DERP relays encrypted WireGuard packets and does not create either Vault VPS Ed25519
private key. The canonical baseline runs no public relay listener on either Vault VPS.
If the Peer Relay extension is later enabled, the added UDP/40000 surface is assessed
there and the opposite-VPS signature requirement remains unchanged.

The design accepts chained multi-boundary exploitation as residual tail risk. For
example, simultaneous compromise of both VPS signing keys, or compromise of a primary
endpoint combined with compromise of the opposite signing VPS during a legitimate live
phase, is outside the single-compromise guarantee and belongs in the risk register.

---

## Section 0 — Primary Device Baseline

### Fedora computer

```bash
getenforce
# Must print: Enforcing

sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --runtime-to-permanent
sudo firewall-cmd --reload

sudo dnf install -y restic rclone libnotify tailscale awscli2 python3
mkdir -p ~/Vault_PC_Ciphertext ~/bin ~/.local/log/vault-sync ~/.config/vault-secrets
chmod 700 ~/.config/vault-secrets
chmod 600 ~/.config/vault-secrets/* 2>/dev/null || true
```

No firewall rule opens port `8000` on the PC. There is no PC rest-server or Caddy
listener in this architecture.

### Android / Termux

Install Termux, Termux:API, and Termux:Widget from the same source. Then:

```bash
pkg update && pkg upgrade -y
pkg install restic termux-api python openssl coreutils netcat-openbsd awscli -y

`awscli` is a required Termux package in this guide, not an implied external dependency.
The unified phone workflow calls `aws sso login --profile vault-phone-gate`,
`aws sts get-caller-identity`, and `aws lambda invoke` against the Phone-specific
issuance gate. It does **not** export an SSO role into restic and the SSO permission set
has no direct S3 access. Immediately after package installation, verify:

```bash
aws --version
```

Later, after `vault-phone-gate` is configured in Section 22, the device-specific SSO
and Lambda smoke tests in that section are mandatory. If the Termux AWS CLI package is
temporarily broken on your device/architecture, stop the S3 rollout and resolve that
client issue; do not replace SSO with long-lived static AWS keys as a shortcut.
termux-setup-storage
mkdir -p ~/Vault_Phone_Ciphertext ~/bin ~/.shortcuts ~/.local/log/vault-sync ~/.config/vault-secrets
chmod 700 ~/.config/vault-secrets
chmod 600 ~/.config/vault-secrets/* 2>/dev/null || true
```

The phone does not install or run rest-server or Caddy for Vault backup reception.
Keep `~/Vault_Phone_Ciphertext` in Termux private internal storage.

---

## Section 1 — Source Restic Passwords

Generate a different high-entropy restic password for each source repository family.
The same source password is used by that source's S3 and RHEL repositories so the
unified script can load one `own_restic_pw`; the repositories remain separate and have
independent repository master keys created during `restic init`.

On the PC:

```bash
install -m 600 /dev/null ~/.config/vault-secrets/own_restic_pw
# Paste the PC source restic password, then remove any accidental extra blank lines.
```

On the phone:

```bash
install -m 600 /dev/null ~/.config/vault-secrets/own_restic_pw
# Paste the Phone source restic password.
```

Store both authoritative recovery copies in the password manager. Do not copy either
source password to the other primary device.

---

## Section 2 — Device-Specific VPS Phase Tokens

Generate a different 256-bit token on each primary device. The historical filename
`oracle_phase_token` is retained so the already-audited local secret layout does not
need a rename migration; there is no Oracle/shared coordinator in this architecture.

Run this independently on the PC and phone:

```bash
mkdir -p ~/.config/vault-secrets
chmod 700 ~/.config/vault-secrets
umask 077
python3 -c 'import secrets,sys; sys.stdout.write(secrets.token_hex(32))' \
    > ~/.config/vault-secrets/oracle_phase_token
chmod 600 ~/.config/vault-secrets/oracle_phase_token

python3 - << 'PY'
from hashlib import sha256
from pathlib import Path
p = Path.home() / ".config" / "vault-secrets" / "oracle_phase_token"
token = p.read_text(encoding="ascii").strip()
print(sha256(token.encode("ascii")).hexdigest())
PY
```

Provision only the PC verifier to `vault-pc` and only the phone verifier to
`vault-phone`:

```text
vault-pc:
  /etc/vault-device/phase-token.sha256 = PC verifier only

vault-phone:
  /etc/vault-device/phase-token.sha256 = Phone verifier only
```

Never put both raw tokens or both verifiers on one VPS. The coordinator derives only
the local-device identity from its own verifier; the opposite device approval is proven
by the opposite VPS Ed25519 signature.

## Section 3 — Two Separate Tailscale Tailnets, Tailnet Lock, and Outbound-Only Invariant

The PC and Phone are deliberately placed in different tailnets:

```text
PC tailnet:    PC + vault-pc + RHEL-PC tailscaled instance
Phone tailnet: Phone + vault-phone + RHEL-Phone tailscaled instance
```

Tailnet Lock is mandatory in both tailnets. The exact initialization and signer layout
are documented in Section 24. The baseline uses `vault-pc + RHEL-PC` as PC-tailnet
signers and `vault-phone + RHEL-Phone` as Phone-tailnet signers. Android cannot be a
Tailnet Lock signing node; the Phone remains a signed/locked peer.

On Fedora, keep local inbound blocking enabled:

```bash
tailscale set --shields-up=true
tailscale set --ssh=false
```

On Android, keep **Allow incoming connections** disabled and do not enable Tailscale SSH.

Each tailnet policy is explicit-default-deny and grants the primary only its own VPS
coordinator/proxy and its own RHEL listener. There is no cross-tailnet PC↔Phone Vault
path. The local inbound block remains valuable even if a tailnet policy is accidentally
broadened.

**Invariant:** a clean primary device never needs another tailnet node to initiate a
Vault application connection to it.

---

## Section 4 — Integrity and Capacity Philosophy

Routine keyed repository verification is split by storage tier:

```text
HOT RHEL REPOSITORY
    source device owns the restic password
    source device performs structural checks and staged content-read verification
    preferred schedule is Saturday: 1/4, then 2/4, then 3/4, then 4/4, repeating
    if a scheduled Saturday is missed, the pending stage runs on the first later successful RHEL transfer; the stage number advances only after success
    four successful stages read the complete hot repository approximately once per four-stage cycle

S3 GLACIER DEEP ARCHIVE
    no routine --read-data-subset in the daily workflow
    cold pack objects may require an archive restore delay before reads
    integrity assurance is backup success + S3 protections + a separate tested restore drill
```

Do not add PAR2 to the S3 Deep Archive repository. PAR2 would create a second parity
object lifecycle and still would not make cold archive packs immediately readable; the
archive restore workflow remains necessary before ordinary reads. PAR2 is relevant only
when an extension introduces a local ciphertext repository/mirror whose raw pack bytes
are directly available, as documented in the mutual-backup extension.

For no-prune mode, repository growth is measured instead of guessed:

- log `data_added_packed` from successful backup JSON summaries;
- log physical RHEL repository size and filesystem/quota utilization;
- warn at 70%;
- require urgent capacity review at 80%; and
- stop new ingestion at 85%.

The 85% threshold is a **migration trigger**, not permission to run an ad-hoc prune.
Follow `Vault_Extension_Capacity_Triggered_Prune_and_Maintenance.md` if the baseline
outgrows the receiver.

Small frequently edited Markdown/source files create historical churn, but the key
capacity metric is the total amount of new packed content produced over time. Large
mutable VM disk images, databases, packet captures, and unbounded logs are the primary
scope risks.

---

## Section 5 — Recovery Principle

The PC and phone do not recover from one another. Device loss is recovered from RHEL
or S3:

```text
Phone lost  → new phone + Phone restic password → restore from RHEL /phone or S3 phone bucket
PC lost     → new PC    + PC restic password    → restore from RHEL /pc or S3 PC bucket
```

RHEL is the preferred on-premises recovery source when reachable. S3 is the off-site
recovery source. Deep Archive restores may require the AWS retrieval workflow before
restic can read cold objects; follow the S3 section's cold-storage warnings.

---

## Retention Mode — Keep-All-History / No-Prune

This variant intentionally contains no routine `restic forget` or `restic prune` path. RHEL stores no source repository password. Capacity pressure is handled by the 70/80/85 monitoring model and the separate retention-migration roadmap.


## Section 22 - AWS S3: Two Buckets, Cross-VPS Proofs, Daily STS Issuance, and Cost Containment

> **Architecture invariant:** S3 has two independent compartments. The PC may receive
> temporary credentials only for the PC bucket and the phone only for the Phone bucket.
> A fresh STS issuance requires both VPS signatures and may occur only once per
> `Europe/Istanbul` calendar day for that device.

### 22.1 Final S3 architecture

```text
PC SSO/MFA
  ↓
Vault-PC-Gate-Invoke permission set
  ├── invoke Vault-PC-S3-Gate only for fresh issuance
  │     + PC-VPS signed proof
  │     + Phone-VPS signed proof
  │       ↓
  │   DynamoDB conditional consume: S3#PC#YYYY-MM-DD
  │       ↓
  │   AssumeRole ONCE, no STS retry
  │       ↓
  │   Vault-PC-S3-BackupRole, 1 hour maximum
  │       ↓ aws:SourceIp = PC VPS reserved IPv4/32
  │   PC VPS exact-host CONNECT proxy
  │       ↓
  │   vault-pc-<unique> bucket only
  │
  └── invoke shared Vault-S3-Completion-Status read-only Lambda
        workflow queries opposite device + exact date/session_expires_at; function
        returns state only when the stored session deadline matches exactly

S3 successful completion:
  snapshot object created
        + later matching lock object removed
        ↓
  device-specific completion revoker writes AWSRevokeOlderSessions cutoff
        ↓
  exact completion row becomes REVOKED
        ↓
  clean opposite primary requests signed CLOSE_PEER
        ↓
  target VPS closes local S3 proxy admission without target DONE cooperation

Phone: symmetric, with PHONE slot, Phone role, Phone VPS egress IP and Phone bucket.
```

The direct Lambda API is used through `aws lambda invoke`. Do not expose a Lambda
Function URL and do not place a long-lived AWS access key on either VPS. The device SSO
role authenticates the Lambda invocation; the Lambda independently verifies both
Ed25519 signatures.

### 22.2 Create two buckets

Create two globally unique lowercase buckets in the chosen S3 region:

```text
vault-pc-yourname
vault-phone-yourname
```

Enable versioning and Block Public Access on both. Do not use one bucket with two
prefixes as the primary isolation boundary.

The daily backup role must not receive archive restore/admin authority. Keep disaster
recovery in a separate MFA-protected administrator/recovery permission path.

### 22.3 Generate the two VPS signing keypairs

Run on `vault-pc`:

```bash
sudo install -d -o root -g root -m 700 /etc/vault-device
sudo openssl genpkey -algorithm ED25519 -out /etc/vault-device/signing-key.pem
sudo chmod 600 /etc/vault-device/signing-key.pem
sudo openssl pkey -in /etc/vault-device/signing-key.pem -pubout   -out /etc/vault-device/signing-key.pub.pem
```

Repeat independently on `vault-phone`.

Exchange **public keys only**. Install both public keys in AWS Lambda configuration and
on RHEL. Never copy a private signing key off its owning VPS.

### 22.4 Create the DynamoDB daily-slot table

Create an on-demand table:

```text
Table name: VaultDailyIssuanceSlots
Partition key: pk (String)
Billing mode: PAY_PER_REQUEST
```

No midnight reset job exists. The calendar date is part of the key:

```text
S3#PC#2026-07-15
S3#PHONE#2026-07-15
```

The issuance Lambda computes the current `Europe/Istanbul` date. A new day naturally
uses a new key. The same row also becomes the S3 completion state record:

```text
pk
ceremony_id
consumed_at
session_expires_at
completion_state = OPEN | REVOKING | REVOKED
snapshot_seen_at / snapshot_key
lock_removed_at / lock_key
completion_revoke_cutoff
completion_revoked_at
```

The issuance gate creates the row with `completion_state=OPEN`. Only the device-specific
completion revoker may add completion evidence or transition the row to `REVOKED`.
Retain old rows as a small audit trail or apply a later TTL policy only for housekeeping;
deleting them is not part of the security decision.

**Calendar-boundary consequence:** this is deliberately a calendar-day rate limit, not a
rolling 24-hour counter. A valid ceremony immediately before `00:00 Europe/Istanbul`
and another valid ceremony immediately after midnight can consume two different daily
slots and therefore create up to two one-hour issuance windows near the boundary. This
is the documented worst case and is why cost/anomaly alerts and the configurable budget
containment layer remain independent controls. Do not describe the gate as “at most one
issuance in every rolling 24 hours.”

### 22.5 Create two S3 backup roles

Create:

```text
Vault-PC-S3-BackupRole
Vault-Phone-S3-BackupRole
```

Set maximum role session duration to one hour. The trust policy of each role must allow
`sts:AssumeRole` only from the corresponding Lambda execution role.

PC role S3 policy, replacing names and the reserved public IPv4:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PCBucket",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::vault-pc-yourname",
      "Condition": {"IpAddress": {"aws:SourceIp": "PC_VPS_RESERVED_IPV4/32"}}
    },
    {
      "Sid": "PCObjects",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::vault-pc-yourname/*",
      "Condition": {"IpAddress": {"aws:SourceIp": "PC_VPS_RESERVED_IPV4/32"}}
    },
    {
      "Sid": "PCLockCleanup",
      "Effect": "Allow",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::vault-pc-yourname/locks/*",
      "Condition": {"IpAddress": {"aws:SourceIp": "PC_VPS_RESERVED_IPV4/32"}}
    },
    {
      "Sid": "DenyVersionDelete",
      "Effect": "Deny",
      "Action": "s3:DeleteObjectVersion",
      "Resource": "arn:aws:s3:::vault-pc-yourname/*"
    }
  ]
}
```

Create the symmetric Phone policy for `vault-phone-yourname` and
`PHONE_VPS_RESERVED_IPV4/32`.

**Do not** give either backup role access to the other bucket. Add a bucket policy
explicit deny for the opposite backup-role ARN as defense in depth.

Create a managed permissions-boundary policy for each backup role from the same exact
repository policy document and attach it as that role's permissions boundary **before**
the completion revoker receives `iam:PutRolePolicy`. This is a compensating control for
the completion Lambda's IAM write primitive: even if that Lambda is compromised and
tries to replace the inline repository policy with a broader allow, the role's effective
permissions remain capped by its own bucket and fixed egress envelope.

### 22.6 Create the two SSO gate-invocation permission sets

Enable IAM Identity Center and require MFA for the dedicated Vault user. Create two
one-hour permission sets:

```text
Vault-PC-Gate-Invoke
Vault-Phone-Gate-Invoke
```

PC inline policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "lambda:InvokeFunction",
    "Resource": [
      "arn:aws:lambda:REGION:ACCOUNT_ID:function:Vault-PC-S3-Gate",
      "arn:aws:lambda:REGION:ACCOUNT_ID:function:Vault-S3-Completion-Status"
    ]
  }]
}
```

Phone uses only `Vault-Phone-S3-Gate` plus the same read-only
`Vault-S3-Completion-Status` function.

These roles intentionally have no `s3:*`, no `sts:AssumeRole`, no DynamoDB permission,
and no completion-revoker/IAM write authority. The status Lambda performs the read on
their behalf and returns only non-secret completion state for an exact session key.

Configure separate profiles:

```text
PC profile:    vault-pc-gate
Phone profile: vault-phone-gate
```

Smoke test each device:

```bash
aws sso login --profile vault-pc-gate
aws sts get-caller-identity --profile vault-pc-gate
aws sso logout
```

Use the matching Phone profile on Android/Termux.

### 22.7 Deploy the two Lambda issuance gates

Use Node.js 22.x and package `@aws-sdk/client-dynamodb` plus
`@aws-sdk/client-sts` with the function. The same source is deployed twice with
different environment variables.

`index.mjs`:

```javascript
import crypto from 'node:crypto';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';

const device = process.env.DEVICE?.toLowerCase();
if (!['pc', 'phone'].includes(device)) throw new Error('DEVICE must be pc or phone');

const expectedTarget = device === 'pc' ? 'S3_PC' : 'S3_PHONE';
const tableName = process.env.TABLE_NAME;
const backupRoleArn = process.env.BACKUP_ROLE_ARN;
const pcPublicKey = Buffer.from(process.env.PC_PUBLIC_KEY_PEM_B64, 'base64').toString('utf8');
const phonePublicKey = Buffer.from(process.env.PHONE_PUBLIC_KEY_PEM_B64, 'base64').toString('utf8');

const ddb = new DynamoDBClient({});
// Exactly one total AssumeRole attempt. If AWS creates credentials but the response is
// lost, retrying AssumeRole could create a second live session. The daily slot remains
// consumed and the ceremony fails closed.
const sts = new STSClient({ maxAttempts: 1 });

function istanbulDate(date) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Europe/Istanbul', year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(date);
  const map = Object.fromEntries(parts.map(p => [p.type, p.value]));
  return `${map.year}-${map.month}-${map.day}`;
}

function fail(message, code = 'Denied') {
  const err = new Error(message);
  err.name = code;
  throw err;
}

function decodeBundle(event) {
  if (!event || typeof event !== 'object') fail('request must be a JSON object', 'InvalidRequest');
  for (const k of ['payload', 'pc_signature', 'phone_signature']) {
    if (typeof event[k] !== 'string' || event[k].length < 8) fail(`missing ${k}`, 'InvalidRequest');
  }
  const raw = Buffer.from(event.payload, 'base64');
  const pcSig = Buffer.from(event.pc_signature, 'base64');
  const phoneSig = Buffer.from(event.phone_signature, 'base64');
  if (raw.length > 4096 || pcSig.length !== 64 || phoneSig.length !== 64) fail('invalid proof sizes');
  if (!crypto.verify(null, raw, pcPublicKey, pcSig)) fail('PC VPS signature verification failed');
  if (!crypto.verify(null, raw, phonePublicKey, phoneSig)) fail('Phone VPS signature verification failed');
  let payload;
  try { payload = JSON.parse(raw.toString('utf8')); } catch { fail('invalid payload JSON'); }
  return payload;
}

function validatePayload(p) {
  if (p.version !== 1 || p.target !== expectedTarget) fail('wrong proof target');
  if (!/^[0-9a-f]{32}$/.test(p.ceremony_id ?? '')) fail('invalid ceremony_id');
  if (!/^[0-9a-f]{64}$/.test(p.nonce ?? '')) fail('invalid nonce');
  const issued = new Date(p.issued_at);
  const expires = new Date(p.expires_at);
  const now = new Date();
  if (Number.isNaN(issued.valueOf()) || Number.isNaN(expires.valueOf())) fail('invalid timestamps');
  const lifetime = expires.valueOf() - issued.valueOf();
  if (lifetime <= 0 || lifetime > 90_000) fail('invalid proof lifetime');
  if (now.valueOf() < issued.valueOf() - 30_000 || now.valueOf() > expires.valueOf()) fail('proof expired or not yet valid');
  const sessionExpires = new Date(p.session_expires_at);
  if (Number.isNaN(sessionExpires.valueOf())) fail('invalid session_expires_at');
  if (sessionExpires.valueOf() <= now.valueOf() ||
      sessionExpires.valueOf() - issued.valueOf() <= 0 ||
      sessionExpires.valueOf() - issued.valueOf() > 3_600_000) {
    fail('invalid or expired Vault session deadline');
  }
  const today = istanbulDate(now);
  if (p.calendar_date !== today) fail('calendar date mismatch');
  return today;
}

export const handler = async (event) => {
  const payload = decodeBundle(event);
  const today = validatePayload(payload);
  const slot = `S3#${device.toUpperCase()}#${today}`;
  const consumedAt = new Date().toISOString();

  try {
    await ddb.send(new PutItemCommand({
      TableName: tableName,
      Item: {
        pk: { S: slot },
        ceremony_id: { S: payload.ceremony_id },
        consumed_at: { S: consumedAt },
        session_expires_at: { S: payload.session_expires_at },
        completion_state: { S: 'OPEN' }
      },
      ConditionExpression: 'attribute_not_exists(pk)'
    }));
  } catch (err) {
    if (err?.name === 'ConditionalCheckFailedException') fail('daily S3 issuance slot already consumed', 'DailySlotConsumed');
    throw err;
  }

  // SECURITY INVARIANT: exactly one SDK attempt. Do not wrap this in a retry loop.
  const response = await sts.send(new AssumeRoleCommand({
    RoleArn: backupRoleArn,
    RoleSessionName: `vault-${device}-${today.replaceAll('-', '')}-${payload.ceremony_id.slice(0, 12)}`,
    DurationSeconds: 3600
  }));
  const c = response.Credentials;
  if (!c?.AccessKeyId || !c?.SecretAccessKey || !c?.SessionToken || !c?.Expiration) {
    fail('STS returned incomplete credentials', 'STSFailure');
  }
  return {
    Version: 1,
    AccessKeyId: c.AccessKeyId,
    SecretAccessKey: c.SecretAccessKey,
    SessionToken: c.SessionToken,
    Expiration: c.Expiration.toISOString()
  };
};
```

PC function environment:

```text
DEVICE=pc
TABLE_NAME=VaultDailyIssuanceSlots
BACKUP_ROLE_ARN=<Vault-PC-S3-BackupRole ARN>
PC_PUBLIC_KEY_PEM_B64=<base64 of PC VPS public PEM>
PHONE_PUBLIC_KEY_PEM_B64=<base64 of Phone VPS public PEM>
```

Phone function uses `DEVICE=phone` and the Phone backup-role ARN.

Lambda execution-role minimum permissions:

```text
dynamodb:PutItem on VaultDailyIssuanceSlots
sts:AssumeRole on its one device-specific backup role
CloudWatch Logs write permissions
```

The STS client in the code is deliberately configured for **one total attempt**. Do
not wrap `AssumeRole` in an application retry loop.

Security/failure semantics:

```text
daily slot consume
        ↓
AssumeRole one attempt
        ↓
clear success → return STS credentials
anything ambiguous/failing → slot remains consumed; no second STS call that day
```

This restriction applies only to credential creation. After one credential is
successfully issued, restic/S3 request retries, reconnects, and transient data-plane
retries are allowed with that **same credential only while the backup is incomplete,
the completion state has not reached `REVOKED`, and the signed hard deadline remains
open**. A successful backup is expected to lose both its VPS admission path and its old
role-session permissions before the one-hour maximum.

### 22.7A Deploy the device-specific S3 completion revokers

A one-hour STS credential is only the maximum credential lifetime. It is **not** the
normal successful-backup lifetime.

Each bucket has its own completion revoker:

```text
Vault-PC-S3-Completion-Revoker
Vault-Phone-S3-Completion-Revoker
```

The revoker receives two repository events from only its own bucket:

```text
ObjectCreated:* under snapshots/
ObjectRemoved:* under locks/
```

Restic creates a snapshot only after its backup tree/blob work has completed. The normal
backup command holds an append lock and releases it when the command unwinds. Therefore
the revoker stores both pieces of evidence and revokes only after:

```text
snapshot_seen_at exists
AND lock_removed_at exists
AND lock_removed_at >= snapshot_seen_at
AND both event times belong to the exact consumed_at .. session_expires_at window
```

This state machine intentionally tolerates S3's duplicate and out-of-order event
delivery. The first stored `completion_revoke_cutoff` is immutable. The cutoff is the
recorded lock-removal event time, not Lambda observation time, so a delayed duplicate
cannot revoke a later legitimate session merely because the event was delivered late.

Before granting `iam:PutRolePolicy` to a completion revoker, attach an exact
bucket/fixed-egress permissions boundary to the corresponding backup role. The boundary
does not grant permissions. It caps any later inline-policy change so compromise of the
revoker cannot broaden the backup role beyond the same repository envelope.

The revoker writes only the standard-named inline deny:

```text
AWSRevokeOlderSessions
```

with `aws:TokenIssueTime < completion_revoke_cutoff`.

A five-minute scheduled reconciliation invokes the same function with
`{"reconcile":true}`. It checks the S3 namespace only for a currently relevant
unrevoked slot. If a matching snapshot exists and no repository lock remains, it may
synthesize completion evidence only when no newer same-device issuance exists.

Completion revoker source (`index.mjs`):

```javascript
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { IAMClient, PutRolePolicyCommand } from '@aws-sdk/client-iam';
import { S3Client, ListObjectsV2Command } from '@aws-sdk/client-s3';

const device = process.env.DEVICE?.toLowerCase();
if (!['pc', 'phone'].includes(device)) throw new Error('DEVICE must be pc or phone');

const tableName = process.env.TABLE_NAME;
const bucketName = process.env.BUCKET_NAME;
const backupRoleName = process.env.BACKUP_ROLE_NAME;
if (!tableName || !bucketName || !backupRoleName) throw new Error('missing required environment');

const ddb = new DynamoDBClient({});
const iam = new IAMClient({});
const s3 = new S3Client({});

function istanbulDate(date) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Europe/Istanbul', year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(date);
  const map = Object.fromEntries(parts.map(p => [p.type, p.value]));
  return `${map.year}-${map.month}-${map.day}`;
}

function slotKey(date) {
  return `S3#${device.toUpperCase()}#${date}`;
}

function eventCandidateDates(date) {
  return [...new Set([istanbulDate(date), istanbulDate(new Date(date.valueOf() - 2 * 60 * 60 * 1000))])];
}

async function getSlot(date) {
  const out = await ddb.send(new GetItemCommand({
    TableName: tableName,
    Key: { pk: { S: slotKey(date) } },
    ConsistentRead: true
  }));
  return out.Item;
}

function parseWindow(item) {
  if (!item?.consumed_at?.S || !item?.session_expires_at?.S) return null;
  const consumed = new Date(item.consumed_at.S);
  const deadline = new Date(item.session_expires_at.S);
  if (Number.isNaN(consumed.valueOf()) || Number.isNaN(deadline.valueOf())) return null;
  return { consumed, deadline };
}

function eventInside(item, eventTime) {
  const w = parseWindow(item);
  return !!w && eventTime.valueOf() >= w.consumed.valueOf() &&
    eventTime.valueOf() <= w.deadline.valueOf();
}

async function findSlotForEvent(eventTime) {
  for (const date of eventCandidateDates(eventTime)) {
    const item = await getSlot(date);
    if (item && eventInside(item, eventTime)) return { date, item };
  }
  return null;
}

async function recordSnapshot(date, key, eventTime) {
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: tableName,
      Key: { pk: { S: slotKey(date) } },
      UpdateExpression: 'SET snapshot_seen_at = if_not_exists(snapshot_seen_at, :t), snapshot_key = if_not_exists(snapshot_key, :k)',
      ConditionExpression: 'attribute_exists(pk) AND (attribute_not_exists(completion_state) OR completion_state <> :revoked)',
      ExpressionAttributeValues: {
        ':t': { S: eventTime.toISOString() },
        ':k': { S: key },
        ':revoked': { S: 'REVOKED' }
      }
    }));
  } catch (err) {
    if (err?.name !== 'ConditionalCheckFailedException') throw err;
  }
}

async function recordLockRemoved(date, key, eventTime) {
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: tableName,
      Key: { pk: { S: slotKey(date) } },
      UpdateExpression: 'SET lock_removed_at = :t, lock_key = :k',
      ConditionExpression: 'attribute_exists(pk) AND (attribute_not_exists(lock_removed_at) OR lock_removed_at < :t) AND (attribute_not_exists(completion_state) OR completion_state <> :revoked)',
      ExpressionAttributeValues: {
        ':t': { S: eventTime.toISOString() },
        ':k': { S: key },
        ':revoked': { S: 'REVOKED' }
      }
    }));
  } catch (err) {
    if (err?.name !== 'ConditionalCheckFailedException') throw err;
  }
}

async function maybeRevoke(date) {
  const item = await getSlot(date);
  if (!item || item.completion_state?.S === 'REVOKED') return false;

  const snapshotSeen = item.snapshot_seen_at?.S ? new Date(item.snapshot_seen_at.S) : null;
  const lockRemoved = item.lock_removed_at?.S ? new Date(item.lock_removed_at.S) : null;
  if (!snapshotSeen || !lockRemoved ||
      Number.isNaN(snapshotSeen.valueOf()) || Number.isNaN(lockRemoved.valueOf()) ||
      lockRemoved.valueOf() < snapshotSeen.valueOf()) return false;

  let attrs;
  try {
    const out = await ddb.send(new UpdateItemCommand({
      TableName: tableName,
      Key: { pk: { S: slotKey(date) } },
      UpdateExpression: 'SET completion_revoke_cutoff = if_not_exists(completion_revoke_cutoff, :cutoff), completion_state = :revoking',
      ConditionExpression: 'attribute_exists(pk) AND (attribute_not_exists(completion_state) OR completion_state <> :revoked)',
      ExpressionAttributeValues: {
        ':cutoff': { S: lockRemoved.toISOString() },
        ':revoking': { S: 'REVOKING' },
        ':revoked': { S: 'REVOKED' }
      },
      ReturnValues: 'ALL_NEW'
    }));
    attrs = out.Attributes;
  } catch (err) {
    if (err?.name === 'ConditionalCheckFailedException') return false;
    throw err;
  }

  const cutoff = attrs?.completion_revoke_cutoff?.S;
  if (!cutoff) throw new Error('completion revoke cutoff missing after state transition');

  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Sid: 'RevokeOlderVaultBackupSessions',
      Effect: 'Deny',
      Action: '*',
      Resource: '*',
      Condition: { DateLessThan: { 'aws:TokenIssueTime': cutoff } }
    }]
  };

  await iam.send(new PutRolePolicyCommand({
    RoleName: backupRoleName,
    PolicyName: 'AWSRevokeOlderSessions',
    PolicyDocument: JSON.stringify(policy)
  }));

  await ddb.send(new UpdateItemCommand({
    TableName: tableName,
    Key: { pk: { S: slotKey(date) } },
    UpdateExpression: 'SET completion_state = :revoked, completion_revoked_at = :now',
    ExpressionAttributeValues: {
      ':revoked': { S: 'REVOKED' },
      ':now': { S: new Date().toISOString() }
    }
  }));
  return true;
}

async function listWithin(prefix, consumed, deadline) {
  const matches = [];
  let ContinuationToken;
  do {
    const out = await s3.send(new ListObjectsV2Command({
      Bucket: bucketName,
      Prefix: prefix,
      ContinuationToken
    }));
    for (const obj of out.Contents ?? []) {
      const t = obj.LastModified;
      if (t && t.valueOf() >= consumed.valueOf() && t.valueOf() <= deadline.valueOf()) {
        matches.push({ key: obj.Key, time: t });
      }
    }
    ContinuationToken = out.IsTruncated ? out.NextContinuationToken : undefined;
  } while (ContinuationToken);
  return matches;
}

async function newerSlotExists(consumedAt) {
  const now = new Date();
  for (const date of eventCandidateDates(now)) {
    const item = await getSlot(date);
    if (!item?.consumed_at?.S) continue;
    const other = new Date(item.consumed_at.S);
    if (!Number.isNaN(other.valueOf()) && other.valueOf() > consumedAt.valueOf()) return true;
  }
  return false;
}

async function reconcile() {
  const now = new Date();
  for (const date of eventCandidateDates(now)) {
    let item = await getSlot(date);
    if (!item || item.completion_state?.S === 'REVOKED') continue;
    const w = parseWindow(item);
    if (!w || now.valueOf() > w.deadline.valueOf() + 5 * 60 * 1000) continue;

    const snapshots = await listWithin('snapshots/', w.consumed, w.deadline);
    if (snapshots.length === 0) continue;
    snapshots.sort((a, b) => a.time - b.time);
    const firstSnapshot = snapshots[0];
    await recordSnapshot(date, firstSnapshot.key, firstSnapshot.time);

    // A missing lock is used only as reconciliation evidence while no newer same-device
    // issuance exists. Normal completion uses the S3 lock-removal event timestamp.
    const locks = await listWithin('locks/', w.consumed, w.deadline);
    if (locks.length === 0 && !(await newerSlotExists(w.consumed))) {
      await recordLockRemoved(date, 'RECONCILED_NO_ACTIVE_LOCK', now);
    }
    await maybeRevoke(date);
  }
}

export const handler = async (event) => {
  if (event?.reconcile === true) {
    await reconcile();
    return { Version: 1, Reconciled: true };
  }

  for (const record of event?.Records ?? []) {
    if (record?.eventSource !== 'aws:s3') continue;
    const key = decodeURIComponent((record.s3?.object?.key ?? '').replace(/\+/g, ' '));
    const eventTime = new Date(record.eventTime);
    if (Number.isNaN(eventTime.valueOf())) continue;

    const found = await findSlotForEvent(eventTime);
    if (!found) continue;

    if (record.eventName?.startsWith('ObjectCreated:') && key.startsWith('snapshots/')) {
      await recordSnapshot(found.date, key, eventTime);
    } else if (record.eventName?.startsWith('ObjectRemoved:') && key.startsWith('locks/')) {
      await recordLockRemoved(found.date, key, eventTime);
    } else {
      continue;
    }
    await maybeRevoke(found.date);
  }

  return { Version: 1, Processed: true };
};
```

Device-specific environment:

```text
PC:
  DEVICE=pc
  TABLE_NAME=VaultDailyIssuanceSlots
  BUCKET_NAME=<PC bucket>
  BACKUP_ROLE_NAME=Vault-PC-S3-BackupRole

Phone:
  DEVICE=phone
  TABLE_NAME=VaultDailyIssuanceSlots
  BUCKET_NAME=<Phone bucket>
  BACKUP_ROLE_NAME=Vault-Phone-S3-BackupRole
```

Each completion execution role is separate and receives only:

```text
dynamodb:GetItem + dynamodb:UpdateItem on VaultDailyIssuanceSlots
s3:ListBucket on its exact bucket, restricted to snapshots/* and locks/*
iam:PutRolePolicy on its exact backup role
CloudWatch Logs write
```

It receives no `sts:AssumeRole`, no S3 object read/write, no opposite bucket, and no
opposite backup role.

### 22.7B Deploy the read-only S3 completion-status Lambda

The clean opposite primary needs a non-secret answer to one question:

> Has AWS independently completed revocation for the opposite device's exact shared
> Vault session?

Deploy one function:

```text
Vault-S3-Completion-Status
```

It has only `dynamodb:GetItem` on `VaultDailyIssuanceSlots`. It cannot update the slot,
change IAM, assume a role, or access S3.

Source (`index.mjs`):

```javascript
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';

const tableName = process.env.TABLE_NAME;
if (!tableName) throw new Error('TABLE_NAME is required');
const ddb = new DynamoDBClient({});

function fail(message) {
  const err = new Error(message);
  err.name = 'InvalidRequest';
  throw err;
}

export const handler = async (event) => {
  const device = event?.device?.toLowerCase();
  const calendarDate = event?.calendar_date;
  const sessionExpiresAt = event?.session_expires_at;
  if (!['pc', 'phone'].includes(device)) fail('device must be pc or phone');
  if (!/^\\d{4}-\\d{2}-\\d{2}$/.test(calendarDate ?? '')) fail('invalid calendar_date');
  const deadline = new Date(sessionExpiresAt);
  if (typeof sessionExpiresAt !== 'string' || Number.isNaN(deadline.valueOf())) fail('invalid session_expires_at');

  const pk = `S3#${device.toUpperCase()}#${calendarDate}`;
  const out = await ddb.send(new GetItemCommand({
    TableName: tableName,
    Key: { pk: { S: pk } },
    ConsistentRead: true
  }));
  const item = out.Item;
  if (!item || item.session_expires_at?.S !== sessionExpiresAt) {
    return { Version: 1, Completed: false, CompletionState: 'ABSENT_OR_SESSION_MISMATCH' };
  }

  const state = item.completion_state?.S ?? 'OPEN';
  return {
    Version: 1,
    Completed: state === 'REVOKED',
    CompletionState: state,
    CompletionRevokedAt: item.completion_revoked_at?.S ?? null
  };
};
```

Environment:

```text
TABLE_NAME=VaultDailyIssuanceSlots
```

Request:

```json
{
  "device": "phone",
  "calendar_date": "2026-07-16",
  "session_expires_at": "2026-07-16T20:15:00Z"
}
```

The caller must supply the exact `calendar_date` and `session_expires_at` decoded from
its own dual-signed S3 proof. A row for another date or another shared deadline is
reported as `ABSENT_OR_SESSION_MISMATCH`.

Both Identity Center gate permission sets may invoke this read-only status function in
addition to their own device-specific issuance gate. They still receive no S3 or
`sts:AssumeRole` authority.

### 22.8 Device invocation and credential export

The phase helper in Section 23 writes a proof JSON file. Invoke the matching Lambda:

PC:

```bash
aws lambda invoke   --profile vault-pc-gate   --function-name Vault-PC-S3-Gate   --cli-binary-format raw-in-base64-out   --payload "fileb://$HOME/.local/run/vault/s3-proof.json"   "$HOME/.local/run/vault/sts.json"

eval "$(
python3 - "$HOME/.local/run/vault/sts.json" << 'PY'
import json, shlex, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
for env,key in [
    ("AWS_ACCESS_KEY_ID","AccessKeyId"),
    ("AWS_SECRET_ACCESS_KEY","SecretAccessKey"),
    ("AWS_SESSION_TOKEN","SessionToken"),
]:
    print(f"export {env}={shlex.quote(d[key])}")
PY
)"
```

Phone uses its profile/function. Immediately after the S3 phase:

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
rm -f ~/.local/run/vault/sts.json ~/.local/run/vault/s3-proof.json
aws sso logout
```

Do not request a second Lambda issuance if the STS file was not produced. Investigate
the failed ceremony and allow the next Istanbul calendar day to create a new slot.

### 22.9 Failed sign-in alert

Keep the CloudTrail/EventBridge/SNS failed `CredentialVerification` alert. The expected
sign-in failure event shape remains:

```text
eventSource = signin.amazonaws.com
eventName   = CredentialVerification
serviceEventDetails.CredentialVerification = Failure
```

Test the rule end to end with one deliberate failed Vault-user sign-in.

### 22.10 Configurable USD 2 monthly budget: email + automatic S3 deny

Create a monthly **cost budget** named:

```text
Vault-Emergency-Cost-Containment
```

Reference default:

```text
Budget amount: USD 2.00/month
Threshold: 100% ACTUAL
```

**USD 2.00 is an example default, not a fixed security constant.** Change it to match
the expected S3 storage, request, retrieval, Lambda, DynamoDB, and related AWS cost
profile after observing normal usage.

If the AWS account also runs unrelated workloads, scope the budget/filtering so normal
non-Vault spend does not trip the Vault containment action. The automatic action still
targets only the two Vault backup roles.

At the same 100% actual threshold configure:

1. email notification to the operator; and
2. an **automatic AWS Budgets IAM-policy action**.

Create a customer-managed policy:

```text
VaultBudgetAlwaysDenyS3
```

with:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EmergencyAlwaysDenyS3",
    "Effect": "Deny",
    "Action": "s3:*",
    "Resource": "*"
  }]
}
```

Configure the automatic budget action to attach this policy to **both**
`Vault-PC-S3-BackupRole` and `Vault-Phone-S3-BackupRole`. Create the required AWS
Budgets service role with only the permissions required for that attachment action.

This emergency deny stops the backup principals from creating further S3 request/API
cost through their roles, not merely from uploading larger objects. It does not make
AWS billing telemetry real time. Treat it as delayed containment; the daily issuance
slots are the hard preventative rate limit.

Document the manual recovery procedure separately. Do not automatically detach the deny
policy merely because the next month begins.

### 22.11 Repository initialization

Initialize PC and Phone repositories through their normal dual-signature ceremony and
device-specific Lambda gate. The one-time init consumes that device daily issuance slot.

PC:

```bash
restic -r "s3:s3.us-east-1.amazonaws.com/vault-pc-yourname"   -o s3.bucket-lookup=path init --repository-version 2
```

Phone uses `vault-phone-yourname`.

The normal backup command may request:

```bash
-o s3.storage-class=DEEP_ARCHIVE
```

Keep the existing cold-storage disaster-recovery caveats: cold restore is a separate
recovery operation and must be tested after restic upgrades.

### 22.12 Copy/paste AWS deployment runbook

The preceding subsections define the security properties. This subsection turns them
into a reproducible build. Use an administrator workstation for the one-time AWS setup;
do not use either VPS as the AWS administrator workstation.

#### 22.12.1 Install and verify AWS CLI v2

On Fedora:

```bash
aws --version
```

If AWS CLI v2 is not installed, install it using the current AWS-supported installation
method for your architecture. After installation:

```bash
aws --version
aws configure list
```

Do not create a long-lived `default` access-key profile merely to follow this guide.
Use your existing administrator access path for setup, then use IAM Identity Center for
the daily Vault device profiles.

Set deployment variables in the current administrator shell. Replace every placeholder:

```bash
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="123456789012"
export PC_BUCKET="vault-pc-REPLACE_WITH_GLOBALLY_UNIQUE_SUFFIX"
export PHONE_BUCKET="vault-phone-REPLACE_WITH_GLOBALLY_UNIQUE_SUFFIX"
export PC_AWS_EGRESS_PUBLIC_IP="203.0.113.10"
export PHONE_AWS_EGRESS_PUBLIC_IP="198.51.100.20"
export SLOT_TABLE="VaultDailyIssuanceSlots"

# These are the stable public source addresses that AWS S3 actually observes for
# outbound TCP connections created by each compartment's exact-host CONNECT proxy.
# The canonical Tailscale/managed-DERP baseline normally uses one stable public IPv4
# per VPS. It is the address that the VPS actually uses for outbound S3 TCP connections.
# Do not guess from a provider console label. On each VPS, before creating the IAM
# policies below, run:
#
#   curl -4 https://checkip.amazonaws.com
#
# Record the stable/reserved result as PC_AWS_EGRESS_PUBLIC_IP or
# PHONE_AWS_EGRESS_PUBLIC_IP. If it changes after a reboot or address reassignment,
# stop here and fix provider routing/public-IP attachment first. Section 23 then
# performs a real through-proxy S3 positive/negative test; that test is authoritative.

printf '%s\n' \
  "AWS_REGION=$AWS_REGION" \
  "AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID" \
  "PC_BUCKET=$PC_BUCKET" \
  "PHONE_BUCKET=$PHONE_BUCKET" \
  "PC_AWS_EGRESS_PUBLIC_IP=$PC_AWS_EGRESS_PUBLIC_IP" \
  "PHONE_AWS_EGRESS_PUBLIC_IP=$PHONE_AWS_EGRESS_PUBLIC_IP"
```

Sanity check the bucket names before creating anything:

```bash
python3 - <<'PY'
import os,re
for name in (os.environ['PC_BUCKET'], os.environ['PHONE_BUCKET']):
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', name):
        raise SystemExit(f'invalid S3 bucket name: {name!r}')
if os.environ['PC_BUCKET'] == os.environ['PHONE_BUCKET']:
    raise SystemExit('PC_BUCKET and PHONE_BUCKET must differ')
print('bucket-name sanity check: OK')
PY
```

#### 22.12.2 Create the two buckets and enable baseline protections

For `us-east-1`:

```bash
aws s3api create-bucket \
  --region "$AWS_REGION" \
  --bucket "$PC_BUCKET"

aws s3api create-bucket \
  --region "$AWS_REGION" \
  --bucket "$PHONE_BUCKET"
```

For another region, use the matching `LocationConstraint` required by S3 in that
region and update every endpoint/policy example in the guide consistently.

Block all public access:

```bash
for BUCKET in "$PC_BUCKET" "$PHONE_BUCKET"; do
  aws s3api put-public-access-block \
    --region "$AWS_REGION" \
    --bucket "$BUCKET" \
    --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

done
```

Enable versioning:

```bash
for BUCKET in "$PC_BUCKET" "$PHONE_BUCKET"; do
  aws s3api put-bucket-versioning \
    --region "$AWS_REGION" \
    --bucket "$BUCKET" \
    --versioning-configuration Status=Enabled

done
```

Verify:

```bash
for BUCKET in "$PC_BUCKET" "$PHONE_BUCKET"; do
  echo "=== $BUCKET ==="
  aws s3api get-public-access-block --bucket "$BUCKET"
  aws s3api get-bucket-versioning --bucket "$BUCKET"
done
```

Expected result: all four public-access flags are `true` and versioning status is
`Enabled` for both buckets.

#### 22.12.3 Create the DynamoDB security-state table

```bash
aws dynamodb create-table \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE" \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

aws dynamodb wait table-exists \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE"

aws dynamodb describe-table \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE" \
  --query 'Table.{Name:TableName,Status:TableStatus,BillingMode:BillingModeSummary.BillingMode,KeySchema:KeySchema}'
```

Expected status is `ACTIVE`. Do not give either primary device permission to write this
table. Only the two Lambda execution roles may perform the conditional `PutItem` used
by the issuance gates.

The table is security state. A support script must **not** delete today's row to “fix” a
failed backup. If an issuance fails after the row was consumed, the correct operational
response is to investigate and wait for the next Istanbul calendar day.

#### 22.12.4 Create Lambda execution roles

Create trust policy:

```bash
cat > /tmp/vault-lambda-trust.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
JSON
```

Create the two roles:

```bash
aws iam create-role \
  --role-name Vault-PC-S3-Gate-ExecutionRole \
  --assume-role-policy-document file:///tmp/vault-lambda-trust.json

aws iam create-role \
  --role-name Vault-Phone-S3-Gate-ExecutionRole \
  --assume-role-policy-document file:///tmp/vault-lambda-trust.json
```

Attach the AWS-managed basic logging policy to each execution role:

```bash
for ROLE in Vault-PC-S3-Gate-ExecutionRole Vault-Phone-S3-Gate-ExecutionRole; do
  aws iam attach-role-policy \
    --role-name "$ROLE" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
done
```

Do not attach general S3 permissions to these roles.

Record ARNs:

```bash
export PC_LAMBDA_ROLE_ARN="$(aws iam get-role --role-name Vault-PC-S3-Gate-ExecutionRole --query 'Role.Arn' --output text)"
export PHONE_LAMBDA_ROLE_ARN="$(aws iam get-role --role-name Vault-Phone-S3-Gate-ExecutionRole --query 'Role.Arn' --output text)"
printf 'PC Lambda role: %s\nPhone Lambda role: %s\n' "$PC_LAMBDA_ROLE_ARN" "$PHONE_LAMBDA_ROLE_ARN"
```

#### 22.12.4A Create completion-revoker and completion-status execution roles

The S3 completion path uses three additional Lambda execution roles. Keep the PC and
Phone revokers separate so neither function can mutate the opposite backup role. The
shared status function is read-only.

```bash
for ROLE in \
  Vault-PC-S3-Completion-ExecutionRole \
  Vault-Phone-S3-Completion-ExecutionRole \
  Vault-S3-Completion-Status-ExecutionRole; do
  aws iam create-role \
    --role-name "$ROLE" \
    --assume-role-policy-document file:///tmp/vault-lambda-trust.json

  aws iam attach-role-policy \
    --role-name "$ROLE" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
done

export PC_COMPLETION_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-PC-S3-Completion-ExecutionRole \
  --query 'Role.Arn' --output text)"
export PHONE_COMPLETION_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-Phone-S3-Completion-ExecutionRole \
  --query 'Role.Arn' --output text)"
export COMPLETION_STATUS_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-S3-Completion-Status-ExecutionRole \
  --query 'Role.Arn' --output text)"

printf 'PC completion role: %s\nPhone completion role: %s\nStatus role: %s\n' \
  "$PC_COMPLETION_ROLE_ARN" "$PHONE_COMPLETION_ROLE_ARN" "$COMPLETION_STATUS_ROLE_ARN"
```

Do not attach an AWS-managed S3 or IAM administration policy to these roles. Exact
least-privilege inline policies are installed only after the backup-role permissions
boundaries in Section 22.12.5 are visibly attached.

#### 22.12.5 Create the two device-specific S3 backup roles

PC backup-role trust policy:

```bash
cat > /tmp/vault-pc-backup-trust.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "$PC_LAMBDA_ROLE_ARN"},
    "Action": "sts:AssumeRole"
  }]
}
JSON
```

Phone backup-role trust policy:

```bash
cat > /tmp/vault-phone-backup-trust.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "$PHONE_LAMBDA_ROLE_ARN"},
    "Action": "sts:AssumeRole"
  }]
}
JSON
```

Create roles and explicitly cap maximum session duration at one hour:

```bash
aws iam create-role \
  --role-name Vault-PC-S3-BackupRole \
  --max-session-duration 3600 \
  --assume-role-policy-document file:///tmp/vault-pc-backup-trust.json

aws iam create-role \
  --role-name Vault-Phone-S3-BackupRole \
  --max-session-duration 3600 \
  --assume-role-policy-document file:///tmp/vault-phone-backup-trust.json

export PC_BACKUP_ROLE_ARN="$(aws iam get-role --role-name Vault-PC-S3-BackupRole --query 'Role.Arn' --output text)"
export PHONE_BACKUP_ROLE_ARN="$(aws iam get-role --role-name Vault-Phone-S3-BackupRole --query 'Role.Arn' --output text)"
```

Create the PC role policy:

```bash
cat > /tmp/vault-pc-s3-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PCBucketMetadata",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::$PC_BUCKET",
      "Condition": {"IpAddress": {"aws:SourceIp": "$PC_AWS_EGRESS_PUBLIC_IP/32"}}
    },
    {
      "Sid": "PCRepositoryObjects",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::$PC_BUCKET/*",
      "Condition": {"IpAddress": {"aws:SourceIp": "$PC_AWS_EGRESS_PUBLIC_IP/32"}}
    },
    {
      "Sid": "PCRepositoryLockCleanup",
      "Effect": "Allow",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::$PC_BUCKET/locks/*",
      "Condition": {"IpAddress": {"aws:SourceIp": "$PC_AWS_EGRESS_PUBLIC_IP/32"}}
    },
    {
      "Sid": "DenyVersionDeletion",
      "Effect": "Deny",
      "Action": "s3:DeleteObjectVersion",
      "Resource": "arn:aws:s3:::$PC_BUCKET/*"
    }
  ]
}
JSON
```

Create the symmetric Phone policy:

```bash
cat > /tmp/vault-phone-s3-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PhoneBucketMetadata",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::$PHONE_BUCKET",
      "Condition": {"IpAddress": {"aws:SourceIp": "$PHONE_AWS_EGRESS_PUBLIC_IP/32"}}
    },
    {
      "Sid": "PhoneRepositoryObjects",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::$PHONE_BUCKET/*",
      "Condition": {"IpAddress": {"aws:SourceIp": "$PHONE_AWS_EGRESS_PUBLIC_IP/32"}}
    },
    {
      "Sid": "PhoneRepositoryLockCleanup",
      "Effect": "Allow",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::$PHONE_BUCKET/locks/*",
      "Condition": {"IpAddress": {"aws:SourceIp": "$PHONE_AWS_EGRESS_PUBLIC_IP/32"}}
    },
    {
      "Sid": "DenyVersionDeletion",
      "Effect": "Deny",
      "Action": "s3:DeleteObjectVersion",
      "Resource": "arn:aws:s3:::$PHONE_BUCKET/*"
    }
  ]
}
JSON
```

Attach as role inline policies:

```bash
aws iam put-role-policy \
  --role-name Vault-PC-S3-BackupRole \
  --policy-name Vault-PC-S3-RepositoryAccess \
  --policy-document file:///tmp/vault-pc-s3-policy.json

aws iam put-role-policy \
  --role-name Vault-Phone-S3-BackupRole \
  --policy-name Vault-Phone-S3-RepositoryAccess \
  --policy-document file:///tmp/vault-phone-s3-policy.json
```

Create exact permissions-boundary policies from the same reviewed documents and attach
them to the matching backup roles:

```bash
export PC_BACKUP_BOUNDARY_ARN="$(aws iam create-policy \
  --policy-name Vault-PC-S3-BackupBoundary \
  --policy-document file:///tmp/vault-pc-s3-policy.json \
  --query 'Policy.Arn' --output text)"

export PHONE_BACKUP_BOUNDARY_ARN="$(aws iam create-policy \
  --policy-name Vault-Phone-S3-BackupBoundary \
  --policy-document file:///tmp/vault-phone-s3-policy.json \
  --query 'Policy.Arn' --output text)"

aws iam put-role-permissions-boundary \
  --role-name Vault-PC-S3-BackupRole \
  --permissions-boundary "$PC_BACKUP_BOUNDARY_ARN"

aws iam put-role-permissions-boundary \
  --role-name Vault-Phone-S3-BackupRole \
  --permissions-boundary "$PHONE_BACKUP_BOUNDARY_ARN"

aws iam get-role --role-name Vault-PC-S3-BackupRole \
  --query '{RoleName:Role.RoleName,Boundary:Role.PermissionsBoundary.PermissionsBoundaryArn}'

aws iam get-role --role-name Vault-Phone-S3-BackupRole \
  --query '{RoleName:Role.RoleName,Boundary:Role.PermissionsBoundary.PermissionsBoundaryArn}'
```

Do not grant `iam:PutRolePolicy` to either completion revoker until these two boundary
ARNs are visibly attached to the exact backup roles.

Verify there is no cross-bucket resource ARN in either policy:

```bash
aws iam get-role-policy --role-name Vault-PC-S3-BackupRole \
  --policy-name Vault-PC-S3-RepositoryAccess --query 'PolicyDocument'

aws iam get-role-policy --role-name Vault-Phone-S3-BackupRole \
  --policy-name Vault-Phone-S3-RepositoryAccess --query 'PolicyDocument'
```

#### 22.12.6 Add bucket-side opposite-role explicit denies

The identity policies above should already provide no cross-bucket allow. The bucket
policies add a second, resource-side invariant: the opposite backup role receives an
explicit deny even if a future administrator accidentally broadens an identity policy.

PC bucket policy:

```bash
cat > /tmp/vault-pc-bucket-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ExplicitlyDenyPhoneBackupRole",
    "Effect": "Deny",
    "Principal": {"AWS": "$PHONE_BACKUP_ROLE_ARN"},
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::$PC_BUCKET",
      "arn:aws:s3:::$PC_BUCKET/*"
    ]
  }]
}
JSON

aws s3api put-bucket-policy \
  --bucket "$PC_BUCKET" \
  --policy file:///tmp/vault-pc-bucket-policy.json
```

Phone bucket policy:

```bash
cat > /tmp/vault-phone-bucket-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ExplicitlyDenyPCBackupRole",
    "Effect": "Deny",
    "Principal": {"AWS": "$PC_BACKUP_ROLE_ARN"},
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::$PHONE_BUCKET",
      "arn:aws:s3:::$PHONE_BUCKET/*"
    ]
  }]
}
JSON

aws s3api put-bucket-policy \
  --bucket "$PHONE_BUCKET" \
  --policy file:///tmp/vault-phone-bucket-policy.json
```

Do not replace the policies with `Principal: "*"` deny rules unless you fully understand
the condition logic. An accidental broad deny can lock out the administrator/recovery
path as well.

#### 22.12.7 Give each Lambda role only `PutItem` and its one `AssumeRole`

PC Lambda policy:

```bash
cat > /tmp/vault-pc-lambda-security-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ConsumeDailySlot",
      "Effect": "Allow",
      "Action": "dynamodb:PutItem",
      "Resource": "arn:aws:dynamodb:$AWS_REGION:$AWS_ACCOUNT_ID:table/$SLOT_TABLE"
    },
    {
      "Sid": "AssumeOnlyPCBackupRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "$PC_BACKUP_ROLE_ARN"
    }
  ]
}
JSON
```

Phone Lambda policy:

```bash
cat > /tmp/vault-phone-lambda-security-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ConsumeDailySlot",
      "Effect": "Allow",
      "Action": "dynamodb:PutItem",
      "Resource": "arn:aws:dynamodb:$AWS_REGION:$AWS_ACCOUNT_ID:table/$SLOT_TABLE"
    },
    {
      "Sid": "AssumeOnlyPhoneBackupRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "$PHONE_BACKUP_ROLE_ARN"
    }
  ]
}
JSON
```

Attach:

```bash
aws iam put-role-policy \
  --role-name Vault-PC-S3-Gate-ExecutionRole \
  --policy-name Vault-PC-Gate-SecurityState \
  --policy-document file:///tmp/vault-pc-lambda-security-policy.json

aws iam put-role-policy \
  --role-name Vault-Phone-S3-Gate-ExecutionRole \
  --policy-name Vault-Phone-Gate-SecurityState \
  --policy-document file:///tmp/vault-phone-lambda-security-policy.json
```

#### 22.12.7A Grant completion revokers and status Lambda exact least privilege

First re-read the permissions-boundary ARN on both backup roles. Stop if either result is
empty:

```bash
aws iam get-role --role-name Vault-PC-S3-BackupRole \
  --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text
aws iam get-role --role-name Vault-Phone-S3-BackupRole \
  --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text
```

Create the PC completion policy:

```bash
cat > /tmp/vault-pc-completion-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadAndUpdateOwnCompletionState",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem"],
      "Resource": "arn:aws:dynamodb:$AWS_REGION:$AWS_ACCOUNT_ID:table/$SLOT_TABLE"
    },
    {
      "Sid": "ListOnlyOwnCompletionPrefixes",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::$PC_BUCKET",
      "Condition": {"StringLike": {"s3:prefix": ["snapshots/*", "locks/*"]}}
    },
    {
      "Sid": "WriteOnlyOwnRoleRevocationPolicy",
      "Effect": "Allow",
      "Action": "iam:PutRolePolicy",
      "Resource": "$PC_BACKUP_ROLE_ARN"
    }
  ]
}
JSON
```

Create the symmetric Phone policy:

```bash
cat > /tmp/vault-phone-completion-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadAndUpdateOwnCompletionState",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem"],
      "Resource": "arn:aws:dynamodb:$AWS_REGION:$AWS_ACCOUNT_ID:table/$SLOT_TABLE"
    },
    {
      "Sid": "ListOnlyOwnCompletionPrefixes",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::$PHONE_BUCKET",
      "Condition": {"StringLike": {"s3:prefix": ["snapshots/*", "locks/*"]}}
    },
    {
      "Sid": "WriteOnlyOwnRoleRevocationPolicy",
      "Effect": "Allow",
      "Action": "iam:PutRolePolicy",
      "Resource": "$PHONE_BACKUP_ROLE_ARN"
    }
  ]
}
JSON
```

The status Lambda receives only a consistent `GetItem` path to the slot table:

```bash
cat > /tmp/vault-completion-status-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ReadCompletionStateOnly",
    "Effect": "Allow",
    "Action": "dynamodb:GetItem",
    "Resource": "arn:aws:dynamodb:$AWS_REGION:$AWS_ACCOUNT_ID:table/$SLOT_TABLE"
  }]
}
JSON

aws iam put-role-policy \
  --role-name Vault-PC-S3-Completion-ExecutionRole \
  --policy-name Vault-PC-S3-Completion-LeastPrivilege \
  --policy-document file:///tmp/vault-pc-completion-policy.json

aws iam put-role-policy \
  --role-name Vault-Phone-S3-Completion-ExecutionRole \
  --policy-name Vault-Phone-S3-Completion-LeastPrivilege \
  --policy-document file:///tmp/vault-phone-completion-policy.json

aws iam put-role-policy \
  --role-name Vault-S3-Completion-Status-ExecutionRole \
  --policy-name Vault-S3-Completion-Status-ReadOnly \
  --policy-document file:///tmp/vault-completion-status-policy.json
```

The completion roles deliberately have no `sts:AssumeRole`, no S3 object read/write,
and no permission over the opposite backup role or bucket. `iam:PutRolePolicy` is the
minimum AWS control used here to install the documented role-session revocation deny;
the exact backup-role permissions boundary is the compensating maximum-permission cap.

#### 22.12.8 Package the Lambda code

On the administrator workstation:

```bash
mkdir -p ~/vault-lambda-gate
cd ~/vault-lambda-gate
npm init -y
npm install @aws-sdk/client-dynamodb @aws-sdk/client-sts
```

Copy the exact `index.mjs` source from Section 22.7 into:

```text
~/vault-lambda-gate/index.mjs
```

Syntax check:

```bash
node --check index.mjs
```

Create deployment ZIP from inside the directory:

```bash
zip -r /tmp/vault-s3-gate.zip index.mjs package.json package-lock.json node_modules
unzip -l /tmp/vault-s3-gate.zip | sed -n '1,30p'
```

The ZIP root must contain `index.mjs`; do not accidentally create a ZIP whose root is
`vault-lambda-gate/index.mjs`.

#### 22.12.8A Package the completion-revoker and completion-status Lambda code

Package the exact completion source from Section 22.7A:

```bash
rm -rf ~/vault-lambda-completion
mkdir -p ~/vault-lambda-completion
cd ~/vault-lambda-completion
npm init -y
npm install @aws-sdk/client-dynamodb @aws-sdk/client-iam @aws-sdk/client-s3
```

Copy Section 22.7A's exact `index.mjs` into:

```text
~/vault-lambda-completion/index.mjs
```

Then:

```bash
node --check index.mjs
zip -r /tmp/vault-s3-completion.zip \
  index.mjs package.json package-lock.json node_modules
```

Package the exact read-only status source from Section 22.7B separately:

```bash
rm -rf ~/vault-lambda-completion-status
mkdir -p ~/vault-lambda-completion-status
cd ~/vault-lambda-completion-status
npm init -y
npm install @aws-sdk/client-dynamodb
```

Copy Section 22.7B's exact `index.mjs` into:

```text
~/vault-lambda-completion-status/index.mjs
```

Then:

```bash
node --check index.mjs
zip -r /tmp/vault-s3-completion-status.zip \
  index.mjs package.json package-lock.json node_modules
```

For both ZIP files, `index.mjs` must be at ZIP root.

#### 22.12.9 Collect the two VPS public keys for Lambda configuration

On `vault-pc`:

```bash
sudo cat /etc/vault-device/signing-key.pub.pem
```

On `vault-phone`:

```bash
sudo cat /etc/vault-device/signing-key.pub.pem
```

Copy **public PEM only** to the administrator workstation and save as:

```text
/tmp/pc-vps-signing-key.pub.pem
/tmp/phone-vps-signing-key.pub.pem
```

Then:

```bash
export PC_PUBLIC_KEY_PEM_B64="$(base64 -w0 /tmp/pc-vps-signing-key.pub.pem)"
export PHONE_PUBLIC_KEY_PEM_B64="$(base64 -w0 /tmp/phone-vps-signing-key.pub.pem)"
```

If your `base64` implementation does not support `-w0`, use:

```bash
export PC_PUBLIC_KEY_PEM_B64="$(base64 /tmp/pc-vps-signing-key.pub.pem | tr -d '\n')"
export PHONE_PUBLIC_KEY_PEM_B64="$(base64 /tmp/phone-vps-signing-key.pub.pem | tr -d '\n')"
```

Never run the corresponding command on either private PEM file.

#### 22.12.10 Create the two Lambda functions

Create the functions. Lambda role creation can take a short time to become usable by
Lambda; if the first `create-function` reports that the role cannot yet be assumed,
verify the trust policy and rerun the administrator command later. This setup retry is
not the security-sensitive STS issuance retry discussed elsewhere; no daily slot exists
yet.

```bash
aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name Vault-PC-S3-Gate \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$PC_LAMBDA_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-s3-gate.zip \
  --timeout 15 \
  --memory-size 128

aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name Vault-Phone-S3-Gate \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$PHONE_LAMBDA_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-s3-gate.zip \
  --timeout 15 \
  --memory-size 128
```

Use JSON files for environment variables; this avoids fragile shell quoting of base64
PEM data:

```bash
python3 - <<'PY'
import json,os
common={
  'TABLE_NAME': os.environ['SLOT_TABLE'],
  'PC_PUBLIC_KEY_PEM_B64': os.environ['PC_PUBLIC_KEY_PEM_B64'],
  'PHONE_PUBLIC_KEY_PEM_B64': os.environ['PHONE_PUBLIC_KEY_PEM_B64'],
}
for device,role,path in [
  ('pc',os.environ['PC_BACKUP_ROLE_ARN'],'/tmp/pc-lambda-env.json'),
  ('phone',os.environ['PHONE_BACKUP_ROLE_ARN'],'/tmp/phone-lambda-env.json'),
]:
    env=dict(common, DEVICE=device, BACKUP_ROLE_ARN=role)
    with open(path,'w',encoding='utf-8') as f:
        json.dump({'Variables':env},f,separators=(',',':'))
PY

aws lambda update-function-configuration \
  --region "$AWS_REGION" \
  --function-name Vault-PC-S3-Gate \
  --environment file:///tmp/pc-lambda-env.json

aws lambda update-function-configuration \
  --region "$AWS_REGION" \
  --function-name Vault-Phone-S3-Gate \
  --environment file:///tmp/phone-lambda-env.json
```

Wait until both functions are active:

```bash
aws lambda wait function-active-v2 --region "$AWS_REGION" --function-name Vault-PC-S3-Gate
aws lambda wait function-active-v2 --region "$AWS_REGION" --function-name Vault-Phone-S3-Gate
```

Verify configuration without printing the public-key values unnecessarily:

```bash
for FN in Vault-PC-S3-Gate Vault-Phone-S3-Gate; do
  aws lambda get-function-configuration \
    --region "$AWS_REGION" \
    --function-name "$FN" \
    --query '{FunctionName:FunctionName,Runtime:Runtime,Handler:Handler,Timeout:Timeout,MemorySize:MemorySize,Role:Role,LastUpdateStatus:LastUpdateStatus}'
done
```

#### 22.12.10A Create and configure completion/status functions

Create the two device-specific completion revokers and the shared read-only status
function:

```bash
aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name Vault-PC-S3-Completion-Revoker \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$PC_COMPLETION_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-s3-completion.zip \
  --timeout 30 \
  --memory-size 256

aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name Vault-Phone-S3-Completion-Revoker \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$PHONE_COMPLETION_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-s3-completion.zip \
  --timeout 30 \
  --memory-size 256

aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name Vault-S3-Completion-Status \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$COMPLETION_STATUS_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-s3-completion-status.zip \
  --timeout 10 \
  --memory-size 128
```

Create environment files:

```bash
python3 - <<'PY'
import json, os

configs = {
    '/tmp/pc-completion-env.json': {
        'DEVICE': 'pc',
        'TABLE_NAME': os.environ['SLOT_TABLE'],
        'BUCKET_NAME': os.environ['PC_BUCKET'],
        'BACKUP_ROLE_NAME': 'Vault-PC-S3-BackupRole',
    },
    '/tmp/phone-completion-env.json': {
        'DEVICE': 'phone',
        'TABLE_NAME': os.environ['SLOT_TABLE'],
        'BUCKET_NAME': os.environ['PHONE_BUCKET'],
        'BACKUP_ROLE_NAME': 'Vault-Phone-S3-BackupRole',
    },
    '/tmp/completion-status-env.json': {
        'TABLE_NAME': os.environ['SLOT_TABLE'],
    },
}
for path, variables in configs.items():
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({'Variables': variables}, f, separators=(',', ':'))
PY

aws lambda update-function-configuration \
  --region "$AWS_REGION" \
  --function-name Vault-PC-S3-Completion-Revoker \
  --environment file:///tmp/pc-completion-env.json

aws lambda update-function-configuration \
  --region "$AWS_REGION" \
  --function-name Vault-Phone-S3-Completion-Revoker \
  --environment file:///tmp/phone-completion-env.json

aws lambda update-function-configuration \
  --region "$AWS_REGION" \
  --function-name Vault-S3-Completion-Status \
  --environment file:///tmp/completion-status-env.json

for FN in \
  Vault-PC-S3-Completion-Revoker \
  Vault-Phone-S3-Completion-Revoker \
  Vault-S3-Completion-Status; do
  aws lambda wait function-active-v2 --region "$AWS_REGION" --function-name "$FN"
done
```

#### 22.12.10B Configure exact S3 snapshot/lock event notifications

Grant only the matching bucket permission to invoke its matching completion revoker:

```bash
aws lambda add-permission \
  --region "$AWS_REGION" \
  --function-name Vault-PC-S3-Completion-Revoker \
  --statement-id AllowPCBucketCompletionEvents \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn "arn:aws:s3:::$PC_BUCKET" \
  --source-account "$AWS_ACCOUNT_ID"

aws lambda add-permission \
  --region "$AWS_REGION" \
  --function-name Vault-Phone-S3-Completion-Revoker \
  --statement-id AllowPhoneBucketCompletionEvents \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn "arn:aws:s3:::$PHONE_BUCKET" \
  --source-account "$AWS_ACCOUNT_ID"

export PC_COMPLETION_FN_ARN="$(aws lambda get-function \
  --region "$AWS_REGION" --function-name Vault-PC-S3-Completion-Revoker \
  --query 'Configuration.FunctionArn' --output text)"
export PHONE_COMPLETION_FN_ARN="$(aws lambda get-function \
  --region "$AWS_REGION" --function-name Vault-Phone-S3-Completion-Revoker \
  --query 'Configuration.FunctionArn' --output text)"
```

Create exact notification documents:

```bash
cat > /tmp/vault-pc-completion-notifications.json <<JSON
{
  "LambdaFunctionConfigurations": [
    {
      "Id": "VaultPCSnapshotCreated",
      "LambdaFunctionArn": "$PC_COMPLETION_FN_ARN",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "snapshots/"}]}}
    },
    {
      "Id": "VaultPCLockRemoved",
      "LambdaFunctionArn": "$PC_COMPLETION_FN_ARN",
      "Events": ["s3:ObjectRemoved:*"],
      "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "locks/"}]}}
    }
  ]
}
JSON

cat > /tmp/vault-phone-completion-notifications.json <<JSON
{
  "LambdaFunctionConfigurations": [
    {
      "Id": "VaultPhoneSnapshotCreated",
      "LambdaFunctionArn": "$PHONE_COMPLETION_FN_ARN",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "snapshots/"}]}}
    },
    {
      "Id": "VaultPhoneLockRemoved",
      "LambdaFunctionArn": "$PHONE_COMPLETION_FN_ARN",
      "Events": ["s3:ObjectRemoved:*"],
      "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "locks/"}]}}
    }
  ]
}
JSON

aws s3api put-bucket-notification-configuration \
  --bucket "$PC_BUCKET" \
  --notification-configuration file:///tmp/vault-pc-completion-notifications.json

aws s3api put-bucket-notification-configuration \
  --bucket "$PHONE_BUCKET" \
  --notification-configuration file:///tmp/vault-phone-completion-notifications.json

aws s3api get-bucket-notification-configuration --bucket "$PC_BUCKET"
aws s3api get-bucket-notification-configuration --bucket "$PHONE_BUCKET"
```

**Warning:** `put-bucket-notification-configuration` replaces the bucket's notification
configuration. In this canonical build these two Vault notifications are the intended
configuration. If the bucket already has unrelated notifications, merge them into the
JSON deliberately instead of overwriting them blindly.

A snapshot-created event alone must not revoke. The revoker requires that snapshot
evidence plus a later `locks/` removal event for the same exact consumed slot window.
Duplicate and out-of-order delivery are expected inputs; the DynamoDB transitions are
idempotent and the first `completion_revoke_cutoff` is immutable.

#### 22.12.10C Configure five-minute completion reconciliation

The normal path is S3 event driven. Add a low-frequency reconciliation path so a delayed
or missed event does not silently preserve a completed authorization window:

```bash
aws events put-rule \
  --region "$AWS_REGION" \
  --name Vault-PC-S3-Completion-Reconcile \
  --schedule-expression 'rate(5 minutes)' \
  --state ENABLED

aws events put-rule \
  --region "$AWS_REGION" \
  --name Vault-Phone-S3-Completion-Reconcile \
  --schedule-expression 'rate(5 minutes)' \
  --state ENABLED

export PC_RECONCILE_RULE_ARN="$(aws events describe-rule \
  --region "$AWS_REGION" --name Vault-PC-S3-Completion-Reconcile \
  --query Arn --output text)"
export PHONE_RECONCILE_RULE_ARN="$(aws events describe-rule \
  --region "$AWS_REGION" --name Vault-Phone-S3-Completion-Reconcile \
  --query Arn --output text)"

aws lambda add-permission \
  --region "$AWS_REGION" \
  --function-name Vault-PC-S3-Completion-Revoker \
  --statement-id AllowPCCompletionReconcile \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn "$PC_RECONCILE_RULE_ARN"

aws lambda add-permission \
  --region "$AWS_REGION" \
  --function-name Vault-Phone-S3-Completion-Revoker \
  --statement-id AllowPhoneCompletionReconcile \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn "$PHONE_RECONCILE_RULE_ARN"

aws events put-targets \
  --region "$AWS_REGION" \
  --rule Vault-PC-S3-Completion-Reconcile \
  --targets "Id=1,Arn=$PC_COMPLETION_FN_ARN,Input={\"reconcile\":true}"

aws events put-targets \
  --region "$AWS_REGION" \
  --rule Vault-Phone-S3-Completion-Reconcile \
  --targets "Id=1,Arn=$PHONE_COMPLETION_FN_ARN,Input={\"reconcile\":true}"
```

The reconciliation logic uses strong S3 list visibility only as missing-event recovery.
It must not synthesize old completion evidence when a newer same-device issuance exists.
The event-derived lock-removal timestamp remains the preferred cutoff.

#### 22.12.11 Create the two Identity Center permission sets

In **IAM Identity Center → Permission sets**:

1. Create `Vault-PC-Gate-Invoke`.
2. Set session duration to **1 hour**.
3. Add this inline policy, replacing region/account if needed:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "lambda:InvokeFunction",
    "Resource": [
      "arn:aws:lambda:us-east-1:123456789012:function:Vault-PC-S3-Gate",
      "arn:aws:lambda:us-east-1:123456789012:function:Vault-S3-Completion-Status"
    ]
  }]
}
```

4. Assign the dedicated Vault user to the AWS account with this permission set.
5. Create `Vault-Phone-Gate-Invoke` with the same two-resource shape, replacing the PC
   gate ARN with `Vault-Phone-S3-Gate` and retaining the shared
   `Vault-S3-Completion-Status` ARN.
6. Assign the same dedicated Vault user, or separate device users if you deliberately
   choose that operational model.

The security boundary is the permission-set role policy, not the friendly profile name.
The status Lambda is read-only and is intentionally invokable from both device profiles
because each clean primary must inspect the **opposite** device's exact shared S3 session
state before requesting close-only peer admission shutdown. Do not add S3, DynamoDB,
IAM, or `sts:AssumeRole` to these permission sets.

On the PC:

```bash
aws configure sso --profile vault-pc-gate
```

Choose `Vault-PC-Gate-Invoke`. On the phone/Termux:

```bash
aws configure sso --profile vault-phone-gate
```

Choose `Vault-Phone-Gate-Invoke`.

Positive smoke test:

```bash
# PC
aws sso login --profile vault-pc-gate
aws sts get-caller-identity --profile vault-pc-gate
aws sso logout
```

Run the symmetric test on the Phone profile.

Negative cross-function test after login:

```bash
# On PC. This should fail with AccessDenied before Lambda code executes.
aws lambda invoke \
  --profile vault-pc-gate \
  --region "$AWS_REGION" \
  --function-name Vault-Phone-S3-Gate \
  --cli-binary-format raw-in-base64-out \
  --payload '{}' \
  /tmp/should-not-exist.json
```

Phone must likewise be denied from invoking `Vault-PC-S3-Gate`.

#### 22.12.12 Install a non-retrying gate-invocation helper on each primary device

The daily workflow must not hide Lambda invocation in a generic retry library. Install
this helper on the PC as `~/bin/vault-aws-gate-invoke`:

```bash
cat > "$HOME/bin/vault-aws-gate-invoke" <<'EOF'
#!/usr/bin/env bash
# Invoke one Vault issuance Lambda exactly once.
# SECURITY: no retry loop is permitted in this helper.
set -euo pipefail

usage() {
  echo "Usage: $0 <aws-profile> <function-name> <proof.json> <sts.json>" >&2
  exit 64
}

[[ $# -eq 4 ]] || usage
PROFILE="$1"
FUNCTION="$2"
PROOF="$3"
OUTPUT="$4"
META="${OUTPUT}.invoke-meta.json"

[[ -s "$PROOF" ]] || { echo "ERROR: proof file missing or empty: $PROOF" >&2; exit 1; }
rm -f "$OUTPUT" "$META"

# Exactly one Lambda request attempt. The CLI itself can retry unless max attempts is
# explicitly pinned to one, so override any profile/default retry configuration here.
if ! AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke \
    --profile "$PROFILE" \
    --function-name "$FUNCTION" \
    --cli-binary-format raw-in-base64-out \
    --payload "fileb://$PROOF" \
    "$OUTPUT" > "$META"; then
  echo "ERROR: Lambda invocation transport/API failed." >&2
  echo "The daily slot may or may not have been consumed. DO NOT invoke again today." >&2
  exit 1
fi

python3 - "$META" "$OUTPUT" <<'PY'
import json,sys
meta=json.load(open(sys.argv[1],encoding='utf-8'))
if meta.get('FunctionError'):
    print(f"ERROR: Lambda returned FunctionError={meta['FunctionError']}",file=sys.stderr)
    print("DO NOT invoke the issuance gate again today.",file=sys.stderr)
    raise SystemExit(1)
try:
    data=json.load(open(sys.argv[2],encoding='utf-8'))
except Exception as exc:
    print(f"ERROR: invalid Lambda result JSON: {exc}",file=sys.stderr)
    print("DO NOT invoke the issuance gate again today.",file=sys.stderr)
    raise SystemExit(1)
required=('AccessKeyId','SecretAccessKey','SessionToken','Expiration')
missing=[k for k in required if not isinstance(data.get(k),str) or not data[k]]
if missing:
    print(f"ERROR: incomplete STS result; missing {missing}",file=sys.stderr)
    print("DO NOT invoke the issuance gate again today.",file=sys.stderr)
    raise SystemExit(1)
print(data['Expiration'])
PY
EOF

chmod 700 "$HOME/bin/vault-aws-gate-invoke"
bash -n "$HOME/bin/vault-aws-gate-invoke"
```

Install the identical helper in Termux at `$HOME/bin/vault-aws-gate-invoke` and run:

```bash
bash -n "$HOME/bin/vault-aws-gate-invoke"
```

The message “DO NOT invoke again today” is intentional. A transport timeout is
ambiguous: AWS may have consumed the DynamoDB slot and may even have created the STS
credential before the response was lost. Exactly-once issuance cannot be reconstructed
by blind client retry. `AWS_MAX_ATTEMPTS=1` is part of the security invariant, not a
performance tweak: AWS CLI/SDK retry settings count the initial request as an attempt,
so a value of one disables the CLI's own automatic request retry for this invocation.
The environment override also wins over a broader retry setting stored in the AWS
profile.

#### 22.12.13 Inspect gate logs without exposing returned credentials

Lambda logs should record ordinary platform errors, but the function source does not
log the returned STS secret values. To inspect recent log streams:

```bash
aws logs tail /aws/lambda/Vault-PC-S3-Gate \
  --region "$AWS_REGION" \
  --since 1h

aws logs tail /aws/lambda/Vault-Phone-S3-Gate \
  --region "$AWS_REGION" \
  --since 1h
```

When debugging, never add `console.log(response.Credentials)` or log the full Lambda
return value. A debugging change that prints credentials creates a new credential
exfiltration surface in CloudWatch Logs.

#### 22.12.14 Configure failed-login email alerting

Create an SNS Standard topic named `FailedLoginAlerts`, subscribe the operator email,
and confirm the subscription. Then create the EventBridge rule described in Section
22.9 using the documented failed `CredentialVerification` event shape.

After the rule is enabled:

1. Sign out of the dedicated Vault Identity Center user.
2. Perform one deliberate failed sign-in.
3. Confirm an email arrives.
4. Inspect the matched event in CloudTrail/EventBridge.
5. Perform a successful sign-in and confirm it does not generate the failure alert.

Do not treat an untested saved rule as an active detection control.

#### 22.12.15 Configure the configurable USD 2 budget containment action

In **Billing and Cost Management → Budgets**:

1. Create a **Cost budget**.
2. Name it `Vault-Emergency-Cost-Containment`.
3. Choose monthly recurrence.
4. Enter `2.00 USD` as the reference starting amount.
5. Treat this number as operator-configurable. After observing normal Vault cost,
   choose a threshold that is above legitimate noise but low enough to bound unexpected
   spend.
6. Where your account layout permits, apply service/tag/account filters so unrelated
   workloads do not trigger the Vault action.
7. Add a `100% of budgeted amount` **ACTUAL** threshold notification to the operator
   email.

Create `VaultBudgetAlwaysDenyS3`:

```bash
cat > /tmp/vault-budget-deny.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EmergencyAlwaysDenyS3",
    "Effect": "Deny",
    "Action": "s3:*",
    "Resource": "*"
  }]
}
JSON

export BUDGET_DENY_POLICY_ARN="$(aws iam create-policy \
  --policy-name VaultBudgetAlwaysDenyS3 \
  --policy-document file:///tmp/vault-budget-deny.json \
  --query 'Policy.Arn' --output text)"

echo "$BUDGET_DENY_POLICY_ARN"
```

Create the AWS Budgets action/service role using the AWS console workflow for an IAM
policy action. Scope the role to attaching/detaching the single
`VaultBudgetAlwaysDenyS3` policy to the two exact Vault backup role names. Do not give
the Budgets action role broad administrator permissions.

Configure the action at the same `100% ACTUAL` threshold and select **automatic
execution**. Target both:

```text
Vault-PC-S3-BackupRole
Vault-Phone-S3-BackupRole
```

Before trusting the automation, manually attach the emergency deny policy to both roles
and test a non-production S3 request through a valid session. It must fail. Then detach
the policy manually and record the exact incident recovery procedure. The budget action
is delayed containment because billing data is not an instant request counter; it is
not a replacement for the daily issuance slots.

Do not configure an automatic month-boundary detach. After a cost containment event,
require operator investigation and explicit manual recovery.

#### 22.12.16 Day-zero AWS security tests

Run these tests before repository initialization:

```text
Test A — one signature missing
Expected: Lambda rejects proof; no DynamoDB row for that slot.

Test A2 — own SSO/MFA succeeds but the opposite primary never joins `s3`
Expected: no dual-signed proof exists, the gate is never validly invoked, and no daily
slot or STS credential is created. MFA alone is not backup-opening authority.

Test B — wrong target
Send an S3_PHONE proof to the PC gate.
Expected: Lambda rejects `wrong proof target`; no PC slot consumed.

Test C — wrong calendar date
Expected: Lambda rejects `calendar date mismatch`.

Test D — first valid invocation
Expected: daily row appears with `completion_state=OPEN`; one STS credential set returned.

Test E — second valid invocation, same device/day
Expected: `DailySlotConsumed`; no second STS result.

Test F — PC role against Phone bucket
Expected: AccessDenied.

Test G — PC credential used without PC VPS egress IP
Expected: AccessDenied because `aws:SourceIp` condition fails.

Test H — emergency deny policy attached
Expected: both backup roles receive S3 AccessDenied regardless of their ordinary allow.

Test I — snapshot-created completion event only
Expected: `snapshot_seen_at` may be recorded, but state remains OPEN; no
`AWSRevokeOlderSessions` cutoff is created yet.

Test J — lock-removal event arrives before snapshot-created event
Expected: duplicate/out-of-order evidence is retained idempotently; revocation occurs
only after both facts exist and `lock_removed_at >= snapshot_seen_at`.

Test K — successful snapshot plus later repository-lock removal
Expected: exact slot transitions OPEN -> REVOKING -> REVOKED, the first
`completion_revoke_cutoff` remains immutable, and the matching backup role has inline
policy `AWSRevokeOlderSessions`.

Test L — old STS reused through the approved VPS after Test K
Expected: after IAM policy propagation, S3 returns AccessDenied even though the original
STS expiration timestamp is still in the future. Do not mint a replacement session.

Test M — read-only completion status exact binding
Expected: the correct device/date/exact shared `session_expires_at` returns REVOKED after
Test K. A changed deadline returns `ABSENT_OR_SESSION_MISMATCH`.

Test N — cross-role revoker privilege
Expected: the PC completion execution role cannot `iam:PutRolePolicy` on the Phone backup
role and cannot list the Phone bucket; Phone is symmetric.

Test O — permissions-boundary containment
Expected: both backup roles still show the exact boundary ARN. A deliberately broad
inline Allow in a disposable validation setup does not expand effective permissions past
the boundary's exact bucket/fixed-egress envelope. Remove the disposable test Allow.

Test P — signed cross-device close with local DONE suppressed
Keep the target S3 phase helper connected after its successful backup. After AWS reports
that target's exact session REVOKED, let the clean opposite workflow issue CLOSE_PEER.
Expected: target coordinator status becomes CLOSED s3 and target proxy authorization is
DENY without target cooperation.

Test Q — close replay/wrong-session binding
Replay an expired close payload or alter its `session_expires_at`.
Expected: peer coordinator rejects it. Repeating the same still-fresh valid close is
idempotent and cannot reopen anything.
```

Inspect the table after the issuance and completion tests:

```bash
aws dynamodb scan \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE" \
  --projection-expression 'pk,ceremony_id,consumed_at,session_expires_at,completion_state,snapshot_seen_at,lock_removed_at,completion_revoke_cutoff,completion_revoked_at'

aws iam get-role-policy \
  --role-name Vault-PC-S3-BackupRole \
  --policy-name AWSRevokeOlderSessions

aws iam get-role-policy \
  --role-name Vault-Phone-S3-BackupRole \
  --policy-name AWSRevokeOlderSessions
```

Never run these “valid invocation” tests with a production day's backup slot unless you
intend to consume that day's one issuance capability. Use a disposable test account or
accept that the day's production backup will not receive another issuance.

---

## Appendix F — Keep-All-History Capacity Budget and Growth Controls

The finalized default does not use a calendar capacity policy. Capacity planning is
therefore based on **unique historical churn**: the amount of previously unseen
content produced over time.

### What consumes repository space

```text
initial unique source data
+ newly added files
+ new blobs created by changed files
+ tree/snapshot/index metadata
+ limited unreferenced data from interrupted operations
= physical repository growth before backend/storage effects
```

Unchanged source data is deduplicated within each repository. Separate repositories do
not deduplicate against each other, so the same 40 GiB collection stored independently
in a PC repository and a phone repository can consume roughly 80 GiB before
compression and content differences are considered.

### Small mutable files are not the main capacity risk

Restic files smaller than 512 KiB are stored as a single blob. Therefore changing a
100 KiB Markdown file can create a new blob for that version. In a keep-all repository
that old version remains referenced by the old snapshot. This is real historical
churn, but the absolute amount is small:

```text
100 KiB of new unique changed content every day × 1,461 days ≈ 143 MiB over 4 years
1 MiB/day                                        ≈ 1.43 GiB
10 MiB/day                                       ≈ 14.3 GiB
50 MiB/day                                       ≈ 71.3 GiB
100 MiB/day                                      ≈ 142.7 GiB
```

Repository v2 may compress text/tree data, so actual stored bytes for Markdown and
source code can be lower. Do not use that as a guaranteed percentage in capacity
planning; measure `data_added_packed` from real backup JSON summaries instead.

### Large mutable artefacts are the real risk

Review these before placing them in the Vault:

- VM disks (`qcow2`, `vmdk`, raw images) that change on every boot.
- Large local databases with high page churn.
- Long-running PCAP captures.
- Continuously appended debug/audit logs.
- Container image exports and build artefacts.
- ISO images, package caches, dependency caches, and generated datasets that can be
  reproduced elsewhere.

The recommended scope rule is: **back up durable work product and irreplaceable data;
do not automatically back up reproducible heavy artefacts.** A Vagrantfile belongs in
the Vault; a disposable 40 GiB VM disk usually does not.

### 70/80/85 capacity policy

```text
<70% filesystem use     normal
70–79%                  review 90-day growth slope
80–84%                  urgent storage/scope decision
>=85%                   disk guard stops/rejects ingestion
```

At 70% or 80%, do not improvise a one-off deletion command. Calculate runway from the
capacity log and decide whether to add storage, reduce backup scope, or explicitly
adopt a new retention architecture.

### Backup frequency

Reducing backup frequency can reduce the number of intermediate file versions captured
for highly mutable files. It does **not** magically eliminate the unique content that
exists when a backup is taken. Daily backups are retained in this guide because the
expected Markdown/source-code workload is small and historical granularity is useful.
For a dedicated high-churn directory, a separate weekly backup scope is a valid future
optimization.

### External HDD mirror deletion guard

Because repository cleanup is no longer a routine operation, the external ciphertext
mirror should not normally experience large legitimate deletion bursts. You may add a
conservative `--max-delete` threshold to `rclone sync` after testing the normal lock/
metadata behavior of your repository. Treat a threshold trip as an investigation
signal; do not automatically raise the limit merely to make the script green.

### Measure, do not guess

For every backup JSON summary, preserve at least:

```text
data_added
data_added_packed
```

(`data_added_packed` is the physically packed/compressed amount reported by current
restic JSON summaries.) Sum the packed additions over 30 and 90 days. The roadmap file
shipped beside this guide shows the 40 GiB starting scenario and the exact runway
formula.


## Section 23 - Two VPS Security Compartments, Cross-Signed Proofs, and Fixed-IP S3 Egress

This section deploys the exact two-VPS architecture used by S3 and RHEL.

### 23.0 Build the two OCI Free Tier RHEL 9 VPSs from zero

This subsection assumes two fresh **RHEL 9 BYOL/BYOI** VPSs on Oracle Cloud
Infrastructure:

```text
vault-pc
vault-phone
```

Use the current active RHEL 9 minor release. At the time of this revision the current
minor is RHEL 9.8. The guide follows the active RHEL 9 stream rather than freezing one
minor forever.

### 23.0A OCI Free Tier shape and BYOI architecture gate

Before importing or launching the image, choose and record the exact shape:

```text
VM.Standard.E2.1.Micro  -> AMD / x86_64
VM.Standard.A1.Flex     -> Ampere / aarch64
```

Before choosing a Free Tier shape, check the current Red Hat Ecosystem Catalog entry for
Oracle Cloud Infrastructure. **BYOL entitlement and CPU-architecture compatibility do
not by themselves prove that Red Hat certifies the exact OCI shape.** Record whether the
chosen shape is currently in the Red Hat-supported OCI set.

Use this decision rule:

```text
exact Free Tier shape is currently Red Hat-certified for the chosen RHEL 9 release
    -> proceed as a supported RHEL-on-OCI deployment

architecture can boot through OCI BYOI but the exact shape is not Red Hat-certified
    -> technically possible may differ from vendor-supported
    -> record the support-status exception in the threat/operations worksheet
    -> do not describe the host as a Red Hat-certified OCI configuration
```

For the actual BYOI import, use the Oracle-documented RHEL custom-image path:

1. In the Red Hat Customer Portal, download the **RHEL 9 KVM guest image** for the exact
   architecture selected for the OCI shape.
2. Preserve the downloaded image filename and SHA-256 in the offline deployment record.
3. In OCI, create or select a dedicated Object Storage bucket used for OS-image staging.
   Do not reuse either Vault backup bucket.
4. Upload the RHEL KVM guest image to that staging bucket.
5. In **Compute -> Custom Images -> Import image**, select the uploaded object.
6. Set:
   `Image type = QCOW2`
7. Set:
   `Launch mode = Paravirtualized`
8. After import, edit the custom-image shape compatibility and enable only the reviewed
   architecture-compatible OCI shape(s).
9. Launch `vault-pc` and `vault-phone` from the imported custom image using the matching
   shape.
10. Connect using the RHEL custom-image default user `cloud-user`, then create
    `vaultadmin` in Section 23.0.1.
11. After both VPSs are commissioned, remove the staging object when the offline
    authoritative image/hash record is safely retained and no rollback/import operation
    still depends on that object.

Do not import an `x86_64` image and try to launch it on Ampere, or import an `aarch64`
image and try to launch it on the AMD shape.

OCI imported RHEL images use the BYOI/custom-image path and paravirtualized launch mode.
Licensing remains the operator's Red Hat BYOL responsibility.

Immediately after first boot, on each VPS:

```bash
uname -m
rpm --eval '%{_arch}'
cat /etc/redhat-release
systemd-detect-virt
getenforce
```

Expected architecture pairs:

```text
E2.1.Micro -> x86_64 / x86_64
A1.Flex    -> aarch64 / aarch64
```

Required SELinux result:

```text
Enforcing
```

If SELinux is disabled, stop. Do not merely run `setenforce 1` on an unlabeled image and
continue. Follow the RHEL relabel/reboot procedure and return only after the host boots
with valid labels and `getenforce` prints `Enforcing`.

Name the hosts:

On the PC-compartment VPS:

```bash
sudo hostnamectl set-hostname vault-pc
```

On the Phone-compartment VPS:

```bash
sudo hostnamectl set-hostname vault-phone
```

Reserve a stable public IPv4 address for each VPS and record the actual **observed
outbound IPv4** later. The S3 backup roles bind ordinary data requests to these exact
`/32` source identities. If the provider changes the egress address, S3 should fail
closed until the IAM policy is deliberately updated.

#### 23.0.1 Register the BYOL host, create the administrator, and harden SSH

Register each RHEL VPS using the operator's Red Hat subscription process. Do not embed
Red Hat account passwords, activation keys, or organization secrets in public cloud-init
metadata.

Verify content access:

```bash
sudo subscription-manager status || true
sudo subscription-manager identity || true
sudo dnf repolist
```

A registration workflow may differ depending on the Red Hat subscription configuration,
but the invariant is:

```text
authentic supported RHEL 9 repositories
security errata available
both VPSs covered by the operator's BYOL entitlement
```

Create the non-root administrator:

```bash
sudo useradd -m -s /bin/bash vaultadmin
sudo usermod -aG wheel vaultadmin

sudo install -d -o vaultadmin -g vaultadmin -m 700 /home/vaultadmin/.ssh
sudo cp /root/.ssh/authorized_keys /home/vaultadmin/.ssh/authorized_keys
sudo chown vaultadmin:vaultadmin /home/vaultadmin/.ssh/authorized_keys
sudo chmod 600 /home/vaultadmin/.ssh/authorized_keys
```

Open a **second** SSH session as `vaultadmin` and verify:

```bash
id
sudo -v
```

The account must be a member of `wheel`. Never close the provider-console/root recovery
session until the second session is proven.

Create `/etc/ssh/sshd_config.d/60-vault-hardening.conf`:

```bash
sudo install -d -m 755 /etc/ssh/sshd_config.d
sudo tee /etc/ssh/sshd_config.d/60-vault-hardening.conf >/dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
EOF

sudo sshd -t
sudo systemctl reload sshd
```

Open a new SSH connection after the reload. If login fails, fix SSH before proceeding.

`AllowTcpForwarding no` applies to administrative SSH. The Vault S3 CONNECT proxy is a
separate service and does not use SSH forwarding.

#### 23.0.2 Install the RHEL package baseline and automatic security maintenance

Update the current active RHEL 9 stream:

```bash
sudo dnf update -y
```

Install the baseline:

```bash
sudo dnf install -y \
  ca-certificates curl jq openssl wireguard-tools \
  firewalld nftables \
  golang git gcc gcc-c++ make \
  dnf-automatic dnf-plugins-core \
  python3 sqlite \
  policycoreutils-python-utils audit
```

Verify the Go toolchain satisfies the guide's `go 1.23` module requirement:

```bash
go version
```

If the installed supported RHEL AppStream toolchain is older than the module requirement,
select a supported Red Hat Go Toolset/AppStream version and re-run the build tests. Do
not solve the problem by piping an arbitrary Internet installer into a root shell.

Add the official Tailscale stable RHEL 9 repository and install Tailscale:

```bash
sudo dnf config-manager --add-repo \
  https://pkgs.tailscale.com/stable/rhel/9/tailscale.repo

sudo dnf install -y tailscale
sudo systemctl enable --now tailscaled
tailscale version
rpm -q tailscale
```

Configure DNF Automatic for package installation and enable the install timer:

```bash
sudo systemctl enable --now dnf-automatic-install.timer
sudo systemctl status dnf-automatic-install.timer --no-pager
sudo systemctl list-timers --all | grep dnf-automatic
```

Automatic updates do not replace review. After kernel, SELinux policy, Tailscale,
systemd, Go toolchain, or firewalld changes, rerun the relevant Vault negative and
hardening acceptance tests.

Record the base state:

```bash
cat /etc/redhat-release
uname -m
getenforce
sudo firewall-cmd --state
sudo dnf repolist
go version
python3 --version
```

#### 23.0.3 Establish the canonical RHEL firewalld boundary

Use **firewalld as the canonical host-firewall owner** on the two RHEL VPSs. Do not
maintain a parallel `/etc/nftables.conf` that flushes firewalld's nftables ruleset.

Keep the provider console or current SSH recovery session open.

On `vault-pc`:

```bash
export SSH_PORT="22"
export ADMIN_SOURCE_CIDR="YOUR_CURRENT_ADMIN_PUBLIC_IP/32"
export PEER_VPS_PUBLIC_IP="PHONE_VPS_PUBLIC_IP"
```

On `vault-phone`, set `PEER_VPS_PUBLIC_IP` to the PC VPS public IPv4.

Identify the public interface and move it to the `drop` zone:

```bash
PUBLIC_IF="$(ip -4 route show default | awk '{print $5; exit}')"
test -n "$PUBLIC_IF"

sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --zone=drop --change-interface="$PUBLIC_IF"
```

Add only the two canonical public inbound exceptions:

```bash
sudo firewall-cmd --permanent --zone=drop \
  --add-rich-rule="rule family=\"ipv4\" source address=\"${ADMIN_SOURCE_CIDR}\" port port=\"${SSH_PORT}\" protocol=\"tcp\" accept"

sudo firewall-cmd --permanent --zone=drop \
  --add-rich-rule="rule family=\"ipv4\" source address=\"${PEER_VPS_PUBLIC_IP}/32\" port port=\"51830\" protocol=\"udp\" accept"

sudo firewall-cmd --reload

sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=drop --list-all
sudo firewall-cmd --zone=drop --list-rich-rules
```

Open a new SSH session before closing the recovery session.

Ensure `PasswordAuthentication` is completely disabled. Since tag manipulation could potentially bypass Tailscale ACLs, do not rely solely on Tailscale to protect SSH. Consider completely isolating SSH from the Vault Tailnet (e.g., running SSH on a physically isolated Admin-only Tailnet) or strictly relying on the public `drop` zone exception above with FIDO2 hardware keys.
At the OCI VCN/provider-firewall layer, mirror the same intent:

```text
SSH       -> operator-approved source only
UDP/51830 -> opposite Vault VPS /32 only
```

Do not open UDP/40000, a self-hosted DERP listener, Headscale HTTPS, or a public backup
listener in the canonical Tailscale baseline.

Tailscale still needs outbound control/DERP/STUN connectivity and the exact-host S3 proxy
needs outbound S3 HTTPS. Do not invent a tiny static destination-IP allowlist for those
managed services. Process/path confinement and the application protocol checks remain
the primary local boundaries.

After Tailscale enrollment, prove the firewalld configuration did not break the required
Tailnet path:

```bash
tailscale status
tailscale netcheck
sudo firewall-cmd --get-active-zones
```

If the Peer Relay extension is enabled later, it adds source-restricted firewalld rich
rules for UDP/40000 and removes them during rollback. If the Headscale extension is
enabled, it adds the documented HTTPS ports only.

#### 23.0.4 Create the private `wg-cross` link with independent keys and an optional PSK

On `vault-pc`:

```bash
sudo install -d -m 700 /etc/wireguard
sudo sh -c 'umask 077; wg genkey > /etc/wireguard/wg-cross.key'
sudo sh -c 'wg pubkey < /etc/wireguard/wg-cross.key > /etc/wireguard/wg-cross.pub'
sudo cat /etc/wireguard/wg-cross.pub
```

On `vault-phone`, run the same commands and record its public key.

Generate one optional WireGuard preshared key on one VPS:

```bash
sudo sh -c 'umask 077; wg genpsk > /etc/wireguard/wg-cross.psk'
sudo cat /etc/wireguard/wg-cross.psk
```

Transfer the exact PSK once through a secure administrative channel to the opposite VPS
and store it as `/etc/wireguard/wg-cross.psk` mode `600`. The PSK is optional defense in
depth; it does not create the two-VPS authorization property. The Ed25519 signing keys
remain the application authorization boundary.

On `vault-pc`, create:

```bash
PC_CROSS_PRIVATE_KEY="$(sudo cat /etc/wireguard/wg-cross.key)"
CROSS_PSK="$(sudo cat /etc/wireguard/wg-cross.psk 2>/dev/null || true)"
PSK_LINE=""
if [ -n "$CROSS_PSK" ]; then
  PSK_LINE="PresharedKey = ${CROSS_PSK}"
fi
PHONE_CROSS_PUBLIC_KEY="PHONE_CROSS_PUBLIC_KEY"
PHONE_CONTROL_PUBLIC_IP="PHONE_CONTROL_PUBLIC_IP"

sudo tee /etc/wireguard/wg-cross.conf >/dev/null <<EOF
[Interface]
Address = 10.254.0.1/30
PrivateKey = ${PC_CROSS_PRIVATE_KEY}
ListenPort = 51830

[Peer]
PublicKey = ${PHONE_CROSS_PUBLIC_KEY}
${PSK_LINE}
AllowedIPs = 10.254.0.2/32
Endpoint = ${PHONE_CONTROL_PUBLIC_IP}:51830
PersistentKeepalive = 25
EOF

sudo chmod 600 /etc/wireguard/wg-cross.conf
```

On `vault-phone`, create the symmetric configuration:

```bash
PHONE_CROSS_PRIVATE_KEY="$(sudo cat /etc/wireguard/wg-cross.key)"
CROSS_PSK="$(sudo cat /etc/wireguard/wg-cross.psk 2>/dev/null || true)"
PSK_LINE=""
if [ -n "$CROSS_PSK" ]; then
  PSK_LINE="PresharedKey = ${CROSS_PSK}"
fi
PC_CROSS_PUBLIC_KEY="PC_CROSS_PUBLIC_KEY"
PC_CONTROL_PUBLIC_IP="PC_CONTROL_PUBLIC_IP"

sudo tee /etc/wireguard/wg-cross.conf >/dev/null <<EOF
[Interface]
Address = 10.254.0.2/30
PrivateKey = ${PHONE_CROSS_PRIVATE_KEY}
ListenPort = 51830

[Peer]
PublicKey = ${PC_CROSS_PUBLIC_KEY}
${PSK_LINE}
AllowedIPs = 10.254.0.1/32
Endpoint = ${PC_CONTROL_PUBLIC_IP}:51830
PersistentKeepalive = 25
EOF

sudo chmod 600 /etc/wireguard/wg-cross.conf
```

Enable on both VPSs:

```bash
sudo systemctl enable --now wg-quick@wg-cross
sudo wg show wg-cross
```

Verify from `vault-pc`:

```bash
ping -c 3 10.254.0.2
sudo wg show wg-cross latest-handshakes
```

Verify from `vault-phone`:

```bash
ping -c 3 10.254.0.1
sudo wg show wg-cross latest-handshakes
```

The `AllowedIPs` value is a single `/32`; no default route and no Tailnet subnet is
routed through `wg-cross`.

#### 23.0.5 Prove `wg-cross` is not a data-plane router

On both VPSs:

```bash
sysctl net.ipv4.ip_forward
```

For this reference design it should be `0`. Do not add NAT/masquerade rules for
`wg-cross`. The coordinator opens only its cross-sign listener on the tunnel. After the
coordinator is installed, verify:

```bash
sudo ss -lntup | grep -E '(:8891|wg-cross)'
```

From `vault-pc`, the Phone VPS cross-sign port should be reachable:

```bash
nc -vz -w3 10.254.0.2 8891
```

A random S3 destination must not become reachable “through” the peer VPS because there
is no routed forwarding path.

#### 23.0.6 Create the local device directory and signing key on each VPS

On each VPS:

```bash
sudo install -d -o root -g root -m 700 /etc/vault-device
sudo install -d -o root -g root -m 700 /var/lib/vault-device
sudo openssl genpkey -algorithm ED25519 \
  -out /etc/vault-device/signing-key.pem
sudo chmod 600 /etc/vault-device/signing-key.pem
sudo openssl pkey \
  -in /etc/vault-device/signing-key.pem \
  -pubout \
  -out /etc/vault-device/signing-key.pub.pem
sudo chmod 644 /etc/vault-device/signing-key.pub.pem
sudo openssl pkey \
  -pubin \
  -in /etc/vault-device/signing-key.pub.pem \
  -text -noout
```

Copy only `/etc/vault-device/signing-key.pub.pem` to the opposite VPS and to the secure
administrator workstation used for Lambda configuration. On each VPS install the
opposite public key as:

```text
/etc/vault-device/peer-signing-key.pub.pem
```

Then:

```bash
sudo chown root:root /etc/vault-device/*.pem
sudo chmod 600 /etc/vault-device/signing-key.pem
sudo chmod 644 /etc/vault-device/signing-key.pub.pem \
               /etc/vault-device/peer-signing-key.pub.pem
```

Compare fingerprints from the original and copied public files:

```bash
sha256sum /etc/vault-device/signing-key.pub.pem \
          /etc/vault-device/peer-signing-key.pub.pem
```

Record the public-key fingerprints in the deployment worksheet. Never use one signing
private key on both VPSs.

#### 23.0.7 Generate primary-device phase tokens and provision only verifiers

On the Fedora PC:

```bash
mkdir -p ~/.config/vault-secrets
chmod 700 ~/.config/vault-secrets
umask 077
python3 -c 'import secrets,sys; sys.stdout.write(secrets.token_hex(32))' \
  > ~/.config/vault-secrets/oracle_phase_token
chmod 600 ~/.config/vault-secrets/oracle_phase_token

python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
p=Path.home()/'.config/vault-secrets/oracle_phase_token'
t=p.read_text(encoding='ascii').strip()
print(sha256(t.encode('ascii')).hexdigest())
PY
```

Copy the printed SHA-256 digest to `vault-pc` and install it:

```bash
printf '%s' 'PC_PHASE_TOKEN_SHA256' | \
  sudo tee /etc/vault-device/phase-token.sha256 >/dev/null
sudo chown root:root /etc/vault-device/phase-token.sha256
sudo chmod 600 /etc/vault-device/phase-token.sha256
```

On the Phone/Termux, generate an independent token with the same Python method and copy
**only its SHA-256 digest** to `vault-phone`.

Negative check: the two verifier files on the VPSs must differ. The raw PC token must
never be copied to the Phone, Phone VPS, RHEL, or AWS. The raw Phone token follows the
symmetric rule.

#### 23.0.8 Build and install `vault-device-coordinator`

On each VPS:

```bash
sudo install -d -o vaultadmin -g vaultadmin -m 755 /usr/local/src/vault-device-coordinator
cd /usr/local/src/vault-device-coordinator
```

Copy the exact Go source from Section 23.4 into:

```text
/usr/local/src/vault-device-coordinator/main.go
```

Create a minimal module:

```bash
cat > go.mod <<'EOF'
module vault-device-coordinator

go 1.23
EOF

gofmt -w main.go
go test ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o vault-device-coordinator ./
sudo install -o root -g root -m 755 vault-device-coordinator /usr/local/sbin/vault-device-coordinator
/usr/local/sbin/vault-device-coordinator -h 2>&1 | head || true
```

The program reads its role-specific addresses from the source constants/environment
shown in Section 23.4. Before building, verify the PC VPS source identifies itself as
`pc`, uses the exact `VPS_TS_IP` recorded in Section 24, and cross peer `10.254.0.2`; verify the Phone
build is symmetric. Do not install a PC-role binary on `vault-phone`.

Install the exact systemd unit from Section 23.4. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-device-coordinator.service
sudo systemctl status vault-device-coordinator.service --no-pager
sudo journalctl -u vault-device-coordinator.service -b --no-pager | tail -100
sudo ss -lntp | grep -E ':8889|127\.0\.0\.1:8890|10\.254\.0\.[12]:8891'
```

Expected listeners:

```text
VPS_TS_IP:8889     local device phase control
127.0.0.1:8890    local S3 proxy status/authz only
10.254.0.x:8891   cross-sign listener over wg-cross only
```

There must be no public `0.0.0.0:8889`, `0.0.0.0:8890`, or `0.0.0.0:8891` listener.

#### 23.0.9 Test cross-signing before AWS or RHEL exists

Enroll the PC in the PC Tailscale tailnet and Phone in the Phone Tailscale tailnet as shown in Section 24. Start the phase helper on both devices for a disposable `s3`
ceremony. The two local coordinators should each log that their own device joined and
that the opposite coordinator signed the exact canonical payload.

On each VPS:

```bash
sudo journalctl -fu vault-device-coordinator.service
```

Expected properties:

```text
PC alone joins PC coordinator      -> no proof released
Phone alone joins Phone coordinator -> no proof released
both present in the same phase     -> both signatures appear in bundle
mismatched phase                   -> no proof released
expired 60-second proof            -> downstream verifier rejects it
```

Do not proceed if one device can obtain a proof while the other device/helper is absent.

#### 23.0.10 Build and install the exact-host S3 CONNECT proxy

Create a dedicated non-login proxy identity first:

```bash
sudo useradd --system --home-dir /var/lib/vault-s3-proxy   --shell /sbin/nologin vaultproxy 2>/dev/null || true
sudo install -d -o vaultproxy -g vaultproxy -m 700 /var/lib/vault-s3-proxy
```

On each VPS:

```bash
sudo install -d -o vaultadmin -g vaultadmin -m 755 /usr/local/src/vault-s3-proxy
cd /usr/local/src/vault-s3-proxy
```

Copy the exact Go source from Section 23.6 to `main.go`, then:

```bash
cat > go.mod <<'EOF'
module vault-s3-proxy

go 1.23
EOF

gofmt -w main.go
go test ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o vault-s3-proxy ./
sudo install -o root -g root -m 755 vault-s3-proxy /usr/local/sbin/vault-s3-proxy
```

Create `/etc/systemd/system/vault-s3-proxy.service`:

```ini
[Unit]
Description=Vault exact-host S3 CONNECT proxy
After=network-online.target vault-device-coordinator.service
Wants=network-online.target
Requires=vault-device-coordinator.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/vault-s3-proxy
Restart=on-failure
RestartSec=2s
User=vaultproxy
Group=vaultproxy
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

Enable and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-s3-proxy.service
sudo systemctl status vault-s3-proxy.service --no-pager
sudo ss -lntp | grep 'VPS_TS_IP:8888'
```

The proxy intentionally needs outbound TCP to approved S3 endpoints. It does not need
Tailscale API credentials, AWS credentials, the coordinator's Ed25519 signing private
key, or access to primary-device raw phase tokens.

Negative proxy tests from the matching primary device while no S3 phase is open:

```bash
curl -v -x http://VPS_TS_IP:8888 https://s3.us-east-1.amazonaws.com/ 2>&1 | tail -30
```

Expected: admission closed/service unavailable.

During an open phase, try an unapproved host:

```bash
curl -v -x http://VPS_TS_IP:8888 https://example.com/ 2>&1 | tail -30
```

Expected: the proxy refuses the destination. Do not add arbitrary domains to the
allowlist to make unrelated AWS CLI commands work. SSO and Lambda invocation happen
directly; only the restic S3 data path uses `HTTPS_PROXY`.

#### 23.0.11 Install the authoritative exact-device Tailscale expiry helper

Do not install a guessed `curl` wrapper here. Section 24 creates one dedicated
`devices:core` OAuth credential in each tailnet, records the exact expected primary
NodeID/IP/hostname, and installs `/usr/local/sbin/vault-tailscale-expire-primary`.

The coordinator's persisted files are already the input contract:

```text
/var/lib/vault-device/expiry.intent
/var/lib/vault-device/session.deadline.json
```

The helper must:

```text
read no device ID from a network request
resolve/check the exact configured tailnet and exact expected primary
require expiry.intent IP == exact expected primary Tailscale IPv4
persist ambiguous partial state before the API call
emit only POST /api/v2/device/<EXACT_EXPECTED_NODE_ID>/expire
never automatically retry an ambiguous expire result
remove expiry.intent/session.deadline only after confirmed exact-device expiry
leave any mismatch or ambiguity fail-closed
```

Complete Section 24.8 through 24.10 before enabling the path unit. The final systemd
path/service wiring is installed there because it depends on the tailnet-specific OAuth
credential and exact NodeID worksheet values.

#### 23.0.12 Freeze the VPS security boundary after testing

After all Section 23/24 day-zero tests pass, record hashes:

```bash
sudo sha256sum \
  /usr/local/sbin/vault-device-coordinator \
  /usr/local/sbin/vault-s3-proxy \
  /usr/local/sbin/vault-tailscale-expire-primary \
  /etc/systemd/system/vault-device-coordinator.service \
  /etc/systemd/system/vault-s3-proxy.service \
  /etc/systemd/system/vault-tailscale-expire-primary.service \
  /etc/systemd/system/vault-tailscale-expire-primary.path
```

Store the hashes in the operator deployment record. Do not make binaries immutable with
`chattr +i` until the update procedure has been rehearsed; an immutable service file can
turn a security update into an emergency if the operator forgets how the lock was
applied.

---

### 23.1 Address plan and listeners

Tailscale assigns the three addresses in each tailnet. Record the exact values from
Section 24 before building the coordinator, proxy, RHEL certificates, Caddy listeners,
or device scripts:

```text
PC tailnet
  PC_PRIMARY_TS_IP
  PC_VPS_TS_IP
  PC_RHEL_TS_IP

Phone tailnet
  PHONE_PRIMARY_TS_IP
  PHONE_VPS_TS_IP
  PHONE_RHEL_TS_IP
```

The Vault-local listener contract is:

```text
vault-pc
  local coordinator:      PC_VPS_TS_IP:8889
  local proxy authz:      127.0.0.1:8890
  S3 CONNECT proxy:       PC_VPS_TS_IP:8888
  wg-cross:               10.254.0.1/30
  cross-sign listener:    10.254.0.1:8891

vault-phone
  local coordinator:      PHONE_VPS_TS_IP:8889
  local proxy authz:      127.0.0.1:8890
  S3 CONNECT proxy:       PHONE_VPS_TS_IP:8888
  wg-cross:               10.254.0.2/30
  cross-sign listener:    10.254.0.2:8891

RHEL PC namespace
  Caddy:                   PC_RHEL_TS_IP:8001

RHEL Phone namespace
  Caddy:                   PHONE_RHEL_TS_IP:8002
```

The two independent tailnets can assign overlapping 100.64.0.0/10 addresses in theory,
but **never assume they do**. The two RHEL network namespaces and daemon sockets keep
the routing domains separate. Use the exact worksheet values and never route one
tailnet into the other.

### 23.2 Build `wg-cross`

Generate independent WireGuard keys on both VPSs. Example PC config:

```ini
[Interface]
Address = 10.254.0.1/30
PrivateKey = <PC_CROSS_PRIVATE_KEY>
ListenPort = 51830

[Peer]
PublicKey = <PHONE_CROSS_PUBLIC_KEY>
AllowedIPs = 10.254.0.2/32
Endpoint = <PHONE_CONTROL_PUBLIC_IP>:51830
PersistentKeepalive = 25
```

Phone is symmetric with `10.254.0.2/30` and the PC endpoint.

Firewall the public WireGuard listener to the opposite VPS public IPv4 when the provider
firewall supports a fixed source rule. The cross tunnel carries only coordinator
signing requests; it is not an S3 or RHEL data path.

Verify:

```bash
ping -c 3 10.254.0.2   # from vault-pc
ping -c 3 10.254.0.1   # from vault-phone
```

### 23.3 Install local phase-token verifiers and signing keys

On `vault-pc`:

```bash
sudo install -d -o root -g root -m 700 /etc/vault-device /var/lib/vault-device
printf '%s' 'PC_PHASE_TOKEN_SHA256' |   sudo tee /etc/vault-device/phase-token.sha256 >/dev/null
sudo chmod 600 /etc/vault-device/phase-token.sha256
```

On `vault-phone` install only the Phone verifier.

Exchange public Ed25519 key PEMs and install the **opposite public key** on each VPS:

```text
vault-pc:
  private: /etc/vault-device/signing-key.pem
  peer public: /etc/vault-device/peer-signing-key.pub.pem

vault-phone:
  private: /etc/vault-device/signing-key.pem
  peer public: /etc/vault-device/peer-signing-key.pub.pem
```

### 23.4 Deploy `vault-device-coordinator`

Create the dedicated coordinator identity before installing the keys/state:

```bash
sudo useradd --system --home-dir /var/lib/vault-device   --shell /sbin/nologin vaultcoord 2>/dev/null || true

sudo install -d -o root -g vaultcoord -m 750 /etc/vault-device
sudo install -d -o vaultcoord -g vaultcoord -m 700 /var/lib/vault-device
```

The coordinator service receives read access to its own phase-token verifier and
Ed25519 key material through group `vaultcoord`. The S3 proxy and expiry helper are not
members of this group.

Source:

```go
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	pairTimeout     = 10 * time.Minute
	dropoutGrace    = 90 * time.Second
	controlTimeout  = 45 * time.Second
	proofLifetime   = 60 * time.Second
	sessionLifetime = time.Hour
)

type proofPayload struct {
	Version          int    `json:"version"`
	CeremonyID       string `json:"ceremony_id"`
	Target           string `json:"target"`
	Nonce            string `json:"nonce"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	CalendarDate     string `json:"calendar_date"`
	SessionExpiresAt string `json:"session_expires_at"`
}

type closePayload struct {
	Version          int    `json:"version"`
	Phase            string `json:"phase"`
	TargetRole       string `json:"target_role"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	SessionExpiresAt string `json:"session_expires_at"`
}

type proofBundle struct {
	Payload        string `json:"payload"`
	PCSignature    string `json:"pc_signature"`
	PhoneSignature string `json:"phone_signature"`
}

type phaseState struct {
	conn           net.Conn
	connected      bool
	joinedAt       time.Time
	disconnectedAt time.Time
	sourceIP       string
	bundleB64      string
	done           bool
	writeMu        sync.Mutex
}

type service struct {
	mu              sync.Mutex
	role            string
	localAddr       string
	peerAddr        string
	peerWGIP        string
	stateDir        string
	tokenHash       [sha256.Size]byte
	privateKey      ed25519.PrivateKey
	peerPubKey      ed25519.PublicKey
	phases          map[string]*phaseState
	sessionDate     string
	sessionDeadline time.Time
	sessionSourceIP string
	sessionActive   bool
	sessionExpired  bool
	expiryPending   bool
}

func envRequired(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func loadTokenHash(path string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != sha256.Size {
		return out, errors.New("token verifier must be exactly one SHA-256 hex digest")
	}
	copy(out[:], decoded)
	return out, nil
}

func loadEd25519Private(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return ed, nil
}

func loadEd25519Public(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return ed, nil
}

func targetFor(role, phase string) (string, bool) {
	if role != "pc" && role != "phone" {
		return "", false
	}
	switch phase {
	case "s3":
		return "S3_" + strings.ToUpper(role), true
	case "rhel":
		return "RHEL_" + strings.ToUpper(role), true
	default:
		return "", false
	}
}

func phaseForTarget(target string) (string, bool) {
	switch target {
	case "S3_PC", "S3_PHONE":
		return "s3", true
	case "RHEL_PC", "RHEL_PHONE":
		return "rhel", true
	default:
		return "", false
	}
}

func roleForTarget(target string) (string, bool) {
	if strings.HasSuffix(target, "_PC") {
		return "pc", true
	}
	if strings.HasSuffix(target, "_PHONE") {
		return "phone", true
	}
	return "", false
}

func oppositeRole(role string) (string, bool) {
	switch role {
	case "pc":
		return "phone", true
	case "phone":
		return "pc", true
	default:
		return "", false
	}
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func istanbulDate(t time.Time) string {
	loc, err := time.LoadLocation("Europe/Istanbul")
	if err != nil {
		// Europe/Istanbul has been UTC+3 for the entire deployment horizon used by this guide.
		loc = time.FixedZone("Europe/Istanbul-fallback", 3*60*60)
	}
	return t.In(loc).Format("2006-01-02")
}

func (s *service) authenticateToken(token string) bool {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return subtle.ConstantTimeCompare(sum[:], s.tokenHash[:]) == 1
}

func readLine(r *bufio.Reader, max int) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > max {
		return "", errors.New("command too long")
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(line)), nil
}

func remoteHost(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}

type persistedSession struct {
	CalendarDate string `json:"calendar_date"`
	SourceIP     string `json:"source_ip"`
	Deadline     string `json:"deadline"`
}

func (s *service) sessionDeadlinePath() string {
	return filepath.Join(s.stateDir, "session.deadline.json")
}

func (s *service) sessionUsedPath(date string) string {
	return filepath.Join(s.stateDir, "session.used."+date)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".vault-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func createExclusive(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *service) localReadySource(phase string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.phases[phase]
	if st == nil || !st.connected || st.done || net.ParseIP(st.sourceIP) == nil {
		return "", false
	}
	return st.sourceIP, true
}

func (s *service) sessionOpenLocked(now time.Time) bool {
	return s.sessionActive && !s.sessionExpired && !s.sessionDeadline.IsZero() && now.Before(s.sessionDeadline)
}

func (s *service) currentSessionDeadline() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessionOpenLocked(time.Now().UTC()) {
		return time.Time{}, false
	}
	return s.sessionDeadline, true
}

func (s *service) proposedDeadline(phase string, now time.Time) (time.Time, error) {
	if deadline, ok := s.currentSessionDeadline(); ok {
		return deadline, nil
	}
	if phase != "s3" || s.role != "pc" {
		return time.Time{}, errors.New("waiting for PC-anchored active Vault session")
	}
	date := istanbulDate(now)
	if _, err := os.Stat(s.sessionDeadlinePath()); err == nil {
		return time.Time{}, errors.New("persisted Vault session still requires expiry completion")
	} else if !os.IsNotExist(err) {
		return time.Time{}, err
	}
	if _, err := os.Stat(s.sessionUsedPath(date)); err == nil {
		return time.Time{}, errors.New("daily Vault session anchor already consumed")
	} else if !os.IsNotExist(err) {
		return time.Time{}, err
	}
	return now.Add(sessionLifetime).Truncate(time.Second), nil
}

func (s *service) activateAnchoredSession(p proofPayload, sourceIP string) error {
	if p.Target != "S3_PC" || net.ParseIP(sourceIP) == nil {
		return errors.New("invalid session anchor")
	}
	deadline, err := time.Parse(time.RFC3339, p.SessionExpiresAt)
	if err != nil {
		return errors.New("invalid session_expires_at")
	}
	now := time.Now().UTC()
	if !deadline.After(now) {
		return errors.New("Vault session deadline already expired")
	}

	s.mu.Lock()
	if s.sessionOpenLocked(now) {
		match := s.sessionDeadline.Equal(deadline) && s.sessionSourceIP == sourceIP
		s.mu.Unlock()
		if !match {
			return errors.New("active Vault session anchor mismatch")
		}
		return nil
	}
	if s.sessionExpired && s.sessionDate == p.CalendarDate {
		s.mu.Unlock()
		return errors.New("daily Vault session already expired")
	}
	s.mu.Unlock()

	if _, err := os.Stat(s.sessionDeadlinePath()); err == nil {
		return errors.New("persisted Vault session still requires expiry completion")
	} else if !os.IsNotExist(err) {
		return err
	}
	usedPath := s.sessionUsedPath(p.CalendarDate)
	if err := createExclusive(usedPath, []byte("used\n"), 0o600); err != nil {
		if os.IsExist(err) {
			return errors.New("daily Vault session anchor already consumed")
		}
		return err
	}
	rec := persistedSession{CalendarDate: p.CalendarDate, SourceIP: sourceIP, Deadline: deadline.Format(time.RFC3339)}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := writeAtomic(s.sessionDeadlinePath(), append(raw, '\n'), 0o600); err != nil {
		// The daily marker deliberately remains consumed. No proof is released.
		return fmt.Errorf("session slot consumed but deadline persistence failed: %w", err)
	}

	s.mu.Lock()
	s.sessionDate = p.CalendarDate
	s.sessionDeadline = deadline
	s.sessionSourceIP = sourceIP
	s.sessionActive = true
	s.sessionExpired = false
	s.expiryPending = false
	s.mu.Unlock()
	log.Printf("Vault session anchored date=%s source=%s hard-deadline=%s", p.CalendarDate, sourceIP, deadline.Format(time.RFC3339))
	return nil
}

func (s *service) requireActiveSession(p proofPayload) error {
	deadline, err := time.Parse(time.RFC3339, p.SessionExpiresAt)
	if err != nil {
		return errors.New("invalid session_expires_at")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessionOpenLocked(time.Now().UTC()) {
		return errors.New("Vault session is not active")
	}
	if !s.sessionDeadline.Equal(deadline) {
		return errors.New("Vault session deadline mismatch")
	}
	return nil
}

func (s *service) restoreSessionState() error {
	raw, err := os.ReadFile(s.sessionDeadlinePath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var rec persistedSession
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339, rec.Deadline)
	if err != nil || rec.CalendarDate == "" || net.ParseIP(rec.SourceIP) == nil {
		return errors.New("invalid persisted Vault session state")
	}
	s.mu.Lock()
	s.sessionDate = rec.CalendarDate
	s.sessionDeadline = deadline
	s.sessionSourceIP = rec.SourceIP
	if time.Now().UTC().Before(deadline) {
		s.sessionActive = true
	} else {
		s.sessionExpired = true
		s.expiryPending = true
	}
	s.mu.Unlock()
	return nil
}

func (s *service) makePayload(phase string) ([]byte, []byte, error) {
	target, ok := targetFor(s.role, phase)
	if !ok {
		return nil, nil, errors.New("invalid phase")
	}
	ceremonyID, err := randomHex(16)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := randomHex(32)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	deadline, err := s.proposedDeadline(phase, now)
	if err != nil {
		return nil, nil, err
	}
	p := proofPayload{
		Version:          1,
		CeremonyID:       ceremonyID,
		Target:           target,
		Nonce:            nonce,
		IssuedAt:         now.Format(time.RFC3339),
		ExpiresAt:        now.Add(proofLifetime).Format(time.RFC3339),
		CalendarDate:     istanbulDate(now),
		SessionExpiresAt: deadline.Format(time.RFC3339),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	return raw, ed25519.Sign(s.privateKey, raw), nil
}

func validateFreshPayload(raw []byte, expectedRequesterRole string) (proofPayload, error) {
	var p proofPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, errors.New("invalid payload JSON")
	}
	if p.Version != 1 {
		return p, errors.New("unsupported proof version")
	}
	requesterRole, ok := roleForTarget(p.Target)
	if !ok || requesterRole != expectedRequesterRole {
		return p, errors.New("target does not belong to requesting peer role")
	}
	phase, ok := phaseForTarget(p.Target)
	if !ok || (phase != "s3" && phase != "rhel") {
		return p, errors.New("invalid target phase")
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return p, errors.New("invalid issued_at")
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return p, errors.New("invalid expires_at")
	}
	now := time.Now().UTC()
	if expires.Sub(issued) <= 0 || expires.Sub(issued) > 90*time.Second {
		return p, errors.New("invalid proof lifetime")
	}
	if now.Before(issued.Add(-30*time.Second)) || now.After(expires) {
		return p, errors.New("proof outside freshness window")
	}
	if p.CalendarDate != istanbulDate(now) {
		return p, errors.New("proof calendar date mismatch")
	}
	sessionExpires, err := time.Parse(time.RFC3339, p.SessionExpiresAt)
	if err != nil {
		return p, errors.New("invalid session_expires_at")
	}
	if !sessionExpires.After(now) || sessionExpires.Sub(issued) > sessionLifetime {
		return p, errors.New("invalid or expired Vault session deadline")
	}
	if len(p.CeremonyID) != 32 || len(p.Nonce) != 64 {
		return p, errors.New("invalid ceremony_id or nonce size")
	}
	return p, nil
}

func (s *service) requestPeerSignature(raw, ownSig []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", s.peerAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	line := "SIGN " + base64.StdEncoding.EncodeToString(raw) + " " + base64.StdEncoding.EncodeToString(ownSig) + "\n"
	if _, err := io.WriteString(conn, line); err != nil {
		return nil, err
	}
	reply, err := readLine(bufio.NewReaderSize(conn, 16384), 16000)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(reply)
	if len(fields) == 1 && fields[0] == "WAIT" {
		return nil, errors.New("peer device not ready")
	}
	if len(fields) != 2 || fields[0] != "OK" {
		return nil, fmt.Errorf("peer rejected proof request: %s", reply)
	}
	sig, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("peer returned invalid signature")
	}
	if !ed25519.Verify(s.peerPubKey, raw, sig) {
		return nil, errors.New("peer signature verification failed locally")
	}
	return sig, nil
}

func (s *service) buildBundle(phase string) (string, error) {
	raw, ownSig, err := s.makePayload(phase)
	if err != nil {
		return "", err
	}
	peerSig, err := s.requestPeerSignature(raw, ownSig)
	if err != nil {
		return "", err
	}
	var payload proofPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	if payload.Target == "S3_PC" {
		sourceIP, ready := s.localReadySource("s3")
		if !ready {
			return "", errors.New("local PC device not ready for session anchor")
		}
		if err := s.activateAnchoredSession(payload, sourceIP); err != nil {
			return "", err
		}
	} else if err := s.requireActiveSession(payload); err != nil {
		return "", err
	}
	bundle := proofBundle{Payload: base64.StdEncoding.EncodeToString(raw)}
	if s.role == "pc" {
		bundle.PCSignature = base64.StdEncoding.EncodeToString(ownSig)
		bundle.PhoneSignature = base64.StdEncoding.EncodeToString(peerSig)
	} else {
		bundle.PCSignature = base64.StdEncoding.EncodeToString(peerSig)
		bundle.PhoneSignature = base64.StdEncoding.EncodeToString(ownSig)
	}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bundleRaw), nil
}

func validateClosePayload(raw []byte, expectedTargetRole string, activeDeadline time.Time) (closePayload, error) {
	var p closePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, errors.New("invalid close payload JSON")
	}
	if p.Version != 1 || p.Phase != "s3" || p.TargetRole != expectedTargetRole {
		return p, errors.New("invalid close payload target")
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return p, errors.New("invalid close issued_at")
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return p, errors.New("invalid close expires_at")
	}
	now := time.Now().UTC()
	if expires.Sub(issued) <= 0 || expires.Sub(issued) > 90*time.Second {
		return p, errors.New("invalid close lifetime")
	}
	if now.Before(issued.Add(-30*time.Second)) || now.After(expires) {
		return p, errors.New("close payload outside freshness window")
	}
	deadline, err := time.Parse(time.RFC3339, p.SessionExpiresAt)
	if err != nil {
		return p, errors.New("invalid close session_expires_at")
	}
	if !deadline.Equal(activeDeadline) {
		return p, errors.New("close session deadline mismatch")
	}
	return p, nil
}

func (s *service) makePeerClosePayload() ([]byte, []byte, error) {
	deadline, ok := s.currentSessionDeadline()
	if !ok {
		return nil, nil, errors.New("no active Vault session")
	}
	targetRole, ok := oppositeRole(s.role)
	if !ok {
		return nil, nil, errors.New("invalid local role")
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := closePayload{
		Version:          1,
		Phase:            "s3",
		TargetRole:       targetRole,
		IssuedAt:         now.Format(time.RFC3339),
		ExpiresAt:        now.Add(60 * time.Second).Format(time.RFC3339),
		SessionExpiresAt: deadline.Format(time.RFC3339),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	return raw, ed25519.Sign(s.privateKey, raw), nil
}

func (s *service) requestPeerClose() error {
	raw, sig, err := s.makePeerClosePayload()
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", s.peerAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	line := "CLOSE " + base64.StdEncoding.EncodeToString(raw) + " " + base64.StdEncoding.EncodeToString(sig) + "\n"
	if _, err := io.WriteString(conn, line); err != nil {
		return err
	}
	reply, err := readLine(bufio.NewReaderSize(conn, 1024), 1024)
	if err != nil {
		return err
	}
	if reply != "CLOSED s3" {
		return fmt.Errorf("peer rejected close request: %s", reply)
	}
	return nil
}

func (s *service) closeLocalS3ForDeadline(deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessionOpenLocked(time.Now().UTC()) || !s.sessionDeadline.Equal(deadline) {
		return errors.New("no matching active Vault session")
	}
	st := s.phases["s3"]
	if st == nil || st.done {
		return nil
	}
	st.done = true
	st.connected = false
	if st.conn != nil {
		_ = st.conn.Close()
	}
	return nil
}

func (s *service) handlePeer(conn net.Conn) {
	defer conn.Close()
	if remoteHost(conn) != s.peerWGIP {
		_, _ = io.WriteString(conn, "REJECT peer source\n")
		return
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	line, err := readLine(bufio.NewReaderSize(conn, 16384), 16000)
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		_, _ = io.WriteString(conn, "REJECT expected SIGN or CLOSE\n")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(raw) > 4096 {
		_, _ = io.WriteString(conn, "REJECT payload\n")
		return
	}
	peerSig, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(peerSig) != ed25519.SignatureSize || !ed25519.Verify(s.peerPubKey, raw, peerSig) {
		_, _ = io.WriteString(conn, "REJECT peer signature\n")
		return
	}

	switch strings.ToUpper(fields[0]) {
	case "SIGN":
		expectedRequesterRole := "pc"
		if s.role == "pc" {
			expectedRequesterRole = "phone"
		}
		payload, err := validateFreshPayload(raw, expectedRequesterRole)
		if err != nil {
			_, _ = io.WriteString(conn, "REJECT "+err.Error()+"\n")
			return
		}
		phase, _ := phaseForTarget(payload.Target)
		sourceIP, ready := s.localReadySource(phase)
		if !ready {
			_, _ = io.WriteString(conn, "WAIT\n")
			return
		}
		if payload.Target == "S3_PC" {
			if err := s.activateAnchoredSession(payload, sourceIP); err != nil {
				_, _ = io.WriteString(conn, "REJECT "+err.Error()+"\n")
				return
			}
		} else if err := s.requireActiveSession(payload); err != nil {
			_, _ = io.WriteString(conn, "REJECT "+err.Error()+"\n")
			return
		}
		sig := ed25519.Sign(s.privateKey, raw)
		_, _ = io.WriteString(conn, "OK "+base64.StdEncoding.EncodeToString(sig)+"\n")
	case "CLOSE":
		deadline, ok := s.currentSessionDeadline()
		if !ok {
			_, _ = io.WriteString(conn, "REJECT no active Vault session\n")
			return
		}
		if _, err := validateClosePayload(raw, s.role, deadline); err != nil {
			_, _ = io.WriteString(conn, "REJECT "+err.Error()+"\n")
			return
		}
		if err := s.closeLocalS3ForDeadline(deadline); err != nil {
			_, _ = io.WriteString(conn, "REJECT "+err.Error()+"\n")
			return
		}
		_, _ = io.WriteString(conn, "CLOSED s3\n")
	default:
		_, _ = io.WriteString(conn, "REJECT expected SIGN or CLOSE\n")
	}
}

func (s *service) ensureBundle(phase string, st *phaseState) error {
	deadline := st.joinedAt.Add(pairTimeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if st.done || !st.connected {
			s.mu.Unlock()
			return errors.New("local device no longer connected")
		}
		if st.bundleB64 != "" {
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()

		bundle, err := s.buildBundle(phase)
		if err == nil {
			s.mu.Lock()
			if st.connected && !st.done && st.bundleB64 == "" {
				st.bundleB64 = bundle
			}
			s.mu.Unlock()
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("peer device did not join within pairing window")
}

func (s *service) writeState(st *phaseState, msg string) error {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	s.mu.Lock()
	conn := st.conn
	connected := st.connected
	s.mu.Unlock()
	if !connected || conn == nil {
		return net.ErrClosed
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := io.WriteString(conn, msg)
	return err
}

func (s *service) joinPhase(phase string, conn net.Conn) (*phaseState, error) {
	now := time.Now()
	sourceIP := remoteHost(conn)
	if sourceIP == "" {
		return nil, errors.New("invalid local Tailnet source")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.phases[phase]
	if st == nil || st.done || (!st.connected && !st.disconnectedAt.IsZero() && now.Sub(st.disconnectedAt) > dropoutGrace) {
		st = &phaseState{conn: conn, connected: true, joinedAt: now, sourceIP: sourceIP}
		s.phases[phase] = st
		return st, nil
	}
	if st.connected {
		return nil, errors.New("phase already occupied by the local device")
	}
	if st.sourceIP != sourceIP {
		return nil, errors.New("reconnect source IP changed during phase grace")
	}
	st.conn = conn
	st.connected = true
	st.disconnectedAt = time.Time{}
	return st, nil
}

func (s *service) markDisconnected(st *phaseState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.connected {
		st.connected = false
		st.disconnectedAt = time.Now()
		if st.conn != nil {
			_ = st.conn.Close()
		}
	}
}

func (s *service) persistExpiryIntent(sourceIP string) error {
	if net.ParseIP(sourceIP) == nil {
		return errors.New("invalid source IP for node-expiry intent")
	}
	return writeAtomic(filepath.Join(s.stateDir, "expiry.intent"), []byte("ip="+sourceIP+"\n"), 0o600)
}

func (s *service) markDone(phase string, st *phaseState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.phases[phase]
	if current != st {
		return errors.New("phase state changed")
	}
	if phase == "rhel" {
		if err := s.persistExpiryIntent(st.sourceIP); err != nil {
			return fmt.Errorf("persist primary-node expiry intent: %w", err)
		}
		s.sessionActive = false
		s.sessionExpired = true
		s.expiryPending = false
		for _, phaseState := range s.phases {
			phaseState.done = true
			phaseState.connected = false
			if phaseState.conn != nil {
				_ = phaseState.conn.Close()
			}
		}
		return nil
	}
	st.done = true
	st.connected = false
	if st.conn != nil {
		_ = st.conn.Close()
	}
	return nil
}

func (s *service) handleLocal(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(conn, 16384)
	line, err := readLine(reader, 4096)
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) == 3 && strings.ToUpper(fields[0]) == "CLOSE_PEER" {
		if strings.ToLower(fields[1]) != "s3" {
			_, _ = io.WriteString(conn, "REJECT close phase\n")
			return
		}
		if !s.authenticateToken(fields[2]) {
			_, _ = io.WriteString(conn, "REJECT token\n")
			return
		}
		if err := s.requestPeerClose(); err != nil {
			_, _ = io.WriteString(conn, "ERROR "+err.Error()+"\n")
			return
		}
		_, _ = io.WriteString(conn, "CLOSED peer-s3\n")
		return
	}
	if len(fields) != 3 || strings.ToUpper(fields[0]) != "JOIN" {
		_, _ = io.WriteString(conn, "REJECT expected JOIN <s3|rhel> <token> or CLOSE_PEER s3 <token>\n")
		return
	}
	phase := strings.ToLower(fields[1])
	if phase != "s3" && phase != "rhel" {
		_, _ = io.WriteString(conn, "REJECT phase\n")
		return
	}
	if !s.authenticateToken(fields[2]) {
		_, _ = io.WriteString(conn, "REJECT token\n")
		return
	}
	st, err := s.joinPhase(phase, conn)
	if err != nil {
		_, _ = io.WriteString(conn, "BUSY "+err.Error()+"\n")
		return
	}
	if err := s.ensureBundle(phase, st); err != nil {
		_ = s.writeState(st, "TIMEOUT "+err.Error()+"\n")
		_ = s.markDone(phase, st)
		return
	}
	s.mu.Lock()
	bundle := st.bundleB64
	s.mu.Unlock()
	if err := s.writeState(st, "OPEN "+phase+" "+bundle+"\n"); err != nil {
		s.markDisconnected(st)
		return
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(controlTimeout))
		line, err := readLine(reader, 256)
		if err != nil {
			s.markDisconnected(st)
			return
		}
		switch strings.ToUpper(line) {
		case "PING":
			if err := s.writeState(st, "PONG\n"); err != nil {
				s.markDisconnected(st)
				return
			}
		case "DONE":
			if err := s.markDone(phase, st); err != nil {
				_ = s.writeState(st, "ERROR "+err.Error()+"\n")
				continue
			}
			_ = s.writeState(st, "DONE "+phase+"\n")
			return
		default:
			_ = s.writeState(st, "ERROR expected PING or DONE\n")
		}
	}
}

func (s *service) sweep() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().UTC()
		s.mu.Lock()
		for phase, st := range s.phases {
			if st.done {
				delete(s.phases, phase)
				continue
			}
			if !st.connected && !st.disconnectedAt.IsZero() && now.Sub(st.disconnectedAt) > dropoutGrace {
				delete(s.phases, phase)
			}
		}
		if s.sessionActive && !s.sessionDeadline.IsZero() && !now.Before(s.sessionDeadline) {
			log.Printf("Vault hard session deadline reached; closing coordinator admissions and queuing primary-node expiry")
			s.sessionActive = false
			s.sessionExpired = true
			s.expiryPending = true
			for _, st := range s.phases {
				st.done = true
				st.connected = false
				if st.conn != nil {
					_ = st.conn.Close()
				}
			}
		}
		pending := s.expiryPending
		sourceIP := s.sessionSourceIP
		s.mu.Unlock()

		if pending {
			if err := s.persistExpiryIntent(sourceIP); err != nil {
				log.Printf("CRITICAL: hard-expiry intent persistence failed; retrying fail-closed: %v", err)
				continue
			}
			s.mu.Lock()
			if s.sessionSourceIP == sourceIP {
				s.expiryPending = false
			}
			s.mu.Unlock()
		}
	}
}

func (s *service) handleStatus(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := readLine(bufio.NewReaderSize(conn, 256), 256)
	if err != nil {
		return
	}
	fields := strings.Fields(strings.ToLower(line))
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.phases["s3"]
	sessionOpen := s.sessionOpenLocked(time.Now().UTC())
	if len(fields) == 2 && fields[0] == "status" && fields[1] == "s3" {
		if s.sessionExpired {
			_, _ = io.WriteString(conn, "EXPIRED s3\n")
		} else if sessionOpen && st != nil && st.connected && !st.done && st.bundleB64 != "" {
			_, _ = io.WriteString(conn, "OPEN s3\n")
		} else if st != nil && !st.done {
			_, _ = io.WriteString(conn, "WAITING s3\n")
		} else {
			_, _ = io.WriteString(conn, "CLOSED s3\n")
		}
		return
	}
	if len(fields) == 3 && fields[0] == "authz" && fields[1] == "s3" {
		candidate := net.ParseIP(fields[2])
		if sessionOpen && candidate != nil && st != nil && st.connected && !st.done && st.bundleB64 != "" && st.sourceIP == candidate.String() {
			_, _ = io.WriteString(conn, "ALLOW s3\n")
		} else {
			_, _ = io.WriteString(conn, "DENY s3\n")
		}
		return
	}
	_, _ = io.WriteString(conn, "REJECT\n")
}

func serve(ln net.Listener, handler func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go handler(conn)
	}
}

func main() {
	role := strings.ToLower(envRequired("VAULT_ROLE"))
	if role != "pc" && role != "phone" {
		log.Fatal("VAULT_ROLE must be pc or phone")
	}
	tokenHash, err := loadTokenHash(envRequired("VAULT_TOKEN_HASH_FILE"))
	if err != nil {
		log.Fatalf("token verifier: %v", err)
	}
	privateKey, err := loadEd25519Private(envRequired("VAULT_SIGNING_KEY_FILE"))
	if err != nil {
		log.Fatalf("signing private key: %v", err)
	}
	peerPubKey, err := loadEd25519Public(envRequired("VAULT_PEER_PUBLIC_KEY_FILE"))
	if err != nil {
		log.Fatalf("peer public key: %v", err)
	}
	s := &service{
		role:       role,
		localAddr:  envRequired("VAULT_LOCAL_ADDR"),
		peerAddr:   envRequired("VAULT_PEER_ADDR"),
		peerWGIP:   envRequired("VAULT_PEER_WG_IP"),
		stateDir:   envRequired("VAULT_STATE_DIR"),
		tokenHash:  tokenHash,
		privateKey: privateKey,
		peerPubKey: peerPubKey,
		phases:     make(map[string]*phaseState),
	}
	if err := s.restoreSessionState(); err != nil {
		log.Fatalf("persisted Vault session state: %v", err)
	}
	localLn, err := net.Listen("tcp", s.localAddr)
	if err != nil {
		log.Fatalf("local listener: %v", err)
	}
	peerListenAddr := envRequired("VAULT_PEER_LISTEN_ADDR")
	peerLn, err := net.Listen("tcp", peerListenAddr)
	if err != nil {
		log.Fatalf("peer listener: %v", err)
	}
	statusAddr := envRequired("VAULT_STATUS_ADDR")
	statusLn, err := net.Listen("tcp", statusAddr)
	if err != nil {
		log.Fatalf("status listener: %v", err)
	}
	log.Printf("vault-device-coordinator role=%s local=%s peer-listen=%s peer=%s status=%s", role, s.localAddr, peerListenAddr, s.peerAddr, statusAddr)
	go s.sweep()
	go serve(localLn, s.handleLocal)
	go serve(statusLn, s.handleStatus)
	serve(peerLn, s.handlePeer)
}
```

Build independently on both VPSs:

```bash
sudo dnf install -y golang
mkdir -p ~/vault-device-coordinator
# save main.go
cd ~/vault-device-coordinator
go mod init vault-device-coordinator
go build -trimpath -ldflags="-s -w" -o vault-device-coordinator main.go
sudo install -o root -g root -m 0755 vault-device-coordinator /usr/local/sbin/
```

PC environment file `/etc/vault-device/coordinator.env`:

```text
VAULT_ROLE=pc
VAULT_LOCAL_ADDR=PC_VPS_TS_IP:8889
VAULT_STATUS_ADDR=127.0.0.1:8890
VAULT_PEER_LISTEN_ADDR=10.254.0.1:8891
VAULT_PEER_ADDR=10.254.0.2:8891
VAULT_PEER_WG_IP=10.254.0.2
VAULT_STATE_DIR=/var/lib/vault-device
VAULT_TOKEN_HASH_FILE=/etc/vault-device/phase-token.sha256
VAULT_SIGNING_KEY_FILE=/etc/vault-device/signing-key.pem
VAULT_PEER_PUBLIC_KEY_FILE=/etc/vault-device/peer-signing-key.pub.pem
```

On `vault-phone`, set `VAULT_ROLE=phone`, use
`VAULT_LOCAL_ADDR=PHONE_VPS_TS_IP:8889`, swap the `10.254.0.1/10.254.0.2` cross-link
addresses, and keep the same loopback status address. Replace the placeholder strings
with the exact worksheet IPs before starting the services.

Systemd unit:

```ini
[Unit]
Description=Vault device compartment coordinator
After=network-online.target tailscaled.service wg-quick@wg-cross.service
Wants=network-online.target
Requires=wg-quick@wg-cross.service

[Service]
Type=simple
EnvironmentFile=/etc/vault-device/coordinator.env
ExecStart=/usr/local/sbin/vault-device-coordinator
User=vaultcoord
Group=vaultcoord
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vault-device
ReadOnlyPaths=/etc/vault-device

[Install]
WantedBy=multi-user.target
```

Before enabling, fix coordinator ownership without printing secrets:

```bash
sudo chown root:vaultcoord /etc/vault-device/coordinator.env
sudo chown root:vaultcoord /etc/vault-device/phase-token.sha256
sudo chown root:vaultcoord /etc/vault-device/signing-key.pem
sudo chown root:vaultcoord /etc/vault-device/signing-key.pub.pem
sudo chown root:vaultcoord /etc/vault-device/peer-signing-key.pub.pem

sudo chmod 640   /etc/vault-device/coordinator.env   /etc/vault-device/phase-token.sha256   /etc/vault-device/signing-key.pem   /etc/vault-device/signing-key.pub.pem   /etc/vault-device/peer-signing-key.pub.pem

sudo chown -R vaultcoord:vaultcoord /var/lib/vault-device
sudo chmod 700 /var/lib/vault-device
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-device-coordinator.service

systemctl show vault-device-coordinator.service -p User -p Group
ps -eo user,group,pid,comm,args | grep vault-device-coordinator | grep -v grep
```

Expected service identity: `vaultcoord:vaultcoord`.

The coordinator creates one canonical payload and signs it locally. The opposite
coordinator signs only the same payload and only if its own device has joined the same
phase. Exact raw payload bytes are preserved in the bundle; AWS and RHEL verify those
same bytes.

### 23.5 Server-side own-primary expiry remains independent of `DONE`

Tailscale device expiry is a **session hygiene and fresh-reauthentication control**. It
is not the AWS or RHEL authorization factor: AWS and RHEL already enforce cross-VPS
proofs, daily slots, and a signed hard deadline.

The coordinator persists the exact local primary source IP and the one-hour session
deadline. Two paths queue the same `expiry.intent`:

```text
cooperative DONE rhel
        OR
persisted signed hard session deadline reached
```

The local systemd path then invokes the exact-device Tailscale helper from Section 24.
Only `vault-pc` can expire the configured PC NodeID in the PC tailnet. Only
`vault-phone` can expire the configured Phone NodeID in the Phone tailnet.

Tailscale's current API authorization caveat is explicit: the helper needs
`devices:core`, which is broader than an expire-only capability. The stored OAuth
credential is therefore root-only and tailnet-specific, and the helper exposes no
caller-controlled API path, method, device ID, tag, name, or IP mutation operation.

If the expire API outcome is ambiguous, the helper **does not retry automatically**.
It leaves persisted partial state and the Vault session remains fail-closed. The hard
AWS/RHEL window has still ended; the unresolved event is an operator incident because
fresh Tailscale reauthentication cannot be proven.

Suppressing cooperative `DONE rhel` can therefore delay early node-expiry cleanup only
until the signed hard deadline. It cannot move the deadline and cannot create a second
daily AWS/RHEL slot. S3 successful-completion containment is handled separately by the
AWS completion state and signed peer-close path.

### 23.6 Deploy the exact-host S3 CONNECT proxy on each VPS

Use the same narrow proxy binary in each compartment. The listener and coordinator
status address are local to that compartment.

Source:

```go
package main

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	proxyAddr             = "VPS_TS_IP:8888"
	coordinatorStatusAddr = "127.0.0.1:8890"
	authzTimeout          = 3 * time.Second
	s3FinalDrain          = 10 * time.Second
	statusPollInterval    = time.Second
	tunnelMaxLifetime     = 65 * time.Minute
	shutdownDrainTimeout  = 120 * time.Second
)

var allowedHosts = map[string]struct{}{
	"s3.amazonaws.com":           {},
	"s3.us-east-1.amazonaws.com": {},
}

func remoteHost(remote string) (string, bool) {
	host, _, err := net.SplitHostPort(remote)
	return host, err == nil && host != ""
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > 192 {
		return "", errors.New("coordinator response too long")
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(line)), nil
}

func coordinatorQuery(command string) (string, error) {
	conn, err := net.DialTimeout("tcp", coordinatorStatusAddr, authzTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(authzTimeout))
	if _, err := io.WriteString(conn, command+"\n"); err != nil {
		return "", err
	}
	return readLine(bufio.NewReaderSize(conn, 256))
}

func sourceAuthorized(sourceIP string) bool {
	ip := net.ParseIP(sourceIP)
	if ip == nil || ip.To4() == nil {
		return false
	}
	response, err := coordinatorQuery("AUTHZ s3 " + ip.String())
	if err != nil {
		log.Printf("S3 AUTHZ fail-closed for %s: coordinator unavailable: %v", sourceIP, err)
		return false
	}
	return response == "ALLOW s3"
}

func s3Status() (string, error) {
	response, err := coordinatorQuery("STATUS s3")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(response)
	if len(fields) != 2 || fields[1] != "s3" {
		return "", errors.New("unexpected coordinator status response")
	}
	switch fields[0] {
	case "OPEN", "BROKEN", "CLOSED", "WAITING", "IDLE", "EXPIRED":
		return fields[0], nil
	default:
		return "", errors.New("unknown coordinator status")
	}
}

func allowedDestination(hostport string) (string, bool) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port != "443" {
		return "", false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, ok := allowedHosts[host]; !ok {
		return "", false
	}
	return net.JoinHostPort(host, "443"), true
}

type activeTunnel struct {
	client net.Conn
	dest   net.Conn
}

type proxyState struct {
	mu             sync.Mutex
	draining       bool
	closeTriggered bool
	active         sync.WaitGroup
	nextID         uint64
	tunnels        map[uint64]*activeTunnel
}

func (p *proxyState) registerTunnel(sourceIP string, client, dest net.Conn) (uint64, bool) {
	p.mu.Lock()
	if p.draining {
		p.mu.Unlock()
		return 0, false
	}
	p.mu.Unlock()

	// The coordinator is authoritative. A second check narrows the TOCTOU window
	// between the first HTTP admission check and tunnel registration. The two-VPS
	// design cannot make this check atomic across hosts; a phase that closes in the
	// remaining milliseconds is still bounded by the CLOSED/EXPIRED drain monitor.
	if !sourceAuthorized(sourceIP) {
		return 0, false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.draining {
		return 0, false
	}
	p.nextID++
	id := p.nextID
	p.tunnels[id] = &activeTunnel{client: client, dest: dest}
	p.active.Add(1)
	return id, true
}

func (p *proxyState) unregisterTunnel(id uint64) {
	p.mu.Lock()
	delete(p.tunnels, id)
	p.mu.Unlock()
	p.active.Done()
}

func (p *proxyState) forceCloseTunnels() int {
	p.mu.Lock()
	tunnels := make([]*activeTunnel, 0, len(p.tunnels))
	for _, tunnel := range p.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	p.mu.Unlock()
	for _, tunnel := range tunnels {
		_ = tunnel.client.Close()
		_ = tunnel.dest.Close()
	}
	return len(tunnels)
}

func (p *proxyState) closeAfterFinalDrain(reason string) {
	p.mu.Lock()
	if p.closeTriggered {
		p.mu.Unlock()
		return
	}
	p.closeTriggered = true
	p.mu.Unlock()

	log.Printf("S3 transport status %s: new CONNECT admission is already fail-closed; existing tunnels have %s to finish", reason, s3FinalDrain)
	timer := time.NewTimer(s3FinalDrain)
	defer timer.Stop()
	<-timer.C
	closed := p.forceCloseTunnels()
	if closed > 0 {
		log.Printf("S3 final-drain grace expired; force-closed %d remaining CONNECT tunnel(s)", closed)
	} else {
		log.Println("S3 final-drain grace completed with no active CONNECT tunnels")
	}
}

func (p *proxyState) observeCoordinator(stop <-chan struct{}) {
	ticker := time.NewTicker(statusPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			status, err := s3Status()
			if err != nil {
				// New CONNECT requests independently fail closed when AUTHZ cannot
				// reach the coordinator. Existing tunnels are not killed on a brief
				// control-plane outage; each tunnel also has a hard max lifetime.
				continue
			}
			if status == "OPEN" {
				p.mu.Lock()
				p.closeTriggered = false
				p.mu.Unlock()
				continue
			}
			if status == "CLOSED" || status == "EXPIRED" {
				go p.closeAfterFinalDrain(status)
			}
		case <-stop:
			return
		}
	}
}

func (p *proxyState) beginDrain() {
	p.mu.Lock()
	p.draining = true
	p.mu.Unlock()
}

func (p *proxyState) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Only CONNECT allowed", http.StatusMethodNotAllowed)
		return
	}
	sourceIP, ok := remoteHost(r.RemoteAddr)
	if !ok {
		http.Error(w, "Invalid Tailnet source", http.StatusForbidden)
		return
	}
	destination, ok := allowedDestination(r.Host)
	if !ok {
		log.Printf("BLOCKED destination: %s", r.Host)
		http.Error(w, "Destination must be an approved S3 hostname on port 443", http.StatusForbidden)
		return
	}
	if !sourceAuthorized(sourceIP) {
		http.Error(w, "S3 phase admission is closed for this device", http.StatusServiceUnavailable)
		return
	}

	dest, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		dest.Close()
		http.Error(w, "Hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		dest.Close()
		return
	}
	tunnelID, admitted := p.registerTunnel(sourceIP, client, dest)
	if !admitted {
		client.Close()
		dest.Close()
		return
	}
	defer p.unregisterTunnel(tunnelID)

	maxTimer := time.AfterFunc(tunnelMaxLifetime, func() {
		log.Printf("CONNECT tunnel %d exceeded hard max lifetime %s; closing", tunnelID, tunnelMaxLifetime)
		_ = client.Close()
		_ = dest.Close()
	})
	defer maxTimer.Stop()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		dest.Close()
		return
	}

	copyDone := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dest, client); copyDone <- struct{}{} }()
	go func() { _, _ = io.Copy(client, dest); copyDone <- struct{}{} }()
	<-copyDone
	client.Close()
	dest.Close()
	<-copyDone
}

func main() {
	proxy := &proxyState{tunnels: make(map[uint64]*activeTunnel)}
	stopMonitor := make(chan struct{})
	go proxy.observeCoordinator(stopMonitor)

	srv := &http.Server{
		Addr:              proxyAddr,
		Handler:           http.HandlerFunc(proxy.handleConnect),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		log.Println("shutdown requested: closing proxy listener and draining active S3 tunnels")
		proxy.beginDrain()
		close(stopMonitor)
		if err := srv.Close(); err != nil && err != http.ErrServerClosed {
			log.Printf("proxy listener close error: %v", err)
		}
	}()

	log.Printf("vault S3 egress proxy listening: proxy=%s coordinator-status=%s", proxyAddr, coordinatorStatusAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("proxy failed: %v", err)
	}

	drained := make(chan struct{})
	go func() { proxy.active.Wait(); close(drained) }()
	select {
	case <-drained:
		log.Println("all active S3 CONNECT tunnels drained cleanly")
	case <-time.After(shutdownDrainTimeout):
		closed := proxy.forceCloseTunnels()
		log.Printf("shutdown drain timeout reached; force-closed %d remaining CONNECT tunnel(s)", closed)
	}
}
```

Build/install as `vault-s3-proxy`. The proxy permits only the exact regional S3
hostnames documented in its allowlist, asks local `127.0.0.1:8890` whether the caller
Tailnet IP is admitted for the active local S3 phase, and applies its bounded final
drain/tunnel lifetime.

Each device points `HTTPS_PROXY` only at its own VPS:

```text
PC:    http://VPS_TS_IP:8888   in the PC tailnet
Phone: http://VPS_TS_IP:8888   in the Phone tailnet
```

Because the tailnets are separate, these identical addresses resolve to different
machines/routing domains.

### 23.7 Install the client phase helper

Install this same helper on PC and Phone as `~/bin/vault-phase-proof.py`:

```python
#!/usr/bin/env python3
import argparse
import base64
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import time

STOP = False


def on_signal(_signum, _frame):
    global STOP
    STOP = True


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def send_done(host: str, port: int, phase: str, token: str) -> None:
    # A new proof is never requested here. DONE is only local coordinator cleanup.
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(f"JOIN {phase} {token}\n".encode("ascii"))
            s.settimeout(5)
            line = s.makefile("rb", buffering=0).readline(20000)
            if line.startswith(b"OPEN "):
                s.sendall(b"DONE\n")
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8889)
    ap.add_argument("--phase", choices=("s3", "rhel"), required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--proof-out", required=True)
    ap.add_argument("--ready-file", required=True)
    args = ap.parse_args()

    token = Path(args.token_file).read_text(encoding="ascii").strip()
    if len(token) != 64 or any(c not in "0123456789abcdefABCDEF" for c in token):
        raise SystemExit("phase token must be exactly 64 hexadecimal characters")

    proof_out = Path(args.proof_out)
    ready_file = Path(args.ready_file)
    proof_out.unlink(missing_ok=True)
    ready_file.unlink(missing_ok=True)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    sock = socket.create_connection((args.host, args.port), timeout=10)
    sock.settimeout(50)
    file = sock.makefile("rb", buffering=0)
    sock.sendall(f"JOIN {args.phase} {token}\n".encode("ascii"))

    first = file.readline(20000)
    if not first:
        raise SystemExit("coordinator closed before phase approval")
    parts = first.decode("ascii", errors="strict").strip().split(" ", 2)
    if len(parts) != 3 or parts[0] != "OPEN" or parts[1] != args.phase:
        raise SystemExit(f"phase rejected: {first.decode('ascii', errors='replace').strip()}")

    try:
        bundle_raw = base64.b64decode(parts[2], validate=True)
        bundle = json.loads(bundle_raw)
        for key in ("payload", "pc_signature", "phone_signature"):
            if not isinstance(bundle.get(key), str):
                raise ValueError(f"missing {key}")
    except Exception as exc:
        raise SystemExit(f"invalid signed proof bundle from coordinator: {exc}")

    atomic_write(proof_out, json.dumps(bundle, separators=(",", ":")).encode("utf-8") + b"\n")
    atomic_write(ready_file, b"ready\n")

    try:
        while not STOP:
            time.sleep(20)
            if STOP:
                break
            sock.sendall(b"PING\n")
            reply = file.readline(256)
            if reply.strip() != b"PONG":
                raise OSError(f"unexpected coordinator reply: {reply!r}")
    finally:
        try:
            sock.sendall(b"DONE\n")
            sock.settimeout(5)
            file.readline(256)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
        ready_file.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Example PC S3 phase:

```bash
mkdir -p ~/.local/run/vault
python3 ~/bin/vault-phase-proof.py   --host 100.64.0.1   --phase s3   --token-file ~/.config/vault-secrets/oracle_phase_token   --proof-out ~/.local/run/vault/s3-proof.json   --ready-file ~/.local/run/vault/s3.ready &
PHASE_PID=$!

while [[ ! -f ~/.local/run/vault/s3.ready ]]; do
  kill -0 "$PHASE_PID" 2>/dev/null || exit 1
  sleep 1
done
```

The Phone runs the same command against its own `100.64.0.1`. A proof appears only
after both local phase sockets exist and both VPS signatures are present.

If a helper socket drops, restarting the helper within the 90-second coordinator grace
may reclaim that local phase state and receive the already-created bundle. It must not
create a second AWS daily issuance because the DynamoDB slot is independent.

At phase completion:

```bash
kill -TERM "$PHASE_PID"
wait "$PHASE_PID" || true
```

### 23.7A Install the close-only peer S3 helper

Install this same helper on PC and Phone as `~/bin/vault-close-peer.py`:

```python
#!/usr/bin/env python3
import argparse
from pathlib import Path
import socket
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', required=True)
    ap.add_argument('--port', type=int, default=8889)
    ap.add_argument('--token-file', required=True)
    args = ap.parse_args()

    token = Path(args.token_file).read_text(encoding='ascii').strip()
    if len(token) != 64 or any(c not in '0123456789abcdefABCDEF' for c in token):
        raise SystemExit('phase token must be exactly 64 hexadecimal characters')

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(f'CLOSE_PEER s3 {token}\n'.encode('ascii'))
        reply = sock.makefile('rb', buffering=0).readline(1024)

    text = reply.decode('ascii', errors='replace').strip()
    if text != 'CLOSED peer-s3':
        print(f'peer close rejected: {text}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
```

Install and syntax-check:

```bash
chmod 700 "$HOME/bin/vault-close-peer.py"
python3 -m py_compile "$HOME/bin/vault-close-peer.py"
```

This helper does **not** accept a target role. The local coordinator derives the
opposite role from its own configured `VAULT_ROLE`, signs a short-lived close payload,
and sends it over `wg-cross`. The receiving coordinator accepts the close only from the
exact peer WireGuard IP, only with the opposite VPS Ed25519 signature, only for phase
`s3`, only for its own role, and only when the payload carries the exact active shared
`session_expires_at` value.

`CLOSE_PEER` can close admission only. It cannot request a proof, create an STS session,
open RHEL, reset a daily slot, or extend the hard deadline. A compromised primary that
owns its own phase token can therefore abuse this path for denial of service against the
opposite S3 phase; under the documented single-compromise threat model that fail-safe
close-only authority is accepted instead of giving the compromised target a containment
veto.

### 23.8 Firewall invariant

Canonical Tailscale/managed-DERP profile:

```text
PUBLIC INPUT TO EACH VPS
  operator-restricted SSH
  UDP/51830 from opposite VPS /32 only (wg-cross)

NO PUBLIC VAULT INPUT
  no UDP/40000 Peer Relay
  no self-hosted DERP TCP/443
  no self-hosted STUN UDP/3478
  no public S3 proxy
  no public coordinator
```

The S3 proxy and coordinator bind only to the matching Tailscale address/loopback/cross
WireGuard address. Tailscale-hosted DERP is Tailscale infrastructure, not a listener on the two
Vault VPSs.

### 23.9 Required tests

Before repository initialization:

```text
[ ] PC alone joins s3 → no proof
[ ] Phone alone joins s3 → no proof
[ ] both join s3 → both receive bundles with the same payload and both signatures
[ ] alter one payload byte → Lambda rejects
[ ] remove either signature → Lambda rejects
[ ] first PC invocation/day → one STS credential
[ ] second PC invocation/day → DailySlotConsumed
[ ] Phone slot remains independent
[ ] STS failure after slot consumption → no Lambda/STS retry
[ ] same issued STS credential supports transient S3 retry only before successful completion revocation and the signed hard deadline
[ ] own SSO/MFA with the opposite primary absent cannot produce a valid fresh S3 issuance proof
[ ] snapshot creation alone does not revoke; later lock removal completes the AWS-side completion condition
[ ] exact-session REVOKED status lets the clean opposite primary close target S3 proxy admission through signed CLOSE_PEER
[ ] PC role cannot access Phone bucket
[ ] Phone role cannot access PC bucket
[ ] S3 request from a non-approved public IP → denied
[ ] DONE rhel persists local node-expiry intent before phase completion
```

The key distinction must remain explicit:

> **credential issuance is non-retryable after daily-slot consumption; S3 data-plane
> operations may retry with the already-issued credential only while that backup remains
> incomplete, the exact completion state is not REVOKED, and the signed hard deadline
> remains open. Successful completion deliberately cuts off reuse of the old session.**

## Section 24 - Two Independent Tailscale Tailnets, Tailnet Lock, Tailscale-hosted DERP, and Exact Own-Device Expiry

### 24.1 Security decision

For this threat model, Tailscale's main architectural advantage is **Tailnet Lock**.
Headscale currently lacks that feature. With Tailnet Lock correctly bootstrapped and
verified, an attacker who controls only the Tailscale coordination plane cannot insert
an unsigned rogue node that locked peers will accept.

The claim is deliberately narrow:

```text
Tailscale control-plane-only compromise
        ↓
unsigned rogue node insertion
        ↓
blocked by Tailnet Lock peer verification
```

Tailnet Lock does **not** stop a compromised coordination plane from causing denial of
service, withholding network information, or distributing policy that denies
connectivity. It also does not save a tailnet after a trusted Tailnet Lock signing node
or a disablement secret is compromised. The cross-VPS Ed25519 proof remains mandatory
for S3 and RHEL even in the Tailscale profile.

### 24.2 Keep exactly two VPS security compartments

The Tailscale plan still uses **two VPSs total**:

```text
vault-pc VPS
    PC coordinator
    PC Ed25519 private signing key
    PC exact-host S3 CONNECT proxy
    PC reserved AWS-approved egress IPv4
    PC Tailscale API expiry helper
    
vault-phone VPS
    Phone coordinator
    Phone Ed25519 private signing key
    Phone exact-host S3 CONNECT proxy
    Phone reserved AWS-approved egress IPv4
    Phone Tailscale API expiry helper
    
vault-pc ⇄ dedicated wg-cross ⇄ vault-phone
```

Do not install Headscale or self-hosted DERP on the two VPSs in this baseline. Keep the dedicated `wg-cross` link for the fixed, narrow
coordinator-to-coordinator signing protocol. Firewall the `wg-cross` listener to the
other VPS reserved public `/32` only; do not replace it with broad public coordinator
HTTP.

### 24.3 Preserve two independent tailnets

The exact compartment-equivalent topology is:

```text
PC tailnet
  PC
  vault-pc
  RHEL-PC Tailscale instance

Phone tailnet
  Phone
  vault-phone
  RHEL-Phone Tailscale instance
```

Do not put PC and Phone into one shared tailnet merely to simplify installation. Tailnet
Lock addresses unauthorized membership, but one shared tailnet would reintroduce a
shared policy/control domain capable of changing reachability for both compartments.

Tailscale's multiple-tailnet-under-one-organization feature is currently alpha and its
documentation directs organizations to contact sales. For a personal deployment, plan
on **two separate Tailscale login identities/tailnets unless your account explicitly has
supported multi-tailnet provisioning**. The RHEL two-`tailscaled` network-namespace
layout already supports separate tailnet identities.

Before proceeding, prove that the account/tailnet arrangement can be created without
merging the compartments. If it cannot, stop and use `Vault_Extension_Headscale_Control_Plane.md` rather than silently weakening
the two-compartment topology.

### 24.4 Tailnet Lock is mandatory on both tailnets

Enable Tailnet Lock independently in the PC and Phone tailnets. Verify the TKA state
from the Linux nodes that expose the `tailscale lock` CLI; use the admin console plus a
real connectivity test for Android.

Tailscale currently requires at least two signing nodes during Tailnet Lock
initialization. **Android cannot currently perform Tailnet Lock signing operations**, so
the Phone itself cannot be one of the two initial signing nodes. Keep the two-VPS total
unchanged and use the infrastructure nodes already present in each compartment:

```text
PC tailnet:    vault-pc + RHEL-PC Tailscale instance
Phone tailnet: vault-phone + RHEL-Phone Tailscale instance
```

The RHEL instances are the two independent `tailscaled` states/sockets/TUNs already
defined in Part 2; each instance belongs only to its matching tailnet. The Phone remains
a locked peer whose node key must be signed, but it is not a signer. The Fedora PC is
capable of CLI signing, but the reference does not make a primary plaintext endpoint a
trusted signing node by default.

Store all Tailnet Lock disablement secrets offline in the authoritative password manager
and an independent recovery copy. Do not place them on either VPS, RHEL, PC backup
scripts, Phone backup scripts, or AWS Lambda.

**Residual signer risk:** Tailnet Lock removes the control-plane-only insertion path; it
does not require two signatures for each new tailnet node. Compromise of one trusted
Tailnet Lock signing node can affect membership in that signing node's own tailnet. A
full root compromise of the single physical RHEL host can also expose both namespace
instances' local Tailscale/Tailnet Lock state, so the RHEL host remains a shared physical
trust boundary for membership recovery. This is why Tailnet Lock is not used as the
Vault dual-device authorization factor. AWS and the RHEL opening gate continue to
require both independent Vault VPS Ed25519 signatures.

After initialization, run on the Linux signing/verification nodes:

```bash
tailscale lock status
```

Use the matching `--socket` path for each RHEL namespace instance. PC-tailnet Linux
nodes must report one consistent trusted-key set and Phone-tailnet Linux nodes another.
Android has no Tailscale CLI and cannot be used to run `tailscale lock status`; verify
the Phone is signed/not `Locked out` in the Tailscale Machines page and prove real
Phone-to-own-services connectivity after signing. Treat any signer-key disagreement or
locked-out primary device as a rollout stop condition.

### 24.5 Recommended transport profile: direct → Tailscale Tailscale-hosted DERP

The recommended Tailscale baseline is intentionally **not** Peer Relay-preferred:

```text
direct WireGuard path when possible
        ↓ if direct fails
Tailscale-hosted DERP fallback
```

In this profile remove from both VPS firewalls/services:

```text
public UDP/40000  Peer Relay listener
public TCP/443    self-hosted DERP listener
public UDP/3478   self-hosted DERP/STUN listener
```

The VPS exact-host S3 proxy remains Tailnet-only; its reserved public IPv4 is used for
**outbound S3 source-IP policy**, not as a public inbound backup listener.

This managed-DERP baseline is preferred for the Tailscale variant because it removes
three public relay/STUN listener classes from each Vault VPS. Tailscale-hosted DERP is
still a relay of WireGuard end-to-end encrypted tailnet traffic. The trade-off is
performance: DERP is a TCP relay path and can be materially slower than direct UDP or a
well-placed Peer Relay for large restic transfers.


> Peer Relay is intentionally absent from this section. Apply `Vault_Extension_Peer_Relay_Performance.md` only after the baseline transport test proves Tailscale-hosted DERP too slow for the real backup delta.

### 24.6 Primary-device expiry: keep the `devices:core` caveat explicit

The elegant Headscale path is local and narrow:

```text
root-owned helper
  ↓
headscale nodes expire <locally validated exact node>
```

Tailscale's API currently exposes device expiry through `devices:core`. That scope also
covers reading devices and mutation endpoints for device removal, authorization, IP,
name, key, and tags. Therefore **do not describe the Tailscale expiry credential as an
"expire-only" credential**.

Use **one separate OAuth trust credential per tailnet/VPS**:

```text
vault-pc credential    → PC tailnet only, devices:core only
vault-phone credential → Phone tailnet only, devices:core only
```

Select only the dedicated helper tag required when creating the credential. Do not add
`all`, `policy_file`, `auth_keys`, Tailnet Lock administration, DNS, route, user, or
other scopes.

The root-owned helper must implement compensating controls before calling the expire
endpoint:

```text
fixed command grammar: no arbitrary API path / verb
fixed expected primary device ID stored root-only
fixed expected primary Tailscale IP / identity binding
live phase source IP must map to that exact expected device
expected tailnet checked
expected hostname checked only as an additional signal, never sole identity
revocation intent persisted before accepting DONE rhel completion
restart-persistent hard session deadline independently queues the same intent if DONE is suppressed
partial completion persisted and bound to exact intent bytes
only POST /api/v2/device/<EXACT_EXPECTED_ID>/expire emitted
any mismatch / API ambiguity → fail closed; no new Vault session
```

The exact storage/delivery standard for this OAuth credential is defined in
`Vault_Post_Install_Detection_and_Credential_Custody.md`. Prefer Tailscale workload
identity federation instead of a stored OAuth client secret **only if the chosen VPS
provider exposes a trustworthy OIDC workload identity that can be pinned to the exact
VM/subject**. Otherwise use an owning-VPS-only systemd service credential, preferring
`LoadCredentialEncrypted=`/TPM-backed `systemd-creds` where the platform supports it;
root-owned mode-`600` `LoadCredential=` storage is the minimum fallback. Never put the
secret in a shell profile, global environment, source tree, cloud-init user-data, or on
the opposite VPS. Encryption at rest does not protect a credential that a fully
root-compromised owning VPS can legitimately use at runtime.

The mandatory post-install guide also deploys an AWS-side Tailscale configuration-audit
watcher. That watcher authenticates through AWS-to-Tailscale workload identity federation
and receives only `logs:configuration:read`; it stores no Tailscale audit secret. Exact
own-primary expiry near a matching daily-slot window is the only expected mutation by
the pinned expiry actor. Other mutations by that actor are CRITICAL.

This is a compensating-control design, not true API least privilege. The Headscale extension's native local expiry is architecturally cleaner on this one point.

### 24.7 Per-session login/MFA behavior

The Tailscale profile must preserve the current operational rule that an expired primary
device cannot silently resume the next Vault ceremony with a still-valid long-lived
network identity.

The local expiry helper expires **only its own primary device** when either (a) the
cooperative `DONE rhel` path persists revocation intent or (b) the restart-persistent
hard session deadline independently queues that intent. Tailscale documents that
expired device keys stop connectivity and a CLI device must reauthenticate
(`tailscale up --force-reauth`) to renew access. The Tailscale API helper must remove
`session.deadline.json` only after the exact expected device expiry succeeds; partial
API state remains fail-closed and blocks a new Vault session.

Use the chosen Tailscale identity provider with MFA required for the Vault user. If you
retain the current Authelia/OIDC authentication model, create separate Tailscale OIDC
client/issuer arrangements for the two compartment tailnets and keep the authenticator
material off PC, Phone, both VPSs, and RHEL.

Do not tag the human primary endpoints merely to make API automation easier without
reviewing key-expiry behavior: Tailscale disables key expiry by default for tagged
devices after authentication. The primary devices are intended to be user-authenticated
and explicitly expired/re-authenticated by this workflow.

#### 24.8 Create a Tailscale deployment worksheet

Record the PC and Phone tailnet values separately:

```text
PC TAILSCALE WORKSHEET
======================
Tailnet ID =
Tailnet DNS name =
Primary PC hostname =
Primary PC NodeID =
Primary PC Tailscale IPv4 =
vault-pc hostname =
vault-pc Tailscale IPv4 =
RHEL-PC hostname =
RHEL-PC Tailscale IPv4 =
OAuth expiry client ID file = /etc/vault-ts-expiry/oauth-client-id
OAuth expiry client secret file = /etc/vault-ts-expiry/oauth-client-secret
OAuth helper tag = tag:vault-expiry-helper

PHONE TAILSCALE WORKSHEET
=========================
Tailnet ID =
Tailnet DNS name =
Primary Phone hostname =
Primary Phone NodeID =
Primary Phone Tailscale IPv4 =
vault-phone hostname =
vault-phone Tailscale IPv4 =
RHEL-Phone hostname =
RHEL-Phone Tailscale IPv4 =
OAuth expiry client ID file = /etc/vault-ts-expiry/oauth-client-id
OAuth expiry client secret file = /etc/vault-ts-expiry/oauth-client-secret
OAuth helper tag = tag:vault-expiry-helper
```

The **Tailnet ID** is the API identifier shown on the Tailscale General page. Do not use
a guessed email/domain value from an old API example. Keep the two tailnet worksheets
separate even if the display names look similar.

#### 24.9 Enroll exactly three nodes in each tailnet before enabling Tailnet Lock

PC tailnet membership:

```text
Fedora PC
vault-pc
RHEL-PC tailscaled instance
```

Phone tailnet membership:

```text
Android Phone
vault-phone
RHEL-Phone tailscaled instance
```

Do not share nodes across the two tailnets.

On `vault-pc`, after installing the current Tailscale package:

```bash
sudo tailscale logout 2>/dev/null || true
sudo tailscale up \
  --hostname=vault-pc \
  --accept-routes=false \
  --accept-dns=false \
  --ssh=false

tailscale status
tailscale ip -4
```

Use the browser URL printed by the CLI and authenticate to the **PC tailnet**. Repeat on
`vault-phone`, authenticating to the **Phone tailnet**.

On Fedora PC:

```bash
sudo tailscale logout 2>/dev/null || true
sudo tailscale up \
  --hostname=vault-primary-pc \
  --accept-routes=false \
  --accept-dns=false \
  --shields-up=true \
  --ssh=false

tailscale status
tailscale ip -4
tailscale set --shields-up=true
tailscale set --ssh=false
```

On Android, sign in to the Phone tailnet in the Tailscale application and keep
**Allow incoming connections** disabled. Android has no Tailscale CLI; do not invent a
Termux `tailscale lock` workflow.

For RHEL, use the two independent daemon sockets from Part 2. Keep the separate
state/socket/TUN services and authenticate each instance to its matching Tailscale
tailnet:

```bash
# RHEL-PC instance
sudo tailscale --socket=/run/tailscale-vault-pc/tailscaled.sock up \
  --hostname=vault-rhel-pc \
  --accept-routes=false \
  --accept-dns=false \
  --ssh=false

# RHEL-Phone instance
sudo tailscale --socket=/run/tailscale-vault-phone/tailscaled.sock up \
  --hostname=vault-rhel-phone \
  --accept-routes=false \
  --accept-dns=false \
  --ssh=false
```

Authenticate each URL to its matching tailnet. Then record addresses:

```bash
# PC-tailnet RHEL instance
sudo tailscale --socket=/run/tailscale-vault-pc/tailscaled.sock ip -4

# Phone-tailnet RHEL instance
sudo tailscale --socket=/run/tailscale-vault-phone/tailscaled.sock ip -4
```

Before proceeding, the Machines page of each tailnet must show exactly its expected
three Vault nodes and no cross-compartment node.

#### 24.10 Reconcile the Tailscale address contract before rebuilding services

The canonical baseline pins:

```text
own VPS = VPS_TS_IP
own RHEL instance = RHEL_TS_IP
```

Tailscale assigns tailnet addresses. **Do not build binaries/configs with stale documentation addresses.** The recommended installation method is to keep the assigned
Tailscale addresses and update the local configuration contract rather than using the
broad production expiry credential as a general IP-management tool.

For each compartment, record:

```text
PRIMARY_TS_IP
VPS_TS_IP
RHEL_TS_IP
```

Then update/rebuild these exact locations:

```text
vault-device-coordinator systemd environment:
  VAULT_LOCAL_ADDR=<VPS_TS_IP>:8889

vault-s3-proxy Go constant:
  proxyAddr = "<VPS_TS_IP>:8888"

RHEL namespace Caddy listener:
  <RHEL_TS_IP>:8001   # PC compartment
  <RHEL_TS_IP>:8002   # Phone compartment

RHEL certificate SAN:
  IP:<RHEL_TS_IP>

primary daily script / RHEL repository URL:
  https://<RHEL_TS_IP>:8001   # PC
  https://<RHEL_TS_IP>:8002   # Phone

Tailscale policy hosts:
  primary = <PRIMARY_TS_IP>
  vault-vps = <VPS_TS_IP>
  rhel = <RHEL_TS_IP>
```

The coordinator already learns the primary source IP from the live local phase socket;
its persisted `expiry.intent` therefore contains the Tailscale primary address observed
for that ceremony. The Tailscale expiry helper below requires that address to equal the
root-owned expected primary IP.

Rebuild the coordinator/proxy after address changes and reissue the RHEL listener
certificate if its SAN changed. Repeat the Part 2 Caddy TLS test before continuing.

#### 24.11 Apply deny-by-default grants in each tailnet

Use a separate policy file in each tailnet. PC-tailnet template:

```json
{
  "tagOwners": {
    "tag:vault-expiry-helper": ["autogroup:admin"]
  },
  "hosts": {
    "vault-primary": "PC_PRIMARY_TS_IP",
    "vault-vps": "PC_VPS_TS_IP",
    "vault-rhel": "PC_RHEL_TS_IP"
  },
  "grants": [
    {
      "src": ["vault-primary"],
      "dst": ["vault-vps"],
      "ip": ["tcp:8889", "tcp:8888"]
    },
    {
      "src": ["vault-primary"],
      "dst": ["vault-rhel"],
      "ip": ["tcp:8001"]
    }
  ],
  "ssh": []
}
```

Phone-tailnet template is symmetric and uses Phone addresses plus `tcp:8002` for RHEL.
Keep the same `tagOwners` declaration so the dedicated expiry OAuth credential can be
created with only `tag:vault-expiry-helper` as its permitted tag. The reference does not
apply that tag to the primary device; the primary remains user-authenticated and untagged.
There is no PC↔Phone grant because the devices are not in the same tailnet. There is no
VPS→primary application grant. The primary devices still keep local inbound blocking.

After saving each policy, test from the primary:

```bash
nc -vz -w3 VPS_TS_IP 8889
nc -vz -w3 VPS_TS_IP 8888
nc -vz -w3 RHEL_TS_IP RHEL_PORT
```

Then test a port that is not granted:

```bash
nc -vz -w3 VPS_TS_IP 22
```

The Vault ports must succeed when their services are listening; the ungranted port must
not become reachable through the tailnet policy.

#### 24.12 Enable Tailnet Lock with Linux infrastructure signers

Enroll all three expected nodes **before** initialization. Tailnet Lock initialization
signs existing nodes. In the PC tailnet:

1. Open **Device management** in the matching Tailscale admin console.
2. Select **Enable Tailnet Lock**.
3. Select `vault-pc` and `vault-rhel-pc` as the two signing nodes.
4. Copy the exact `tailscale lock init ...` command generated by the console.
5. Run that command on `vault-pc`.
6. Save the ten printed disablement secrets offline. One valid disablement secret can
   disable Tailnet Lock; the values are shown only during initialization.

Do the symmetric operation in the Phone tailnet with `vault-phone` and
`vault-rhel-phone` as signing nodes.

Verify PC-tailnet state:

```bash
# vault-pc
tailscale lock status
tailscale lock log

# RHEL-PC
sudo tailscale --socket=/run/tailscale-vault-pc/tailscaled.sock lock status
```

Verify Phone-tailnet state:

```bash
# vault-phone
tailscale lock status
tailscale lock log

# RHEL-Phone
sudo tailscale --socket=/run/tailscale-vault-phone/tailscaled.sock lock status
```

The trusted signing-key sets must match within each tailnet. The PC tailnet and Phone
tailnet have independent TKA state.

The Fedora PC can also run `tailscale lock status` as a non-signer verification node.
Android cannot perform signing operations or run the CLI. In the Phone-tailnet Machines
page, verify the Phone is not marked **Locked out**, then prove it reaches only its own
VPS/RHEL services.

When adding a new node after Tailnet Lock is enabled, do not temporarily disable the
lock. Find the locked-out node in the Machines page, choose **Sign machine → CLI**, copy
the generated `tailscale lock sign ...` command, and run it on one of the trusted Linux
signers in that tailnet.

Do not enable Tailscale Device Approval in parallel with Tailnet Lock; the reference
profile uses Tailnet Lock as the membership integrity feature.

#### 24.13 Create a dedicated `devices:core` OAuth credential on each tailnet

In the PC-tailnet **Trust credentials** page:

1. Create an OAuth credential.
2. Grant only **Devices / Core — Write** (`devices:core`).
3. Select only the target device's tag (e.g., `tag:pc-device` or similar) as the credential tag permission (Tag Ownership) so the token cannot manipulate tags of the VPS or RHEL server.
4. Do not grant `all`, policy, auth-key, DNS, route, user, Tailnet Lock, or logging
   scopes.
5. Copy the client ID and client secret once.

Repeat independently in the Phone tailnet. Never reuse the PC credential in the Phone
tailnet.

On the matching VPS:

```bash
sudo install -d -o root -g root -m 700 /etc/vault-ts-expiry
sudo install -m 600 /dev/null /etc/vault-ts-expiry/oauth-client-id
sudo install -m 600 /dev/null /etc/vault-ts-expiry/oauth-client-secret

sudoedit /etc/vault-ts-expiry/oauth-client-id
sudoedit /etc/vault-ts-expiry/oauth-client-secret
```

Each file contains exactly one value and no explanatory text.

The OAuth client secret is long-lived until revoked. Tailscale access tokens minted from
it are short-lived, but the stored client secret remains a high-value credential. The
scope is broader than expire-only; the fixed helper below is a compensating control.

#### 24.14 Record the exact expected primary NodeID and identity

Use a temporary access token only for setup verification. From the matching VPS:

```bash
CLIENT_ID=$(sudo cat /etc/vault-ts-expiry/oauth-client-id)
CLIENT_SECRET=$(sudo cat /etc/vault-ts-expiry/oauth-client-secret)
OAUTH_TAG='tag:vault-expiry-helper'

ACCESS_TOKEN=$(curl --fail --silent --show-error \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d grant_type=client_credentials \
  --data-urlencode scope=devices:core \
  --data-urlencode tags="$OAUTH_TAG" \
  https://api.tailscale.com/api/v2/oauth/token \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl --fail --silent --show-error \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://api.tailscale.com/api/v2/tailnet/TAILNET_ID/devices" \
  | python3 -m json.tool

unset ACCESS_TOKEN CLIENT_SECRET
```

From the matching device record, copy the preferred `nodeId`, exact `addresses` entry,
and `hostname`. Confirm:

```text
keyExpiryDisabled = false
isExternal = false
tags = []
```

The primary endpoints remain user-authenticated and untagged. Do not tag them to make
automation easier; reauthentication of tagged devices changes key-expiry behavior.

Create root-owned config on `vault-pc`:

```bash
sudo tee /etc/vault-ts-expiry/config.json >/dev/null <<'JSON'
{
  "tailnet_id": "PC_TAILNET_ID",
  "expected_node_id": "PC_PRIMARY_NODE_ID",
  "expected_tailscale_ipv4": "PC_PRIMARY_TS_IP",
  "expected_hostname": "PC_PRIMARY_HOSTNAME",
  "oauth_tag": "tag:vault-expiry-helper"
}
JSON
sudo chown root:root /etc/vault-ts-expiry/config.json
sudo chmod 600 /etc/vault-ts-expiry/config.json
```

Create the symmetric Phone config on `vault-phone`.

#### 24.15 Install the fixed Tailscale expiry helper

Install this exact Python helper on each VPS as
`/usr/local/sbin/vault-tailscale-expire-primary`:

```python
#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API_BASE = "https://api.tailscale.com"
CONFIG = Path("/etc/vault-ts-expiry/config.json")
CLIENT_ID_FILE = Path("/etc/vault-ts-expiry/oauth-client-id")
CLIENT_SECRET_FILE = Path("/etc/vault-ts-expiry/oauth-client-secret")
INTENT = Path("/var/lib/vault-device/expiry.intent")
DEADLINE = Path("/var/lib/vault-device/session.deadline.json")
PARTIAL = Path("/var/lib/vault-device/tailscale-expiry.partial")


def die(message: str) -> None:
    print(f"CRITICAL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text_secret(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        die(f"cannot read {path}: {exc}")
    if not value:
        die(f"{path} is empty")
    return value


def load_config() -> dict:
    try:
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"invalid config: {exc}")
    required = {
        "tailnet_id",
        "expected_node_id",
        "expected_tailscale_ipv4",
        "expected_hostname",
        "oauth_tag",
    }
    missing = sorted(required - set(cfg))
    if missing:
        die(f"config missing fields: {', '.join(missing)}")
    if not re.fullmatch(r"100\.(?:6[4-9]|[78]\d|9[0-9]|1[01]\d|12[0-7])(?:\.\d{1,3}){2}", cfg["expected_tailscale_ipv4"]):
        die("expected_tailscale_ipv4 is not in 100.64.0.0/10")
    if not cfg["oauth_tag"].startswith("tag:"):
        die("oauth_tag must start with tag:")
    return cfg


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(path.parent)


def oauth_token(client_id: str, client_secret: str, scope: str, tag: str) -> str:
    form = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "scope": scope,
            "tags": tag,
        }
    ).encode("ascii")
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        API_BASE + "/api/v2/oauth/token",
        data=form,
        method="POST",
        headers={
            "Authorization": "Basic " + basic,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "vault-tailscale-expire-primary/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.load(resp)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        die(f"OAuth token request failed: {exc}")
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        die("OAuth response did not contain access_token")
    return token


def api_json(path: str, token: str) -> dict:
    req = urllib.request.Request(
        API_BASE + path,
        method="GET",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "User-Agent": "vault-tailscale-expire-primary/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        die(f"Tailscale GET {path} failed: {exc}")


def expire_once(node_id: str, token: str) -> None:
    # Fixed verb and fixed endpoint grammar. No caller-controlled URL or method exists.
    quoted = urllib.parse.quote(node_id, safe="")
    path = f"/api/v2/device/{quoted}/expire"
    req = urllib.request.Request(
        API_BASE + path,
        data=b"",
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Length": "0",
            "User-Agent": "vault-tailscale-expire-primary/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if not 200 <= resp.status < 300:
                die(f"unexpected expire status {resp.status}")
    except urllib.error.HTTPError as exc:
        die(f"Tailscale expire returned HTTP {exc.code}")
    except urllib.error.URLError as exc:
        # PARTIAL intentionally remains. An API-side success followed by a lost response
        # is ambiguous; automatic retry is forbidden by this helper's fail-closed model.
        die(f"Tailscale expire outcome ambiguous: {exc}")


def main() -> None:
    cfg = load_config()
    if not INTENT.exists():
        die("expiry.intent does not exist")
    try:
        intent_bytes = INTENT.read_bytes()
    except OSError as exc:
        die(f"cannot read expiry intent: {exc}")
    m = re.fullmatch(rb"ip=([^\r\n]+)\n", intent_bytes)
    if not m:
        die("expiry.intent has unexpected grammar")
    intent_ip = m.group(1).decode("ascii", errors="strict")
    if intent_ip != cfg["expected_tailscale_ipv4"]:
        die("expiry intent IP does not equal the configured exact primary IP")

    intent_hash = hashlib.sha256(intent_bytes).hexdigest()
    if PARTIAL.exists():
        previous = read_text_secret(PARTIAL)
        if previous != intent_hash:
            die("partial expiry state belongs to different intent bytes")
        die("previous Tailscale expire attempt is ambiguous; verify the exact device manually and recover explicitly; automatic retry is disabled")

    client_id = read_text_secret(CLIENT_ID_FILE)
    client_secret = read_text_secret(CLIENT_SECRET_FILE)
    token = oauth_token(client_id, client_secret, "devices:core", cfg["oauth_tag"])

    tailnet = urllib.parse.quote(cfg["tailnet_id"], safe="")
    listed = api_json(f"/api/v2/tailnet/{tailnet}/devices", token)
    devices = listed.get("devices")
    if not isinstance(devices, list):
        die("device list response is malformed")

    exact = [d for d in devices if d.get("nodeId") == cfg["expected_node_id"]]
    if len(exact) != 1:
        die(f"expected exactly one configured NodeID in expected tailnet, found {len(exact)}")
    if sum(cfg["expected_tailscale_ipv4"] in (d.get("addresses") or []) for d in devices) != 1:
        die("expected primary Tailscale IPv4 is not uniquely bound inside the expected tailnet")

    device = exact[0]
    if cfg["expected_tailscale_ipv4"] not in (device.get("addresses") or []):
        die("configured NodeID does not own the expected Tailscale IPv4")
    if device.get("hostname") != cfg["expected_hostname"]:
        die("configured NodeID hostname mismatch")
    if device.get("isExternal") is True:
        die("expected primary unexpectedly appears as an external/shared device")
    if device.get("keyExpiryDisabled") is True:
        die("primary device key expiry is disabled")
    if device.get("tags"):
        die("primary device unexpectedly has tags; reference profile requires a user-authenticated untagged primary")

    # Persist exact-intent partial state before the only expire API call. If the call
    # times out after server-side success, we block rather than retry a broad-scope API
    # credential automatically.
    try:
        write_exclusive(PARTIAL, (intent_hash + "\n").encode("ascii"))
    except FileExistsError:
        die("partial expiry state appeared concurrently")
    except OSError as exc:
        die(f"could not persist partial expiry state: {exc}")

    expire_once(cfg["expected_node_id"], token)

    # Re-read the intent and require byte-for-byte stability before cleanup.
    try:
        if INTENT.read_bytes() != intent_bytes:
            die("expiry.intent changed after API success; leave fail-closed state for operator review")
    except OSError as exc:
        die(f"cannot re-read expiry intent after API success: {exc}")

    for path in (INTENT, DEADLINE, PARTIAL):
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            die(f"expire succeeded but cleanup failed for {path}: {exc}")
    fsync_dir(INTENT.parent)
    print("exact expected primary device expired successfully; Vault session state cleared")


if __name__ == "__main__":
    main()
```

Install and syntax-check:

```bash
sudo install -o root -g root -m 755 \
  /PATH/TO/vault-tailscale-expire-primary \
  /usr/local/sbin/vault-tailscale-expire-primary

python3 -m py_compile /usr/local/sbin/vault-tailscale-expire-primary
```

The helper has no command-line argument for device ID, API path, or HTTP verb. It:

```text
reads exact expiry.intent bytes
requires ip=<configured exact primary Tailscale IP>
requests devices:core token from own-tailnet OAuth credential
lists only configured expected tailnet
requires exactly one configured NodeID match
requires expected IP uniquely present in that tailnet
requires exact hostname
requires non-external, untagged, key-expiry-enabled primary
persists SHA-256(intent) to tailscale-expiry.partial
POSTs only /api/v2/device/<EXACT_NODE_ID>/expire once
clears expiry.intent + session.deadline.json only after explicit 2xx success
```

If the API call times out after the partial marker is written, the helper **does not
retry automatically**. A response-loss case could be “expire succeeded, response lost.”
The persistent partial marker blocks automation until the operator verifies the exact
primary device in the Tailscale admin console/API and performs explicit recovery. This
is availability-sacrificing fail-closed behavior around a broad `devices:core`
credential.

#### 24.16 Wire the same coordinator expiry intent to the Tailscale helper

Preserve the coordinator's existing `/var/lib/vault-device/expiry.intent` grammar and
wire it to the exact-device Tailscale helper.

Create `/etc/systemd/system/vault-tailscale-expire-primary.service`:

```ini
[Unit]
Description=Expire exact expected Vault primary through Tailscale API
Wants=network-online.target
After=network-online.target
ConditionPathExists=/var/lib/vault-device/expiry.intent

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/vault-tailscale-expire-primary
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/etc/vault-ts-expiry
ReadWritePaths=/var/lib/vault-device
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/vault-tailscale-expire-primary.path`:

```ini
[Unit]
Description=Watch for persistent Vault primary expiry intent

[Path]
PathExists=/var/lib/vault-device/expiry.intent
Unit=vault-tailscale-expire-primary.service

[Install]
WantedBy=multi-user.target
```

Enable the path unit:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-tailscale-expire-primary.path
sudo systemctl status vault-tailscale-expire-primary.path --no-pager
```

Do not manually create a production `expiry.intent` just to see the service run; doing
so is designed to expire the exact primary. Use a disposable test tailnet/device for
the first API test, then run the real end-to-end hard-deadline test once you are ready
to reauthenticate the primary.

#### 24.17 Prove expiry, reauthentication, and hard-deadline behavior

On the matching primary, record the current Tailscale IP and prove Vault connectivity.
Start a real dual-device ceremony, then let the matching local workflow reach
`DONE rhel`. Expected on its own VPS:

```bash
sudo journalctl -u vault-device-coordinator.service -b --no-pager | tail -100
sudo journalctl -u vault-tailscale-expire-primary.service -b --no-pager | tail -100
sudo test ! -e /var/lib/vault-device/expiry.intent
sudo test ! -e /var/lib/vault-device/session.deadline.json
sudo test ! -e /var/lib/vault-device/tailscale-expiry.partial
```

The exact primary must lose tailnet connectivity after expiry. On Fedora, renew only by
an explicit reauthentication:

```bash
sudo tailscale up --force-reauth
sudo tailscale set --shields-up=true
sudo tailscale set --ssh=false
```

On Android, use the Tailscale app's reauthentication/sign-in flow when the expired
Phone identity prompts for renewal. Do not replace this with a reusable auth key in the
Vault daily script.

Repeat a separate test while suppressing cooperative `DONE rhel`. The persistent signed
one-hour deadline must independently create the same `expiry.intent`, invoke the exact-
device helper, and expire the own primary. For node-expiry cleanup, `DONE rhel` is an
early-close optimization only; S3 successful-completion containment is tested separately.

Then inject an invalid intent IP on a disposable test VPS state directory or helper copy:

```text
ip=100.64.0.250
```

Expected: helper fails before the expire POST. Inject a wrong NodeID/hostname into a
copy of `config.json`; expected: helper fails closed. The real production OAuth secret
must never be used with a modified helper that accepts arbitrary URLs or device IDs.

#### 24.18 Validate the managed-DERP baseline

With Peer Relay and standalone DERP disabled on both Vault VPSs:

```bash
sudo ss -lntup | grep -E '(:40000|:3478)' && echo 'UNEXPECTED RELAY LISTENER'
sudo ss -lntp | grep ':443'
```

TCP/443 may still belong to ordinary management/web services if retained for another
purpose, but no self-hosted Vault DERP listener should remain in the Tailscale profile.

On Fedora:

```bash
tailscale netcheck
tailscale status
tailscale ping PC_VPS_TS_IP
tailscale ping PC_RHEL_TS_IP
```

Use the Tailscale admin/app visibility and the actual backup logs to determine whether
the representative campus path is direct or relayed. Run a realistic restic delta and
measure whether it completes comfortably inside the signed one-hour Vault session. Do
not enable Peer Relay because a synthetic ping is slower; enable it only if real backup
throughput/reliability is insufficient.

If the optional performance profile is required, enable a compartment-local Peer Relay
according to the current Tailscale Peer Relay instructions, open only its selected
UDP/40000 listener, and grant relay capability only to the intended same-tailnet
participants. Then repeat the real campus test and the one-VPS-compromise threat review.

#### 24.19 Tailscale Definition of Done

```text
[ ] Exactly two independent tailnets exist; no PC/Phone shared tailnet was introduced.
[ ] Each tailnet contains only primary + own VPS + matching RHEL instance.
[ ] Actual Tailscale IPs were reconciled with coordinator/proxy/RHEL/client configs.
[ ] Deny-by-default grants expose only own coordinator, proxy, and own RHEL listener.
[ ] Primary inbound blocking remains enabled locally.
[ ] Tailnet Lock is initialized independently in both tailnets.
[ ] vault-pc + RHEL-PC are the PC-tailnet signers.
[ ] vault-phone + RHEL-Phone are the Phone-tailnet signers.
[ ] Android Phone is signed and not Locked out but is not treated as a signer.
[ ] Disablement secrets are stored offline and absent from all Vault hosts/scripts.
[ ] One devices:core OAuth credential exists per tailnet/VPS and no broader scope is granted.
[ ] Exact NodeID, IP, hostname, untagged state, and key-expiry-enabled state are pinned root-only.
[ ] Fixed expiry helper source passes Python syntax check and accepts no arbitrary API path/verb.
[ ] Ambiguous API outcome leaves persistent partial state and blocks automatic retry.
[ ] DONE rhel expires exactly the own primary and requires explicit reauthentication.
[ ] Suppressed DONE still expires the own primary at the signed hard deadline.
[ ] AWS Lambda still rejects one-signature proof and each role reaches only own bucket.
[ ] RHEL still rejects one-signature proof and per-repository capacity isolation still works.
[ ] Tailscale-hosted DERP baseline was measured on the real restricted network.
[ ] Peer Relay remains disabled unless a recorded performance test justified it.
```

## PART 2: SELF-HOSTED RHEL BACKUP SERVER
================================================================================

# Self-Hosted RHEL Backup Server — Dual-Compartment, Dual-Signature, Keyless No-Prune Reference

> **Variant identity:** this reference is outbound-only / keep-all-history / no-prune.
> RHEL is an on-premises ciphertext receiver. It stores neither the PC nor the Phone
> restic repository password. PC and Phone remain source-only and never expose a Vault
> receiver.

> **Read this part in order.** The network namespace services, Caddy listeners, local
> signature gate, rootless backends, quota boundaries, and Tailscale enrollment depend
> on one another. Do not copy only the rest-server unit and assume the authorization
> model still exists.

---

## 1. What RHEL Does and Does Not Do

RHEL receives two independent repositories:

```text
PC plaintext
  ↓ restic encrypts on PC
PC Tailscale tailnet
  ↓
RHEL-PC Caddy :8001
  ↓ only after local dual-signature gate
PC backend :8081
  ↓
/var/lib/vault-rhel/repos/pc

Phone plaintext
  ↓ restic encrypts on Phone
Phone Tailscale tailnet
  ↓
RHEL-Phone Caddy :8002
  ↓ only after local dual-signature gate
Phone backend :8082
  ↓
/var/lib/vault-rhel/repos/phone
```

RHEL does **not**:

```text
hold PC own_restic_pw
hold Phone own_restic_pw
run restic forget/prune
run keyed restic check
mount or restore a repository unattended
trust either VPS saying "OPEN rhel"
use traffic quietness as the hard expiry clock
use a cloud/KMS service to verify signatures
```

RHEL locally verifies both VPS Ed25519 signatures on the exact same proof payload that
the AWS gate uses. It consumes a device/day opening slot **before** starting a backend.
The signed global `session_expires_at` is then converted into a systemd-managed hard
stop timer. Endpoint-controlled `DONE` can close early; it cannot extend the deadline.

### 1.1 Honest physical-host boundary

The two network namespaces, users, Caddy instances, htpasswd files, backend containers,
and storage allocations are independent service compartments. They reduce the blast
radius of a non-root service compromise and prevent a PC capacity event from normally
stopping Phone ingestion.

They do not turn one motherboard and one root account into two physical security
boundaries:

```text
RHEL root compromise
        ↓
PC ciphertext tree may be copied
Phone ciphertext tree may be copied
```

In this no-prune variant the repository passwords are absent, so RHEL root still does
not automatically gain decryption capability. Key absence is not an egress control; an
attacker can still copy encrypted repository bytes.

---

## 2. Reference Hardware, OS, and Preflight Worksheet

Reference OS: supported RHEL 9 on an SELinux-enabled local filesystem.

Before typing commands, record:

```text
RHEL host name:                  vault-rhel
PC Tailscale tailnet ID/DNS:       <record from Section 24 worksheet>
Phone Tailscale tailnet ID/DNS:    <record from Section 24 worksheet>
PC RHEL Tailscale IP:              PC_RHEL_TS_IP
Phone RHEL Tailscale IP:           PHONE_RHEL_TS_IP
PC Caddy listener:                 PC_RHEL_TS_IP:8001
Phone Caddy listener:              PHONE_RHEL_TS_IP:8002
PC host veth:                    169.254.10.1/30
PC namespace veth:               169.254.10.2/30
Phone host veth:                 169.254.20.1/30
Phone namespace veth:            169.254.20.2/30
PC repository mount/path:        /var/lib/vault-rhel/repos/pc
Phone repository mount/path:     /var/lib/vault-rhel/repos/phone
PC repository hard allocation:   ______ GiB
Phone repository hard allocation:______ GiB
Global host emergency threshold: 85%
rest-server version:             0.14.0
```

The two RHEL instances live in different Linux network namespaces and connect to different Tailscale tailnets. They may receive different Tailscale IPv4 addresses; record and use the exact `PC_RHEL_TS_IP` and `PHONE_RHEL_TS_IP` values from Section 24.

Every literal `PC_RHEL_TS_IP`, `PHONE_RHEL_TS_IP`, `PC_VPS_TS_IP`, `PHONE_VPS_TS_IP`, or `VPS_TS_IP` in a command/config block is a deployment placeholder. Replace it with the matching worksheet IPv4 before running the block. Do not paste the placeholder text into OpenSSL SANs, Caddy addresses, Go constants, or shell URLs.

---

## 3. Physical and Boot Hardening

This part is local-attack defense. It is separate from the network threat model but a
backup server is high-value enough that the assumptions should be written down.

### 3.1 BIOS/UEFI

Set an administrator/setup password and store it in the password manager. Disable boot
from removable media after installation. Disable unused hardware interfaces where the
actual firmware supports per-port control. Keep only the NIC/Wi-Fi adapter required by
the deployment.

Do **not** enable a power-on password if the operating model requires remote smart-plug
power-up; that would make unattended boot impossible. Document this tradeoff.

Set:

```text
Restore on AC Power Loss = Power On
```

only if the smart-plug power model in Section 16 is used.

### 3.2 Disk encryption decision

Full-disk encryption is preferred for theft protection, but unattended smart-plug boot
and a local passphrase prompt conflict. Choose deliberately:

```text
manual local unlock available
    → LUKS/FDE can be used

fully unattended remote power-on required
    → document why unattended root filesystem unlock is accepted or redesign the boot path
```

Do not claim both "unattended from anywhere" and "human must type a local LUKS
passphrase" in the same deployment profile.

---

## 4. SELinux and Base Packages

Verify enforcement first:

```bash
getenforce
# Must print: Enforcing
```

If `Permissive`:

```bash
sudo setenforce 1
sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
```

If SELinux is `Disabled`, set it to enforcing in `/etc/selinux/config` and follow the
RHEL relabel/reboot procedure before continuing. A permissive host logs denials but does
not enforce the containment this guide relies on.

Update and install:

```bash
sudo dnf update -y
sudo dnf install -y \
  firewalld nftables podman policycoreutils-python-utils \
  httpd-tools caddy tailscale golang python3 jq curl tar openssl \
  smartmontools util-linux xfsprogs

sudo systemctl enable --now firewalld
sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --runtime-to-permanent
sudo firewall-cmd --reload
```

Record versions:

```bash
cat /etc/redhat-release
getenforce
podman --version
caddy version
tailscale version
go version
```

---

## 5. Create Dedicated Users and Directories

Use one unprivileged backend identity per repository:

```bash
sudo useradd --system --create-home \
  --home-dir /var/lib/vault-rhel/users/resticpc \
  --shell /sbin/nologin resticpc 2>/dev/null || true

sudo useradd --system --create-home \
  --home-dir /var/lib/vault-rhel/users/resticphone \
  --shell /sbin/nologin resticphone 2>/dev/null || true
```

Allocate non-overlapping subordinate ID ranges for rootless Podman if they are not
already present:

```bash
grep '^resticpc:' /etc/subuid || \
  sudo usermod --add-subuids 200000-265535 resticpc
grep '^resticpc:' /etc/subgid || \
  sudo usermod --add-subgids 200000-265535 resticpc

grep '^resticphone:' /etc/subuid || \
  sudo usermod --add-subuids 265536-331071 resticphone
grep '^resticphone:' /etc/subgid || \
  sudo usermod --add-subgids 265536-331071 resticphone
```

Create directories:

```bash
sudo install -d -o root -g root -m 700 /etc/vault-rhel
sudo install -d -o root -g root -m 700 /etc/vault-rhel/keys
sudo install -d -o root -g root -m 700 /etc/vault-rhel/tls
sudo install -d -o root -g root -m 700 /etc/vault-rhel/caddy
sudo install -d -o root -g root -m 700 /var/lib/vault-rhel/gate
sudo install -d -o root -g root -m 700 /var/lib/vault-rhel/images
sudo install -d -o root -g root -m 700 /var/lib/vault-rhel/capacity

sudo install -d -o resticpc -g resticpc -m 700 /var/lib/vault-rhel/repos/pc
sudo install -d -o resticphone -g resticphone -m 700 /var/lib/vault-rhel/repos/phone
```

Never make the whole `/var/lib/vault-rhel/repos` tree writable by both service users.
Verify:

```bash
namei -l /var/lib/vault-rhel/repos/pc
namei -l /var/lib/vault-rhel/repos/phone
sudo -u resticpc test -w /var/lib/vault-rhel/repos/pc
sudo -u resticpc test ! -w /var/lib/vault-rhel/repos/phone
sudo -u resticphone test -w /var/lib/vault-rhel/repos/phone
sudo -u resticphone test ! -w /var/lib/vault-rhel/repos/pc
```

All four tests must behave as described.

---

## 6. Per-Repository Capacity Isolation Before Data Arrives

Do this **before** initializing either repository. A single global 85% disk guard is not
a compartment boundary: PC malware could append junk to its own legitimate repository
until the shared filesystem is full and thereby deny Phone backups.

### 6.1 Preferred: separate LVs/filesystems

The clean reference layout is:

```text
/dev/mapper/vg-vault_pc    → /var/lib/vault-rhel/repos/pc
/dev/mapper/vg-vault_phone → /var/lib/vault-rhel/repos/phone
```

Example LVM command shape. Replace devices and sizes with the actual worksheet values;
do not paste placeholder device names into production:

```bash
# EXAMPLE ONLY — inspect lsblk and pvs/vgs first.
lsblk -f
sudo pvs
sudo vgs

# sudo lvcreate -L <PC_REPO_SIZE> -n vault_pc <VG>
# sudo lvcreate -L <PHONE_REPO_SIZE> -n vault_phone <VG>
# sudo mkfs.xfs /dev/<VG>/vault_pc
# sudo mkfs.xfs /dev/<VG>/vault_phone
```

Add the two filesystems to `/etc/fstab` by UUID, mount, and restore ownership:

```bash
sudo mount -a
sudo chown resticpc:resticpc /var/lib/vault-rhel/repos/pc
sudo chmod 700 /var/lib/vault-rhel/repos/pc
sudo chown resticphone:resticphone /var/lib/vault-rhel/repos/phone
sudo chmod 700 /var/lib/vault-rhel/repos/phone
findmnt /var/lib/vault-rhel/repos/pc
findmnt /var/lib/vault-rhel/repos/phone
```

Leave explicit OS/emergency headroom. The sum of both repository allocations must not
consume the entire physical SSD.

### 6.2 Alternative: XFS project quotas

Use this only if both repository directories must share one XFS filesystem. Confirm the
filesystem and project-quota mount option first:

```bash
findmnt -no FSTYPE,OPTIONS /var/lib/vault-rhel/repos
```

The filesystem must be XFS with project quota support enabled (`prjquota`/`pquota` in
the validated RHEL mount configuration).

Append unique project IDs:

```text
# /etc/projid
vaultpc:1001
vaultphone:1002

# /etc/projects
1001:/var/lib/vault-rhel/repos/pc
1002:/var/lib/vault-rhel/repos/phone
```

Then:

```bash
REPO_MOUNT='<REPO_FILESYSTEM_MOUNTPOINT>'
sudo xfs_quota -x -c 'project -s vaultpc' "$REPO_MOUNT"
sudo xfs_quota -x -c 'project -s vaultphone' "$REPO_MOUNT"

sudo xfs_quota -x -c 'limit -p bhard=<PC_HARD_LIMIT> vaultpc' "$REPO_MOUNT"
sudo xfs_quota -x -c 'limit -p bhard=<PHONE_HARD_LIMIT> vaultphone' "$REPO_MOUNT"

sudo xfs_quota -x -c 'report -p -h' "$REPO_MOUNT"
```

Choose hard limits from measured 30/90-day `data_added_packed` growth, not from a
round-number guess. The global 85% guard must be an emergency brake reached **after** a
malicious/abnormal single repository hits its own boundary.

---

## 7. Create the Two Linux Network Namespaces Persistently

The RHEL host joins both Tailscale tailnets through two isolated `tailscaled`
instances. The namespaces must survive a reboot via systemd recreation; a one-time
interactive `ip netns add` command is not enough.

Create `/usr/local/sbin/vault-rhel-netns-setup`:

```bash
#!/usr/bin/env bash
set -euo pipefail

create_side() {
  local ns="$1" host_if="$2" ns_if="$3" host_cidr="$4" ns_cidr="$5"

  ip netns list | awk '{print $1}' | grep -Fxq "$ns" || ip netns add "$ns"

  if ! ip link show "$host_if" >/dev/null 2>&1; then
    ip link add "$host_if" type veth peer name "$ns_if"
    ip link set "$ns_if" netns "$ns"
  fi

  ip addr replace "$host_cidr" dev "$host_if"
  ip link set "$host_if" up
  ip -n "$ns" link set lo up
  ip -n "$ns" addr replace "$ns_cidr" dev "$ns_if"
  ip -n "$ns" link set "$ns_if" up
}

create_side vault-pc    pc-veth-host pc-veth-ns 169.254.10.1/30 169.254.10.2/30
create_side vault-phone ph-veth-host ph-veth-ns 169.254.20.1/30 169.254.20.2/30

# This design does not route one namespace through the host to another network.
sysctl -w net.ipv4.ip_forward=0 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
```

```bash
sudo chmod 755 /usr/local/sbin/vault-rhel-netns-setup
```

Create `/usr/local/sbin/vault-rhel-netns-teardown`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ip netns del vault-pc 2>/dev/null || true
ip netns del vault-phone 2>/dev/null || true
```

```bash
sudo chmod 755 /usr/local/sbin/vault-rhel-netns-teardown
```

Create `/etc/systemd/system/vault-rhel-netns.service`:

```ini
[Unit]
Description=Vault RHEL PC and Phone network namespaces
Before=vault-tailscaled-pc.service vault-tailscaled-phone.service
Before=vault-caddy-pc.service vault-caddy-phone.service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/vault-rhel-netns-setup
ExecStop=/usr/local/sbin/vault-rhel-netns-teardown

[Install]
WantedBy=multi-user.target
```

Test and enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-rhel-netns
sudo ip netns list
sudo ip -n vault-pc addr
sudo ip -n vault-phone addr
ping -c1 169.254.10.2
ping -c1 169.254.20.2
sudo ip netns exec vault-pc ping -c1 169.254.10.1
sudo ip netns exec vault-phone ping -c1 169.254.20.1
```

Expected: each namespace reaches only its own host veth address. Do not add a default
route through the host veth; `tailscaled` uses its own userspace/control connectivity
and TUN path inside the namespace.

---

## 8. Run Two Independent `tailscaled` Services

Create state and run directories:

```bash
sudo install -d -o root -g root -m 700 /var/lib/tailscale-vault-pc
sudo install -d -o root -g root -m 700 /var/lib/tailscale-vault-phone
sudo install -d -o root -g root -m 755 /run/tailscale-vault-pc
sudo install -d -o root -g root -m 755 /run/tailscale-vault-phone
```

Create `/etc/systemd/system/vault-tailscaled-pc.service`:

```ini
[Unit]
Description=Vault RHEL PC-compartment tailscaled
Requires=vault-rhel-netns.service
After=vault-rhel-netns.service network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/ip netns exec vault-pc /usr/sbin/tailscaled \
  --state=/var/lib/tailscale-vault-pc/tailscaled.state \
  --socket=/run/tailscale-vault-pc/tailscaled.sock \
  --tun=tailscale-pc
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/vault-tailscaled-phone.service`:

```ini
[Unit]
Description=Vault RHEL Phone-compartment tailscaled
Requires=vault-rhel-netns.service
After=vault-rhel-netns.service network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/ip netns exec vault-phone /usr/sbin/tailscaled \
  --state=/var/lib/tailscale-vault-phone/tailscaled.state \
  --socket=/run/tailscale-vault-phone/tailscaled.sock \
  --tun=tailscale-phone
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Reload/start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-tailscaled-pc vault-tailscaled-phone
sudo systemctl --no-pager --full status vault-tailscaled-pc vault-tailscaled-phone

sudo ip netns exec vault-pc tailscale \
  --socket=/run/tailscale-vault-pc/tailscaled.sock status || true
sudo ip netns exec vault-phone tailscale \
  --socket=/run/tailscale-vault-phone/tailscaled.sock status || true
```

The first `status` calls may show that authentication is required. Complete the one-time
RHEL enrollment in Section 24 after the two matching Tailscale tailnets exist.

After enrollment verify:

```bash
sudo ip netns exec vault-pc tailscale \
  --socket=/run/tailscale-vault-pc/tailscaled.sock ip -4
sudo ip netns exec vault-phone tailscale \
  --socket=/run/tailscale-vault-phone/tailscaled.sock ip -4
```

Record the exact address printed by each command. The command must run against its own socket and namespace. Never use the host default `/run/tailscale/tailscaled.sock` for these
instances.

---

## 9. Build a Pinned Local rest-server Container Image

The reference uses rest-server `0.14.0`, the current signed release baseline used by
this guide. Do not use an unpinned `:latest` container image. Build a minimal local image
from the upstream release binary.

```bash
sudo install -d -o root -g root -m 755 /usr/local/src/vault-rest-server-image
sudo tee /usr/local/src/vault-rest-server-image/Containerfile >/dev/null <<'EOF'
FROM registry.access.redhat.com/ubi9/ubi-micro:latest
ARG RSERVER_VERSION=0.14.0
ARG TARGETARCH=amd64
ADD https://github.com/restic/rest-server/releases/download/v${RSERVER_VERSION}/rest-server_${RSERVER_VERSION}_linux_${TARGETARCH}.tar.gz /tmp/rest-server.tar.gz
RUN mkdir -p /extract && \
    tar -xzf /tmp/rest-server.tar.gz -C /extract && \
    install -m 0755 /extract/rest-server /usr/local/bin/rest-server && \
    rm -rf /tmp/rest-server.tar.gz /extract
ENTRYPOINT ["/usr/local/bin/rest-server"]
EOF

cd /usr/local/src/vault-rest-server-image
sudo podman build \
  --build-arg RSERVER_VERSION=0.14.0 \
  --build-arg TARGETARCH=amd64 \
  -t localhost/vault-rest-server:0.14.0 .
sudo podman image inspect localhost/vault-rest-server:0.14.0 >/dev/null
```

On ARM64 RHEL use the release asset architecture that matches `uname -m` and test the
asset name before building. Record the image digest:

```bash
sudo podman image inspect localhost/vault-rest-server:0.14.0 \
  --format '{{.Digest}} {{.Id}}' \
  | sudo tee /var/lib/vault-rhel/images/rest-server-0.14.0.digest
```

The backend users need access to the local image. Rootless Podman image stores are per
user; build/import the image independently for each service identity:

```bash
sudo podman save localhost/vault-rest-server:0.14.0 \
  -o /var/lib/vault-rhel/images/vault-rest-server-0.14.0.tar
sudo chmod 644 /var/lib/vault-rhel/images/vault-rest-server-0.14.0.tar

for u in resticpc resticphone; do
  uid="$(id -u "$u")"
  sudo install -d -o "$u" -g "$u" -m 700 "/run/vault-${u}"
  sudo -u "$u" env \
    HOME="/var/lib/vault-rhel/users/${u}" \
    XDG_RUNTIME_DIR="/run/vault-${u}" \
    podman load -i /var/lib/vault-rhel/images/vault-rest-server-0.14.0.tar
  sudo -u "$u" env \
    HOME="/var/lib/vault-rhel/users/${u}" \
    XDG_RUNTIME_DIR="/run/vault-${u}" \
    podman image inspect localhost/vault-rest-server:0.14.0 >/dev/null
done
```

If the rootless `podman info`/load commands fail, stop and fix the user namespace,
`/etc/subuid`, `/etc/subgid`, home ownership, or runtime-directory problem. Do not switch
the backend to rootful Podman as an undocumented convenience.

---

## 10. Create Independent Basic-Auth Credentials

RHEL stores bcrypt hashes; PC and Phone store only their own plaintext client credential
in their local mode-`600` `rhel_htpasswd` files.

PC listener:

```bash
sudo htpasswd -B -c /etc/vault-rhel/pc.htpasswd vaultpc
sudo chown root:resticpc /etc/vault-rhel/pc.htpasswd
sudo chmod 640 /etc/vault-rhel/pc.htpasswd
```

Phone listener:

```bash
sudo htpasswd -B -c /etc/vault-rhel/phone.htpasswd vaultphone
sudo chown root:resticphone /etc/vault-rhel/phone.htpasswd
sudo chmod 640 /etc/vault-rhel/phone.htpasswd
```

Generate two different strong passwords in the password manager. Copy the PC listener
plaintext password only to the PC as:

```text
~/.config/vault-secrets/rhel_htpasswd
```

and the Phone listener plaintext password only to the Phone at the same local filename.

Verify cross-credential isolation later: the PC password must fail on port `8002`, and
the Phone password must fail on port `8001`.

---

## 11. Create a Private TLS CA and Two RHEL Listener Certificates

The Tailscale transport already encrypts WireGuard traffic. Caddy TLS is a
second application-layer server-authentication boundary and allows restic/curl to pin
the intended RHEL listener certificate.

Generate the RHEL Vault CA offline or during a trusted local provisioning session:

```bash
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out /etc/vault-rhel/tls/vault-rhel-ca.key
sudo openssl req -new -x509 -sha256 -days 3650 \
  -key /etc/vault-rhel/tls/vault-rhel-ca.key \
  -out /etc/vault-rhel/tls/vault-rhel-ca.crt \
  -subj '/CN=Vault RHEL Internal CA/O=Vault'
```

PC certificate:

```bash
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /etc/vault-rhel/tls/rhel-pc.key
sudo openssl req -new \
  -key /etc/vault-rhel/tls/rhel-pc.key \
  -out /etc/vault-rhel/tls/rhel-pc.csr \
  -subj '/CN=rhel-pc/O=Vault'

cat <<'EOF' | sudo tee /etc/vault-rhel/tls/rhel-pc-ext.cnf >/dev/null
subjectAltName = IP:PC_RHEL_TS_IP,DNS:rhel-pc
extendedKeyUsage = serverAuth
keyUsage = digitalSignature,keyEncipherment
EOF

sudo openssl x509 -req -sha256 -days 825 \
  -in /etc/vault-rhel/tls/rhel-pc.csr \
  -CA /etc/vault-rhel/tls/vault-rhel-ca.crt \
  -CAkey /etc/vault-rhel/tls/vault-rhel-ca.key \
  -CAcreateserial \
  -out /etc/vault-rhel/tls/rhel-pc.crt \
  -extfile /etc/vault-rhel/tls/rhel-pc-ext.cnf
```

Phone certificate:

```bash
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /etc/vault-rhel/tls/rhel-phone.key
sudo openssl req -new \
  -key /etc/vault-rhel/tls/rhel-phone.key \
  -out /etc/vault-rhel/tls/rhel-phone.csr \
  -subj '/CN=rhel-phone/O=Vault'

cat <<'EOF' | sudo tee /etc/vault-rhel/tls/rhel-phone-ext.cnf >/dev/null
subjectAltName = IP:PHONE_RHEL_TS_IP,DNS:rhel-phone
extendedKeyUsage = serverAuth
keyUsage = digitalSignature,keyEncipherment
EOF

sudo openssl x509 -req -sha256 -days 825 \
  -in /etc/vault-rhel/tls/rhel-phone.csr \
  -CA /etc/vault-rhel/tls/vault-rhel-ca.crt \
  -CAkey /etc/vault-rhel/tls/vault-rhel-ca.key \
  -CAserial /etc/vault-rhel/tls/vault-rhel-ca.srl \
  -out /etc/vault-rhel/tls/rhel-phone.crt \
  -extfile /etc/vault-rhel/tls/rhel-phone-ext.cnf
```

Permissions:

```bash
sudo chown root:root /etc/vault-rhel/tls/vault-rhel-ca.key
sudo chmod 600 /etc/vault-rhel/tls/vault-rhel-ca.key
sudo chmod 644 /etc/vault-rhel/tls/vault-rhel-ca.crt
sudo chown root:root /etc/vault-rhel/tls/rhel-*.crt
sudo chmod 644 /etc/vault-rhel/tls/rhel-*.crt
sudo chown root:root /etc/vault-rhel/tls/rhel-*.key
sudo chmod 600 /etc/vault-rhel/tls/rhel-*.key
```

Copy **only** `/etc/vault-rhel/tls/vault-rhel-ca.crt` to PC and Phone. Store as:

```text
PC:    ~/.config/vault/rhel-ca.crt
Phone: ~/.config/vault/rhel-ca.crt
```

Do not copy the CA private key or listener private keys to a primary device.

---

## 12. Create the Two Rootless Backend Services

> [!NOTE]
> **(Optional)** The custom Seccomp profile used in the `podman run` commands below (`--security-opt seccomp=...`) and its associated notification system are optional. It is recommended to implement this part after mastering writing seccomp policies. Podman already has its own seccomp policy against container escape scenarios. If you choose not to implement it, simply remove the `--security-opt seccomp=` line from the service definitions.

Create `/etc/systemd/system/vault-rhel-pc-rest-server.service`:

```ini
[Unit]
Description=Vault RHEL PC append-only rest-server
After=vault-rhel-netns.service
Requires=vault-rhel-netns.service

[Service]
Type=simple
User=resticpc
Group=resticpc
Environment=HOME=/var/lib/vault-rhel/users/resticpc
Environment=XDG_RUNTIME_DIR=/run/vault-resticpc
RuntimeDirectory=vault-resticpc
RuntimeDirectoryMode=0700
ExecStartPre=-/usr/bin/podman rm -f vault-rhel-pc-rest-server
ExecStart=/usr/bin/podman run --rm \
  --name vault-rhel-pc-rest-server \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --security-opt seccomp=/etc/vault-rhel/vault-rest-server-seccomp.json \
  --memory=512m \
  --pids-limit=100 \
  --network=none \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v /var/lib/vault-rhel/repos/pc:/data:Z \
  -v /var/lib/vault-rhel/sockets/pc:/sockets:Z \
  -v /etc/vault-rhel/pc.htpasswd:/auth/htpasswd:ro,Z \
  localhost/vault-rest-server:0.14.0 \
  --path /data \
  --listen unix:///sockets/rest-server.sock \
  --append-only \
  --private-repos \
  --htpasswd-file /auth/htpasswd \
  --log -
ExecStop=/usr/bin/podman stop -t 10 vault-rhel-pc-rest-server
Restart=no
RuntimeMaxSec=59min50s
TimeoutStopSec=10s
KillMode=control-group
SendSIGKILL=yes
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vault-rhel/repos/pc /run/vault-resticpc /var/lib/vault-rhel/users/resticpc /var/lib/vault-rhel/sockets/pc
ReadOnlyPaths=/etc/vault-rhel/pc.htpasswd

[Install]
# Intentionally no WantedBy: the gate starts this unit per ceremony.
```

Create `/etc/systemd/system/vault-rhel-phone-rest-server.service`:

```ini
[Unit]
Description=Vault RHEL Phone append-only rest-server
After=vault-rhel-netns.service
Requires=vault-rhel-netns.service

[Service]
Type=simple
User=resticphone
Group=resticphone
Environment=HOME=/var/lib/vault-rhel/users/resticphone
Environment=XDG_RUNTIME_DIR=/run/vault-resticphone
RuntimeDirectory=vault-resticphone
RuntimeDirectoryMode=0700
ExecStartPre=-/usr/bin/podman rm -f vault-rhel-phone-rest-server
ExecStart=/usr/bin/podman run --rm \
  --name vault-rhel-phone-rest-server \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --security-opt seccomp=/etc/vault-rhel/vault-rest-server-seccomp.json \
  --memory=512m \
  --pids-limit=100 \
  --network=none \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v /var/lib/vault-rhel/repos/phone:/data:Z \
  -v /var/lib/vault-rhel/sockets/phone:/sockets:Z \
  -v /etc/vault-rhel/phone.htpasswd:/auth/htpasswd:ro,Z \
  localhost/vault-rest-server:0.14.0 \
  --path /data \
  --listen unix:///sockets/rest-server.sock \
  --append-only \
  --private-repos \
  --htpasswd-file /auth/htpasswd \
  --log -
ExecStop=/usr/bin/podman stop -t 10 vault-rhel-phone-rest-server
Restart=no
RuntimeMaxSec=59min50s
TimeoutStopSec=10s
KillMode=control-group
SendSIGKILL=yes
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vault-rhel/repos/phone /run/vault-resticphone /var/lib/vault-rhel/users/resticphone /var/lib/vault-rhel/sockets/phone
ReadOnlyPaths=/etc/vault-rhel/phone.htpasswd

[Install]
# Intentionally no WantedBy: the gate starts this unit per ceremony.
```

Validate without enabling:

```bash
sudo systemctl daemon-reload
sudo systemd-analyze verify \
  /etc/systemd/system/vault-rhel-pc-rest-server.service \
  /etc/systemd/system/vault-rhel-phone-rest-server.service

sudo systemctl is-enabled vault-rhel-pc-rest-server.service || true
sudo systemctl is-enabled vault-rhel-phone-rest-server.service || true
sudo systemctl is-active vault-rhel-pc-rest-server.service || true
sudo systemctl is-active vault-rhel-phone-rest-server.service || true
```

Expected at normal boot: both `disabled`/not enabled and `inactive`.

---

## 13. Create Caddy Configurations Inside the Network Namespaces

Caddy is persistent; the rest-server backend is not. Caddy exposes the narrow gate and
REST protocol surface even while the backend is stopped. A gate request reaches the
local RHEL gate on the host veth; the restic protocol routes to the matching backend
only when the gate has started it.

Create `/etc/vault-rhel/caddy/pc.Caddyfile`:

```caddyfile
https://PC_RHEL_TS_IP:8001 {
    tls /etc/vault-rhel/tls/rhel-pc.crt /etc/vault-rhel/tls/rhel-pc.key

    @gate path /__vault_gate /__vault_done
    handle @gate {
        reverse_proxy 169.254.10.1:8090
    }

    @restic {
        method GET POST HEAD DELETE
        path / /config /keys/* /locks/* /snapshots/* /index/* /data/*
    }
    handle @restic {
        basicauth {
            {$VAULT_PC_USER} {$VAULT_PC_HTPASSWD_HASH}
        }
        reverse_proxy unix//var/lib/vault-rhel/sockets/pc/rest-server.sock
    }

    handle {
        respond "Vault protocol path denied" 404
    }

    log {
        output file /var/log/vault-rhel-caddy-pc.log
        format json
    }
}
```

Create `/etc/vault-rhel/caddy/phone.Caddyfile` with:

```caddyfile
https://PHONE_RHEL_TS_IP:8002 {
    tls /etc/vault-rhel/tls/rhel-phone.crt /etc/vault-rhel/tls/rhel-phone.key

    @gate path /__vault_gate /__vault_done
    handle @gate {
        reverse_proxy 169.254.20.1:8090
    }

    @restic {
        method GET POST HEAD DELETE
        path / /config /keys/* /locks/* /snapshots/* /index/* /data/*
    }
    handle @restic {
        basicauth {
            {$VAULT_PHONE_USER} {$VAULT_PHONE_HTPASSWD_HASH}
        }
        reverse_proxy unix//var/lib/vault-rhel/sockets/phone/rest-server.sock
    }

    handle {
        respond "Vault protocol path denied" 404
    }

    log {
        output file /var/log/vault-rhel-caddy-phone.log
        format json
    }
}
```

Use the same positive REST method/path allowlist. The allowlist narrows parser/request
surface; `rest-server --append-only` remains the authoritative repository-mutation
restriction.

Caddy inside a namespace must be able to read its certificate/key and write its own log.
Create separate service identities/directories:

```bash
sudo useradd --system --home-dir /var/lib/vault-caddy-pc --shell /sbin/nologin vaultcaddypc 2>/dev/null || true
sudo useradd --system --home-dir /var/lib/vault-caddy-phone --shell /sbin/nologin vaultcaddyphone 2>/dev/null || true
sudo install -d -o vaultcaddypc -g vaultcaddypc -m 700 /var/lib/vault-caddy-pc
sudo install -d -o vaultcaddyphone -g vaultcaddyphone -m 700 /var/lib/vault-caddy-phone
sudo touch /var/log/vault-rhel-caddy-pc.log /var/log/vault-rhel-caddy-phone.log
sudo chown vaultcaddypc:vaultcaddypc /var/log/vault-rhel-caddy-pc.log
sudo chown vaultcaddyphone:vaultcaddyphone /var/log/vault-rhel-caddy-phone.log
```

Allow the two service users to read only their listener key:

```bash
sudo chown root:vaultcaddypc /etc/vault-rhel/tls/rhel-pc.key
sudo chmod 640 /etc/vault-rhel/tls/rhel-pc.key
sudo chown root:vaultcaddyphone /etc/vault-rhel/tls/rhel-phone.key
sudo chmod 640 /etc/vault-rhel/tls/rhel-phone.key
```

Create `/etc/systemd/system/vault-caddy-pc.service`:

```ini
[Unit]
Description=Vault RHEL PC namespace Caddy
Requires=vault-rhel-netns.service vault-tailscaled-pc.service
After=vault-rhel-netns.service vault-tailscaled-pc.service

[Service]
Type=notify
User=vaultcaddypc
Group=vaultcaddypc
ExecStart=/usr/bin/ip netns exec vault-pc /usr/bin/caddy run \
  --environ --config /etc/vault-rhel/caddy/pc.Caddyfile
ExecReload=/usr/bin/ip netns exec vault-pc /usr/bin/caddy reload \
  --config /etc/vault-rhel/caddy/pc.Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/vault-rhel/caddy/pc.Caddyfile /etc/vault-rhel/tls/rhel-pc.crt /etc/vault-rhel/tls/rhel-pc.key
ReadWritePaths=/var/lib/vault-caddy-pc /var/log/vault-rhel-caddy-pc.log /var/lib/vault-rhel/sockets/pc

[Install]
WantedBy=multi-user.target
```

Create the symmetric `vault-caddy-phone.service` using `vault-phone`,
`phone.Caddyfile`, `vaultcaddyphone`, and the Phone paths.

Validate both configs from the correct namespace:

```bash
sudo ip netns exec vault-pc caddy validate --config /etc/vault-rhel/caddy/pc.Caddyfile
sudo ip netns exec vault-phone caddy validate --config /etc/vault-rhel/caddy/phone.Caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now vault-caddy-pc vault-caddy-phone

sudo ip netns exec vault-pc ss -lntp | grep ':8001'
sudo ip netns exec vault-phone ss -lntp | grep ':8002'
```

The host namespace must not show a public `0.0.0.0:8001` or `0.0.0.0:8002` listener.

---

## 14. Install Both VPS Public Signing Keys on RHEL

On `vault-pc` and `vault-phone`, Section 23 generated Ed25519 signing keypairs. Copy
only the public keys to a trusted provisioning workstation and then to RHEL.

Install:

```bash
sudo install -o root -g root -m 644 pc-vps-ed25519.pub \
  /etc/vault-rhel/keys/pc-vps-ed25519.pub
sudo install -o root -g root -m 644 phone-vps-ed25519.pub \
  /etc/vault-rhel/keys/phone-vps-ed25519.pub

sudo sha256sum /etc/vault-rhel/keys/*.pub
```

Compare the fingerprints with the values printed locally on the respective VPS. A public
key sent through the opposite compromised VPS is not an independent trust bootstrap.
Use a trusted administrative channel or manually compare fingerprints.

---

## 15. Build and Install the Local Dual-Signature Gate

Save the following source as `/usr/local/src/vault-rhel-gate/main.go`:

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const stateDir = "/var/lib/vault-rhel/gate"

type proofPayload struct {
	Version          int    `json:"version"`
	CeremonyID       string `json:"ceremony_id"`
	Target           string `json:"target"`
	Nonce            string `json:"nonce"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	CalendarDate     string `json:"calendar_date"`
	SessionExpiresAt string `json:"session_expires_at"`
}

type proofBundle struct {
	Payload        string `json:"payload"`
	PCSignature    string `json:"pc_signature"`
	PhoneSignature string `json:"phone_signature"`
}

type slotRecord struct {
	Target           string `json:"target"`
	CalendarDate     string `json:"calendar_date"`
	CeremonyID       string `json:"ceremony_id"`
	ConsumedAt       string `json:"consumed_at"`
	SessionExpiresAt string `json:"session_expires_at"`
	DoneToken        string `json:"done_token"`
	DoneTokenHash    string `json:"done_token_sha256"`
}

type server struct {
	pcPublicKey    ed25519.PublicKey
	phonePublicKey ed25519.PublicKey
}

func loadEd25519Public(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return ed, nil
}

func istanbulDate(t time.Time) string {
	loc, err := time.LoadLocation("Europe/Istanbul")
	if err != nil {
		loc = time.FixedZone("Europe/Istanbul-fallback", 3*60*60)
	}
	return t.In(loc).Format("2006-01-02")
}

func expectedTarget(kind string) string {
	if kind == "pc" {
		return "RHEL_PC"
	}
	return "RHEL_PHONE"
}

func unitFor(kind string) string {
	if kind == "pc" {
		return "vault-rhel-pc-rest-server.service"
	}
	return "vault-rhel-phone-rest-server.service"
}

func slotPath(kind, date string) string {
	return filepath.Join(stateDir, strings.ToUpper(kind)+"#"+date+".consumed.json")
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *server) verifyBundle(bundle proofBundle, expected string) (proofPayload, error) {
	var p proofPayload
	raw, err := base64.StdEncoding.DecodeString(bundle.Payload)
	if err != nil || len(raw) > 4096 {
		return p, errors.New("invalid payload encoding")
	}
	pcSig, err := base64.StdEncoding.DecodeString(bundle.PCSignature)
	if err != nil || len(pcSig) != ed25519.SignatureSize {
		return p, errors.New("invalid PC signature encoding")
	}
	phoneSig, err := base64.StdEncoding.DecodeString(bundle.PhoneSignature)
	if err != nil || len(phoneSig) != ed25519.SignatureSize {
		return p, errors.New("invalid phone signature encoding")
	}
	if !ed25519.Verify(s.pcPublicKey, raw, pcSig) {
		return p, errors.New("PC VPS signature verification failed")
	}
	if !ed25519.Verify(s.phonePublicKey, raw, phoneSig) {
		return p, errors.New("Phone VPS signature verification failed")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, errors.New("invalid payload JSON")
	}
	if p.Version != 1 || p.Target != expected {
		return p, errors.New("wrong proof target or version")
	}
	if len(p.CeremonyID) != 32 || len(p.Nonce) != 64 {
		return p, errors.New("invalid ceremony_id or nonce size")
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return p, errors.New("invalid issued_at")
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return p, errors.New("invalid expires_at")
	}
	now := time.Now().UTC()
	lifetime := expires.Sub(issued)
	if lifetime <= 0 || lifetime > 90*time.Second {
		return p, errors.New("invalid proof lifetime")
	}
	if now.Before(issued.Add(-30*time.Second)) || now.After(expires) {
		return p, errors.New("proof expired or not yet valid")
	}
	if p.CalendarDate != istanbulDate(now) {
		return p, errors.New("calendar date mismatch")
	}
	sessionExpires, err := time.Parse(time.RFC3339, p.SessionExpiresAt)
	if err != nil {
		return p, errors.New("invalid session_expires_at")
	}
	if !sessionExpires.After(now.Add(15*time.Second)) || sessionExpires.Sub(issued) > time.Hour {
		return p, errors.New("Vault session hard deadline is invalid or too close")
	}
	return p, nil
}

func readSlot(path string) (slotRecord, error) {
	var rec slotRecord
	raw, err := os.ReadFile(path)
	if err != nil {
		return rec, err
	}
	err = json.Unmarshal(raw, &rec)
	return rec, err
}

func createSlot(path string, rec slotRecord) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	dir, err := os.Open(stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func systemctl(args ...string) error {
	cmd := exec.Command("/usr/bin/systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func serviceActive(unit string) bool {
	return systemctl("is-active", "--quiet", unit) == nil
}

func hardStopTimerName(kind, ceremonyID string) string {
	return "vault-rhel-" + kind + "-hard-stop-" + ceremonyID[:12]
}

func scheduleHardStop(kind, ceremonyID string, deadline time.Time) error {
	// Start the stop job 10 seconds before the signed session deadline. The service
	// unit has TimeoutStopSec=10s and SendSIGKILL=yes, so teardown is bounded by
	// the signed hard deadline even if the client suppresses DONE or keeps traffic active.
	stopAt := deadline.Add(-10 * time.Second)
	delay := time.Until(stopAt)
	if delay <= 0 {
		return errors.New("session deadline too close for bounded stop")
	}
	seconds := int64(delay / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	unit := unitFor(kind)
	timer := hardStopTimerName(kind, ceremonyID)
	cmd := exec.Command(
		"/usr/bin/systemd-run",
		"--unit="+timer,
		"--on-active="+fmt.Sprintf("%ds", seconds),
		"--timer-property=AccuracySec=1s",
		"/usr/bin/systemctl", "stop", unit,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schedule hard-stop timer: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *server) openHandler(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/__vault_gate" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		defer r.Body.Close()
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid body"})
			return
		}
		var bundle proofBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON"})
			return
		}
		p, err := s.verifyBundle(bundle, expectedTarget(kind))
		if err != nil {
			jsonResponse(w, http.StatusForbidden, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		path := slotPath(kind, p.CalendarDate)
		if rec, err := readSlot(path); err == nil {
			if rec.CeremonyID == p.CeremonyID && serviceActive(unitFor(kind)) {
				jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "already_open": true, "done_token": rec.DoneToken})
				return
			}
			jsonResponse(w, http.StatusConflict, map[string]any{"ok": false, "error": "daily RHEL opening slot already consumed"})
			return
		} else if !os.IsNotExist(err) {
			jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "slot state unreadable"})
			return
		}

		doneToken, err := randomHex(32)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "token generation failed"})
			return
		}
		sum := sha256.Sum256([]byte(doneToken))
		rec := slotRecord{
			Target:           p.Target,
			CalendarDate:     p.CalendarDate,
			CeremonyID:       p.CeremonyID,
			ConsumedAt:       time.Now().UTC().Format(time.RFC3339),
			SessionExpiresAt: p.SessionExpiresAt,
			DoneToken:        doneToken,
			DoneTokenHash:    hex.EncodeToString(sum[:]),
		}
		if err := createSlot(path, rec); err != nil {
			if os.IsExist(err) {
				jsonResponse(w, http.StatusConflict, map[string]any{"ok": false, "error": "daily RHEL opening slot already consumed"})
			} else {
				jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "could not consume daily slot"})
			}
			return
		}
		// SECURITY INVARIANT: the slot is now consumed. Timer scheduling or service-start
		// failure is fail-closed and the service is not started again by a later gate request.
		sessionDeadline, err := time.Parse(time.RFC3339, p.SessionExpiresAt)
		if err != nil || scheduleHardStop(kind, p.CeremonyID, sessionDeadline) != nil {
			log.Printf("CRITICAL: %s slot consumed but hard-stop timer could not be scheduled", kind)
			jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "slot consumed; hard-stop timer failed; no retry today"})
			return
		}
		if err := systemctl("start", unitFor(kind)); err != nil {
			log.Printf("CRITICAL: %s slot consumed but backend start failed: %v", kind, err)
			jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "slot consumed; backend start failed; no retry today"})
			return
		}
		log.Printf("authorized %s RHEL window ceremony=%s date=%s hard-deadline=%s", kind, p.CeremonyID, p.CalendarDate, p.SessionExpiresAt)
		jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "already_open": false, "done_token": doneToken})
	}
}

type doneRequest struct {
	DoneToken string `json:"done_token"`
}

func (s *server) doneHandler(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/__vault_done" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var req doneRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.DoneToken) != 64 {
			jsonResponse(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid done token"})
			return
		}
		// A legitimate RHEL window can cross Europe/Istanbul midnight. Daily opening
		// slots are keyed by the proof calendar date, so DONE must consider both the
		// current Istanbul day and the immediately previous day. The signed global
		// session ceiling is one hour, therefore an older slot cannot represent a live
		// legitimate ceremony. We accept only one exact constant-time token-hash match.
		now := time.Now().UTC()
		loc, err := time.LoadLocation("Europe/Istanbul")
		if err != nil {
			loc = time.FixedZone("Europe/Istanbul-fallback", 3*60*60)
		}
		todayLocal := now.In(loc)
		candidateDates := []string{
			todayLocal.Format("2006-01-02"),
			todayLocal.AddDate(0, 0, -1).Format("2006-01-02"),
		}

		provided := sha256.Sum256([]byte(req.DoneToken))
		matches := 0
		seenSlots := 0
		for _, date := range candidateDates {
			rec, readErr := readSlot(slotPath(kind, date))
			if readErr != nil {
				if os.IsNotExist(readErr) {
					continue
				}
				jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "slot state unreadable"})
				return
			}
			seenSlots++
			expected, decodeErr := hex.DecodeString(rec.DoneTokenHash)
			if decodeErr != nil || len(expected) != sha256.Size {
				jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "slot token hash invalid"})
				return
			}
			if subtle.ConstantTimeCompare(provided[:], expected) == 1 {
				matches++
			}
		}
		if seenSlots == 0 {
			jsonResponse(w, http.StatusConflict, map[string]any{"ok": false, "error": "no current or previous-day RHEL slot"})
			return
		}
		if matches != 1 {
			jsonResponse(w, http.StatusForbidden, map[string]any{"ok": false, "error": "done token mismatch or ambiguous match"})
			return
		}
		if err := systemctl("stop", unitFor(kind)); err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "backend stop failed"})
			return
		}
		log.Printf("closed %s RHEL backend by done token", kind)
		jsonResponse(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func muxFor(s *server, kind string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/__vault_gate", s.openHandler(kind))
	mux.HandleFunc("/__vault_done", s.doneHandler(kind))
	return mux
}

func main() {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Fatal(err)
	}
	pcKey, err := loadEd25519Public("/etc/vault-rhel/keys/pc-vps-ed25519.pub")
	if err != nil {
		log.Fatalf("PC public key: %v", err)
	}
	phoneKey, err := loadEd25519Public("/etc/vault-rhel/keys/phone-vps-ed25519.pub")
	if err != nil {
		log.Fatalf("Phone public key: %v", err)
	}
	s := &server{pcPublicKey: pcKey, phonePublicKey: phoneKey}

	pcAddr := "169.254.10.1:8090"
	phoneAddr := "169.254.20.1:8090"
	pcSrv := &http.Server{Addr: pcAddr, Handler: muxFor(s, "pc"), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	phoneSrv := &http.Server{Addr: phoneAddr, Handler: muxFor(s, "phone"), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}

	go func() {
		log.Printf("RHEL PC gate listening on %s", pcAddr)
		if err := pcSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	log.Printf("RHEL phone gate listening on %s", phoneAddr)
	if err := phoneSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
```

Build with a dedicated module:

```bash
sudo install -d -o root -g root -m 755 /usr/local/src/vault-rhel-gate
# Save the code block above as /usr/local/src/vault-rhel-gate/main.go
cd /usr/local/src/vault-rhel-gate
sudo go mod init vault-rhel-gate 2>/dev/null || true
sudo gofmt -w main.go
sudo go vet ./...
sudo go test ./...
sudo go build -trimpath -ldflags='-s -w' -o vault-rhel-gate main.go
sudo install -o root -g root -m 0755 vault-rhel-gate /usr/local/sbin/vault-rhel-gate
/usr/local/sbin/vault-rhel-gate --help 2>&1 | head || true
```

Create `/etc/systemd/system/vault-rhel-gate.service`:

```ini
[Unit]
Description=Vault RHEL dual-signature daily admission gate
After=vault-rhel-netns.service
Requires=vault-rhel-netns.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/sbin/vault-rhel-gate
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadOnlyPaths=/etc/vault-rhel/keys
ReadWritePaths=/var/lib/vault-rhel/gate /run /run/systemd

[Install]
WantedBy=multi-user.target
```

The gate is root because its narrow responsibility includes scheduling a transient
systemd timer and starting/stopping exactly two fixed service unit names. Do not add a
request parameter that contains a service name or arbitrary shell command.

Start and verify the link-local listeners:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-rhel-gate
sudo systemctl --no-pager --full status vault-rhel-gate
sudo ss -lntp | grep -E '169\.254\.(10|20)\.1:8090'
```

Expected exactly:

```text
169.254.10.1:8090
169.254.20.1:8090
```

No `0.0.0.0:8090` listener is allowed.

### 15.1 What the gate verifies

For `/__vault_gate`, the local Go gate verifies in order:

```text
body size bounded
valid proof-bundle JSON
payload base64 decodes to exact raw bytes
PC signature length and Ed25519 verification
Phone signature length and Ed25519 verification
payload JSON parses
version == 1
exact expected target: RHEL_PC or RHEL_PHONE
ceremony_id and nonce sizes
proof lifetime >0 and <=90 seconds
proof not future-dated beyond clock-skew allowance
proof not expired
calendar_date == Europe/Istanbul current calendar date
session_expires_at parses
session deadline has enough teardown time remaining
session deadline is no more than one hour from proof issue
```

Only then does it create, using `O_CREAT|O_EXCL`, one of:

```text
/var/lib/vault-rhel/gate/PC#YYYY-MM-DD.consumed.json
/var/lib/vault-rhel/gate/PHONE#YYYY-MM-DD.consumed.json
```

The slot is consumed **before** the hard-stop timer and backend start. If timer
scheduling or service-start failure is fail-closed and the service is not started again by a later gate request.

A repeated HTTP request for the **same ceremony ID** is idempotent only while the
matching backend is already active: it returns the same `done_token`. It does not create
a new opening. After the backend is stopped, the consumed daily slot blocks a fresh
ceremony.

### 15.2 Hard expiry is not a watchdog heuristic

Before the gate starts a backend it schedules:

```text
systemd transient timer
  ↓ fires 10 seconds before signed session_expires_at
systemctl stop exact backend unit
  ↓ TimeoutStopSec=10s
  ↓ KillMode=control-group
  ↓ SendSIGKILL=yes
signed session deadline reached
```

`RuntimeMaxSec=59min50s` remains a second local fallback. The hard close does not depend
on:

```text
remote VPS status polling
client DONE
control socket liveness
network traffic quietness
exact own-primary Tailscale expiry succeeding
```

This specifically closes the old uncertainty gap where a malicious endpoint could keep
backend traffic active while a remote watchdog waited for quietness.

### 15.3 Test a forged or single-signed proof

Before initializing repositories, use the proof tooling in Section 23 to create a valid
bundle and save a copy. Then deliberately remove/replace one signature and POST it:

```bash
curl --cacert ~/.config/vault/rhel-ca.crt \
  -H 'Content-Type: application/json' \
  --data-binary @bad-proof.json \
  https://PC_RHEL_TS_IP:8001/__vault_gate
```

Expected: HTTP `403`; no daily slot file; PC backend remains inactive.

On RHEL:

```bash
sudo find /var/lib/vault-rhel/gate -maxdepth 1 -type f -print
sudo systemctl is-active vault-rhel-pc-rest-server.service || true
```

Repeat for the Phone listener.

---

## 16. RHEL Firewall and Namespace Ingress

The Tailscale grant policy is one boundary; the RHEL host must not expose host-side veth
services to the physical LAN or internet.

The default firewalld zone remains `drop`. Do not add public services `8001`, `8002`,
`8081`, `8082`, or `8090` to the physical NIC zone.

Inspect:

```bash
sudo firewall-cmd --get-default-zone
sudo firewall-cmd --list-all --zone=drop
sudo ss -lntup
sudo ip netns exec vault-pc ss -lntup
sudo ip netns exec vault-phone ss -lntup
```

Expected topology:

```text
host namespace:
  unix//var/lib/vault-rhel/sockets/pc/rest-server.sock only while PC backend active
  169.254.10.1:8090 always, local PC gate
  unix//var/lib/vault-rhel/sockets/phone/rest-server.sock only while Phone backend active
  169.254.20.1:8090 always, local Phone gate

vault-pc namespace:
  PC_RHEL_TS_IP:8001 Caddy
  tailscale-pc

vault-phone namespace:
  PHONE_RHEL_TS_IP:8002 Caddy
  tailscale-phone
```

From PC, port `8002` must be unreachable. From Phone, port `8001` must be unreachable.
From the physical LAN, neither port is an authorized Vault path.

---

## 17. One-Time Repository Initialization Through the Real Dual Gate

Do not start the backend manually for repository initialization. Initialization is a
repository mutation and must prove that the real gate and cross-sign path work.

### 17.1 PC repository

On PC, run the daily proof helper for the RHEL phase exactly as Part 3 does. After a
successful `/__vault_gate`, load only the PC's own restic password and PC RHEL htpasswd:

```bash
export RESTIC_PASSWORD="$(cat "$HOME/.config/vault-secrets/own_restic_pw")"
RHEL_HTPASSWD="$(cat "$HOME/.config/vault-secrets/rhel_htpasswd")"
RHEL_AUTH="$(python3 - "$RHEL_HTPASSWD" <<'PY'
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
)"
export RESTIC_REPOSITORY="rest:https://vaultpc:${RHEL_AUTH}@PC_RHEL_TS_IP:8001/"
export RESTIC_CACERT="$HOME/.config/vault/rhel-ca.crt"

restic init --repository-version 2
restic snapshots

unset RESTIC_REPOSITORY RESTIC_PASSWORD RESTIC_CACERT RHEL_HTPASSWD RHEL_AUTH
```

Post the `done_token` using the Part 3 helper immediately after initialization.

### 17.2 Phone repository

The Phone performs the symmetric operation against `:8002` as user `vaultphone` with
its own local `own_restic_pw` and `rhel_htpasswd`.

After both are initialized, verify on RHEL:

```bash
sudo find /var/lib/vault-rhel/repos/pc -maxdepth 2 -type f | head
sudo find /var/lib/vault-rhel/repos/phone -maxdepth 2 -type f | head
sudo systemctl is-active vault-rhel-pc-rest-server.service || true
sudo systemctl is-active vault-rhel-phone-rest-server.service || true
```

The repositories contain encrypted restic structures; both backend services should be
inactive after cooperative DONE.

---

## 18. Keyless-RHEL Verification

The no-prune reference prohibits source repository passwords on RHEL.

Search likely secret paths:

```bash
sudo find /etc /root /var/lib/vault-rhel -xdev -type f \
  \( -iname '*restic*pass*' -o -iname '*repository*password*' -o -iname '*own_restic_pw*' \) \
  -print
```

Review every result manually. The encrypted repository itself legitimately contains
restic key objects; this test is for copied plaintext operational secrets.

Also inspect shell histories and environment files:

```bash
sudo grep -RIl --exclude='*.log' --exclude='db.sqlite*' \
  'RESTIC_PASSWORD=' /root /etc /var/lib/vault-rhel 2>/dev/null || true
```

The intended result is no unattended repository password file and no RHEL script that
can run `restic forget`, `prune`, `mount`, or `restore` against the repositories.

---

## 19. Per-Repository and Global Capacity Guards

Quota/filesystem boundaries are the hard isolation layer. Guards add notifications and
stop services before the host becomes unstable.

Create `/usr/local/sbin/vault-rhel-capacity-guard`:

```bash
#!/usr/bin/env bash
set -euo pipefail

PC_PATH='/var/lib/vault-rhel/repos/pc'
PHONE_PATH='/var/lib/vault-rhel/repos/phone'
GLOBAL_PATH='/var/lib/vault-rhel'
STATE='/var/lib/vault-rhel/capacity'
mkdir -p "$STATE"
chmod 700 "$STATE"

pct() {
  df -P "$1" | awk 'NR==2 {gsub(/%/,"",$5); print $5}'
}

record() {
  local side="$1" path="$2"
  printf '%s side=%s df_pct=%s bytes=%s\n' \
    "$(date -Iseconds)" "$side" "$(pct "$path")" "$(du -sb "$path" | awk '{print $1}')" \
    >> "$STATE/capacity.log"
}

record pc "$PC_PATH"
record phone "$PHONE_PATH"

# Separate filesystems: df% is per allocation. XFS-project-quota deployments should
# replace these tests with xfs_quota project utilization parsing validated locally.
PC_PCT="$(pct "$PC_PATH")"
PHONE_PCT="$(pct "$PHONE_PATH")"
GLOBAL_PCT="$(pct "$GLOBAL_PATH")"

if (( PC_PCT >= 85 )); then
  systemctl stop vault-rhel-pc-rest-server.service || true
  logger -p authpriv.crit -t vault-rhel "PC repository allocation ${PC_PCT}%: PC backend stopped"
fi
if (( PHONE_PCT >= 85 )); then
  systemctl stop vault-rhel-phone-rest-server.service || true
  logger -p authpriv.crit -t vault-rhel "Phone repository allocation ${PHONE_PCT}%: Phone backend stopped"
fi
if (( GLOBAL_PCT >= 85 )); then
  systemctl stop vault-rhel-pc-rest-server.service || true
  systemctl stop vault-rhel-phone-rest-server.service || true
  logger -p authpriv.crit -t vault-rhel "GLOBAL filesystem ${GLOBAL_PCT}%: both backends stopped"
fi
```

```bash
sudo chmod 755 /usr/local/sbin/vault-rhel-capacity-guard
```

Create timer:

```ini
# /etc/systemd/system/vault-rhel-capacity-guard.service
[Unit]
Description=Vault RHEL per-repository and global capacity guard

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vault-rhel-capacity-guard
```

```ini
# /etc/systemd/system/vault-rhel-capacity-guard.timer
[Unit]
Description=Run Vault RHEL capacity guard every five seconds while host is active

[Timer]
OnBootSec=15s
OnUnitActiveSec=5s
AccuracySec=1s
Unit=vault-rhel-capacity-guard.service

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-rhel-capacity-guard.timer
systemctl list-timers --all | grep vault-rhel-capacity
```

For XFS project-quota mode, replace the per-side `df` percentage with project quota
usage divided by the configured project hard limit. Do not pretend `df` separates two
directories on the same filesystem.

Interpretation:

```text
<70% own allocation   normal
70–79%                review 90-day growth slope
80–84%                urgent storage/scope decision
>=85% own allocation  stop matching backend only
>=85% global host     stop both backends
```

Do not automatically delete snapshots in this no-prune variant.

### 19.1 Boot-Time Global Disk Usage Guard

To prevent system instability and ensure a hard limit on capacity, a strict pre-boot check is enforced for the RHEL-based backup server. When the total disk usage of the RHEL server (including system files, other applications, and everything else) reaches or exceeds 85%, all backup operations are strictly prohibited.

**Boot-Time Verification Workflow:**
1. **Startup Check:** The disk usage ratio is evaluated every time the system boots, strictly *before* the backup services (rest-server Podman capsules and Caddy systemd services) are allowed to start.
2. **Threshold Exceeded (>=85%):** If the calculated total disk usage is 85% or higher:
   - The Caddy (systemd) and rest-server (Podman) services will **not** be started.
   - The backup destination folders (`/var/lib/vault-rhel/repos/`) will be explicitly made **read-only**, completely preventing any future backups.
3. **Mid-Transfer Tolerance:** Because this guard operates exclusively during the device startup sequence, if the total disk usage is 84% before a backup starts and grows to 90% during the transfer, that specific ongoing transfer will not be interrupted. The lock-down changes will take permanent effect the next day when the RHEL server is booted again and the boot-time check detects the >=85% state.

**Client Experience:**
When this capacity lockdown is active, attempting to send a backup from the PC (Terminal) or Phone (Termux) will result in a `"rejected"` message displayed on the client screen, as the remote receiver services remain intentionally offline.

**Physical Console Verification:**
To confirm whether the `"rejected"` status is caused by this disk usage guard, an operator with physical access to the RHEL server console can type the command `usage` into the terminal:
- The terminal will evaluate and display the current disk usage ratio.
- If the value is `<85%`, it will output only the disk usage percentage.
- If the value is `>=85%`, it will output the percentage accompanied by the following explicit warning:
  `"Backup operations have been stopped because disk usage exceeded 85%."`

---

## 20. Power-Up, Cooldown, and Shutdown

The optional Tapo/smart-plug design is a **power trigger only**. It is not an
authorization factor. Turning the machine on starts:

```text
network namespaces
two tailscaled daemons
two persistent Caddy listeners
local RHEL gate
capacity guard
```

It does **not** start either rest-server backend.

Create a conservative local shutdown helper `/usr/local/sbin/vault-rhel-idle-shutdown`:

```bash
#!/usr/bin/env bash
set -euo pipefail

PC_UNIT='vault-rhel-pc-rest-server.service'
PHONE_UNIT='vault-rhel-phone-rest-server.service'
MIN_UP_SECONDS=900
COOLDOWN_SECONDS=300

UP="$(cut -d. -f1 /proc/uptime)"
(( UP >= MIN_UP_SECONDS )) || exit 0

systemctl is-active --quiet "$PC_UNIT" && exit 0
systemctl is-active --quiet "$PHONE_UNIT" && exit 0

sleep "$COOLDOWN_SECONDS"

systemctl is-active --quiet "$PC_UNIT" && exit 0
systemctl is-active --quiet "$PHONE_UNIT" && exit 0

/usr/local/sbin/vault-rhel-capacity-guard
sync
systemctl poweroff
```

A timer may call this every five minutes. The cooldown is an operational convenience;
it is **not** the RHEL security expiry mechanism. The signed session deadline and
systemd hard-stop timer remain authoritative even if the shutdown helper is broken.

If a smart plug is used, never cut AC while RHEL is still running. The plug turns power
**on**; normal `systemctl poweroff` performs shutdown. Restore AC-loss behavior and
smart-plug scheduling only after filesystem and power-loss tests.

---

## 21. Static Configuration Freeze and Update Procedure

After day-zero tests pass, calculate hashes:

```bash
sudo sha256sum \
  /etc/vault-rhel/keys/*.pub \
  /etc/systemd/system/vault-rhel-*.service \
  /etc/systemd/system/vault-tailscaled-*.service \
  /etc/systemd/system/vault-caddy-*.service \
  /etc/vault-rhel/caddy/*.Caddyfile \
  /usr/local/sbin/vault-rhel-gate \
  /usr/local/sbin/vault-rhel-capacity-guard \
  | sudo tee /var/lib/vault-rhel/config-baseline.sha256
```

Optionally apply `chattr +i` to stable root-owned configuration files **only after**
writing the update procedure below in the operations notes. Do not make dynamic slot
files, logs, Tailscale state, or repository data immutable.

Update procedure:

```text
1. Stop new Vault ceremonies.
2. Confirm both backends inactive.
3. Copy current config/hash baseline offline.
4. Remove +i only from the exact files being changed.
5. Apply one change.
6. Run syntax/build tests.
7. Run negative authorization tests.
8. Recalculate hashes.
9. Re-apply +i where used.
10. Resume ceremonies.
```

An unexpected request to unfreeze a security file is an investigation point, not a
routine troubleshooting shortcut.

---

## 22. RHEL Day-Zero Acceptance Test Matrix

Do not place real Vault data on RHEL until every row passes.

### 22.1 Boot state

```bash
sudo reboot
```

After reboot:

```bash
systemctl is-active vault-rhel-netns
systemctl is-active vault-tailscaled-pc
systemctl is-active vault-tailscaled-phone
systemctl is-active vault-caddy-pc
systemctl is-active vault-caddy-phone
systemctl is-active vault-rhel-gate
systemctl is-active vault-rhel-pc-rest-server.service || true
systemctl is-active vault-rhel-phone-rest-server.service || true
```

Expected: infrastructure/gate active; both backends inactive.

### 22.2 Cross-tailnet isolation

From PC:

```text
RHEL :8001 reachable
RHEL :8002 unreachable
```

From Phone:

```text
RHEL :8002 reachable
RHEL :8001 unreachable
```

### 22.3 Single-signature rejection

Post a bundle with only one valid VPS signature. Expected HTTP 403, no slot, no backend.

### 22.4 Wrong-target rejection

Post a valid `RHEL_PHONE` proof to PC `:8001`. Expected HTTP 403.

### 22.5 Expired-proof rejection

Wait past proof `expires_at` and POST. Expected HTTP 403 and no slot.

### 22.6 Successful PC opening

Run the real PC RHEL ceremony. Expected:

```bash
sudo ls -l /var/lib/vault-rhel/gate/PC#*.consumed.json
sudo systemctl is-active vault-rhel-pc-rest-server.service
sudo systemctl is-active vault-rhel-phone-rest-server.service || true
systemctl list-timers --all | grep vault-rhel-pc-hard-stop
```

PC active, Phone inactive, hard-stop timer present.

### 22.7 Same-ceremony HTTP retry

Repeat the exact PC gate request while PC backend is active. Expected HTTP 200 with
`already_open=true` and the same `done_token`.

### 22.8 Fresh PC opening same day

Stop PC backend and submit a new PC ceremony on the same Istanbul date. Expected HTTP
409; slot remains consumed.

### 22.9 DONE early close

Open Phone legitimately, POST its correct `done_token`. Expected Phone backend inactive
immediately; PC state unchanged.

### 22.10 Suppressed DONE hard close

Open a canary ceremony, do not POST DONE, and observe the signed deadline. The systemd
hard-stop timer must begin stopping the exact backend ten seconds before the deadline;
by the signed deadline the bounded stop semantics must have terminated the backend.

### 22.11 Capacity isolation

On a disposable test filesystem/quota configuration, force the PC allocation to its
hard limit. PC writes/backend must fail/stop while the Phone allocation remains usable.
Do not perform this test with production repositories already containing irreplaceable
history.

### 22.12 Keyless receiver

Verify no repository password exists on RHEL and that running `restic snapshots` locally
without importing a source password cannot decrypt either repository.

---

## 23. RHEL Failure and Recovery Runbook

### Network drops during an active backup

Do not request a new RHEL authorization. Restic/S3 data-plane retries are distinct from
authorization issuance. While the same backend is active and the signed deadline has
not closed it, retry the same restic operation using the same repository credentials.

If the backend has already stopped or the daily slot is consumed, the supported outcome
is a missed RHEL copy for that day. Do not delete the slot file to "make it work."

### Gate slot consumed, hard-stop timer failed

This is a critical fail-closed event. The code returns:

```text
slot consumed; hard-stop timer failed; no retry today
```

Investigate systemd/systemd-run and the gate journal. Do not remove the slot. Fix the
infrastructure for the next Istanbul calendar day.

### Gate slot consumed, backend start failed

Same policy: no retry today. Inspect:

```bash
journalctl -u vault-rhel-gate -n 200 --no-pager
journalctl -u vault-rhel-pc-rest-server -n 200 --no-pager
journalctl -u vault-rhel-phone-rest-server -n 200 --no-pager
```

### Capacity guard trip

Inspect:

```bash
tail -n 100 /var/lib/vault-rhel/capacity/capacity.log
df -h
sudo xfs_quota -x -c 'report -p -h' REPO_MOUNTPOINT  # replace placeholder; quota mode
```

In no-prune mode the supported responses are:

```text
add/replace storage
migrate a repository to a larger allocation
reduce future source backup scope prospectively
retire/rebuild under a deliberately chosen prune architecture
```

Do not import the restic repository password onto RHEL for improvised cleanup.

### One Tailscale instance fails

A PC-tailnet failure must not cause the Phone backend to start, and vice versa. Inspect
the exact service/socket:

```bash
systemctl status vault-tailscaled-pc
sudo ip netns exec vault-pc tailscale --socket=/run/tailscale-vault-pc/tailscaled.sock status

systemctl status vault-tailscaled-phone
sudo ip netns exec vault-phone tailscale --socket=/run/tailscale-vault-phone/tailscaled.sock status
```

Never troubleshoot by replacing both with one host `tailscaled` state.

---

## 24. RHEL Security Summary

```text
one primary compromised
  → cannot create opposite VPS signature

one compartment VPS compromised
  → owns one signature, one Tailscale tailnet/signing-node compartment, one S3 egress IP
  → opposite signature absent

one VPS/Tailnet Lock signer compartment compromised
  → opposite signing key absent

RHEL non-root PC backend compromised
  → PC repository path only; Phone user/path/service separate

RHEL root compromised
  → both ciphertext trees may be copied
  → no source repository password stored in no-prune reference

client suppresses DONE
  → signed session deadline + systemd hard stop remains

PC appends junk to own repository
  → PC filesystem/quota boundary reached first
  → Phone allocation remains available
```

The RHEL implementation follows the same capability-opening order as AWS:

```text
verify both VPS signatures
        ↓
consume device/day slot
        ↓
open exactly one bounded capability
```

That ordering is not an optimization. It is the fail-closed security invariant.

## PART 3: COMPLETE PRIMARY-DEVICE INSTALLATION AND DAILY AUTOMATION
================================================================================

# Unified Outbound-Only Workflow — Full PC and Phone Implementation

This part is intentionally operational. It creates the directories, routine secret
files, phase helper, AWS issuance helper, complete PC script, complete Termux widget,
smoke tests, one-time repository initialization, daily operator procedure, and failure
runbook.

The two primary workflows are symmetric but **not interchangeable**:

```text
PC
  belongs only to the PC Tailscale tailnet
  calls only Vault-PC-S3-Gate
  receives only Vault-PC-S3-BackupRole
  reaches only PC S3 bucket
  reaches only RHEL-PC :8001

Phone
  belongs only to the Phone Tailscale tailnet
  calls only Vault-Phone-S3-Gate
  receives only Vault-Phone-S3-BackupRole
  reaches only Phone S3 bucket
  reaches only RHEL-Phone :8002
```

The opposite device remains a live security reviewer because the opposite VPS will not
sign a proof unless its own primary device has authenticated and joined the same phase.
AWS and RHEL verify both signatures themselves.

---

## 1. Install Primary-Device Dependencies

### 1.1 Fedora PC

```bash
sudo dnf update -y
sudo dnf install -y restic rclone libnotify tailscale awscli2 python3 curl jq coreutils

restic version
tailscale version
aws --version
python3 --version
```

The AWS CLI must support IAM Identity Center commands used below:

```bash
aws sso login help >/dev/null
aws lambda invoke help >/dev/null
```

### 1.2 Android / Termux

Install Termux, Termux:API, and Termux:Widget from the same trusted distribution source.
Then:

```bash
pkg update && pkg upgrade -y
pkg install -y restic termux-api python curl jq coreutils netcat-openbsd awscli
termux-setup-storage

restic version
aws --version
python --version
```

The Termux AWS package must successfully expose:

```bash
aws sso login help >/dev/null
aws lambda invoke help >/dev/null
```

If the installed package cannot perform IAM Identity Center SSO, stop the S3 rollout and
fix/replace that client package. Do not put a long-lived AWS access key on the Phone as
a compatibility shortcut.

AWS CLI v2 uses PKCE by default on modern versions; on the Phone script this guide uses
`aws sso login --use-device-code` because AWS documents device authorization for a
device where the verification URL may be opened separately. The MFA requirement still
belongs to IAM Identity Center.

---

## 2. Create Source Directories, Runtime Directories, and Secret Files

PC:

```bash
mkdir -p "$HOME/Vault_PC_Ciphertext"
mkdir -p "$HOME/bin" "$HOME/.local/run/vault" "$HOME/.local/log/vault-sync" "$HOME/.local/state/vault"
mkdir -p "$HOME/.config/vault-secrets" "$HOME/.config/vault"
chmod 700 "$HOME/.config/vault-secrets" "$HOME/.local/run/vault" "$HOME/.local/state/vault"
```

Phone:

```bash
mkdir -p "$HOME/Vault_Phone_Ciphertext"
mkdir -p "$HOME/bin" "$HOME/.shortcuts" "$HOME/.local/run/vault" "$HOME/.local/log/vault-sync" "$HOME/.local/state/vault"
mkdir -p "$HOME/.config/vault-secrets" "$HOME/.config/vault"
chmod 700 "$HOME/.config/vault-secrets" "$HOME/.local/run/vault" "$HOME/.local/state/vault"
```

`Vault_PC_Ciphertext` and `Vault_Phone_Ciphertext` are names retained for compatibility
with earlier scripts; on the originating device these are the **plaintext source
folders**. The ciphertext exists in restic repositories at RHEL and S3.

Create three routine secret files independently on each device:

```text
~/.config/vault-secrets/own_restic_pw
~/.config/vault-secrets/rhel_htpasswd
~/.config/vault-secrets/oracle_phase_token
```

The historical `oracle_phase_token` filename is retained for compatibility. It is a
local per-device coordinator token, not an Oracle-host identity.

Generate the source's own restic repository password in the password manager, then:

```bash
install -m 600 /dev/null "$HOME/.config/vault-secrets/own_restic_pw"
# Paste only this device's own restic password; remove accidental blank lines.
```

Copy only this device's RHEL listener password from Section 10 of Part 2:

```bash
install -m 600 /dev/null "$HOME/.config/vault-secrets/rhel_htpasswd"
# PC gets vaultpc listener plaintext password.
# Phone gets vaultphone listener plaintext password.
```

Generate the phase token independently:

```bash
umask 077
python3 -c 'import secrets,sys; sys.stdout.write(secrets.token_hex(32))' \
  > "$HOME/.config/vault-secrets/oracle_phase_token"
chmod 600 "$HOME/.config/vault-secrets/oracle_phase_token"

python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
p=Path.home()/'.config/vault-secrets/oracle_phase_token'
t=p.read_text(encoding='ascii').strip()
assert len(t)==64
print(sha256(t.encode('ascii')).hexdigest())
PY
```

Provision only the printed hash to the matching VPS as described in Section 23. Never
copy the PC raw token to Phone or Phone raw token to PC.

Copy the RHEL CA certificate created in Part 2 to:

```text
~/.config/vault/rhel-ca.crt
```

Verify:

```bash
openssl x509 -in "$HOME/.config/vault/rhel-ca.crt" -noout -subject -issuer -dates
chmod 644 "$HOME/.config/vault/rhel-ca.crt"
```

---

## 3. Configure the Two Device-Specific AWS IAM Identity Center Profiles

The AWS Section created two permission sets that can only invoke their own Lambda gate.
Configure the PC:

```bash
aws configure sso --profile vault-pc-gate
```

Select the PC gate-invoke permission set and default region `us-east-1`.

Phone:

```bash
aws configure sso --profile vault-phone-gate --use-device-code
```

Select the Phone gate-invoke permission set.

Smoke tests:

```bash
# PC
aws sso login --profile vault-pc-gate
aws sts get-caller-identity --profile vault-pc-gate
aws sso logout

# Phone / Termux
aws sso login --profile vault-phone-gate --use-device-code
aws sts get-caller-identity --profile vault-phone-gate
aws sso logout
```

These SSO roles must not list/get/put S3 objects and must not call `sts:AssumeRole`
directly. The AWS day-zero negative tests in Section 22 are mandatory.

---

## 4. Install the Dual-Signed Phase Helper

Install the identical helper as `$HOME/bin/vault-phase-proof.py` on both devices:

```python
#!/usr/bin/env python3
import argparse
import base64
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import time

STOP = False


def on_signal(_signum, _frame):
    global STOP
    STOP = True


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def send_done(host: str, port: int, phase: str, token: str) -> None:
    # A new proof is never requested here. DONE is only local coordinator cleanup.
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(f"JOIN {phase} {token}\n".encode("ascii"))
            s.settimeout(5)
            line = s.makefile("rb", buffering=0).readline(20000)
            if line.startswith(b"OPEN "):
                s.sendall(b"DONE\n")
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8889)
    ap.add_argument("--phase", choices=("s3", "rhel"), required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--proof-out", required=True)
    ap.add_argument("--ready-file", required=True)
    args = ap.parse_args()

    token = Path(args.token_file).read_text(encoding="ascii").strip()
    if len(token) != 64 or any(c not in "0123456789abcdefABCDEF" for c in token):
        raise SystemExit("phase token must be exactly 64 hexadecimal characters")

    proof_out = Path(args.proof_out)
    ready_file = Path(args.ready_file)
    proof_out.unlink(missing_ok=True)
    ready_file.unlink(missing_ok=True)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    sock = socket.create_connection((args.host, args.port), timeout=10)
    sock.settimeout(50)
    file = sock.makefile("rb", buffering=0)
    sock.sendall(f"JOIN {args.phase} {token}\n".encode("ascii"))

    first = file.readline(20000)
    if not first:
        raise SystemExit("coordinator closed before phase approval")
    parts = first.decode("ascii", errors="strict").strip().split(" ", 2)
    if len(parts) != 3 or parts[0] != "OPEN" or parts[1] != args.phase:
        raise SystemExit(f"phase rejected: {first.decode('ascii', errors='replace').strip()}")

    try:
        bundle_raw = base64.b64decode(parts[2], validate=True)
        bundle = json.loads(bundle_raw)
        for key in ("payload", "pc_signature", "phone_signature"):
            if not isinstance(bundle.get(key), str):
                raise ValueError(f"missing {key}")
    except Exception as exc:
        raise SystemExit(f"invalid signed proof bundle from coordinator: {exc}")

    atomic_write(proof_out, json.dumps(bundle, separators=(",", ":")).encode("utf-8") + b"\n")
    atomic_write(ready_file, b"ready\n")

    try:
        while not STOP:
            time.sleep(20)
            if STOP:
                break
            sock.sendall(b"PING\n")
            reply = file.readline(256)
            if reply.strip() != b"PONG":
                raise OSError(f"unexpected coordinator reply: {reply!r}")
    finally:
        try:
            sock.sendall(b"DONE\n")
            sock.settimeout(5)
            file.readline(256)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
        ready_file.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

```bash
chmod 700 "$HOME/bin/vault-phase-proof.py"
python3 -m py_compile "$HOME/bin/vault-phase-proof.py"
```

This helper:

```text
opens the local device's coordinator socket
presents only its own phase token
waits for opposite-device participation via cross-VPS signing
receives one dual-signed proof bundle
writes it atomically mode 600
keeps the local phase socket alive with PING/PONG
sends cooperative DONE on normal SIGTERM
```

The helper does **not** call AWS and does **not** open RHEL. It only obtains the signed
proof that AWS/RHEL will verify themselves.

---

## 5. Install the Non-Retrying AWS Gate Helper

Use the exact `vault-aws-gate-invoke` helper from Section 22.12.12 on both devices.
Verify:

```bash
chmod 700 "$HOME/bin/vault-aws-gate-invoke"
bash -n "$HOME/bin/vault-aws-gate-invoke"
```

There must be exactly one `aws lambda invoke` command and no `until`, generic retry
wrapper, or second invocation after an ambiguous error.

---

## 6. Install the Complete PC Daily Workflow

Create `$HOME/bin/vault-daily-pc`:

```bash
#!/usr/bin/env bash
# vault-daily-pc — one complete PC Vault ceremony: S3 then RHEL.
# Authorization issuance is fail-closed. S3 data-plane commands may retry only while
# the current backup is incomplete and the exact completion state is not REVOKED. RHEL
# retries reuse only the already-open backend and remain bounded by the signed deadline.
set -euo pipefail
umask 077

SIDE='pc'
COORDINATOR='100.64.0.1'
PHASE_PORT='8889'
S3_PROXY='http://VPS_TS_IP:8888'
AWS_PROFILE='vault-pc-gate'
AWS_FUNCTION='Vault-PC-S3-Gate'
S3_COMPLETION_STATUS_FUNCTION='Vault-S3-Completion-Status'
PEER_DEVICE='phone'
S3_REPOSITORY='s3:s3.us-east-1.amazonaws.com/vault-pc-yourname'
SOURCE_DIR="$HOME/Vault_PC_Ciphertext"
RHEL_URL='https://PC_RHEL_TS_IP:8001'
RHEL_USER='vaultpc'
RHEL_CA="$HOME/.config/vault/rhel-ca.crt"
PHASE_TOKEN="$HOME/.config/vault-secrets/oracle_phase_token"
RESTIC_PW_FILE="$HOME/.config/vault-secrets/own_restic_pw"
RHEL_PW_FILE="$HOME/.config/vault-secrets/rhel_htpasswd"
RUN="$HOME/.local/run/vault"
LOG_DIR="$HOME/.local/log/vault-sync"
STATE_DIR="$HOME/.local/state/vault"

mkdir -p "$RUN" "$LOG_DIR" "$STATE_DIR"
chmod 700 "$RUN" "$LOG_DIR" "$STATE_DIR"
LOG="$LOG_DIR/$(date +%Y%m%d-%H%M%S)-pc-daily.log"
PHASE_PID=''
PHASE_NAME=''
STS_EXPIRATION=''
S3_CALENDAR_DATE=''
S3_SESSION_EXPIRES_AT=''
RHEL_DONE_TOKEN=''

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG"; }
fail() { log "ERROR: $*"; return 1; }

cleanup() {
  local rc=$?
  set +e
  if [[ -n "$PHASE_PID" ]]; then
    kill -TERM "$PHASE_PID" 2>/dev/null
    wait "$PHASE_PID" 2>/dev/null
  fi
  unset HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
  unset RESTIC_PASSWORD RHEL_HTPASSWD RHEL_AUTH RHEL_REPO RHEL_DONE_TOKEN
  S3_CALENDAR_DATE=''
  S3_SESSION_EXPIRES_AT=''
  rm -f "$RUN"/*.ready "$RUN"/*-proof.json "$RUN"/sts.json "$RUN"/sts.json.invoke-meta.json
  rm -f "$RUN"/completion-status-query.json "$RUN"/completion-status.json "$RUN"/completion-status.json.invoke-meta.json
  rm -f "$RUN"/rhel-gate.json "$RUN"/rhel-done.json
  aws sso logout >/dev/null 2>&1 || true
  log "cleanup complete rc=$rc"
  exit "$rc"
}
trap cleanup EXIT INT TERM HUP

require_file() {
  [[ -s "$1" ]] || { echo "Missing required file: $1" >&2; exit 1; }
  [[ "$(stat -c '%a' "$1")" == '600' ]] || {
    echo "Required secret must be mode 600: $1" >&2
    exit 1
  }
}

for f in "$PHASE_TOKEN" "$RESTIC_PW_FILE" "$RHEL_PW_FILE" "$RHEL_CA"; do
  [[ -s "$f" ]] || { echo "Missing required file: $f" >&2; exit 1; }
done
require_file "$PHASE_TOKEN"
require_file "$RESTIC_PW_FILE"
require_file "$RHEL_PW_FILE"

command -v restic >/dev/null
command -v aws >/dev/null
command -v curl >/dev/null
command -v python3 >/dev/null
[[ -x "$HOME/bin/vault-phase-proof.py" ]]
[[ -x "$HOME/bin/vault-close-peer.py" ]]
[[ -x "$HOME/bin/vault-aws-gate-invoke" ]]

# Device-side inbound prohibition is a local control independent of Tailscale grant policy.
sudo tailscale set --shields-up=true --ssh=false >/dev/null
tailscale status >/dev/null

wait_ready() {
  local pid="$1" file="$2" deadline=$((SECONDS + 650))
  while [[ ! -s "$file" ]]; do
    kill -0 "$pid" 2>/dev/null || return 1
    (( SECONDS < deadline )) || return 1
    sleep 1
  done
}

start_phase() {
  local phase="$1"
  local proof="$RUN/${phase}-proof.json"
  local ready="$RUN/${phase}.ready"
  rm -f "$proof" "$ready"
  log "joining ${phase} ceremony; the Phone workflow must join its own compartment"
  python3 "$HOME/bin/vault-phase-proof.py" \
    --host "$COORDINATOR" --port "$PHASE_PORT" --phase "$phase" \
    --token-file "$PHASE_TOKEN" --proof-out "$proof" --ready-file "$ready" &
  PHASE_PID=$!
  PHASE_NAME="$phase"
  if ! wait_ready "$PHASE_PID" "$ready"; then
    wait "$PHASE_PID" 2>/dev/null || true
    PHASE_PID=''
    fail "${phase} proof did not become ready"
    return 1
  fi
  log "${phase} dual-signed proof ready"
}

finish_phase() {
  if [[ -n "$PHASE_PID" ]]; then
    log "closing local ${PHASE_NAME} control phase"
    kill -TERM "$PHASE_PID" 2>/dev/null || true
    wait "$PHASE_PID" 2>/dev/null || true
    PHASE_PID=''
    PHASE_NAME=''
  fi
}

load_s3_session_identity() {
  read -r S3_CALENDAR_DATE S3_SESSION_EXPIRES_AT < <(
    python3 - "$RUN/s3-proof.json" <<'PY'
import base64
import json
import sys

bundle = json.load(open(sys.argv[1], encoding='utf-8'))
payload = json.loads(base64.b64decode(bundle['payload'], validate=True))
calendar_date = payload.get('calendar_date')
session_expires_at = payload.get('session_expires_at')
if not isinstance(calendar_date, str) or not isinstance(session_expires_at, str):
    raise SystemExit('missing S3 session identity')
print(calendar_date, session_expires_at)
PY
  )
  [[ -n "$S3_CALENDAR_DATE" && -n "$S3_SESSION_EXPIRES_AT" ]]
  log "S3 session identity date=$S3_CALENDAR_DATE deadline=$S3_SESSION_EXPIRES_AT"
}

wait_for_peer_s3_completion_and_close() {
  local target="$1" calendar_date="$2" session_deadline="$3"
  local query="$RUN/completion-status-query.json"
  local out="$RUN/completion-status.json"
  local meta="$RUN/completion-status.json.invoke-meta.json"
  local deadline_epoch now_epoch rc completed state attempt

  python3 - "$target" "$calendar_date" "$session_deadline" > "$query" <<'PY'
import json
import sys
print(json.dumps({
    'device': sys.argv[1],
    'calendar_date': sys.argv[2],
    'session_expires_at': sys.argv[3],
}, separators=(',', ':')))
PY
  deadline_epoch="$(python3 - "$session_deadline" <<'PY'
from datetime import datetime
import sys
print(int(datetime.fromisoformat(sys.argv[1].replace('Z', '+00:00')).timestamp()))
PY
)"

  while true; do
    now_epoch="$(date +%s)"
    if (( now_epoch >= deadline_epoch )); then
      fail "peer S3 completion barrier reached the signed hard deadline before ${target} became REVOKED"
      return 1
    fi

    rm -f "$out" "$meta"
    set +e
    AWS_MAX_ATTEMPTS=3 AWS_RETRY_MODE=standard aws lambda invoke \
      --profile "$AWS_PROFILE" \
      --function-name "$S3_COMPLETION_STATUS_FUNCTION" \
      --cli-binary-format raw-in-base64-out \
      --payload "fileb://$query" \
      "$out" > "$meta" 2>>"$LOG"
    rc=$?
    set -e

    if (( rc == 0 )); then
      read -r completed state < <(
        python3 - "$out" "$meta" <<'PY'
import json
import sys

out_path, meta_path = sys.argv[1:]
meta = json.load(open(meta_path, encoding='utf-8'))
if meta.get('FunctionError'):
    print('false ERROR')
    raise SystemExit
body = json.load(open(out_path, encoding='utf-8'))
print('true' if body.get('Completed') is True else 'false', body.get('CompletionState', 'UNKNOWN'))
PY
      )
      if [[ "$completed" == 'true' && "$state" == 'REVOKED' ]]; then
        log "AWS reports ${target} S3 session REVOKED for the exact shared deadline; requesting close-only peer admission shutdown"
        for attempt in 1 2 3; do
          if python3 "$HOME/bin/vault-close-peer.py" \
            --host "$COORDINATOR" --port "$PHASE_PORT" \
            --token-file "$PHASE_TOKEN"; then
            log "peer ${target} S3 admission close acknowledged"
            return 0
          fi
          (( attempt < 3 )) || break
          sleep 3
        done
        fail "AWS confirmed ${target} REVOKED but signed peer close was not acknowledged"
        return 1
      fi
      log "waiting for ${target} S3 completion state; current=${state}"
    else
      log "completion-status invoke failed rc=$rc; retrying read-only status poll"
    fi
    sleep 3
  done
}

load_sts_env() {
  local file="$1"
  eval "$(python3 - "$file" <<'PY'
import json, shlex, sys
p=sys.argv[1]
d=json.load(open(p,encoding='utf-8'))
for env,key in (
    ('AWS_ACCESS_KEY_ID','AccessKeyId'),
    ('AWS_SECRET_ACCESS_KEY','SecretAccessKey'),
    ('AWS_SESSION_TOKEN','SessionToken'),
):
    v=d.get(key)
    if not isinstance(v,str) or not v:
        raise SystemExit(f'missing {key}')
    print(f'export {env}={shlex.quote(v)}')
print(f"export STS_EXPIRATION={shlex.quote(d['Expiration'])}")
PY
)"
}

seconds_until_sts_expiry() {
  python3 - "$STS_EXPIRATION" <<'PY'
from datetime import datetime,timezone
import sys
v=sys.argv[1].replace('Z','+00:00')
t=datetime.fromisoformat(v)
print(int((t-datetime.now(timezone.utc)).total_seconds()))
PY
}

restic_backup_json_retry() {
  local label="$1" log_json="$2"; shift 2
  local attempt rc remaining
  : > "$log_json"
  for attempt in 1 2 3; do
    log "$label attempt ${attempt}/3"
    set +e
    restic "$@" --json 2>&1 | tee -a "$log_json" "$LOG"
    rc=${PIPESTATUS[0]}
    set -e
    if (( rc == 0 )); then
      return 0
    fi
    if [[ -n "$STS_EXPIRATION" ]]; then
      remaining="$(seconds_until_sts_expiry 2>/dev/null || echo 0)"
      if (( remaining < 120 )); then
        log "$label failed and STS has <120s remaining; no new issuance is allowed"
        return "$rc"
      fi
    fi
    (( attempt < 3 )) || return "$rc"
    log "$label transient failure; retrying same data-plane command with same authorization in 15s"
    sleep 15
  done
}

restic_command_retry() {
  local label="$1"; shift
  local attempt rc
  for attempt in 1 2 3; do
    log "$label attempt ${attempt}/3"
    if restic "$@" 2>&1 | tee -a "$LOG"; then
      return 0
    else
      rc=${PIPESTATUS[0]}
    fi
    (( attempt < 3 )) || return "$rc"
    log "$label transient failure; retrying same open data-plane window in 15s"
    sleep 15
  done
}

summary_from_json() {
  python3 - "$1" <<'PY'
import json,sys
last=None
for line in open(sys.argv[1],encoding='utf-8',errors='replace'):
    try: obj=json.loads(line)
    except Exception: continue
    if obj.get('message_type') == 'summary': last=obj
if not last:
    print('No JSON summary found')
    raise SystemExit
print('new={files_new} changed={files_changed} unmodified={files_unmodified} data_added={data_added} data_added_packed={data_added_packed}'.format(**{k:last.get(k,'?') for k in ['files_new','files_changed','files_unmodified','data_added','data_added_packed']}))
PY
}

rhel_gate_same_proof_retry() {
  local proof="$1" output="$2" attempt
  rm -f "$output"
  for attempt in 1 2 3; do
    log "RHEL gate HTTP attempt ${attempt}/3 using the same exact proof bundle"
    if curl --fail --silent --show-error \
      --connect-timeout 10 --max-time 20 \
      --cacert "$RHEL_CA" \
      -H 'Content-Type: application/json' \
      --data-binary @"$proof" \
      "$RHEL_URL/__vault_gate" > "$output"; then
      return 0
    fi
    (( attempt < 3 )) || return 1
    sleep 3
  done
}

post_rhel_done() {
  python3 - "$RHEL_DONE_TOKEN" > "$RUN/rhel-done.json" <<'PY'
import json,sys
print(json.dumps({'done_token':sys.argv[1]},separators=(',',':')))
PY
  curl --fail --silent --show-error \
    --connect-timeout 10 --max-time 20 \
    --cacert "$RHEL_CA" \
    -H 'Content-Type: application/json' \
    --data-binary @"$RUN/rhel-done.json" \
    "$RHEL_URL/__vault_done" >/dev/null
}

log '=== PC Vault daily workflow started ==='
log 'Both devices must start the S3 phase within the coordinator pairing window.'

export RESTIC_PASSWORD="$(cat "$RESTIC_PW_FILE")"

# ---------------------------------------------------------------------------
# S3 PHASE
# ---------------------------------------------------------------------------
start_phase s3
load_s3_session_identity

log 'starting AWS IAM Identity Center login; complete MFA on the separate authenticator'
aws sso login --profile "$AWS_PROFILE"
aws sts get-caller-identity --profile "$AWS_PROFILE" >/dev/null

# Exactly one Lambda invocation helper; do not wrap this in a retry loop.
"$HOME/bin/vault-aws-gate-invoke" \
  "$AWS_PROFILE" "$AWS_FUNCTION" "$RUN/s3-proof.json" "$RUN/sts.json"
load_sts_env "$RUN/sts.json"

export HTTPS_PROXY="$S3_PROXY"
S3_JSON="$LOG_DIR/$(date +%Y%m%d-%H%M%S)-pc-s3-backup.jsonl"
if ! restic_backup_json_retry 'PC→S3 backup' "$S3_JSON" \
  -r "$S3_REPOSITORY" \
  -o s3.bucket-lookup=path \
  -o s3.region=us-east-1 \
  -o s3.storage-class=DEEP_ARCHIVE \
  backup "$SOURCE_DIR"; then
  fail 'PC→S3 backup failed after same-credential data-plane retries; do not request a second STS issuance today'
  exit 1
fi
summary_from_json "$S3_JSON" | tee -a "$LOG"
date -Iseconds > "$STATE_DIR/last-pc-s3-success"

# Do not run routine restic check against Deep Archive. See cold-storage warning.
# Successful restic completion is independently observed by AWS from snapshot creation
# followed by a later repository-lock removal. Drop local STS values immediately, close
# our own proxy phase, then keep the MFA-backed SSO session only for the read-only
# opposite-device completion barrier.
unset HTTPS_PROXY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
STS_EXPIRATION=''
finish_phase
if ! wait_for_peer_s3_completion_and_close "$PEER_DEVICE" "$S3_CALENDAR_DATE" "$S3_SESSION_EXPIRES_AT"; then
  fail 'S3 completion barrier failed; do not continue to RHEL in this ceremony'
  exit 1
fi
aws sso logout >/dev/null 2>&1 || true
rm -f "$RUN/s3-proof.json" "$RUN/s3.ready" "$RUN/sts.json" "$RUN/sts.json.invoke-meta.json"
rm -f "$RUN/completion-status-query.json" "$RUN/completion-status.json" "$RUN/completion-status.json.invoke-meta.json"


# ---------------------------------------------------------------------------
# RHEL PHASE
# ---------------------------------------------------------------------------
start_phase rhel
if ! rhel_gate_same_proof_retry "$RUN/rhel-proof.json" "$RUN/rhel-gate.json"; then
  fail 'RHEL gate failed. The daily RHEL opening slot may be consumed; do not create a new ceremony today.'
  exit 1
fi

RHEL_DONE_TOKEN="$(python3 - "$RUN/rhel-gate.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
v=d.get('done_token')
if not isinstance(v,str) or len(v)!=64: raise SystemExit('missing/invalid done_token')
print(v)
PY
)"
RHEL_HTPASSWD="$(cat "$RHEL_PW_FILE")"
RHEL_AUTH="$(python3 - "$RHEL_HTPASSWD" <<'PY'
import sys,urllib.parse
print(urllib.parse.quote(sys.argv[1],safe=''))
PY
)"
RHEL_REPO="rest:https://${RHEL_USER}:${RHEL_AUTH}@PC_RHEL_TS_IP:8001/"
RHEL_JSON="$LOG_DIR/$(date +%Y%m%d-%H%M%S)-pc-rhel-backup.jsonl"

if ! restic_backup_json_retry 'PC→RHEL backup' "$RHEL_JSON" \
  -r "$RHEL_REPO" --cacert "$RHEL_CA" backup "$SOURCE_DIR"; then
  fail 'PC→RHEL backup failed after same-window retries'
  exit 1
fi
summary_from_json "$RHEL_JSON" | tee -a "$LOG"

# Saturday-anchored / catch-up staged content-read verification.
# Normal sequence: first due Saturday 1/4, next Saturday 2/4, then 3/4, then 4/4,
# repeating. If a due Saturday is missed, exactly one pending stage runs on the first
# later successful RHEL transfer. The stage number and next-due marker advance only
# after a successful check, so a failed check or a missed Saturday never skips 2/4,
# 3/4, or 4/4.
CHECK_STAGE_FILE="$STATE_DIR/pc-rhel-check-stage"
CHECK_NEXT_DUE_FILE="$STATE_DIR/pc-rhel-check-next-saturday"

vault_today_istanbul() {
  python3 - <<'PYDATE'
from datetime import datetime
from zoneinfo import ZoneInfo
print(datetime.now(ZoneInfo("Europe/Istanbul")).date().isoformat())
PYDATE
}

vault_next_saturday_on_or_after() {
  python3 - "$1" <<'PYDATE'
from datetime import date, timedelta
import sys
start = date.fromisoformat(sys.argv[1])
delta = (5 - start.weekday()) % 7
print((start + timedelta(days=delta)).isoformat())
PYDATE
}

vault_next_saturday_after() {
  python3 - "$1" <<'PYDATE'
from datetime import date, timedelta
import sys
start = date.fromisoformat(sys.argv[1]) + timedelta(days=1)
delta = (5 - start.weekday()) % 7
print((start + timedelta(days=delta)).isoformat())
PYDATE
}

TODAY_ISTANBUL="$(vault_today_istanbul)"
if [ ! -s "$CHECK_NEXT_DUE_FILE" ]; then
  FIRST_DUE="$(vault_next_saturday_on_or_after "$TODAY_ISTANBUL")"
  printf '%s
' "$FIRST_DUE" > "$CHECK_NEXT_DUE_FILE"
  log "PC→RHEL staged check schedule initialized; first 1/4 stage due $FIRST_DUE"
fi

NEXT_DUE="$(cat "$CHECK_NEXT_DUE_FILE")"
STAGE="$(cat "$CHECK_STAGE_FILE" 2>/dev/null || echo 1)"
case "$STAGE" in 1|2|3|4) ;; *) STAGE=1 ;; esac

if [[ "$TODAY_ISTANBUL" < "$NEXT_DUE" ]]; then
  log "PC→RHEL staged content-read check not due until Saturday slot $NEXT_DUE; pending stage ${STAGE}/4"
else
  SUBSET="${STAGE}/4"
  if ! restic_command_retry "PC→RHEL scheduled/catch-up keyed integrity check subset $SUBSET" \
    -r "$RHEL_REPO" --cacert "$RHEL_CA" check --read-data-subset="$SUBSET"; then
    fail 'RHEL staged integrity check failed; stage and Saturday due markers are not advanced'
    exit 1
  fi
  NEXT_STAGE=$(( (STAGE % 4) + 1 ))
  CANDIDATE_NEXT="$(python3 - "$NEXT_DUE" <<'PYDATE'
from datetime import date, timedelta
import sys
print((date.fromisoformat(sys.argv[1]) + timedelta(days=7)).isoformat())
PYDATE
)"
  if [[ "$CANDIDATE_NEXT" < "$TODAY_ISTANBUL" || "$CANDIDATE_NEXT" == "$TODAY_ISTANBUL" ]]; then
    CANDIDATE_NEXT="$(vault_next_saturday_after "$TODAY_ISTANBUL")"
  fi
  printf '%s
' "$NEXT_STAGE" > "$CHECK_STAGE_FILE"
  printf '%s
' "$CANDIDATE_NEXT" > "$CHECK_NEXT_DUE_FILE"
  log "PC→RHEL staged check $SUBSET complete; next stage ${NEXT_STAGE}/4 due $CANDIDATE_NEXT"
fi

date -Iseconds > "$STATE_DIR/last-pc-rhel-success"
post_rhel_done
RHEL_DONE_TOKEN=''
finish_phase

log '=== PC Vault daily workflow completed successfully ==='
notify-send 'Vault PC backup complete' 'S3 and RHEL phases completed.' --icon=security-high 2>/dev/null || true
```

```bash
chmod 700 "$HOME/bin/vault-daily-pc"
bash -n "$HOME/bin/vault-daily-pc"
```

Replace only:

```text
vault-pc-yourname
```

with the exact PC bucket name created in Section 22. Do not replace the Phone bucket in
a PC script because no Phone bucket belongs in this workflow.

### 6.1 Why the retry loop is safe

The PC script has retry loops around **restic data-plane operations only**. It does not
loop around `vault-aws-gate-invoke`.

```text
Lambda/STS issuance retry
  NO

same STS credentials + same S3 phase + retry restic network operation
  YES, bounded in-process

same RHEL backend + same proof/ceremony + retry HTTP gate response
  YES, exact same proof; RHEL gate is idempotent while matching backend is active

same open RHEL backend + retry restic operation
  YES, bounded in-process
```

If the whole process crashes and loses the STS credentials, do not run a new daily
workflow expecting a second issuance. The daily slot has intentionally burned. In-process
retry exists to tolerate ordinary transient network faults without creating a new
credential.

---

## 7. Install the Complete Phone / Termux Daily Workflow

Create `$HOME/.shortcuts/vault-daily-phone`:

```bash
#!/usr/bin/env bash
# vault-daily-phone — one complete Phone Vault ceremony: S3 then RHEL.
# Authorization issuance is fail-closed. S3 data-plane commands may retry only while
# the current backup is incomplete and the exact completion state is not REVOKED. RHEL
# retries reuse only the already-open backend and remain bounded by the signed deadline.
set -euo pipefail
umask 077
termux-wake-lock 2>/dev/null || true

SIDE='phone'
COORDINATOR='100.64.0.1'
PHASE_PORT='8889'
S3_PROXY='http://VPS_TS_IP:8888'
AWS_PROFILE='vault-phone-gate'
AWS_FUNCTION='Vault-Phone-S3-Gate'
S3_COMPLETION_STATUS_FUNCTION='Vault-S3-Completion-Status'
PEER_DEVICE='pc'
S3_REPOSITORY='s3:s3.us-east-1.amazonaws.com/vault-phone-yourname'
SOURCE_DIR="$HOME/Vault_Phone_Ciphertext"
RHEL_URL='https://PHONE_RHEL_TS_IP:8002'
RHEL_USER='vaultphone'
RHEL_CA="$HOME/.config/vault/rhel-ca.crt"
PHASE_TOKEN="$HOME/.config/vault-secrets/oracle_phase_token"
RESTIC_PW_FILE="$HOME/.config/vault-secrets/own_restic_pw"
RHEL_PW_FILE="$HOME/.config/vault-secrets/rhel_htpasswd"
RUN="$HOME/.local/run/vault"
LOG_DIR="$HOME/.local/log/vault-sync"
STATE_DIR="$HOME/.local/state/vault"

mkdir -p "$RUN" "$LOG_DIR" "$STATE_DIR"
chmod 700 "$RUN" "$LOG_DIR" "$STATE_DIR"
LOG="$LOG_DIR/$(date +%Y%m%d-%H%M%S)-phone-daily.log"
PHASE_PID=''
PHASE_NAME=''
STS_EXPIRATION=''
S3_CALENDAR_DATE=''
S3_SESSION_EXPIRES_AT=''
RHEL_DONE_TOKEN=''

log() { printf '%s %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG"; }
fail() { log "ERROR: $*"; return 1; }

cleanup() {
  local rc=$?
  set +e
  if [[ -n "$PHASE_PID" ]]; then
    kill -TERM "$PHASE_PID" 2>/dev/null
    wait "$PHASE_PID" 2>/dev/null
  fi
  unset HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
  unset RESTIC_PASSWORD RHEL_HTPASSWD RHEL_AUTH RHEL_REPO RHEL_DONE_TOKEN
  S3_CALENDAR_DATE=''
  S3_SESSION_EXPIRES_AT=''
  rm -f "$RUN"/*.ready "$RUN"/*-proof.json "$RUN"/sts.json "$RUN"/sts.json.invoke-meta.json
  rm -f "$RUN"/completion-status-query.json "$RUN"/completion-status.json "$RUN"/completion-status.json.invoke-meta.json
  rm -f "$RUN"/rhel-gate.json "$RUN"/rhel-done.json
  aws sso logout >/dev/null 2>&1 || true
  log "cleanup complete rc=$rc"
  exit "$rc"
}
trap cleanup EXIT INT TERM HUP

require_file() {
  [[ -s "$1" ]] || { echo "Missing required file: $1" >&2; exit 1; }
  [[ "$(stat -c '%a' "$1")" == '600' ]] || {
    echo "Required secret must be mode 600: $1" >&2
    exit 1
  }
}

for f in "$PHASE_TOKEN" "$RESTIC_PW_FILE" "$RHEL_PW_FILE" "$RHEL_CA"; do
  [[ -s "$f" ]] || { echo "Missing required file: $f" >&2; exit 1; }
done
require_file "$PHASE_TOKEN"
require_file "$RESTIC_PW_FILE"
require_file "$RHEL_PW_FILE"

command -v restic >/dev/null
command -v aws >/dev/null
command -v curl >/dev/null
command -v python3 >/dev/null
[[ -x "$HOME/bin/vault-phase-proof.py" ]]
[[ -x "$HOME/bin/vault-close-peer.py" ]]
[[ -x "$HOME/bin/vault-aws-gate-invoke" ]]

# Device-side inbound prohibition is a local control independent of Tailscale grant policy.
# Android enforces the equivalent local inbound rule in the Tailscale app.
# Keep 'Allow incoming connections' disabled before starting the widget.
# Standard non-root Termux does not manage tailscaled with the host CLI.
termux-toast 'Confirm Tailscale is connected and Allow incoming connections is OFF' 2>/dev/null || true

wait_ready() {
  local pid="$1" file="$2" deadline=$((SECONDS + 650))
  while [[ ! -s "$file" ]]; do
    kill -0 "$pid" 2>/dev/null || return 1
    (( SECONDS < deadline )) || return 1
    sleep 1
  done
}

start_phase() {
  local phase="$1"
  local proof="$RUN/${phase}-proof.json"
  local ready="$RUN/${phase}.ready"
  rm -f "$proof" "$ready"
  log "joining ${phase} ceremony; the Phone workflow must join its own compartment"
  python3 "$HOME/bin/vault-phase-proof.py" \
    --host "$COORDINATOR" --port "$PHASE_PORT" --phase "$phase" \
    --token-file "$PHASE_TOKEN" --proof-out "$proof" --ready-file "$ready" &
  PHASE_PID=$!
  PHASE_NAME="$phase"
  if ! wait_ready "$PHASE_PID" "$ready"; then
    wait "$PHASE_PID" 2>/dev/null || true
    PHASE_PID=''
    fail "${phase} proof did not become ready"
    return 1
  fi
  log "${phase} dual-signed proof ready"
}

finish_phase() {
  if [[ -n "$PHASE_PID" ]]; then
    log "closing local ${PHASE_NAME} control phase"
    kill -TERM "$PHASE_PID" 2>/dev/null || true
    wait "$PHASE_PID" 2>/dev/null || true
    PHASE_PID=''
    PHASE_NAME=''
  fi
}

load_s3_session_identity() {
  read -r S3_CALENDAR_DATE S3_SESSION_EXPIRES_AT < <(
    python3 - "$RUN/s3-proof.json" <<'PY'
import base64
import json
import sys

bundle = json.load(open(sys.argv[1], encoding='utf-8'))
payload = json.loads(base64.b64decode(bundle['payload'], validate=True))
calendar_date = payload.get('calendar_date')
session_expires_at = payload.get('session_expires_at')
if not isinstance(calendar_date, str) or not isinstance(session_expires_at, str):
    raise SystemExit('missing S3 session identity')
print(calendar_date, session_expires_at)
PY
  )
  [[ -n "$S3_CALENDAR_DATE" && -n "$S3_SESSION_EXPIRES_AT" ]]
  log "S3 session identity date=$S3_CALENDAR_DATE deadline=$S3_SESSION_EXPIRES_AT"
}

wait_for_peer_s3_completion_and_close() {
  local target="$1" calendar_date="$2" session_deadline="$3"
  local query="$RUN/completion-status-query.json"
  local out="$RUN/completion-status.json"
  local meta="$RUN/completion-status.json.invoke-meta.json"
  local deadline_epoch now_epoch rc completed state attempt

  python3 - "$target" "$calendar_date" "$session_deadline" > "$query" <<'PY'
import json
import sys
print(json.dumps({
    'device': sys.argv[1],
    'calendar_date': sys.argv[2],
    'session_expires_at': sys.argv[3],
}, separators=(',', ':')))
PY
  deadline_epoch="$(python3 - "$session_deadline" <<'PY'
from datetime import datetime
import sys
print(int(datetime.fromisoformat(sys.argv[1].replace('Z', '+00:00')).timestamp()))
PY
)"

  while true; do
    now_epoch="$(date +%s)"
    if (( now_epoch >= deadline_epoch )); then
      fail "peer S3 completion barrier reached the signed hard deadline before ${target} became REVOKED"
      return 1
    fi

    rm -f "$out" "$meta"
    set +e
    AWS_MAX_ATTEMPTS=3 AWS_RETRY_MODE=standard aws lambda invoke \
      --profile "$AWS_PROFILE" \
      --function-name "$S3_COMPLETION_STATUS_FUNCTION" \
      --cli-binary-format raw-in-base64-out \
      --payload "fileb://$query" \
      "$out" > "$meta" 2>>"$LOG"
    rc=$?
    set -e

    if (( rc == 0 )); then
      read -r completed state < <(
        python3 - "$out" "$meta" <<'PY'
import json
import sys

out_path, meta_path = sys.argv[1:]
meta = json.load(open(meta_path, encoding='utf-8'))
if meta.get('FunctionError'):
    print('false ERROR')
    raise SystemExit
body = json.load(open(out_path, encoding='utf-8'))
print('true' if body.get('Completed') is True else 'false', body.get('CompletionState', 'UNKNOWN'))
PY
      )
      if [[ "$completed" == 'true' && "$state" == 'REVOKED' ]]; then
        log "AWS reports ${target} S3 session REVOKED for the exact shared deadline; requesting close-only peer admission shutdown"
        for attempt in 1 2 3; do
          if python3 "$HOME/bin/vault-close-peer.py" \
            --host "$COORDINATOR" --port "$PHASE_PORT" \
            --token-file "$PHASE_TOKEN"; then
            log "peer ${target} S3 admission close acknowledged"
            return 0
          fi
          (( attempt < 3 )) || break
          sleep 3
        done
        fail "AWS confirmed ${target} REVOKED but signed peer close was not acknowledged"
        return 1
      fi
      log "waiting for ${target} S3 completion state; current=${state}"
    else
      log "completion-status invoke failed rc=$rc; retrying read-only status poll"
    fi
    sleep 3
  done
}

load_sts_env() {
  local file="$1"
  eval "$(python3 - "$file" <<'PY'
import json, shlex, sys
p=sys.argv[1]
d=json.load(open(p,encoding='utf-8'))
for env,key in (
    ('AWS_ACCESS_KEY_ID','AccessKeyId'),
    ('AWS_SECRET_ACCESS_KEY','SecretAccessKey'),
    ('AWS_SESSION_TOKEN','SessionToken'),
):
    v=d.get(key)
    if not isinstance(v,str) or not v:
        raise SystemExit(f'missing {key}')
    print(f'export {env}={shlex.quote(v)}')
print(f"export STS_EXPIRATION={shlex.quote(d['Expiration'])}")
PY
)"
}

seconds_until_sts_expiry() {
  python3 - "$STS_EXPIRATION" <<'PY'
from datetime import datetime,timezone
import sys
v=sys.argv[1].replace('Z','+00:00')
t=datetime.fromisoformat(v)
print(int((t-datetime.now(timezone.utc)).total_seconds()))
PY
}

restic_backup_json_retry() {
  local label="$1" log_json="$2"; shift 2
  local attempt rc remaining
  : > "$log_json"
  for attempt in 1 2 3; do
    log "$label attempt ${attempt}/3"
    set +e
    restic "$@" --json 2>&1 | tee -a "$log_json" "$LOG"
    rc=${PIPESTATUS[0]}
    set -e
    if (( rc == 0 )); then
      return 0
    fi
    if [[ -n "$STS_EXPIRATION" ]]; then
      remaining="$(seconds_until_sts_expiry 2>/dev/null || echo 0)"
      if (( remaining < 120 )); then
        log "$label failed and STS has <120s remaining; no new issuance is allowed"
        return "$rc"
      fi
    fi
    (( attempt < 3 )) || return "$rc"
    log "$label transient failure; retrying same data-plane command with same authorization in 15s"
    sleep 15
  done
}

restic_command_retry() {
  local label="$1"; shift
  local attempt rc
  for attempt in 1 2 3; do
    log "$label attempt ${attempt}/3"
    if restic "$@" 2>&1 | tee -a "$LOG"; then
      return 0
    else
      rc=${PIPESTATUS[0]}
    fi
    (( attempt < 3 )) || return "$rc"
    log "$label transient failure; retrying same open data-plane window in 15s"
    sleep 15
  done
}

summary_from_json() {
  python3 - "$1" <<'PY'
import json,sys
last=None
for line in open(sys.argv[1],encoding='utf-8',errors='replace'):
    try: obj=json.loads(line)
    except Exception: continue
    if obj.get('message_type') == 'summary': last=obj
if not last:
    print('No JSON summary found')
    raise SystemExit
print('new={files_new} changed={files_changed} unmodified={files_unmodified} data_added={data_added} data_added_packed={data_added_packed}'.format(**{k:last.get(k,'?') for k in ['files_new','files_changed','files_unmodified','data_added','data_added_packed']}))
PY
}

rhel_gate_same_proof_retry() {
  local proof="$1" output="$2" attempt
  rm -f "$output"
  for attempt in 1 2 3; do
    log "RHEL gate HTTP attempt ${attempt}/3 using the same exact proof bundle"
    if curl --fail --silent --show-error \
      --connect-timeout 10 --max-time 20 \
      --cacert "$RHEL_CA" \
      -H 'Content-Type: application/json' \
      --data-binary @"$proof" \
      "$RHEL_URL/__vault_gate" > "$output"; then
      return 0
    fi
    (( attempt < 3 )) || return 1
    sleep 3
  done
}

post_rhel_done() {
  python3 - "$RHEL_DONE_TOKEN" > "$RUN/rhel-done.json" <<'PY'
import json,sys
print(json.dumps({'done_token':sys.argv[1]},separators=(',',':')))
PY
  curl --fail --silent --show-error \
    --connect-timeout 10 --max-time 20 \
    --cacert "$RHEL_CA" \
    -H 'Content-Type: application/json' \
    --data-binary @"$RUN/rhel-done.json" \
    "$RHEL_URL/__vault_done" >/dev/null
}

log '=== Phone Vault daily workflow started ==='
log 'Both devices must start the S3 phase within the coordinator pairing window.'

export RESTIC_PASSWORD="$(cat "$RESTIC_PW_FILE")"

# ---------------------------------------------------------------------------
# S3 PHASE
# ---------------------------------------------------------------------------
start_phase s3
load_s3_session_identity

log 'starting AWS IAM Identity Center device-code login; authorize in Android browser and complete MFA'
aws sso login --profile "$AWS_PROFILE" --use-device-code
aws sts get-caller-identity --profile "$AWS_PROFILE" >/dev/null

# Exactly one Lambda invocation helper; do not wrap this in a retry loop.
"$HOME/bin/vault-aws-gate-invoke" \
  "$AWS_PROFILE" "$AWS_FUNCTION" "$RUN/s3-proof.json" "$RUN/sts.json"
load_sts_env "$RUN/sts.json"

export HTTPS_PROXY="$S3_PROXY"
S3_JSON="$LOG_DIR/$(date +%Y%m%d-%H%M%S)-phone-s3-backup.jsonl"
if ! restic_backup_json_retry 'Phone→S3 backup' "$S3_JSON" \
  -r "$S3_REPOSITORY" \
  -o s3.bucket-lookup=path \
  -o s3.region=us-east-1 \
  -o s3.storage-class=DEEP_ARCHIVE \
  backup "$SOURCE_DIR"; then
  fail 'Phone→S3 backup failed after same-credential data-plane retries; do not request a second STS issuance today'
  exit 1
fi
summary_from_json "$S3_JSON" | tee -a "$LOG"
date -Iseconds > "$STATE_DIR/last-phone-s3-success"

# Do not run routine restic check against Deep Archive. See cold-storage warning.
# Successful restic completion is independently observed by AWS from snapshot creation
# followed by a later repository-lock removal. Drop local STS values immediately, close
# our own proxy phase, then keep the MFA-backed SSO session only for the read-only
# opposite-device completion barrier.
unset HTTPS_PROXY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
STS_EXPIRATION=''
finish_phase
if ! wait_for_peer_s3_completion_and_close "$PEER_DEVICE" "$S3_CALENDAR_DATE" "$S3_SESSION_EXPIRES_AT"; then
  fail 'S3 completion barrier failed; do not continue to RHEL in this ceremony'
  exit 1
fi
aws sso logout >/dev/null 2>&1 || true
rm -f "$RUN/s3-proof.json" "$RUN/s3.ready" "$RUN/sts.json" "$RUN/sts.json.invoke-meta.json"
rm -f "$RUN/completion-status-query.json" "$RUN/completion-status.json" "$RUN/completion-status.json.invoke-meta.json"


# ---------------------------------------------------------------------------
# RHEL PHASE
# ---------------------------------------------------------------------------
start_phase rhel
if ! rhel_gate_same_proof_retry "$RUN/rhel-proof.json" "$RUN/rhel-gate.json"; then
  fail 'RHEL gate failed. The daily RHEL opening slot may be consumed; do not create a new ceremony today.'
  exit 1
fi

RHEL_DONE_TOKEN="$(python3 - "$RUN/rhel-gate.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
v=d.get('done_token')
if not isinstance(v,str) or len(v)!=64: raise SystemExit('missing/invalid done_token')
print(v)
PY
)"
RHEL_HTPASSWD="$(cat "$RHEL_PW_FILE")"
RHEL_AUTH="$(python3 - "$RHEL_HTPASSWD" <<'PY'
import sys,urllib.parse
print(urllib.parse.quote(sys.argv[1],safe=''))
PY
)"
RHEL_REPO="rest:https://${RHEL_USER}:${RHEL_AUTH}@PHONE_RHEL_TS_IP:8002/"
RHEL_JSON="$LOG_DIR/$(date +%Y%m%d-%H%M%S)-phone-rhel-backup.jsonl"

if ! restic_backup_json_retry 'Phone→RHEL backup' "$RHEL_JSON" \
  -r "$RHEL_REPO" --cacert "$RHEL_CA" backup "$SOURCE_DIR"; then
  fail 'Phone→RHEL backup failed after same-window retries'
  exit 1
fi
summary_from_json "$RHEL_JSON" | tee -a "$LOG"

# Saturday-anchored / catch-up staged content-read verification.
# Normal sequence: first due Saturday 1/4, next Saturday 2/4, then 3/4, then 4/4,
# repeating. If a due Saturday is missed, exactly one pending stage runs on the first
# later successful RHEL transfer. The stage number and next-due marker advance only
# after a successful check, so a failed check or a missed Saturday never skips 2/4,
# 3/4, or 4/4.
CHECK_STAGE_FILE="$STATE_DIR/phone-rhel-check-stage"
CHECK_NEXT_DUE_FILE="$STATE_DIR/phone-rhel-check-next-saturday"

vault_today_istanbul() {
  python3 - <<'PYDATE'
from datetime import datetime
from zoneinfo import ZoneInfo
print(datetime.now(ZoneInfo("Europe/Istanbul")).date().isoformat())
PYDATE
}

vault_next_saturday_on_or_after() {
  python3 - "$1" <<'PYDATE'
from datetime import date, timedelta
import sys
start = date.fromisoformat(sys.argv[1])
delta = (5 - start.weekday()) % 7
print((start + timedelta(days=delta)).isoformat())
PYDATE
}

vault_next_saturday_after() {
  python3 - "$1" <<'PYDATE'
from datetime import date, timedelta
import sys
start = date.fromisoformat(sys.argv[1]) + timedelta(days=1)
delta = (5 - start.weekday()) % 7
print((start + timedelta(days=delta)).isoformat())
PYDATE
}

TODAY_ISTANBUL="$(vault_today_istanbul)"
if [ ! -s "$CHECK_NEXT_DUE_FILE" ]; then
  FIRST_DUE="$(vault_next_saturday_on_or_after "$TODAY_ISTANBUL")"
  printf '%s
' "$FIRST_DUE" > "$CHECK_NEXT_DUE_FILE"
  log "Phone→RHEL staged check schedule initialized; first 1/4 stage due $FIRST_DUE"
fi

NEXT_DUE="$(cat "$CHECK_NEXT_DUE_FILE")"
STAGE="$(cat "$CHECK_STAGE_FILE" 2>/dev/null || echo 1)"
case "$STAGE" in 1|2|3|4) ;; *) STAGE=1 ;; esac

if [[ "$TODAY_ISTANBUL" < "$NEXT_DUE" ]]; then
  log "Phone→RHEL staged content-read check not due until Saturday slot $NEXT_DUE; pending stage ${STAGE}/4"
else
  SUBSET="${STAGE}/4"
  if ! restic_command_retry "Phone→RHEL scheduled/catch-up keyed integrity check subset $SUBSET" \
    -r "$RHEL_REPO" --cacert "$RHEL_CA" check --read-data-subset="$SUBSET"; then
    fail 'RHEL staged integrity check failed; stage and Saturday due markers are not advanced'
    exit 1
  fi
  NEXT_STAGE=$(( (STAGE % 4) + 1 ))
  CANDIDATE_NEXT="$(python3 - "$NEXT_DUE" <<'PYDATE'
from datetime import date, timedelta
import sys
print((date.fromisoformat(sys.argv[1]) + timedelta(days=7)).isoformat())
PYDATE
)"
  if [[ "$CANDIDATE_NEXT" < "$TODAY_ISTANBUL" || "$CANDIDATE_NEXT" == "$TODAY_ISTANBUL" ]]; then
    CANDIDATE_NEXT="$(vault_next_saturday_after "$TODAY_ISTANBUL")"
  fi
  printf '%s
' "$NEXT_STAGE" > "$CHECK_STAGE_FILE"
  printf '%s
' "$CANDIDATE_NEXT" > "$CHECK_NEXT_DUE_FILE"
  log "Phone→RHEL staged check $SUBSET complete; next stage ${NEXT_STAGE}/4 due $CANDIDATE_NEXT"
fi

date -Iseconds > "$STATE_DIR/last-phone-rhel-success"
post_rhel_done
RHEL_DONE_TOKEN=''
finish_phase

log '=== Phone Vault daily workflow completed successfully ==='
termux-notification --title 'Vault Phone backup complete' --content 'S3 and RHEL phases completed.' 2>/dev/null || termux-toast 'Vault Phone backup complete' 2>/dev/null || true
termux-wake-unlock 2>/dev/null || true
```

```bash
chmod 700 "$HOME/.shortcuts/vault-daily-phone"
bash -n "$HOME/.shortcuts/vault-daily-phone"
```

Replace only `vault-phone-yourname` with the exact Phone bucket name.

Add the widget:

```text
Android home screen
  → long press
  → Widgets
  → Termux:Widget
  → choose vault-daily-phone
```

Before tapping the widget:

```text
Tailscale connected to the Phone Tailscale tailnet
Allow incoming connections = OFF
separate authenticator available
```

The script uses AWS's device-code SSO flow so the authorization URL/code may be handled
in the Android browser. It still requires the IAM Identity Center MFA policy configured
in Section 22.

---

## 8. One-Time S3 Repository Initialization Through the Daily Gate

An empty bucket is not a restic repository. Initialize each repository through the same
cross-signed daily issuance path used by production. This intentionally consumes that
device's S3 slot for the current Istanbul calendar day.

### 8.1 PC S3 repository

Start the Phone S3 helper/workflow at the same time so both VPSs can sign. On PC:

```bash
RUN="$HOME/.local/run/vault"
mkdir -p "$RUN"; chmod 700 "$RUN"

python3 "$HOME/bin/vault-phase-proof.py" \
  --host 100.64.0.1 --phase s3 \
  --token-file "$HOME/.config/vault-secrets/oracle_phase_token" \
  --proof-out "$RUN/s3-proof.json" --ready-file "$RUN/s3.ready" &
PHASE_PID=$!
while [[ ! -s "$RUN/s3.ready" ]]; do kill -0 "$PHASE_PID" || exit 1; sleep 1; done

aws sso login --profile vault-pc-gate
"$HOME/bin/vault-aws-gate-invoke" \
  vault-pc-gate Vault-PC-S3-Gate "$RUN/s3-proof.json" "$RUN/sts.json"

eval "$(python3 - "$RUN/sts.json" <<'PY'
import json,shlex,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
for env,key in [('AWS_ACCESS_KEY_ID','AccessKeyId'),('AWS_SECRET_ACCESS_KEY','SecretAccessKey'),('AWS_SESSION_TOKEN','SessionToken')]:
    print(f'export {env}={shlex.quote(d[key])}')
PY
)"
export RESTIC_PASSWORD="$(cat "$HOME/.config/vault-secrets/own_restic_pw")"
export HTTPS_PROXY='http://VPS_TS_IP:8888'

restic -r s3:s3.us-east-1.amazonaws.com/vault-pc-yourname \
  -o s3.bucket-lookup=path -o s3.region=us-east-1 \
  init --repository-version 2

kill -TERM "$PHASE_PID"; wait "$PHASE_PID" || true
unset HTTPS_PROXY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN RESTIC_PASSWORD
aws sso logout
```

### 8.2 Phone S3 repository

Use the same sequence with:

```text
profile:  vault-phone-gate
function: Vault-Phone-S3-Gate
bucket:   vault-phone-yourname
SSO:      aws sso login --profile vault-phone-gate --use-device-code
```

Do not initialize both buckets with one role or one credential set.

---

## 9. One-Time RHEL Repository Initialization

Follow Part 2 Section 17. Both devices must join the `rhel` phase, obtain dual-signed
proofs, open only their own RHEL backend, and run `restic init --repository-version 2`.

Do not bypass the RHEL gate by manually starting both backend services for convenience.
The first real repository mutation is part of the security acceptance test.

---

## 10. Daily Operator Procedure

A normal day is intentionally simple:

```text
1. Ensure the RHEL server is powered on and booted if using on-demand power.
2. Prepare the configured MFA factor for each device identity (prefer phishing-resistant FIDO/passkey; if using the documented cross-device TOTP layout, keep each seed only on the opposite primary).
3. Confirm PC Tailscale is logged out/expired from the previous ceremony as expected.
4. Confirm Phone is in the Phone tailnet and **Allow incoming connections** is OFF.
5. Start PC `vault-daily-pc`.
6. Within 10 minutes tap the Phone `vault-daily-phone` widget.
7. Complete any Tailscale identity-provider reauthentication/MFA challenges required after exact device expiry.
8. Complete PC IAM Identity Center MFA and Phone IAM Identity Center MFA.
9. Let S3 data-plane backups finish; transient restic retries reuse the already-issued STS credential only while that backup is incomplete and its completion state is not REVOKED.
10. AWS observes each successful snapshot commit followed by a later repository-lock removal, records an immutable cutoff, and revokes the matching older role session.
11. Each clean primary polls the read-only status Lambda for the opposite device and the exact shared session deadline; after REVOKED it requests a signed close-only peer S3 admission shutdown.
12. Only after both workflows pass this S3 completion barrier do they transition to RHEL and receive fresh dual-signed RHEL proofs inside the same signed one-hour Vault session.
13. RHEL backups/checks complete.
14. Cooperative RHEL DONE stops each backend early; the RHEL systemd hard-stop remains the security boundary.
15. Each VPS expires only its own exact primary Tailscale device.
16. RHEL may cool down and power off through the local operational helper.
```

A few seconds or minutes of human timing skew is expected. The first local phase may
wait up to the coordinator pairing limit for the opposite device. Do not share a phase
token or create an "absent device" bypass.

---

## 11. S3 Cold-Storage Integrity Policy

The S3 repository uses Glacier Deep Archive for cold pack data. Current restic
documentation describes S3 Glacier/Deep Archive restore support as experimental/early
alpha and lists a limited set of known-working commands. Therefore the daily script does
**not** run `restic check --read-data-subset` against the cold S3 repository.

Daily S3 assurance is:

```text
restic client successfully creates a snapshot
AWS S3 versioning remains enabled
bucket/role isolation and source-IP conditions remain tested
Lambda daily issuance and cost controls remain tested
```

Cryptographic read verification is performed routinely against the hot RHEL repository
from the source device that owns the repository password.

S3 needs a separate disaster-recovery drill. At a documented interval and after material
restic upgrades:

```text
1. Use the separate MFA-protected recovery permission path with RestoreObject.
2. Follow the currently tested restic `s3-restore` recovery procedure.
3. Restore a canary snapshot to an isolated temporary directory.
4. Compare expected canary hashes/content.
5. Record restic version, feature flags, AWS restore tier, elapsed time, and cost.
6. Remove temporary recovered plaintext securely after validation.
```

Do not represent an untested cold archive as a proven recovery source.

---

## 12. Logs and Success Records

PC logs:

```text
~/.local/log/vault-sync/*-pc-daily.log
~/.local/log/vault-sync/*-pc-s3-backup.jsonl
~/.local/log/vault-sync/*-pc-rhel-backup.jsonl
~/.local/state/vault/last-pc-s3-success
~/.local/state/vault/last-pc-rhel-success
```

Phone uses the corresponding `phone` names.

Preserve at least `data_added` and `data_added_packed` from JSON summaries for capacity
planning. The script's summary parser prints both. Do not upload these logs to the
opposite primary device as a new shared data path unless that is separately designed.

A successful daily workflow means **both** state timestamps were updated. A notification
is convenience, not proof; inspect exit status and logs if either timestamp is stale.

---

## 13. Failure Semantics — What to Do, Exactly

### The opposite device never joins the phase

The proof helper exits/fails after the pairing window. No AWS/RHEL daily slot is
consumed because no dual-signed proof reached the gate. Fix the opposite device and
start a fresh paired ceremony.

### Lambda transport/API error

The helper prints:

```text
The daily slot may or may not have been consumed. DO NOT invoke again today.
```

Stop. Inspect Lambda/DynamoDB logs from an administrative session. Do not run the daily
script again to "see if it works."

### STS result returned successfully, S3 network drops

The PC/Phone daily script retries the same restic command up to three times using the
same STS variables and the same S3 phase **only while the backup has not successfully
completed and AWS has not marked the exact session REVOKED**. No new issuance Lambda
call occurs.

If those attempts fail, the day's S3 copy is missed. The script exits and cleanup closes
the local phase. Investigate connectivity; wait until the next daily slot. If the backup
already reached successful snapshot-plus-lock-release completion, the completion revoker
may invalidate the old STS before a later retry; that is intentional and the script must
not request replacement credentials.

### Whole script/process crashes after STS issuance

Temporary credentials may have existed only in that process environment and the daily
slot is already consumed. Do not request a replacement credential. This is the accepted
availability cost of fail-closed issuance.

### RHEL gate HTTP response is lost

The script retries the **same proof file**, same ceremony ID, at most three times. If the
first request consumed the slot and started the matching backend, the gate returns the
same stored `done_token` while that backend is active.

### RHEL restic network drops

The script retries the same restic data-plane command while the same backend is open.
The hard signed session deadline still wins. No second RHEL opening is created.

### Client suppresses DONE

For **S3**, local `DONE` suppression is not a containment veto after a successful backup.
AWS completion evidence is snapshot creation followed by a later repository-lock
removal. The matching role session is revoked, and the clean opposite primary can use
its close-only signed peer path to close the target VPS's S3 proxy admission for the
exact shared deadline. If the backup never successfully creates a snapshot/lock-release
completion sequence, the signed one-hour hard deadline remains the final ceiling.

For **RHEL**, `DONE rhel` remains an authenticated early-close signal. The backend
remains only until the RHEL systemd hard-stop timer/deadline, and each VPS uses its
persisted hard session deadline to queue exact own-node expiry. Suppressing RHEL DONE
cannot extend beyond the hard session ceiling.

### Budget emergency deny is attached

Treat it as an incident. Do not automatically detach the policy at month boundary. Review
Billing/Cost Explorer, Lambda/DynamoDB/CloudTrail logs, S3 request activity, and both VPS
journals. Detach only after identifying and containing the cause.

---

## 14. Primary-Device Loss and Recovery

### PC lost

You need:

```text
PC restic password from the password manager
RHEL PC repository or PC S3 bucket
AWS recovery/admin MFA path if using Deep Archive
new trusted PC installation
```

Do not copy the Phone `own_restic_pw` to the replacement PC. Rebuild the PC compartment
identity/token and expire/remove the old primary node from the PC Tailscale tailnet
plane before re-enrollment.

### Phone lost

Use the symmetric Phone repository/password. The replacement Phone receives a new phase
token and is enrolled only in the Phone control plane. Remove/expire the old Phone node.

### One VPS lost

Restore that compartment VPS from **configuration notes and authoritative secrets**, not
by cloning the opposite VPS disk. Generate a new signing key unless a protected backup
of the exact compartment key is intentionally part of the recovery plan. If the signing
key changes, update both AWS Lambda public-key configuration and the RHEL public-key
file, then rerun all dual-signature negative tests before production.

The other VPS must not be reconfigured to sign both sides during recovery.

---

## 15. Primary Day-Zero Acceptance Matrix

Before real data:

```text
[ ] PC secrets directory 700; each routine secret 600.
[ ] Phone secrets directory 700; each routine secret 600.
[ ] PC and Phone phase-token hashes differ.
[ ] PC Shields Up=true and Tailscale SSH disabled.
[ ] Android incoming connections disabled.
[ ] PC cannot reach Phone tailnet/RHEL listener.
[ ] Phone cannot reach PC tailnet/RHEL listener.
[ ] PC SSO role invokes only PC issuance Lambda plus shared read-only S3 completion-status Lambda.
[ ] Phone SSO role invokes only Phone issuance Lambda plus shared read-only S3 completion-status Lambda.
[ ] Own MFA succeeds but opposite primary absent → no dual proof, no slot, no STS issuance.
[ ] One-signature proof is rejected by both Lambdas and RHEL.
[ ] PC role cannot access Phone bucket.
[ ] Phone role cannot access PC bucket.
[ ] Copied STS credential outside own VPS source IP is denied by S3.
[ ] Second valid Lambda invocation same device/day is DailySlotConsumed.
[ ] Same-credential S3 transient retry before completion revocation does not call issuance Lambda again.
[ ] Each completion revoker receives only its own bucket snapshot/lock events and can mutate only its own backup role revocation policy.
[ ] Snapshot + later lock removal moves exact slot to REVOKED; snapshot alone does not.
[ ] Old STS is denied after completion revocation propagates even before its original Expiration.
[ ] Exact opposite-session REVOKED status triggers signed CLOSE_PEER and closes target proxy admission without target DONE.
[ ] Wrong-deadline/expired CLOSE payload is rejected; valid repeated close is idempotent.
[ ] PC RHEL gate opens only PC backend.
[ ] Phone RHEL gate opens only Phone backend.
[ ] Same RHEL ceremony HTTP retry returns same done_token while active.
[ ] New RHEL ceremony same device/day is rejected after slot consumption.
[ ] RHEL keyed check is initiated by the source device, not RHEL.
[ ] Suppressed local S3 DONE cannot preserve admission after successful completion evidence and signed peer close; incomplete sessions still cannot survive the signed hard deadline.
[ ] Suppressed RHEL DONE cannot survive the signed hard deadline.
[ ] Cooperative DONE expires each primary node through its own VPS helper.
[ ] Suppressed DONE still queues own-node expiry at hard deadline.
[ ] USD 2 example budget threshold is documented as operator-configurable.
[ ] Failed Identity Center credential verification sends email.
[ ] Emergency AlwaysDeny S3 test blocks both backup roles.
[ ] S3 Deep Archive recovery canary procedure has been scheduled and documented.
```

Only after this matrix passes should the folders contain irreplaceable production data.

---

# PART 2A: PRODUCTION SERVICE CONFINEMENT — SYSTEMD AND PODMAN HARDENING
================================================================================

> **Mandatory production-entry hardening.**
>
> Apply this part after the canonical services are installed and individually functional,
> but before the final production acceptance matrix and before storing irreplaceable data.
> This stage is deliberately service-specific. Do not paste one universal
> `SystemCallFilter=` or a generic "maximum hardening" block over Tailscale, Podman,
> Caddy, WireGuard, and the Vault Go services.
>
> The source boundary remains exact:
>
> ```text
> Fedora restic source:  ~/Vault_PC_Ciphertext only
> Phone restic source:   ~/Vault_Phone_Ciphertext only
> ```
>
> Files are placed into those source folders by the operator. The Vault workflow does not
> crawl Documents, Pictures, Downloads, the whole home directory, or arbitrary Android
> shared storage to decide what should be backed up.

## H1. Hardening policy and non-claims

The security objective is blast-radius reduction after compromise of a Vault service or
one of its child processes:

```text
compromised custom VPS service
  -> no new Linux capabilities
  -> no home access
  -> no kernel/module/control-group mutation
  -> only declared state paths writable

compromised RHEL rest-server container
  -> rootless Podman boundary
  -> read-only container root filesystem
  -> all container capabilities dropped
  -> no-new-privileges
  -> SELinux separation remains enabled
  -> only its own repository bind mount is writable

compromised Fedora Vault workflow
  -> mount namespace hides the ordinary home tree
  -> only the one transfer source is exposed read-only
  -> only explicit Vault/AWS runtime paths are re-exposed
```

This does **not** claim that systemd sandboxing defeats malware already running as the
same Fedora desktop user outside the Vault unit. Such malware may already read files
that the desktop user can read. The sandbox constrains the Vault service process tree;
it is not an endpoint EDR or a new authorization factor.

Do not add `--privileged`, `--security-opt label=disable`, `seccomp=unconfined`, or a
broad host bind mount to any Vault Podman command. Any such change is an architecture
review event, not routine troubleshooting.

## H2. Fedora — run the PC workflow as a confined user service

The phone/Termux workflow is not managed by systemd and is unchanged by this section.
On Fedora, create the exact source and required workflow paths first:

```bash
mkdir -p \
  "$HOME/Vault_PC_Ciphertext" \
  "$HOME/.local/run/vault" \
  "$HOME/.local/log/vault-sync" \
  "$HOME/.local/state/vault" \
  "$HOME/.cache/restic" \
  "$HOME/.aws" \
  "$HOME/.config/vault" \
  "$HOME/.config/vault-secrets"

chmod 700 \
  "$HOME/.local/run/vault" \
  "$HOME/.local/state/vault" \
  "$HOME/.config/vault-secrets"
```

Create the user unit directory:

```bash
mkdir -p "$HOME/.config/systemd/user"
```

Create `$HOME/.config/systemd/user/vault-daily-pc.service`:

```ini
[Unit]
Description=Vault PC daily backup workflow — confined single-source execution
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%h/bin/vault-daily-pc

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=tmpfs
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

# Re-expose only the paths the complete workflow actually needs.
BindReadOnlyPaths=%h/Vault_PC_Ciphertext
BindReadOnlyPaths=%h/bin
BindReadOnlyPaths=%h/.config/vault
BindReadOnlyPaths=%h/.config/vault-secrets
BindPaths=%h/.local/run/vault
BindPaths=%h/.local/log/vault-sync
BindPaths=%h/.local/state/vault
BindPaths=%h/.cache/restic
BindPaths=%h/.aws

[Install]
WantedBy=default.target
```

Why `.aws` is re-exposed read-write: the canonical PC workflow performs IAM Identity
Center login and later `aws sso logout`; the AWS CLI needs its local SSO/config/cache
state. This does not change the restic source argument. In the script,
`SOURCE_DIR="$HOME/Vault_PC_Ciphertext"` remains the only source passed to
`restic backup`.

Do **not** add `%h`, `%h/Documents`, `%h/Pictures`, `%h/Downloads`, or `%h/.ssh` as a
broad `BindPaths=`/`BindReadOnlyPaths=` entry.

Validate the unit:

```bash
systemd-analyze --user verify "$HOME/.config/systemd/user/vault-daily-pc.service"
systemctl --user daemon-reload
systemctl --user cat vault-daily-pc.service
```

Run the sandbox proof before a real backup:

```bash
systemd-run --user --wait --pipe --collect \
  --property=ProtectHome=tmpfs \
  --property=BindReadOnlyPaths="$HOME/Vault_PC_Ciphertext" \
  /usr/bin/bash -lc '
    test -r "$HOME/Vault_PC_Ciphertext"
    test ! -e "$HOME/.ssh"
    test ! -e "$HOME/Documents"
    test ! -e "$HOME/Pictures"
  '
```

Expected: exit status `0`.

Then start the real workflow only through the unit:

```bash
systemctl --user start vault-daily-pc.service
systemctl --user status vault-daily-pc.service --no-pager
journalctl --user -u vault-daily-pc.service -b --no-pager
```

Do not also run `$HOME/bin/vault-daily-pc` directly as the normal production path. A
manual direct run bypasses the systemd filesystem sandbox and must be treated as a
break-glass diagnostic action.

### H2.1 Fedora source-folder write test

The workflow must be able to read but not mutate the source through its sandbox mount.
Use a disposable canary:

```bash
printf 'vault-source-canary\n' > "$HOME/Vault_PC_Ciphertext/.vault-hardening-canary"

systemd-run --user --wait --pipe --collect \
  --property=ProtectHome=tmpfs \
  --property=BindReadOnlyPaths="$HOME/Vault_PC_Ciphertext" \
  /usr/bin/bash -lc '
    grep -q vault-source-canary "$HOME/Vault_PC_Ciphertext/.vault-hardening-canary"
    ! printf changed > "$HOME/Vault_PC_Ciphertext/.vault-hardening-canary"
  '

grep -q vault-source-canary "$HOME/Vault_PC_Ciphertext/.vault-hardening-canary"
rm -f "$HOME/Vault_PC_Ciphertext/.vault-hardening-canary"
```

Expected: the transient unit reads the canary, its write attempt fails, and the original
canary remains unchanged.

## H3. RHEL 9 Vault VPSs — dedicated users, DAC, and systemd confinement

The canonical `vault-pc` and `vault-phone` hosts are RHEL 9 BYOL/BYOI systems with
SELinux **Enforcing**.

The canonical baseline does **not** require the operator to write, generate, review, or
install a custom SELinux policy module for the Vault coordinator, S3 proxy, expiry
helper, or Headscale. These are custom native services, and this guide deliberately does
not make SELinux policy engineering a production prerequisite.

For the custom native Vault daemons, the claimed process-isolation boundary is:

```text
dedicated Unix service identity
        +
DAC owner/group/mode separation
        +
systemd mount namespace / filesystem sandbox
        +
empty capability set where compatible
        +
NoNewPrivileges
        +
device, kernel, control-group and address-family restrictions
```

SELinux remains Enforcing for the host and for distribution/container policy. In
particular, the rootless Podman rest-server containers keep their normal SELinux
container confinement and `:Z` bind-mount labeling.

Do not override the vendor `tailscaled.service` or `wg-quick@wg-cross.service` with a
generic empty-capability profile. TUN, routing, network namespace, and WireGuard
requirements are different from the custom Vault Go daemons.

### H3.1 Verify the custom-daemon identities and DAC boundaries

The earlier install sections make the custom services non-root:

```text
vault-device-coordinator.service -> vaultcoord
vault-s3-proxy.service            -> vaultproxy
```

Verify on both VPSs:

```bash
systemctl show vault-device-coordinator.service -p User -p Group
systemctl show vault-s3-proxy.service -p User -p Group

ps -eo user,group,pid,comm,args | \
  grep -E 'vault-device-coordinator|vault-s3-proxy' | grep -v grep
```

The exact-device expiry helper remains root-owned. Its broad `devices:core` credential
and fail-closed partial-state semantics are already modeled as one compartment's
privileged expiry boundary. `vaultcoord` and `vaultproxy` must not be added to a group
that reads `/etc/vault-ts-expiry`.

Verify the negative DAC boundaries without printing secrets:

```bash
sudo -u vaultproxy test ! -r /etc/vault-device/signing-key.pem
sudo -u vaultproxy test ! -r /etc/vault-device/coordinator.env

sudo -u vaultcoord test ! -r /etc/vault-ts-expiry/config.json
sudo -u vaultcoord test ! -r /home/vaultadmin/.ssh/authorized_keys

sudo stat -c '%U %G %a %n' \
  /etc/vault-device/signing-key.pem \
  /etc/vault-device/coordinator.env \
  /etc/vault-ts-expiry/config.json
```

A failed negative test is a production blocker. Fix ownership/group membership/mode
instead of compensating with a broader systemd or SELinux exception.

### H3.2 Complete systemd confinement

Apply these additions to `vault-device-coordinator.service`:

```ini
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077
```

Keep:

```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vault-device
ReadOnlyPaths=/etc/vault-device
```

Apply these additions to `vault-s3-proxy.service`:

```ini
PrivateDevices=yes
ProtectKernelLogs=yes
RestrictRealtime=yes
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
```

Preserve its existing strict filesystem, kernel, SUID/SGID, personality,
`MemoryDenyWriteExecute`, architecture, and address-family restrictions.

Apply these additions to `vault-tailscale-expire-primary.service`:

```ini
PrivateDevices=yes
RestrictRealtime=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
UMask=0077
```

Keep `/etc/vault-ts-expiry` read-only and `/var/lib/vault-device` as the helper's only
declared persistent writable path.

Reload and inspect:

```bash
sudo systemctl daemon-reload

sudo systemd-analyze security vault-device-coordinator.service
sudo systemd-analyze security vault-s3-proxy.service
sudo systemd-analyze security vault-tailscale-expire-primary.service

sudo systemctl restart vault-device-coordinator.service vault-s3-proxy.service
sudo systemctl status vault-device-coordinator.service vault-s3-proxy.service --no-pager
```

A lower `systemd-analyze security` score is not a security objective by itself. Do not
add a speculative `SystemCallFilter=` merely to improve the number. A filter that breaks
deadline persistence, proxy drain, cross-signing, or expiry is a security regression.

### H3.3 SELinux rule for native custom services: Enforcing host, no local Vault policy module

Verify the host remains Enforcing:

```bash
getenforce
sestatus
```

Expected:

```text
Enforcing
```

It is acceptable for a custom native Vault daemon to appear in the RHEL targeted
policy's ordinary unconfined service domain. The canonical guide does **not** claim that
SELinux provides an additional per-daemon MAC boundary for these native custom
services.

You may record the observed contexts for diagnostics:

```bash
ps -eZ | grep vault-device-coordinator || true
ps -eZ | grep vault-s3-proxy || true
```

Do not perform any of the following as part of the canonical install:

```text
sepolicy generate --init for Vault custom daemons
audit2allow -M for Vault custom daemons
semodule -i of a locally generated Vault policy
semanage permissive -a for a new Vault custom domain
host-wide SELinux permissive/disabled mode
```

If an experienced SELinux policy engineer later develops and independently reviews a
narrow custom policy, treat that as a separate optional hardening extension with its own
threat-model delta and complete acceptance matrix. It is not required for this baseline.

SELinux denials involving packaged services or Podman/container labeling must still be
investigated. Do not respond to an AVC by disabling SELinux, using
`--security-opt label=disable`, or relabeling broad host trees without understanding the
cause.

### H3.4 RHEL VPS negative tests

Run on both VPSs:

```bash
getenforce

systemctl show vault-device-coordinator.service \
  -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome
systemctl show vault-s3-proxy.service \
  -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome

sudo -u vaultproxy test ! -r /etc/vault-device/signing-key.pem
sudo -u vaultcoord test ! -r /etc/vault-ts-expiry/config.json
sudo -u vaultcoord test ! -r /home/vaultadmin/.ssh/authorized_keys
```

Then rerun the end-to-end ceremony/proxy/deadline/expiry tests.

Required result:

```text
host SELinux = Enforcing
coordinator identity = vaultcoord
S3 proxy identity = vaultproxy
negative DAC reads fail
systemd sandbox settings match the reviewed unit
authorization and hard-deadline behavior still work
```

The desired result is not "a custom SELinux domain exists." No such custom-domain claim
is part of the canonical threat model.

### H3.5 Platform/shape drift is a security review event

Record on each VPS:

```bash
cat /etc/redhat-release
uname -m
rpm --eval '%{_arch}'
systemd-detect-virt
getenforce
```

Changing from `E2.1.Micro/x86_64` to `A1.Flex/aarch64`, changing the imported RHEL major
version, or migrating from RHEL 9 to RHEL 10 requires:

```text
rebuild custom binaries for the target architecture
revalidate official Tailscale/Headscale/Caddy artifacts
revalidate DAC ownership/modes and systemd hardening
rerun Podman/SELinux container-label tests on the backup host
rerun the complete day-zero negative matrix
re-measure the real S3 egress IPv4
```

Do not restore an x86_64 custom image snapshot onto an Arm shape or treat a major RHEL
upgrade as an ordinary unattended package update.

## H4. RHEL — per-service filesystem and kernel isolation

### H4.1 Rootless rest-server Podman baseline is mandatory

The canonical two backend units already use rootless service identities:

```text
vault-rhel-pc-rest-server.service    User=resticpc
vault-rhel-phone-rest-server.service User=resticphone
```

and their Podman commands must retain:

```text
--read-only
--cap-drop=all
--security-opt=no-new-privileges
--memory=512m
--pids-limit=100
```

The PC container receives only:

```text
/var/lib/vault-rhel/repos/pc -> /data read-write
/etc/vault-rhel/pc.htpasswd -> /auth/htpasswd read-only
```

The Phone container receives only the symmetric Phone paths. Never mount
`/var/lib/vault-rhel/repos`, `/etc`, `/root`, the maintenance credential directory, or
the opposite repository into either container.

SELinux must remain enforcing:

```bash
getenforce
```

Expected:

```text
Enforcing
```

The `:Z` labels in the canonical bind mounts are retained. Do not work around an AVC by
adding `--security-opt label=disable`. Inspect and correct the exact label/path problem.

### H4.2 Complete the backend systemd confinement

Add the following lines to **both** rootless rest-server units:

```ini
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077
```

Do not add an empty `CapabilityBoundingSet=` or a speculative `SystemCallFilter=` around
the Podman-launching unit without retesting the exact rootless Podman/conmon/runtime
version. The outer systemd service must still be able to launch and supervise the
already-unprivileged container. The container itself drops all capabilities.

### H4.3 Caddy services

Add to both `vault-caddy-pc.service` and `vault-caddy-phone.service`:

```ini
PrivateDevices=yes
PrivateUsers=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=512M
TasksMax=50
UMask=0077
```

Retain each service's own config, certificate/key, state, and log path allowlists. Do not
give either Caddy unit access to:

```text
/var/lib/vault-rhel/repos
/etc/vault-rhel-maintenance
/var/lib/vault-rhel/gate
```

### H4.4 Capacity guard

Replace the `[Service]` section of
`vault-rhel-capacity-guard.service` with:

```ini
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vault-rhel-capacity-guard

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
UMask=0077

ReadOnlyPaths=/var/lib/vault-rhel/repos
ReadWritePaths=/var/lib/vault-rhel/capacity
```

The guard invokes `systemctl stop` for fixed backend unit names. Therefore test the
effective unit on the target RHEL/systemd release. If `ProtectControlGroups=yes` or the
service-manager access path prevents the fixed `systemctl stop` action, do not broadly
disable the entire hardening profile. Remove only the specific incompatible directive,
record the exception, and repeat the 85% stop test.

### H4.5 Gate and namespace services

`vault-rhel-gate.service` is deliberately root because it starts/stops exactly two fixed
backend units and creates the hard-stop timer. Add:

```ini
PrivateDevices=yes
ProtectKernelLogs=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077
```

Do not empty its capability bounding set until the exact `systemd-run`/service-manager
path has been proven on the installed RHEL release.

`vault-rhel-netns.service` and the two custom `vault-tailscaled-*.service` units are
network-privileged infrastructure. Do not apply the generic empty-capability profile.
Their hardening is validated by exact namespace/topology tests, local firewall policy,
separate state directories, and the absence of a host default tailscaled state merge.

## H5. Hardening acceptance matrix

Run after every initial deployment and after systemd, Podman, Caddy, Tailscale, or
container-runtime upgrades:

```bash
# Fedora
systemd-analyze --user verify "$HOME/.config/systemd/user/vault-daily-pc.service"
systemctl --user cat vault-daily-pc.service
systemctl --user start vault-daily-pc.service

# VPS — run on each compartment VPS
sudo systemctl cat vault-device-coordinator.service
sudo systemctl cat vault-s3-proxy.service
sudo systemctl cat vault-tailscale-expire-primary.service
sudo systemd-analyze security vault-device-coordinator.service
sudo systemd-analyze security vault-s3-proxy.service
sudo systemd-analyze security vault-tailscale-expire-primary.service

# RHEL
getenforce
sudo systemctl cat vault-rhel-pc-rest-server.service
sudo systemctl cat vault-rhel-phone-rest-server.service
sudo systemctl cat vault-caddy-pc.service
sudo systemctl cat vault-caddy-phone.service
sudo systemctl cat vault-rhel-gate.service
sudo systemctl cat vault-rhel-capacity-guard.service

sudo -u resticpc podman inspect vault-rhel-pc-rest-server 2>/dev/null || true
sudo -u resticphone podman inspect vault-rhel-phone-rest-server 2>/dev/null || true
```

Mandatory negative tests:

```text
[ ] Fedora confined source can be read but not modified.
[ ] Fedora confined unit cannot see ~/.ssh, Documents, Pictures, or Downloads.
[ ] Running the PC workflow directly is documented as sandbox bypass, not normal use.
[ ] VPS coordinator can write only its declared Vault state path.
[ ] S3 proxy still refuses non-S3 CONNECT destinations.
[ ] Exact-device expiry still works after the expiry-helper hardening.
[ ] RHEL PC container has no Phone repository bind mount.
[ ] RHEL Phone container has no PC repository bind mount.
[ ] Both Podman containers remain non-privileged, read-only-rootfs, cap-drop=all.
[ ] SELinux remains Enforcing and no Vault container uses label=disable.
[ ] Caddy units cannot read repository or maintenance-secret paths.
[ ] RHEL signed hard-stop timer still terminates the matching backend by the deadline.
[ ] Capacity guard can still stop the exact affected backend at the tested threshold.
[ ] Direct/DERP transport behavior is unchanged by service hardening.
```

**Stage A checks (after H4.3 only):**

```text
[ ] Both units start clean: systemctl daemon-reload && systemctl restart vault-caddy-pc vault-caddy-phone
[ ] systemctl status shows active (running), no immediate crash-loop
[ ] TLS handshake still succeeds from a real client against PC_RHEL_TS_IP:8001 and PHONE_RHEL_TS_IP:8002
[ ] Certificate/key still readable (no ReadOnlyPaths permission errors in journalctl)
[ ] Log file still being written (ReadWritePaths for the log path unaffected)
```

**Stage B checks:**

```text
[ ] systemd-analyze security vault-caddy-pc.service / vault-caddy-phone.service — score improves, no new permission errors
[ ] Full PC backup cycle succeeds end-to-end
[ ] Full Phone backup cycle succeeds end-to-end
[ ] Largest realistic snapshot transfer does not hit MemoryMax=512M (check journalctl for OOM/cgroup kill)
[ ] TasksMax=50 not hit under concurrent PC+Phone activity, if concurrency is possible
[ ] MemoryDenyWriteExecute=yes does not crash Caddy on TLS handshake / HTTP/2 negotiation
[ ] Caddy's outbound connection to its own unix socket upstream still works under RestrictAddressFamilies
```

**Stage C checks:**

```text
[ ] SystemCallFilter=@system-service, EPERM mode, zero denials over one full backup cycle on PC
[ ] Same, zero denials on Phone
[ ] Any observed denial is symmetric across PC and Phone before being approved (Section 26 rule) — asymmetric denial is fail-closed, do not approve
[ ] Gate path (/__vault_gate, /__vault_done) still reaches 169.254.10.1:8090 / 169.254.20.1:8090 unaffected
[ ] Non-allowlisted method/path still returns 404 "Vault protocol path denied" unaffected
```

**Stage D checks (if implemented):**

```text
[ ] basicauth at Caddy rejects invalid credentials with a Caddy-side 401
[ ] rest-server's own access log shows no corresponding entry for the rejected request (confirms it never reached rest-server)
[ ] Valid credentials still pass through both auth checks (Caddy + rest-server) end-to-end
```

Any failure in the hard-deadline, daily-slot, exact-device expiry, or repository-isolation
tests is fail-closed. Revert the last hardening change for that exact service, document
the incompatible directive, and retest. Do not weaken unrelated units.

## H6. Effective-configuration freeze

After all tests pass, include the hardened unit definitions in the RHEL/VPS configuration
baseline:

```bash
sudo systemctl cat \
  vault-device-coordinator.service \
  vault-s3-proxy.service \
  vault-tailscale-expire-primary.service 2>/dev/null \
  | sha256sum
```

On RHEL:

```bash
sudo sha256sum \
  /etc/systemd/system/vault-rhel-*.service \
  /etc/systemd/system/vault-caddy-*.service \
  /etc/systemd/system/vault-tailscaled-*.service \
  | sudo tee /var/lib/vault-rhel/systemd-hardening-baseline.sha256
```

On Fedora:

```bash
sha256sum "$HOME/.config/systemd/user/vault-daily-pc.service" \
  > "$HOME/.local/state/vault/systemd-hardening-baseline.sha256"
```

A later intentional change is permitted, but it must follow the same
change -> verify -> negative-test -> new-baseline sequence.

## Section 25 - Restricted Networks: Direct → Tailscale-hosted DERP Baseline

The canonical transport decision is deliberately simple:

```text
direct UDP/WireGuard if available
        ↓ if unavailable
Tailscale-hosted DERP fallback
```

A Wi-Fi network that blocks UDP is expected to force the `relay` path. This is a
transport degradation, not an authorization degradation. The same tailnet grants,
phase-token verification, cross-VPS signatures, AWS daily slots, RHEL daily slots, and
hard deadline remain in force.

Verify on each primary device:

```bash
tailscale netcheck
tailscale status
tailscale ping OWN_VPS_HOSTNAME
tailscale ping OWN_RHEL_HOSTNAME
```

Record representative transfer time on home, campus/dorm, and mobile networks. Do not
infer path from throughput alone; inspect `tailscale status`/`tailscale ping` output.

If direct UDP fails but Tailscale-hosted DERP completes normal backup deltas comfortably inside
the hard session window, keep this baseline. If Tailscale-hosted DERP is too slow and the real
network permits UDP to a controlled relay, apply `Vault_Extension_Peer_Relay_Performance.md`.

If Tailscale backend/DERP HTTPS is also blocked, abort the backup. There is no direct-S3
or public-RHEL bypass.

## Section 26 - What to do if the transfer process hits a seccomp restriction due to an update

> [!NOTE]
> **(Optional)** The custom Seccomp restriction and notification system described in this section are optional. It is recommended to implement this part after mastering writing seccomp policies. Podman already has its own seccomp policy against container escape scenarios.

Because this architecture enforces strict Seccomp container isolation with automated updates, a legitimate software update to the `rest-server` binary might occasionally introduce a new system call. When this happens, Seccomp will instantly kill the container and interrupt the backup.

This system is designed for **Friend-Assisted Remediation**. If you lose access, a non-technical person with physical access to the RHEL server can help you recover it using two simple terminal commands: `vault-check-block` and `vault-approve-syscall`.

### Phase 1: Verify the Anomaly
Before approving any blocked commands, you must manually verify that the block was caused by a legitimate update and not an attacker.
1. **The "Both Devices Must Fail" Rule:** Because both the PC and Phone containers run the exact same `rest-server` binary, a new system call requirement should trigger on **both** devices when they attempt their respective backups. If the PC backup fails due to Seccomp but the Phone backup succeeds without issue, this is a massive anomaly indicating the PC container executed a different (potentially malicious) code path. Do not approve the syscall!
2. **Google the Syscall:** Once your friend runs `vault-check-block` and texts you the name of the blocked syscall (e.g., `epoll_pwait`), search for it online to understand what it does.
3. **Check Software Updates:** Check the recent release notes for the `rest-server` software or the Go compiler. Verify if network or memory allocation changes were recently introduced that logically align with the blocked syscall.

### Phase 2: Intervention and Recovery Steps

**Step 1: Check the Blocked Syscall**
Ask the person with physical access to log into the RHEL server terminal and run:
```bash
vault-check-block
```
They should copy the output (e.g., *"The backup container was killed because it attempted to use system call: epoll_pwait (Syscall #232)"*) and send it to you.

**Step 2: Authorize the Syscall**
Once you have performed the three verification checks in Phase 1 and are confident it is safe, tell your friend to run the approval alias with the name of the syscall. For example:
```bash
vault-approve-syscall epoll_pwait
```
This script will automatically append the syscall to the Seccomp whitelist JSON file and instantly restart both container services.

**Step 3: Unlocking the Backup Repository**
Because the transfer was abruptly killed, Restic leaves the repository "locked" (though data is never corrupted). From your laptop or phone, run:
```bash
restic unlock
```
You can now resume your backups!
