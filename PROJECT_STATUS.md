# Project Status

## Architecture Freeze

**Date:** 2026-07-15

## Current Phase

Pre-deployment architecture review completed.

The project is currently shelved pending personal audit and real deployment testing.

## Documentation Status

*   `docs/core/Vault_Zero_Trust_Master_Guide_CORE.md`: **FINALIZED (v1)** - The immutable reference for the core backup architecture.
*   `docs/core/Vault_Post_Install_Detection_and_Credential_Custody.md`: **FINALIZED (v1)** - The reference for the detection plane (AWS VaultAuditWatch) and credential hygiene. Includes Honeypot setup.
*   `docs/extensions/Vault_Extension_Host_Level_Containment.md`: **PROPOSED** - Advanced hardening for SELinux, kernel monitoring (Falco), and hardware VM isolation.
*   `docs/extensions/Vault_Extension_OOB_Notification_Routing.md`: **PROPOSED** - Cross-routed notification strategy (PC -> Phone, Phone -> PC) using E-mail and Telegram.
*   `docs/extensions/Vault_Extension_Offline_CA_and_Console_Lockdown.md`: **PROPOSED** - Offline SSH CA (QR Code) authentication and PBKDF2 Break-Glass Console Lockdown.

## Current State

* Core architecture drafted
* Threat model and residual-risk register drafted
* Detection and credential-custody plan drafted
* Deployment-time revalidation checklist drafted
* Optional architecture extensions documented
* Personal architecture audit pending
* Production deployment pending
* Real campus-network validation pending
* Representative daily-delta timing tests pending
* S3 Deep Archive cold-restore drill pending
* Long-term operational validation pending

## Current Core Decisions

### Endpoint Model

* PC and phone are independent security compartments.
* Primary devices are source-only in the core baseline.
* No reciprocal PC-to-phone Vault data plane is enabled.
* A single endpoint must not independently authorize a Vault backup session.

### Authorization Model

* Cross-authorization is required between the independent endpoint compartments.
* Two independent VPS coordinators enforce the authorization ceremony.
* AWS and RHEL admission require both expected infrastructure signatures.
* Vault sessions use a fixed signed hard deadline.
* The core session ceiling is one hour.
* `DONE` is an early-close signal and not a security factor.

### AWS Model

* PC and phone use separate S3 buckets.
* PC and phone use separate IAM backup roles.
* AWS backup credentials are short-lived.
* One daily AWS issuance slot exists per device compartment.
* The slot is consumed before the single STS credential-creation attempt.
* Ambiguous or failed STS issuance does not restore the daily slot.
* Credential refresh loops are not part of the core design.

### RHEL Model

* The core RHEL baseline is ciphertext-only.
* RHEL does not retain restic repository passwords for unattended maintenance.
* PC and phone repositories are isolated.
* Append-only ingestion is used.
* Backup backends are disabled at boot.
* Signed session admission temporarily starts the required backend.
* Hard-stop enforcement is bound to the signed session deadline.
* No default prune or unattended restic maintenance is enabled.

### Network Model

* Tailscale is the core control and transport plane.
* Tailnet Lock is enabled.
* Primary Tailnet inbound connections are disabled.
* Peer Relay is not configured.
* UDP/40000 is not opened.
* No self-hosted DERP listener is used.
* No self-hosted STUN listener is used.
* Tailscale-hosted DERP is the expected fallback when direct connectivity fails.
* Real deployment transport behavior must be measured on the campus network.

### Detection Model

* Detection is independent from the VPS authorization plane.
* AWS-side monitoring observes daily-slot consumption and STS caller behavior.
* Tailscale configuration audit events are monitored.
* Unexpected device mutations are default-deny detection events.
* Detection blindness is itself an alert condition.

## Explicitly Disabled by Default

* Mutual PC-to-phone backup
* Peer Relay
* UDP/40000 relay listener
* Self-hosted DERP
* Self-hosted STUN
* RHEL prune
* RHEL unattended restic maintenance
* RHEL repository-password custody
* Headscale control plane

These features or architecture changes are documented only as optional extensions where applicable.

## Production Readiness

**NOT PRODUCTION VALIDATED**

The current documents represent a reviewed architecture snapshot.

Before deployment:

1. Complete the personal architecture audit.
2. Run the deployment-time revalidation checklist.
3. Validate current external platform assumptions.
4. Complete core day-zero acceptance and negative tests.
5. Measure real campus-network transport behavior.
6. Measure representative daily backup durations.
7. Confirm the one-hour signed session ceiling remains operationally sufficient.
8. Complete recovery and cold-storage drills before relying on those paths.

## Current Project Policy

The architecture is frozen, but external product versions and assumptions are not.

Future changes should be classified as:

```text
NO CHANGE
LOCAL PATCH
SECURITY REVIEW REQUIRED
ARCHITECTURE REDESIGN REQUIRED
```

Do not add a feature merely because it is available.

A change should be driven by:

* a broken documented assumption
* measured deployment behavior
* a materially narrower trust boundary
* a security control that no longer works as documented

## Next Planned Review

A personal audit will compare:

* the original project design
* architecture change history
* the current core architecture
* the current threat model

The next major architecture decisions should occur only after this audit or after real deployment measurements invalidate a current assumption.

## Potential Future Enhancement: Read-Only Repository Bind Mount

**Classification:** ARCHITECTURE REDESIGN REQUIRED

The current `rest-server` container bind-mounts the repository directory
(`/var/lib/vault-rhel/repos/{pc,phone}`) with read-write permissions. A more aggressive
isolation model would make this mount read-only and route writes through a dedicated
sidecar or FUSE layer that enforces append-only semantics at the filesystem level (not
just the application level).

This would prevent a compromised `rest-server` from writing arbitrary files to the
repository even if it bypasses the application-level `--append-only` flag.

**Not implemented because:**

* `rest-server` requires direct write access to the repository directory.
* Would require a custom write proxy or FUSE filesystem.
* Significant architectural change with new failure modes.
* Current mitigations (Podman rootless + SELinux + seccomp + `--network=none`) already
  make this attack path extremely unlikely.

**Revisit if:**

* A `rest-server` or Go `net/http` CVE demonstrates real-world RCE risk.
* A mature, audited append-only FUSE layer becomes available.
* The threat model is upgraded to assume kernel-level adversary capabilities.

## Rejected Architectural Concepts

### 1. Human-in-the-loop Single-Click Remediation

**Classification:** EXPLICITLY REJECTED

Currently, the AWS-side `VaultAuditWatch` lambda sends a passive SNS alert (e.g., email or SMS) if a `devices:core` OAuth token is misused. It does not automatically remediate the issue, adhering to the "Detection is not Prevention" philosophy to avoid giving a cloud Lambda autonomous write access to the Tailnet (which would create a new Single Point of Failure).

A proposed middle-ground was a "Human-in-the-loop" webhook mechanism (e.g., via AWS API Gateway). The alert would include a cryptographically signed, one-time link. Clicking the link would trigger a strictly scoped Lambda function to revoke the compromised OAuth client.

**Rejected because:**
* **Breaches Passive Visibility:** Giving a notification endpoint (e.g., Telegram or E-mail) the power to trigger destructive infrastructure changes means compromising the notification endpoint compromises the Vault.
* **SPOF Risk:** The architecture requires the notification sinks to have zero write access. The current fail-closed gates (Ed25519) limit the blast radius of a stolen OAuth token to Denial-of-Service, making a 5-minute manual remediation window (where the user logs into the Tailscale Admin console securely) the only acceptable path.

## Potential Future Enhancement: Network Cloaking with Single Packet Authorization (SPA)

**Classification:** ARCHITECTURE EXTENSION / OPTIONAL HARDENING

Currently, the core architecture uses Caddy as an application-layer (L7) gate. Even without a valid Ed25519 cross-signature, Caddy's TCP port (443) remains open to the Tailnet. If an attacker bypasses the Tailscale ACL (e.g., via tag manipulation), they can establish a TCP connection and attempt to exploit memory or parsing bugs in Caddy or the Go TLS stack.

An alternative is to use Single Packet Authorization (SPA) via `fwknop` to completely hide TCP ports from unauthenticated network scanners. The `nftables` policy on RHEL for port 443 (and 22) would be set to `DROP` by default. Before a backup, the client sends an HMAC-signed UDP packet to RHEL, which temporarily opens the TCP port specifically for that client's IP address.

**Not implemented because:**
* The current Caddy L7 boundary provides a strong, memory-safe (Go) barrier.
* Introducing `fwknopd` adds a root-privileged C daemon processing unauthenticated UDP packets. While HMAC strongly mitigates parsing risks, it adds complexity and a low-level, hard-to-audit component to a single-maintainer project.
* The risk of a Go `net/http` or TLS stack CVE is currently deemed low enough to not warrant the operational complexity of a network knock.


