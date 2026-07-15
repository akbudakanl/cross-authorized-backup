# Project Status

## Architecture Freeze

**Date:** 2026-07-15

## Current Phase

Pre-deployment architecture review completed.

The project is currently shelved pending personal audit and real deployment testing.

## Current State

* Canonical architecture drafted
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

## Current Canonical Decisions

### Endpoint Model

* PC and phone are independent security compartments.
* Primary devices are source-only in the canonical baseline.
* No reciprocal PC-to-phone Vault data plane is enabled.
* A single endpoint must not independently authorize a Vault backup session.

### Authorization Model

* Cross-authorization is required between the independent endpoint compartments.
* Two independent VPS coordinators enforce the authorization ceremony.
* AWS and RHEL admission require both expected infrastructure signatures.
* Vault sessions use a fixed signed hard deadline.
* The canonical session ceiling is one hour.
* `DONE` is an early-close signal and not a security factor.

### AWS Model

* PC and phone use separate S3 buckets.
* PC and phone use separate IAM backup roles.
* AWS backup credentials are short-lived.
* One daily AWS issuance slot exists per device compartment.
* The slot is consumed before the single STS credential-creation attempt.
* Ambiguous or failed STS issuance does not restore the daily slot.
* Credential refresh loops are not part of the canonical design.

### RHEL Model

* The canonical RHEL baseline is ciphertext-only.
* RHEL does not retain restic repository passwords for unattended maintenance.
* PC and phone repositories are isolated.
* Append-only ingestion is used.
* Backup backends are disabled at boot.
* Signed session admission temporarily starts the required backend.
* Hard-stop enforcement is bound to the signed session deadline.
* No default prune or unattended restic maintenance is enabled.

### Network Model

* Tailscale is the canonical control and transport plane.
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
4. Complete canonical day-zero acceptance and negative tests.
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
* the current canonical architecture
* the current threat model

The next major architecture decisions should occur only after this audit or after real deployment measurements invalidate a current assumption.
