# Cross-Authorized Backup

An experimental multi-endpoint backup security architecture built around **cross-authorization, bounded backup sessions, and independently enforced backup controls**.

The project explores a specific security question:

> How can a backup system limit the ability of a single compromised source endpoint to continuously abuse backup credentials, interact with backup infrastructure, or attempt recovery-path corruption?

The architecture adapts **dual-control, separation-of-duties, and multi-party authorization principles** to a personal-scale, endpoint-oriented backup environment.

Independent source-device security compartments participate in fresh backup authorization so that one endpoint, even with its own MFA path, cannot unilaterally mint a new backup session. Successful S3 backup completion is then observed independently of a cooperative endpoint and used to contain the remaining authorization window rather than simply waiting for credential expiry.

The design is not an implementation of a specific enterprise multi-party approval product. Instead, it applies the underlying dual-control principle to a personal 3-2-1 backup architecture.

## Design Themes

The current architecture explores:

* client-side encrypted restic repositories
* independent PC and phone security compartments
* live cross-authorization for fresh backup sessions
* dual infrastructure signatures
* fixed, non-renewable backup session deadlines
* short-lived AWS credentials
* fail-closed daily credential issuance limits
* successful-completion-triggered S3 session containment
* signed cross-compartment close signaling
* separate S3 buckets and IAM roles
* append-only backup ingestion
* ciphertext-only RHEL storage in the canonical baseline
* Tailscale with Tailnet Lock
* independent detection and credential-custody controls

The threat model is particularly concerned with compromised-endpoint abuse and backup or recovery-path corruption patterns associated with advanced ransomware-style operations.

The project does **not** claim to be ransomware-proof.

## Trust Model & System Assumptions

This system operates strictly on a **Trust-On-First-Use (TOFU)** model:
* **Initial Clean State:** It is assumed that all participating endpoints and infrastructure—the computer, phone, and RHEL backup server—are completely secure, uncompromised, and free of any malicious software at the time of initial system installation and cryptographic key generation.
* **Post-Provisioning Protection:** The threat model specifically addresses post-installation security degradation, preventing an endpoint that becomes compromised *after* initial deployment from unilaterally abusing backup credentials, corrupting recovery paths, or minting unauthorized backup sessions.

## Authorization Model

Fresh backup authorization is intentionally asymmetric with session closure.

```text
Fresh session:
  PC live participation
  AND Phone live participation
  AND PC-VPS signature
  AND Phone-VPS signature
  AND requesting endpoint SSO/MFA
  AND unused device/day issuance slot

Successful S3 completion:
  independently observed repository completion
        ↓
  matching role-session revocation begins
        ↓
  opposite clean compartment can trigger a signed close
  of the completed endpoint's S3 proxy admission

Hard deadline:
  remains the final fail-closed ceiling for incomplete,
  failed, or otherwise unconfirmed sessions
```

The opposite endpoint does **not** inspect the other device's files or verify its backup contents. Its security role is to prevent unilateral fresh authorization and to provide an independent close authority that a compromised source endpoint cannot veto by suppressing its own completion signal.

## Origin

The project began as a practical attempt to build disciplined 3-2-1 backups for a laptop and phone while reusing an off-site desktop computer as a RHEL backup node during university.

It initially focused on encrypted backup storage and redundancy.

During architecture review, the project evolved after examining a different problem:

> What happens if one of the devices performing backups is already compromised?

This question gradually shifted the design from a conventional personal backup deployment toward a threat-model-driven backup authorization architecture.

## Personal Design Philosophy & Archival Purpose

This repository represents a highly opinionated, personal architecture tailored to a specific set of security assumptions, hardware constraints, and operational preferences (such as physical console administration without remote SSH).

Rather than serving as a turn-key, one-size-fits-all product for general distribution, this repository functions primarily as:
1. **A Personal Infrastructure Archive & Blueprint:** A persistent, version-controlled reference to ensure deterministic disaster recovery and track architectural evolution over time.
2. **An Educational Case Study:** An exploration of applying zero-trust, dual-control, and micro-VM isolation principles to personal-scale 3-2-1 backup infrastructure.

Others are welcome to study, adapt, or draw inspiration from the design decisions documented here.

## Future Security Considerations (Post-Quantum)

The current cross-authorization plane relies on Ed25519 signatures. While Ed25519 provides strong security against conventional attacks, it is theoretically vulnerable to Cryptographically Relevant Quantum Computers (CRQCs) using Shor's algorithm. 

Because the `vault-pc` and `vault-phone` public keys are static, an adversary with access to a CRQC could derive the private keys over time and instantly forge the dual-socket authorization signatures (e.g. `S3_PC` or `RHEL_PHONE` payloads) to bypass the AWS Lambda or RHEL gates. Rate limiting or time-outs cannot protect against this, as the forged signatures would appear mathematically valid and timely.

To achieve quantum resistance for the authorization plane in the future, the architecture must migrate from Ed25519 to NIST-standardized Post-Quantum Cryptography (PQC) digital signatures:
- **ML-DSA (CRYSTALS-Dilithium)** or **SLH-DSA (SPHINCS+)** for VPS-to-VPS and VPS-to-Lambda signatures.
- **Hybrid Approach:** A transition period should use a hybrid signature (e.g., Ed25519 + ML-DSA) where AWS Lambda/RHEL require both to be valid, providing protection against both quantum threats and potential mathematical flaws in the new PQC algorithms.

*(Note: The actual backup data is encrypted by restic using AES-256, which is symmetric and remains highly resistant to quantum attacks via Grover's algorithm.)*

## Status

**Experimental / pre-deployment architecture**

Architecture baseline established: **2026-07-15**  
Latest security-design revision: **2026-07-28**

The current design has undergone extensive architecture and threat-model review.

However, it has not yet completed:

* real campus-network deployment validation
* representative daily-delta performance testing
* full production acceptance testing
* long-term operational validation
* S3 cold-storage recovery drills

This repository currently serves as a private architecture archive and future engineering record.

It is not a turnkey secure backup product and makes no production-readiness claim.

## Repository Structure

```text
docs/
├── canonical/
│   ├── Vault_Master_Guide.md
│   ├── Vault_Threat_Model.md
│   └── Vault_Detection_and_Credential_Custody.md
│
├── extensions/
│   ├── Vault_Extension_Mutual_Backup.md
│   ├── Vault_Extension_Capacity_Triggered_Prune_and_Maintenance.md
│   ├── Vault_Extension_Headscale_Control_Plane.md
│   └── Vault_Extension_Peer_Relay_Performance.md
│
├── operations/
│   ├── Vault_Device_Retirement_and_Migration_Runbook.md
│   └── Vault_Deployment_Time_Revalidation_Checklist.md
│
└── changes/
    └── Vault_2026-07-16_STS_Completion_Revocation_CHANGELOG.md
```

The canonical documents describe the reviewed baseline.

Extensions document optional trust-model or operational changes and are not enabled by default.

Operational documents cover deployment-time revalidation and device lifecycle procedures.

Change records preserve material security-design corrections separately from the canonical source of truth. They document why an architectural assumption changed; they do not replace the current canonical guides.

## Project History

Project work began before this Git repository was created.

The repository was initialized after the first major architecture-review phase to preserve the July 2026 architecture baseline and track future deployment testing, failed assumptions, and design changes honestly.

The 2026-07-16 completion-containment revision is intentionally preserved as a visible design change: the original architecture already prevented one endpoint plus its own MFA path from independently obtaining a fresh S3 session, but successful backup completion still relied too heavily on cooperative endpoint signaling for early closure. The revised design adds independently observed completion, role-session revocation, and signed cross-compartment close authority.

Future changes should be driven by measured deployment behavior, discovered failure modes, or materially changed security assumptions rather than feature accumulation.

### Caddy hardening (RHEL)

Both `vault-caddy-pc.service` and `vault-caddy-phone.service` run under systemd
sandboxing equivalent in intent to the rootless Podman rest-server containers:
read-only root filesystem (`ProtectSystem=strict`), all capabilities dropped
(`CapabilityBoundingSet=`/`AmbientCapabilities=` empty), a user-namespace remap
(`PrivateUsers=yes`), memory/task limits (`MemoryMax=512M`, `TasksMax=50`), a broad
syscall group filter (`SystemCallFilter=@system-service`), write^execute memory
denial (`MemoryDenyWriteExecute=yes`), and an address-family allowlist restricted to
exactly what the TLS listener and unix-socket upstream require
(`AF_INET AF_INET6 AF_UNIX`).

Caddy remains the sole network-reachable component in the RHEL backup path; rest-server
is unreachable except via the unix socket Caddy proxies to, after Caddy's
method/path allowlist (`@restic`) has already rejected anything outside the exact
restic REST surface.

**Known deferred item:** running Caddy inside Podman (matching the rest-server
container model) instead of raw systemd. Not required by the current threat model —
see `Caddy_Hardening_Implementation_Plan.md` §3 for the full rationale, trigger
conditions, and implementation outline if revisited.
