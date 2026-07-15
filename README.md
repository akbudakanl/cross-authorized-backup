# Cross-Authorized Backup

An experimental multi-endpoint backup security architecture built around **cross-authorization, bounded backup sessions, and independently enforced backup controls**.

The project explores a specific security question:

> How can a backup system limit the ability of a single compromised source endpoint to continuously abuse backup credentials, interact with backup infrastructure, or attempt recovery-path corruption?

The architecture adapts enterprise **dual-control, separation-of-duties, and multi-party authorization principles** to a personal-scale, endpoint-oriented backup environment.

Enterprise backup and recovery systems increasingly use independent authorization boundaries to reduce the risk that a single compromised administrative identity can unilaterally affect protected recovery paths.

This project explores a related model at the endpoint level: independent source-device security compartments cross-authorize bounded backup sessions so that compromise of one endpoint alone does not grant a continuously available backup capability.

The design is not an implementation of a specific enterprise multi-party approval product. Instead, it applies the underlying dual-control principle to a personal 3-2-1 backup architecture.

## Design Themes

The current architecture explores:

* client-side encrypted restic repositories
* independent PC and phone security compartments
* cross-authorization between source endpoints
* dual infrastructure signatures
* fixed, non-renewable backup session deadlines
* short-lived AWS credentials
* fail-closed daily credential issuance limits
* separate S3 buckets and IAM roles
* append-only backup ingestion
* ciphertext-only RHEL storage in the canonical baseline
* Tailscale with Tailnet Lock
* independent detection and credential-custody controls

The threat model is particularly concerned with compromised-endpoint abuse and backup or recovery-path corruption patterns associated with advanced ransomware-style operations.

The project does **not** claim to be ransomware-proof.

## Origin

The project began as a practical attempt to build disciplined 3-2-1 backups for a laptop and phone while reusing an off-site desktop computer as a RHEL backup node during university.

It initially focused on encrypted backup storage and redundancy.

During architecture review, the project evolved after examining a different problem:

> What happens if one of the devices performing backups is already compromised?

This question gradually shifted the design from a conventional personal backup deployment toward a threat-model-driven backup authorization architecture.

## Status

**Experimental / pre-deployment architecture**

Architecture freeze date: **2026-07-15**

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
│   ├── Vault_Detection_and_Credential_Custody.md
│   └── Vault_Deployment_Time_Revalidation_Checklist.md
│
└── extensions/
    ├── Vault_Extension_Mutual_Backup.md
    ├── Vault_Extension_Capacity_Triggered_Prune_and_Maintenance.md
    ├── Vault_Extension_Headscale_Control_Plane.md
    └── Vault_Extension_Peer_Relay_Performance.md
```

The canonical documents describe the reviewed baseline.

Extensions document optional trust-model or operational changes and are not enabled by default.

## Project History

Project work began before this Git repository was created.

The repository was initialized after the first major architecture-review phase to preserve the July 2026 architecture freeze and track future deployment testing, failed assumptions, and design changes honestly.

Future changes should be driven by measured deployment behavior or materially changed security assumptions rather than feature accumulation.
