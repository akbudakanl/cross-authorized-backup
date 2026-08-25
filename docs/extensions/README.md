# Vault Extensions

This directory contains optional architecture extensions, alternative configurations, and rejected concepts.

## Extension Status Index

| Extension | Status | Reason |
|-----------|--------|--------|
| [Automated Diagnostics](Vault_Extension_Automated_Diagnostics.md) | `integrated` | Core concepts integrated into the Core master guide. |
| [Capacity Triggered Prune](Vault_Extension_Capacity_Triggered_Prune_and_Maintenance.md) | `rejected` | Security reasons (violates no-prune/keep-all-history mode). |
| [Endpoint Monitoring During Pre-Auth Process](Vault_Extension_Endpoint_Monitoring_During_Pre_Auth_Process.md) | `pending` | Advanced endpoint detection during the open-gate backup window. |
| [Headscale Control Plane](Vault_Extension_Headscale_Control_Plane.md) | `rejected` | Security considerations and extra infrastructure requirements (no Tailnet Lock). |
| [Host Level Containment](Vault_Extension_Host_Level_Containment.md) | `integrated` | Advanced hardening natively integrated via Firecracker microVMs. |
| [L4 Connection Enforcement via SPA](Vault_Extension_L4_Connection_Enforcement_via_SPA.md) | `rejected` | Rendered obsolete by Bare Firecracker architecture; conflicts with host minimal attack surface principles. |
| [Mutual Backup](Vault_Extension_Mutual_Backup.md) | `rejected` | Security reasons (unwanted inbound connections). |
| [OOB Notification Routing](Vault_Extension_OOB_Notification_Routing.md) | `accepted` | Mandatory for security but pending completion of detection/notification systems. |
| [Offline CA and Console Lockdown](Vault_Extension_Offline_CA_and_Console_Lockdown.md) | `integrated` | Architecture natively integrated into the Core structure. |
| [PQC & Native Communication Auth Process](Vault_Extension_PQC_Native_Communication_Auth_Process.md) | `pending` | Mutual ML-DSA authentication assuming full Tailnet breach. |
| [Peer Relay Performance](Vault_Extension_Peer_Relay_Performance.md) | `rejected` | Conditionally rejected to avoid opening additional UDP ports unless TCP meltdown occurs. |
| [Replace Kata with Custom Firecracker VM](Vault_Extension_Replace_Kata_with_Custom_Firecracker_VM.md) | `pending` | Architecture path to eliminate Kata's vsock orchestration channels for maximum VM isolation. |
| [S3 Hybrid Storage Tiering](Vault_Extension_S3_Hybrid_Storage_Tiering.md) | `pending` | Hot metadata / cold data via lifecycle rules; fixes latent all-GDA incremental-breakage; includes storage-class assertion and rejected-alternatives record. Deferred pending operator review. |
| [S3 Request Quota Proxy](Vault_Extension_S3_Request_Quota_Proxy.md) | `integrated` | Integrated as core §23.6A (mandatory counting egress proxy with request quotas); this file preserves rationale and rejected alternatives. |
| [Totally Self-Hosted 321 Backup Strategy](Vault_Extension_Totally_Self_Hosted_321_Backup_Strategy.md) | `accepted` | Valid alternative architecture to eliminate AWS S3 dependency. |
