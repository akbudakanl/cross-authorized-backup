# Vault Extension: Honeypot and Canary Detection

**Status:** Draft / Planned
**Target Component:** Entire Infrastructure
**Risk Addressed:** T-07 (Silent Compromise), Unnoticed Lateral Movement, Container Escapes.

## 1. Overview

A core principle of the Vault architecture is that "Detection blindness is itself an alert condition." While the canonical architecture focuses heavily on prevention (cross-authorization, strict IAM bounds, Podman isolation), this extension introduces an active detection layer.

By placing deceptive artifacts (canaries) and traps (honeypots) throughout the architecture, any unauthorized probing or exploitation attempts will trigger immediate, high-priority alerts.

## 2. Canary Files (Host-Level & Container-Level)

A canary file is a fake credential or configuration file that is monitored for access. The legitimate Vault system never reads these files.

### 2.1. Container-Level Canaries
**Goal:** Detect Remote Code Execution (RCE) inside the `rest-server` container.
- **Method:** Place a file named `.auth-token-master` or `.restic-admin-token` in the root of the container image, but outside the bind-mounted repository directory.
- **Monitoring:** An `inotifywait` process (running in a sidecar or directly on the host targeting the overlayfs mount) watches this file.
- **Trigger:** If the file is opened for reading, an alarm is triggered. Legitimate `rest-server` logic only operates on the `/data` path and never accesses these files.

### 2.2. Host-Level Canaries (RHEL)
**Goal:** Detect Container Escapes or unauthorized RHEL SSH access.
- **Method:** Deploy fake, tempting files on the RHEL filesystem:
  - `/var/lib/vault-rhel/repos/pc/.vault-admin-key.bak`
  - `/root/.aws/credentials`
  - `/etc/vault-rhel/.ssh/authorized_keys.disabled`
- **Monitoring:** Use `auditd` to watch these files.
  - `auditctl -w /root/.aws/credentials -p r -k vault-canary-read`
- **Trigger:** If `auditd` logs a read event (`type=SYSCALL ... key="vault-canary-read"`), it confirms an attacker has breached the host and is hunting for lateral movement credentials.

## 3. Network Honeypots

**Goal:** Detect lateral movement attempts or automated port-scanning within the RHEL environment or the Tailscale network.

- **Implementation:** 
  Run lightweight netcat/python listeners on commonly targeted but unused ports on the RHEL server (e.g., `TCP 22` [if SSH is moved], `TCP 8080`, `TCP 3389`).
- **Trigger:** Any connection attempt to these ports generates an instant alert. The canonical architecture ensures the phone and PC never attempt to connect to anything other than the exact Caddy proxy port (e.g., 443).

## 4. Cloud Canaries (AWS)

**Goal:** Detect compromised AWS credentials or unauthorized reconnaissance in the AWS environment.

- **Implementation:**
  Create a fake S3 bucket (e.g., `vault-backup-archive-admin-do-not-delete`) or a fake DynamoDB table (`VaultMasterKeys`).
- **Monitoring:** AWS CloudTrail is configured to alert on any API calls made to these specific resources.
- **Trigger:** Because the canonical IAM roles are strictly bound to their respective production resources, any access attempt against these canaries indicates that an attacker has stolen credentials (perhaps via a separate breach) and is exploring the AWS account.

## 5. DNS Canaries (Sinkhole)

**Goal:** Detect out-of-band communication attempts from a compromised container.

- **Implementation:**
  Since the `rest-server` container operates with `--network=none` (if the Advanced Containment extension is enabled), it should never perform DNS lookups. 
- **Monitoring:** The RHEL host's `systemd-resolved` or a local DNS sinkhole logs all DNS queries.
- **Trigger:** If a DNS query originates from the container's network namespace (or any unexpected namespace), it indicates a compromised process trying to download a secondary payload or beacon to a Command and Control (C2) server.
