# Vault Extension: Host-Level Containment and Isolation Upgrades

**Classification:** ADVANCED HARDENING / RESIDUAL RISK MANAGEMENT
**Status:** PROPOSED

## 1. The Shared-Kernel Residual Risk

The canonical Vault architecture uses two strictly separated Tailnets (`vault-pc` and `vault-phone`) running in isolated network namespaces (via Podman/Docker containers) on a single physical RHEL server. 

This provides excellent **Network Identity Isolation** (a compromised phone cannot route to the PC's tailnet). However, it provides limited **Host-Level Data Isolation**. Because both containers share the same Linux kernel, a sophisticated attacker who achieves Remote Code Execution (RCE) in `rest-server` and subsequently executes a Container Escape (e.g., via a kernel exploit) could potentially cross the namespace boundary and access the other compartment's data.

While the existing container hardening (`--network=none`, `seccomp`, read-only rootfs) makes this attack path extremely difficult, it does not make it impossible. This document outlines three progressive upgrades to narrow this gap.

---

## 2. Low-Cost Enhancements (Immediate)

### 2.1. SELinux Enforcing + Custom Policy (MAC)
RHEL ships with SELinux enforcing by default, which already confines container processes. However, relying on the default container policy (`container_t`) can be tightened.
* **Action:** Bind the container boundaries not just to namespaces and `seccomp`, but to a strict Mandatory Access Control (MAC) layer.
* **Implementation:** Create a custom SELinux policy specifically for the `rest-server` containers. The policy must strictly deny any capability to transition contexts, execute shells, or interact with kernel keyrings, creating an independent barrier against cross-namespace movement even if a kernel vulnerability is exploited.

### 2.2. Runtime Detection (auditd / Falco)
Following the Vault's core philosophy ("Detection is not Prevention, but Detection is Mandatory"), host-level anomalies must be monitored just as strictly as Tailscale API anomalies.
* **Action:** Implement kernel-level monitoring for container escape attempts.
* **Implementation:** Use `auditd` (native to RHEL) or `Falco` (eBPF-based) to monitor system calls.
* **Triggers:**
  * Unexpected `setns` or `nsenter` system calls.
  * Unusual process ancestry (e.g., `rest-server` spawning `bash` or `sh`).
  * Attempts to mount or remount filesystems within the container.
* **Alerting:** Route these triggers to the existing `Honeypot` local alert system (which will push out-of-band alerts via E-mail/Telegram).

---

## 3. Medium-Cost Upgrade (Future Enhancement)

### 3.1. Hardware-Level VM Isolation (KVM/QEMU)
To achieve true, hermetic isolation between the PC and Phone compartments, the shared-kernel architecture must be abandoned.
* **Action:** Run the compartments as two independent Virtual Machines.
* **Implementation:** Utilize the physical host's virtualization capabilities (KVM/QEMU/libvirt).
  * `VM-1 (vault-pc)`: Runs its own kernel, Tailscale daemon, and Caddy/rest-server.
  * `VM-2 (vault-phone)`: Runs its own kernel, Tailscale daemon, and Caddy/rest-server.
* **Security Benefit:** Hypervisor-enforced CPU and memory isolation is orders of magnitude stronger than container namespaces. An RCE and kernel exploit in `VM-1` yields root access *only* in `VM-1`. It provides zero visibility or access to `VM-2`'s memory or disks.
* **Cost:** Adds the operational overhead of patching and maintaining two separate Linux operating systems and managing hypervisor storage provisioning.

---

## 4. Risk Register (Residual Risk Acceptance)

Until Phase 3 (VM Isolation) is implemented, the Vault architecture formally acknowledges and accepts the following residual risk:

**Risk:** "A zero-day Linux kernel vulnerability combined with a zero-day Go `net/http` or `rest-server` RCE could allow an attacker to escape the container and access the adjacent compartment on the shared RHEL host."

**Compensating Controls:**
1. Restic data is encrypted at rest (attacker cannot read existing backups without the client's repository password).
2. Podman rootless, `seccomp`, and `--network=none` drop critical capabilities required for most kernel exploits.
3. SELinux (MAC) prevents arbitrary process execution.
4. `auditd`/Falco provides immediate out-of-band alerting upon namespace crossing attempts. 

These compensating controls reduce the likelihood of this risk from "Probable" to "Highly Unlikely", making the shared-kernel architecture an acceptable trade-off for the reduced maintenance burden compared to managing multiple VMs.
