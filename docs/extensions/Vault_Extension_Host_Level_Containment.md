# Vault Extension: Advanced Host-Level Containment and Monitoring

**Classification:** ADVANCED HARDENING / RESIDUAL RISK MANAGEMENT
**Status:** PROPOSED / OPTIONAL

## 1. Overview and Residual Risk

The canonical Vault architecture uses strict systemd and rootless Podman sandboxing (`PrivateUsers`, `seccomp`, read-only rootfs, empty capabilities). Most of the basic and intermediate containment features are already active in the mainline configuration.

However, because both the PC and Phone containers/namespaces share the same Linux kernel, a sophisticated attacker who achieves Remote Code Execution (RCE) in a service and subsequently executes a Container Escape (e.g., via a zero-day kernel exploit) could potentially cross the namespace boundary.

This document outlines the remaining advanced, optional upgrades to narrow this gap or detect escape attempts, which have not been merged into the default deployment.

## 2. Advanced Containment Policies (Optional)

### 2.1. Strict Custom Seccomp and Notification System
While Podman provides a strong default seccomp profile, a strict whitelist seccomp profile (`vault-rest-server-seccomp.json`) can be applied to `rest-server`, allowing only the absolute minimum syscalls required by the Go binary.
* **Implementation:** Described in Section 12 and Section 26 of the Master Guide as an optional configuration. It requires the friend-assisted remediation scripts (`vault-check-block`, `vault-approve-syscall`) to handle legitimate software updates that introduce new syscalls.

### 2.2. Custom SELinux Policy (MAC)
RHEL ships with SELinux enforcing by default, which already confines container processes (`container_t`). 
* **Implementation:** Create a custom SELinux policy specifically for the `rest-server` and Caddy containers that strictly denies any capability to transition contexts, execute shells, or interact with kernel keyrings, creating an independent barrier against cross-namespace movement even if a kernel vulnerability is exploited.

### 2.3. Caddy Response Size Limit
If the RHEL host is compromised or the `rest-server` is manipulated, an attacker might try to send an oversized response payload to the device during a connection to exploit a parsing bug in `restic` or exhaust memory.
* **Implementation:** Add a strict constraint in the Caddyfile to limit the maximum `Content-Length` of any response (e.g., 128 MB).

```caddyfile
@oversized_response {
    expression {http.response.header.Content-Length} > 134217728
}
handle @oversized_response {
    respond "Response too large" 502
}
```

## 3. Runtime Detection (auditd / Falco)

Following the Vault's core philosophy ("Detection is not Prevention, but Detection is Mandatory"), host-level anomalies must be monitored just as strictly as Tailscale API anomalies.
* **Action:** Implement kernel-level monitoring for container escape attempts.
* **Implementation:** Use `auditd` (native to RHEL) or `Falco` (eBPF-based) to monitor system calls.
* **Triggers:**
  * Unexpected `setns` or `nsenter` system calls.
  * Unusual process ancestry (e.g., `rest-server` spawning `bash` or `sh`).
  * Attempts to mount or remount filesystems within the container.
* **Alerting:** Route these triggers to the existing `Honeypot` local alert system (which will push out-of-band alerts via E-mail/Telegram).

## 4. Hardware-Level MicroVM Isolation (Firecracker / crosvm)

To achieve true, hermetic isolation between the PC and Phone compartments without the heavy overhead of traditional VMs, the shared-kernel architecture can be replaced with hardware-assisted MicroVMs.
* **Action:** Run the compartments as two independent, extremely lightweight MicroVMs using modern, memory-safe hypervisors.
* **Implementation:** Utilize KVM backed by a Rust-based VMM (Virtual Machine Monitor) such as **Firecracker** or **crosvm**, which are specifically designed for GUI-less, highly secure, server-side containment.
  * `MicroVM-1 (vault-pc)`: Runs its own minimal kernel, Tailscale daemon, and Caddy/rest-server.
  * `MicroVM-2 (vault-phone)`: Runs its own minimal kernel, Tailscale daemon, and Caddy/rest-server.
* **Security Benefit:** Using memory-safe languages (Rust) for the VMM eliminates entire classes of hypervisor escape vulnerabilities common in legacy C-based emulators like QEMU. Hypervisor-enforced CPU and memory isolation is orders of magnitude stronger than container namespaces. An RCE and kernel exploit in `MicroVM-1` yields root access *only* in `MicroVM-1`, providing zero visibility into `MicroVM-2`'s memory or disks.
* **Cost:** Adds the operational overhead of building minimal kernel images, managing MicroVM lifecycle, and handling hypervisor storage provisioning (e.g., virtio block devices) instead of relying on simple host-level XFS/ZFS quotas.

## 5. Risk Register (Residual Risk Acceptance)

Until Phase 4 (VM Isolation) is implemented, the Vault architecture formally acknowledges and accepts the following residual risk:

**Risk:** "A zero-day Linux kernel vulnerability combined with a zero-day Go `net/http` or `rest-server` RCE could allow an attacker to escape the container and access the adjacent compartment on the shared RHEL host."

**Compensating Controls:**
1. Restic data is encrypted at rest (attacker cannot read existing backups without the client's repository password).
2. Rootless containers, `seccomp`, and `--network=none` drop critical capabilities required for most kernel exploits.
3. Caddy systemd isolation (`PrivateUsers`, `MemoryDenyWriteExecute`) heavily restricts the edge listener.
4. SELinux (MAC) prevents arbitrary process execution.

These compensating controls reduce the likelihood of this risk from "Probable" to "Highly Unlikely", making the shared-kernel architecture an acceptable trade-off for the reduced maintenance burden compared to managing multiple VMs.
