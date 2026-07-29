# Vault Extension: Advanced Host-Level Containment and Monitoring

**Classification:** ADVANCED HARDENING / RESIDUAL RISK MANAGEMENT
**Status:** PROPOSED / OPTIONAL

## 1. Overview and Residual Risk

The canonical Vault architecture uses strict systemd and rootless Podman sandboxing (`PrivateUsers`, `seccomp`, read-only rootfs, empty capabilities). Most of the basic and intermediate containment features are already active in the mainline configuration.

However, because both the PC and Phone containers/namespaces share the same Linux kernel, a sophisticated attacker who achieves Remote Code Execution (RCE) in a service and subsequently executes a Container Escape (e.g., via a zero-day kernel exploit) could potentially cross the namespace boundary.

This document outlines the remaining advanced, optional upgrades to narrow this gap or detect escape attempts, focusing on proportionate engineering trade-offs.

## 2. Advanced Containment Policies (Optional)

### 2.1. Strict Custom Seccomp and Notification System
While Podman provides a strong default seccomp profile, a strict whitelist seccomp profile (`vault-rest-server-seccomp.json`) can be applied to `rest-server`, allowing only the absolute minimum syscalls required by the Go binary.
* **Implementation:** Described in Section 12 and Section 26 of the Master Guide as an optional configuration. It requires the friend-assisted remediation scripts (`vault-check-block`, `vault-approve-syscall`) to handle legitimate software updates that introduce new syscalls.

### 2.2. Custom SELinux Policy (MAC)
RHEL ships with SELinux enforcing by default, which already confines container processes (`container_t`). 
* **Implementation:** Create a custom SELinux policy specifically for the `rest-server` and Caddy containers that strictly denies any capability to transition contexts, execute shells, or interact with kernel keyrings.

### 2.3. Caddy Response Size Limit
If the RHEL host is compromised or the `rest-server` is manipulated, an attacker might try to send an oversized response payload to the device to exploit a parsing bug in `restic` or exhaust memory.
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
* **Implementation:** Use `auditd` (native to RHEL) or `Falco` (eBPF-based) to monitor system calls (e.g., unexpected `setns`/`nsenter`, or `rest-server` spawning `bash`).

## 4. Synthetic Userspace Kernel (gVisor / runsc)

To drastically reduce the host kernel attack surface without writing fragile, custom seccomp profiles, the architecture can utilize **gVisor**.

gVisor intercepts application system calls and implements them in a memory-safe userspace "synthetic kernel" written in Go. The container process rarely talks to the real host Linux kernel directly.

* **Implementation (Drop-in Replacement):** gVisor integrates perfectly with the existing rootless Podman architecture. It requires zero changes to the network namespaces, image management, or systemd services, other than appending `--runtime=runsc` to the `podman run` command.
* **Security Benefit:** Even without a custom seccomp profile, the massive system call attack surface of the Linux kernel is shielded from the attacker. A successful container escape would first require exploiting the Go-based gVisor synthetic kernel, and then finding a secondary vulnerability in the host kernel.
* **Cost / Trade-offs:** 
  * gVisor does not support 100% of Linux syscalls (e.g., certain `io_uring` or `ptrace` behaviors may fail).
  * The userspace network stack incurs a performance penalty. While backup transfers are throughput-sensitive rather than latency-sensitive, large blob transfer speeds must be benchmarked and validated against the H5 acceptance matrix.

## 5. Hardware-Level MicroVM Isolation (Firecracker)

To achieve true, hermetic hardware isolation, the shared-kernel architecture can be replaced with hardware-assisted MicroVMs backed by a memory-safe (Rust) hypervisor: **Firecracker**. 

* **Security Benefit:** Unlike gVisor which isolates at the userspace syscall layer, Firecracker utilizes KVM for hardware-enforced CPU and memory isolation. An escape requires exploiting the VMM (virtio-block/net emulation), which is historically a much harder, rarer vulnerability class than standard Linux LPEs.
* **The "Zero Maintenance" Fallacy:** While extremely secure, transitioning from Podman to Firecracker introduces massive, disproportionate engineering overhead:
  * **Guest Kernel Maintenance:** You must compile, pin, and continuously patch a custom, minimal virtio-supported Linux kernel.
  * **Rootfs Maintenance:** Every service requires its own manually built, minimal ext4 root filesystem image.
  * **Lifecycle Orchestration:** Standard systemd/Podman tooling cannot be used natively. You must build or adopt orchestration (like `firecracker-containerd`) to boot, stop, and log the VMs.
  * **Networking Architecture:** Bridging Firecracker's TAP interfaces into the existing strictly compartmentalized dual-Tailnet namespace model is highly complex and threatens the simplicity of the current identity plane.
  * **Seccomp Shift:** Firecracker does not eliminate the need for seccomp; AWS strongly recommends wrapping the Firecracker VMM itself inside a `jailer` with its own seccomp constraints.

**Conclusion:** Firecracker represents the absolute highest tier of isolation but requires a fundamental re-architecture. For proportionate security with near-zero maintenance overhead, **gVisor (Phase 4)** is the recommended middle-ground.

## 6. Risk Register (Residual Risk Acceptance)

Until Phase 4 (gVisor) or Phase 5 (Firecracker) is implemented, the Vault architecture formally acknowledges and accepts the following residual risk:

**Risk:** "A zero-day Linux kernel vulnerability combined with a zero-day Go `net/http` or `rest-server` RCE could allow an attacker to escape the container and access the adjacent compartment on the shared RHEL host."

**Compensating Controls:**
1. Restic data is encrypted at rest (attacker cannot read existing backups without the client's repository password).
2. Rootless containers and `--network=none` drop critical capabilities required for most kernel exploits.
3. Caddy systemd isolation (`PrivateUsers`, `MemoryDenyWriteExecute`) heavily restricts the edge listener.
4. SELinux (MAC) prevents arbitrary process execution.

These compensating controls reduce the likelihood of this risk from "Probable" to "Highly Unlikely", making the shared-kernel architecture an acceptable trade-off for the reduced maintenance burden.
