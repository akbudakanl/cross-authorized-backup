# Vault Extension: Replace Kata with Custom Firecracker VM

**Status:** `pending` (Pending / Conceptual)
**Reason:** Explores the removal of Kata Containers to eliminate the `kata-agent` and `kata-shim` vsock orchestration channels. These channels lower VM isolation for container management features (like `exec` and `logs`) that are fundamentally unnecessary for this specific "black box" backup project.

## Overview

Kata Containers provides excellent hardware isolation by wrapping OCI containers in Firecracker MicroVMs. However, to maintain compatibility with container engines like Podman (allowing features like `podman exec` or `podman logs`), Kata injects a `kata-agent` into the guest VM. This agent constantly communicates with a `kata-shim` on the host via a `vsock` channel. 

For the Cross-Authorized Backup Vault, the MicroVM is intended to be an absolute "black box." We do not need interactive shell access (`exec`) or live orchestration once the VM boots; it only needs to run `rest-server` and accept network traffic. The presence of the vsock orchestration channel theoretically increases the VM escape attack surface because the host must parse complex IPC messages from the guest. 

This extension outlines the roadmap for abandoning Kata/Podman and deploying a pure, custom-built Firecracker VM to achieve the absolute minimum attack surface.

## Architectural Trade-offs

| Feature | Kata Containers | Custom Firecracker VM |
| :--- | :--- | :--- |
| **Attack Surface** | Low (Agent/Shim written in memory-safe Rust/Go) | **Absolute Minimum** (Only virtio-net and virtio-block parsing on host) |
| **Complexity** | Low (Standard `podman run` commands) | **Extreme** (Requires manual kernel compilation, rootfs building, and API orchestration) |
| **SELinux Integration**| Automatic via Podman | Manual policy writing required |
| **Updates** | `podman pull rest-server:latest` | Automated Immutable Infrastructure CI/CD pipeline |

## Roadmap for Custom Firecracker Implementation

To transition to a custom Firecracker architecture without requiring SSH access to the VM (Immutable Infrastructure), the following components must be developed from scratch:

### 1. Uncompressed Linux Kernel (`vmlinux`)
Firecracker does not have a BIOS/UEFI and cannot boot standard ISOs. You must provide a raw, uncompressed Linux kernel.
- **Task:** Compile a minimal Linux kernel with `virtio-net`, `virtio-block`, and `ext4` drivers built-in (not as modules), or source a pre-built minimal kernel.

### 2. Immutable Root Filesystem (`rootfs.ext4`)
The VM needs an operating system image containing the `rest-server` binary and an init system.
- **Task:** Write an automated "baking" script (e.g., using `debootstrap`, Alpine `mkimage`, or `Packer`).
- The script must format an `ext4` image, install a minimal OS (like Alpine Linux), copy the `rest-server` binary, and configure the `init` system (PID 1) to automatically mount the secondary block device (the backup `.img`) and start `rest-server` on boot.
- **Crucial:** No SSH daemon (`sshd`) should be installed.

### 3. Host Network Orchestration (TAP/TUN)
Kata handles network plumbing automatically. Without it, the host must route traffic manually to the VM.
- **Task:** Write a script to create a TAP interface (e.g., `tap0`) on the RHEL host.
- Configure `iptables` or `nftables` to route traffic from the external physical interface (or Tailscale interface) to the TAP interface.
- Ensure the VM's `rootfs` is configured with a static IP matching the TAP subnet.

### 4. Firecracker API Orchestration
Firecracker is controlled via a local Unix socket API, not a traditional CLI.
- **Task:** Develop a Python or Bash orchestration script that runs on the host. 
- When a backup is authorized (Pre-Auth Gate opens), this script must:
  1. Start the `firecracker` process.
  2. Send a `PUT /boot-source` request with the kernel path.
  3. Send a `PUT /drives` request for the `rootfs.ext4`.
  4. Send a `PUT /drives` request for the actual backup payload (`pc.img`).
  5. Send a `PUT /network-interfaces` request for `tap0`.
  6. Send a `PUT /actions` request to `InstanceStart`.

### 5. Automated Upgrade Pipeline
- Since there is no SSH access, updates to `rest-server` require destroying the old `rootfs.ext4` and running the baking script (Step 2) to generate a fresh image with the new binary.
