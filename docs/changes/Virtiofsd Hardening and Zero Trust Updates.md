# Virtiofsd Hardening and Zero Trust Updates

This document summarizes the architectural security changes applied to the Vault project documentation based on our threat modeling discussion.

## Changes Made

### 1. `Vault_Zero_Trust_Master_Guide_CORE.md`
- **Kata Sandbox Enforcement:** Added a new sub-section under `H4.1.1` detailing the requirement to use `--sandbox=namespace` (or chroot) in Kata's `virtio_fs_extra_args`. We also recommended restricting `xattr` passthrough to shrink the system call attack surface.
- **Caddy Read-Only Mounts:** Updated the Caddy Podman section to emphasize the `:ro` (read-only) flag on its configuration and certificate mounts. Added an explanation detailing how this neutralizes the majority of `virtiofsd` write-primitive vulnerabilities.
- **Rest-Server Contrast:** Explicitly documented why the `rest-server` cannot use this `:ro` mitigation (since it must write backups to disk), reinforcing the necessity of separating the two services.
- **Fstab Restrictions:** Introduced a requirement to mount the ZFS/Btrfs backend dataset with `noexec,nodev,nosuid` flags in `/etc/fstab` to prevent the host kernel from executing any malicious binaries written during a hypothetical container breakout.

### 2. `Vault_Threat_Model_and_Risk_Register.md`
- **Residual Risk Added:** Located the Threat Register and appended a new residual risk under Appendix H: `### H-R4 — Virtiofsd Sandbox Escape / Write Primitive Abuse`. 
- **Risk Documentation:** Documented that despite SELinux, namespaces, and noexec restrictions, the `rest-server`'s inherent write access means a novel zero-day in `virtiofsd` could theoretically corrupt the backup repository. This formalizes the necessity of independent, off-site replication as the ultimate failsafe.

> [!TIP]
> The Zero Trust architecture is now fully aligned with modern Kata Container best practices, ensuring that a compromise of the web server (Caddy) or the application (rest-server) faces multiple overlapping hardware, systemd, and filesystem blockades before it can affect the host or other compartments.
