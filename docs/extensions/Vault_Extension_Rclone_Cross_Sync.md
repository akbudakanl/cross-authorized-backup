# Extension: Zero-Knowledge Cross-Sync via Offline Loop Mounts and Rclone

**Concept:** Instead of using `restic copy` (which dangerously requires the receiving device to hold the decryption password) or attempting to copy the massive `.img` sparse block file directly over the network, this extension utilizes `rclone` in combination with an offline read-only loop mount to synchronize just the underlying encrypted Restic `pack` files.

## Architecture & Workflow

This extension reuses the existing dual-signature gate ceremony (canonical guide, Section 15)
rather than introducing a separate, always-reachable credential and endpoint. The sync window
is ephemeral and dual-authorized, exactly like the primary backup ceremony.

1. **Ceremony-gated open:** The receiving device (e.g., Phone) initiates a sync request. This
   goes through the same dual-signature proof mechanism already used for backups — both
   devices' VPSs sign a payload whose `target` field indicates "PC sync-read" rather than
   "PC backup-write." A single device cannot open this on its own, for the same reason it
   cannot open a backup ceremony on its own.

2. **On verified proof, the RHEL gate:**
   - Mounts `pc.img` read-only via loop device: `mount -o loop,ro /var/lib/vault-rhel/repos/pc.img /mnt/vault-ro/pc`
   - Applies `chattr +i /var/lib/vault-rhel/repos/pc.img` as an independent second protection layer (not relying on the loop mount's `ro` flag alone)
   - Starts a sync-specific Caddy instance, hardened identically to the primary per-device
     Caddy instances (rootless, `--cap-drop=all`, `--security-opt=no-new-privileges`,
     matching systemd/SELinux confinement) — this is a new network-facing entry point and
     must not be held to a lower bar than the primary instances.
   - Issues a freshly generated, single-use credential for this session only (not the
     standing `pc.htpasswd` credential).

3. **Rclone sync:** The Phone connects using `rclone sync` (the `http` backend, matched against
   Caddy's `file_server browse` directory listing) with the ephemeral credential. Only new pack
   files are transferred.

4. **On completion or timeout, the gate tears down:** stops the sync Caddy instance, removes the
   `chattr +i` flag, unmounts the loop device, and invalidates the credential. No component from
   this extension remains reachable outside an active, dual-authorized session.

**Zero-knowledge property preserved:** the Phone never receives the PC's restic password —
it downloads ciphertext pack files only, verified identically to before.

## Strategic Advantages

- **Zero-Knowledge Disaster Recovery:** It achieves true trustless mirroring. The Phone downloads and stores the PC's backup data strictly as encrypted ciphertext blobs.
- **No Password Sharing:** The Phone **never possesses the PC's Restic decryption password**. The encryption keys remain physically isolated.
- **Efficient Delta-Sync:** It solves the `.img` delta-sync problem gracefully by reverting to file-level sync for the read-path, without compromising the block-level security boundaries of the write-path (the Firecracker MicroVM).

## Implementation Complexity (Why it's an Extension)

This now depends on the existing gate daemon (Section 15) supporting a second `target` type
("sync-read") in addition to "backup-write." This is an extension to the gate's proof-verification
logic, not a new trust mechanism — the signature verification, replay protection, and dual-device
requirement are unchanged from the existing implementation.

**Status:** Recommended extension for users requiring geographically distributed Disaster Recovery without violating Zero Trust encryption boundaries.
