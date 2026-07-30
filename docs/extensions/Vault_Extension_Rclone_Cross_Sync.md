# Extension: Zero-Knowledge Cross-Sync via Offline Loop Mounts and Rclone

**Concept:** Instead of using `restic copy` (which dangerously requires the receiving device to hold the decryption password) or attempting to copy the massive `.img` sparse block file directly over the network, this extension utilizes `rclone` in combination with an offline read-only loop mount to synchronize just the underlying encrypted Restic `pack` files.

## Architecture & Workflow

1. **Offline Host Mount:** 
   When a device's (e.g., PC) primary backup ceremony finishes and its Firecracker MicroVM shuts down, the RHEL Host automatically mounts the block device file as a read-only loop device on the host itself:
   ```bash
   sudo mount -o loop,ro /var/lib/vault-rhel/repos/pc.img /mnt/vault-ro/pc
   ```

2. **Read-Only Caddy File Server:** 
   A separate, highly restricted Caddy endpoint (e.g., `https://PC_RHEL_TS_IP:8001/raw-repo/`) serves the `/mnt/vault-ro/pc` directory directly as a static file server. This endpoint is protected by a secondary htpasswd credential (e.g., `pc-sync.htpasswd`).

3. **Rclone Sync:** 
   The receiving device (e.g., Phone) connects to this Caddy endpoint using `rclone sync`. Because `rclone` can see the individual file sizes and timestamps inside the loop-mounted filesystem, it elegantly downloads **only the newly added Restic pack files** rather than transferring the entire `.img` block file over the network.

## Strategic Advantages

- **Zero-Knowledge Disaster Recovery:** It achieves true trustless mirroring. The Phone downloads and stores the PC's backup data strictly as encrypted ciphertext blobs.
- **No Password Sharing:** The Phone **never possesses the PC's Restic decryption password**. The encryption keys remain physically isolated.
- **Efficient Delta-Sync:** It solves the `.img` delta-sync problem gracefully by reverting to file-level sync for the read-path, without compromising the block-level security boundaries of the write-path (the Firecracker MicroVM).

## Implementation Complexity (Why it's an Extension)

This architecture is not part of the mandatory canonical setup because it increases operational complexity. It requires managing loop mounts and teardowns automatically upon ceremony completion (e.g., via `ExecStopPost` in systemd) and expands the Caddy configuration surface. It should only be implemented if decentralized/cross-device redundancy is strictly required by your threat model.

**Status:** Recommended extension for users requiring geographically distributed Disaster Recovery without violating Zero Trust encryption boundaries.
