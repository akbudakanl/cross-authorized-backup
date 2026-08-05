---
status: accepted
---
# Extension: Totally Self-Hosted 3-2-1 Backup Strategy

This is an alternative architecture for users who wish to entirely eliminate the AWS S3 (Cloud) dependency from the core guide while strictly preserving the 3-2-1 backup rule and Zero Trust boundaries.

**Concept:** This extension provides an architecture for implementing the 3-2-1 backup rule entirely on-premises, without relying on any cloud providers (like AWS S3). It uses a permanently attached external USB hard drive on the RHEL backup server as the 3rd destination, completely isolated from the MicroVMs to maintain the strict Zero Trust threat model.

## Core Architectural Principle: The Opaque Carrier

In our threat model, if a primary device (e.g., PC) is compromised, the attacker has full control over the `pc.img` block device within the Firecracker MicroVM. A sophisticated attacker can intentionally corrupt or maliciously craft the `ext4` filesystem structures inside `pc.img`.

If the RHEL Host attempts to mount or parse this maliciously crafted filesystem, it exposes the Host kernel (or even user-space parser tools) to parsing vulnerabilities (e.g., buffer overflows in ext4 drivers). 

### Why we don't use `guestfish` or host-side mounting
Tools like `guestfish` (libguestfs) exist to safely parse untrusted filesystems by spinning up an ephemeral KVM instance to read the files without exposing the Host kernel. While this protects the RHEL Host during the transfer, it still violates our core principle: **The Host should never interpret the data.**

Our threat model explicitly accepts that if an attacker compromises the PC and plants a malicious exploit inside the backup, and we later download that `.img` to a *new* replacement PC, the new PC might get compromised. We accept this lateral movement across the *same trust boundary* (PC to new PC). 

However, we **do not accept** any risk of the attacker jumping from the PC's backup into the RHEL Host, because the RHEL Host is a shared environment (it also hosts the Phone's backups and the cryptographic gate). The only acceptable exit path from the MicroVM must be a strict hypervisor VM Escape. Parsing the filesystem—even safely via `guestfish`—is an unnecessary deviation from treating the backup as an opaque binary blob.

Therefore, the `.img` files are **never mounted or parsed** on the RHEL Host. They are treated purely as a sequence of bytes.

## Workflow & Implementation

To efficiently sync a 50GB+ `.img` file without copying the entire file every day, we use **Restic** itself at the host level, leveraging its memory-safe (Go) Content-Defined Chunking.

1. **Hardware Setup:** 
   An external HDD is permanently attached to the RHEL Host (e.g., mounted at `/mnt/usb-backup`).
   
2. **Host-Level Restic Repository:**
   A Restic repository is initialized on the external HDD. Because the contents of `pc.img` and `phone.img` are *already* encrypted by the primary devices before they reach the server, this secondary Restic layer does not need a strong password. We initialize it using Restic's passwordless feature (available in v0.16.0+):
   ```bash
   restic init --repo /mnt/usb-backup/rhel-offline-repo --insecure-no-password
   ```

3. **Automated Delta Sync:**
   After the primary dual-signature gate ceremony completes and the MicroVM shuts down, a systemd timer on the RHEL Host triggers a backup of the raw `.img` files:
   ```bash
   restic -r /mnt/usb-backup/rhel-offline-repo --insecure-no-password backup /var/lib/vault-rhel/repos/pc.img /var/lib/vault-rhel/repos/phone.img
   ```

### Advantages
- **Zero Filesystem Parsing:** The Host kernel only reads raw bytes. Filesystem parser VM escapes are mathematically impossible.
- **Delta Efficiency:** Restic perfectly handles the block-level changes inside the `.img` files, only copying the new megabytes of data instead of copying the whole 50GB file.
- **Blast Radius Containment:** Even if the MicroVM is fully compromised and the `.img` is corrupted, the RHEL Host safely backs up the corrupted blob to the USB without ever knowing it's corrupted. The RHEL Host remains pristine.

## Trust Model of the External Drive

This extension targets users who want a **totally self-hosted** setup — no cloud services, no third-party infrastructure, no network-attached storage requiring additional trust decisions. Every component is physically under your control.

### TOFU Coverage

The external drive is covered by the same TOFU (Trust On First Use) model that governs all other devices in this architecture (PC, Phone, RHEL server). This means the drive is granted an initial trust upon its first connection and is thereafter treated as a known, trusted entity within the system's cryptographic and policy framework.

> [!IMPORTANT]
> **Exclusive RHEL Attachment Requirement:** While the external drive is initially trusted, it should only ever be physically connected to the RHEL backup server — not to the PC, phone, or any other machine. Connecting it to a different device would unnecessarily widen the trust boundary and could expose the stored `.img` blobs (even if opaque) to an untrusted environment, undermining the isolation this architecture relies on.

### The Drive Is Not a Transport Channel

It is essential to understand the role of the external drive within this threat model:

**The external drive does not act as a transport channel or relay.** It is not a conduit through which data flows between two active endpoints. It is purely a **passive, additional storage unit** — a third physical copy of the already-encrypted, already-opaque `.img` blobs that the RHEL Host has already received and stored. No device other than RHEL reads from or writes to it as part of the normal backup workflow.

> [!NOTE]
> **Alternative: Second Internal Disk.** The external USB hard drive is the recommended approach for this extension due to its physical portability and off-shelf availability. However, a **second internal disk installed directly in the RHEL server** is a functionally and architecturally equivalent alternative. Both choices result in the same security properties: a physically separate storage medium, exclusive to the RHEL server, that holds opaque `.img` files without any filesystem parsing or active network routing.
