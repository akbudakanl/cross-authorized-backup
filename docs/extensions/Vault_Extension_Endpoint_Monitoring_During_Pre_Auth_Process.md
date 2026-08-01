# Vault Extension: Endpoint Monitoring During Pre-Auth Process

**Status:** `pending` (Pending / Experimental)
**Reason:** Explores advanced local endpoint (Fedora/Linux) detection to prevent process hijacking or concurrent shadow backups during the brief 15-minute open-gate window.

## Overview

Even with the dual-ceremony system ensuring the backup gate is only open for 15 minutes, a sophisticated patient attacker with existing malware on the client endpoint could wait for this 15-minute window to launch their attack, knowing the network path to the RHEL/S3 vault is briefly open. 

Since the attacker is forced to attack *during* the active backup session, they lose their stealth. We can weaponize this loss of stealth by implementing strict monitoring exactly during the transfer moment. The following three methods are proposed to effectively track and detect unauthorized parallel data streams or process hijacking on the Linux (Fedora) client endpoint.

## 1. Target-Specific Socket/PID Matching (Endpoint Network Monitoring)

The most direct way to detect a parallel unauthorized connection is to ensure that *only* the specific `restic` process we spawned is talking to the vault.

When the backup script launches `restic`, it captures the Process ID (PID).
A background loop in the script scans all active network connections every second using Linux utilities like `ss` or `lsof`.

```bash
# Example logic for Fedora/Linux
# Find connections to the RHEL Tailscale IP on port 8001
ss -ntp | grep "<RHEL_TAILSCALE_IP>:8001"
```

If the monitoring loop detects any process other than the known `restic` PID connecting to the vault's IP and port, it means a rogue process (`malware`) is attempting to piggyback on the open gate. The script must immediately kill the connection, abort the backup, and trigger an alert.

> [!NOTE]
> **Mobile Phone (Termux) Limitation:** On Android/Termux, strict PID-to-Socket mapping tools like `ss` or `netstat` often fail or lack permission to read global process states without root access. If this method cannot be natively implemented in Termux, consider using **RethinkDNS** (or a similar local VPN/firewall application). RethinkDNS logs all outbound network traffic per-app. You can use its logging capabilities to audit if any app other than Termux attempted to contact the Vault IP during the 15-minute window.

## 2. Snapshot Counting (Mathematical Proof)

If an attacker tries to inject their own garbage data or alternative backup concurrently, they must alter the repository state by creating a new snapshot.

1.  Before starting the backup, the client script queries the total number of snapshots in the repository (e.g., `100`).
2.  The script runs the legitimate `restic backup` command.
3.  Immediately after completion, before closing the gate, the script queries the snapshot count again.
4.  The expected result is exactly `101`. If the count is `102` or higher, it mathematically proves a secondary actor injected a snapshot during the 15-minute window.

## 3. Transferred Data Volume Auditing

If an attacker attempts to inject data into an existing snapshot or manipulate the current transfer without incrementing the snapshot count, we can compare the volume of data sent vs. received.

1.  The client `restic` backup outputs a JSON summary detailing exactly how many bytes were transferred.
2.  The RHEL `rest-server` logs exactly how many bytes were appended to the repository during the active session.
3.  The client script retrieves the server's byte count and compares it to its own. If the client sent 500 MB but the server recorded 800 MB written, an unauthorized injection of 300 MB occurred during the session.
