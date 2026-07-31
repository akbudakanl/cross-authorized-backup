# Vault Extension: Offline SSH CA & Console Break-Glass Lockdown

**Classification:** ARCHITECTURE EXTENSION / OPTIONAL HARDENING

This extension file explains the history of the Offline CA and Console Lockdown architecture, which has been integrated into the Canonical structure, as well as the optional physical paper (Break-Glass) recovery concept.

## Outdated version before this implementation

In the older version of the standard architecture, SSH access to a VPS server was protected by an Ed25519 key and a TOTP (Time-Based One-Time Password). In this structure, the `/etc/ssh/sshd_config` file was set to `AuthenticationMethods publickey,keyboard-interactive` and a PAM module like `google-authenticator` was used.

However, a TOTP (6-digit code) mathematically has a 1 in 1,000,000 predictability. Moreover, in the old architecture, the management consoles of Cloud Providers (AWS Session Manager, OCI Cloud Shell) were left open, even though they had the potential to bypass OS-level SSH protections. This created weak links in the "Zero Trust" chain.

## Updated version

In the current Canonical (default) architecture, TOTP and Cloud Provider Web Console dependencies have been completely eliminated. In this updated version, access is entirely delegated to a decentralized, air-gapped certificate authority (Phone).

1. **The Entry Gate (SSH Offline CA):** Only someone coming from within the Tailscale network, possessing the PC's SSH key, and having this key **signed via QR Code by the Certificate Authority (CA) on the Phone (Offline/Air-Gapped)** at the time of connection can gain access.
    - The phone generates its own CA key and never extracts it. Only `ca.pub` is copied to the VPS.
    - By using `TrustedUserCAKeys /etc/ssh/ca.pub` in `sshd_config`, the server stops prompting for TOTP and only accepts this signed certificate.
    - During an SSH request, the public key is scanned by the phone via a QR code, and the signed certificate is retrieved back to the PC via another QR code to log in.

2. **The Backdoor (Cloud Console Lockdown):** Even if the Admin Console (VNC/Serial TTY) provided by the cloud provider is accessed, the operating system will not respond to any keystrokes.
    - The terminal screens have been deafened using the `sudo systemctl mask getty@tty1.service` and `serial-getty@ttyS0.service` commands.

> [!WARNING]
> **Total Data Loss Risk (Ruthless Lockdown):** This current architecture ruthlessly locks out the administrator (Admin) from their own server as well. Because the OCI Web Console is locked down, if the Phone (CA device) breaks or is lost, it is mathematically and physically **impossible** to access the rented VPSs. You will lose your data.

## Optional enhancement idea

Because the console is deafened, in the event of an SSH system (CA) crash or loss, the following "Paper-Stored Admin Console Access Key (Break-Glass)" structure can be **optionally** established. This enhancement is not included in the Canonical file, and its implementation is entirely voluntary.

### Offline Break-Glass (Emergency Password on Paper)

When the system is locked down, your only way out is to drop into `single-user mode` via the bootloader (GRUB) to regain console access.

1. **Generating the PBKDF2 Password (Physical Paper):**
   - A completely random password of 64-128 characters in length is generated.
   - This password is **never** saved in a password manager; it is written directly on a physical piece of paper/steel plate and locked in a safe.

2. **Locking the GRUB Bootloader:**
   - The PBKDF2 hash of the generated password is extracted and embedded into the GRUB configuration:
     ```bash
     grub2-setpassword
     # (The password on the paper is entered, the system hashes and saves it)
     ```

**If an emergency occurs:**
1. Log into the cloud panel.
2. Reboot the server.
3. While on the Boot screen, retrieve the emergency paper.
4. Press the "E" key on the GRUB screen, enter the password from the paper, and boot the system into `single-user mode` (or `init=/bin/bash`) to regain console access.

This way, even if your cloud provider is hacked, the attacker is prevented from accessing the server's operating system or data without possessing that physical piece of paper.
