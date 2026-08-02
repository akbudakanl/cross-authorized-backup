# PQC & Native Communication Auth Process (Mutual ML-DSA)

> [!IMPORTANT]
> **STATUS: PENDING - VERY IMPORTANT TO REVIEW**
> This document represents the pinnacle of the Zero Trust architecture, based on the "Assume Breach" assumption where the network (Tailnet) layer is completely compromised. If implemented, it will directly impact the project's security model. Please review carefully.

## 1. Motivation and Threat Model Shift (Assume Breach)
In the current architecture, network security heavily relies on Tailscale and Tailnet Lock. However, according to the "Assume Breach" philosophy in cybersecurity, we assume: **"Tailnet Lock has been bypassed somehow, and a rogue device can join the network at any moment."**

If the network is compromised, IP restrictions or network-based firewalls (including fwknop/SPA) will become useless. In this case, we must completely detach security from the Network Layer (L3/L4) and move it to the Application Layer (L7).

## 2. Architectural Solution: Native Communication Auth Process
Since no device on the network (IP address or Tailscale identity) can be trusted, every component communicating with each other will be forced to perform mutual cryptographic authentication (Mutual Asymmetric Authentication) BEFORE communication begins. Communication will never be initiated with an unrecognized (unsigned) device.

### 2.1 Post-Quantum Cryptography (ML-DSA) Preference
This mutual signing process could also be done with classic Ed25519. However, in a scenario where we assume the network is compromised, we must factor in the future Quantum Computer threat (Shor's algorithm). An attacker infiltrating the network would only need to crack the keys.
Therefore, this native communication authentication within the application must absolutely be performed using Quantum-Resistant algorithms meeting **NIST FIPS 204 (ML-DSA)** standards.

## 3. Operating Principle and Scope

### 3.1 Communication Flow (Mutual Signing)
Before any data (payload) or command (e.g., `JOIN s3`) is processed:
1. **Client** signs its request with its own ML-DSA Private Key.
2. **Server (VPS or RHEL Gate)** verifies the client's ML-DSA Public Key. If verification fails, the connection is instantly dropped.
3. When responding, the Server signs the packet with its own ML-DSA Private Key.
4. The Client verifies the Server's Public Key. If it's a rogue server, the operation is aborted.

### 3.2 Applicable Communication Nodes
This system will be integrated into **all** components communicating over the Tailnet:
*   **Phone ↔ Phone VPS (Coordinator):** Commands sent by the phone are signed with ML-DSA.
*   **PC ↔ PC VPS (Coordinator):** Commands from the PC are signed with ML-DSA.
*   **VPS ↔ VPS (`wg-cross` Tunnel and Dual Vault Ceremony):** The two coordinators (`vault-pc` and `vault-phone`) communicate over WireGuard for the "Dual Vault" cross-signing process. Since WireGuard's own encryption (Curve25519) is vulnerable to quantum computers, this tunnel is considered broken. Therefore, before sending a signature packet (`SIGN`) to each other, the VPSes perform mutual authentication with **ML-DSA** to verify the communication *genuinely* comes from the other VPS. This is absolutely NOT excessive encryption; on the contrary, it is a very healthy natural addition that patches the quantum vulnerability of the lower layer (WireGuard) at the upper layer (Application), adhering perfectly to the "Defense-in-Depth" principle.
*   **Client ↔ Self-Hosted Server (RHEL):** The `vault-rhel-gate` application only accepts ML-DSA signed packets.
*   **Client ↔ AWS S3 (Lambda Gate):** The Lambda function requires a valid ML-DSA signature as cryptographic proof of authentication.

## 4. Conclusion (SPA/fwknop Alternative)
This extension serves as a direct, more elegant alternative to the SPA (Single Packet Authorization / fwknop) method. While fwknop attempts to solve the "preventing the server from communicating with a malicious client" scenario by manipulating network-level firewalls (which requires high privileges and C-based daemons), this native auth process solves the exact same problem gracefully at the application layer. Instead of temporary IP whitelisting, it ensures that devices communicate with each other completely independent of their IP addresses or the network they are on, relying **solely on the cryptographic hardware/keys they possess**. Even if the Tailscale network turns into the open internet, the system remains 100% secure.
