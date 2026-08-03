# PQC & Native Communication Auth Process (Hybrid Ed25519 + ML-DSA)

> [!IMPORTANT]
> **STATUS: PENDING - VERY IMPORTANT TO REVIEW**
> This document represents the pinnacle of the Zero Trust architecture, based on the "Assume Breach" assumption where the network (Tailnet) layer is completely compromised. If implemented, it will directly impact the project's security model. Please review carefully.

## 1. Motivation and Threat Model Shift (Assume Breach)
In the current architecture, network security heavily relies on Tailscale and Tailnet Lock. However, according to the "Assume Breach" philosophy in cybersecurity, we assume: **"Tailnet Lock has been bypassed somehow, and a rogue device can join the network at any moment."**

If the network is compromised, IP restrictions or network-based firewalls (including fwknop/SPA) will become useless. In this case, we must completely detach security from the Network Layer (L3/L4) and move it to the Application Layer (L7). This also natively future-proofs the architecture against migrations to alternative VPN backplanes (e.g., Headscale) that lack Tailnet Lock functionality, gracefully closing a major documented security gap.

## 2. Architectural Solution: Native Communication Auth Process
Since no device on the network (IP address or Tailscale identity) can be trusted, every component communicating with each other will be forced to perform mutual cryptographic authentication (Mutual Asymmetric Authentication) BEFORE communication begins. Communication will never be initiated with an unrecognized (unsigned) device.

### 2.1 The Industry Standard: Hybrid Cryptography (Ed25519 + ML-DSA)
This mutual signing process could technically be done with classic Ed25519. However, factoring in the future Quantum Computer threat (CRQC - Cryptographically Relevant Quantum Computer), relying *solely* on Ed25519 introduces a specific risk of future forgery and impersonation.

Conversely, relying *solely* on ML-DSA is also risky because lattice-based cryptography (standardized in 2024) has not been analyzed for as long as classical Elliptic Curve Cryptography. A yet-undiscovered classical vulnerability could compromise ML-DSA.

Therefore, the system MUST implement the current industry standard (similar to Cloudflare/Chrome's approach to TLS): **Hybrid Signatures (Ed25519 AND ML-DSA)**. 
*   **Combination Rule:** Since there is no official NIST standard for combining hybrid signatures yet, the logic is kept simple and deterministic: **Both signatures must independently verify.** If either signature is missing or fails verification, the authentication is rejected.

### 2.2 Library Maturity and Implementation (Don't Roll Your Own Crypto)
A fundamental rule of cryptography is to never write your own implementation. Fortunately, ML-DSA has reached a maturity level where robust, vetted libraries are available:
*   **Go Standard Library (Recommended):** Go 1.27 introduces native ML-DSA support via the `crypto/mldsa` package (implementing FIPS 204 with MLDSA44, MLDSA65, and MLDSA87), deeply integrated into `crypto/x509` and `crypto/tls`. When this project is actively developed, relying solely on the Go standard library will likely be sufficient.
*   **Cloudflare CIRCL (Alternative/Current):** If experimentation begins before Go 1.27 is stable, Cloudflare's `circl` (Cloudflare Interoperable, Reusable Cryptographic Library) provides a production-ready, highly-vetted implementation of ML-DSA currently used in their TLS/QUIC stacks.
Neither option requires trusting an unvetted or single-developer implementation.

## 3. Operating Principle and Scope

### 3.1 Communication Flow (Mutual Hybrid Signing)
Before any data (payload) or command (e.g., `JOIN s3`) is processed:
1. **Client** signs its request with BOTH its Ed25519 and ML-DSA Private Keys.
2. **Server (VPS or RHEL Gate)** verifies BOTH of the client's Public Keys. If either verification fails, the connection is instantly dropped.
3. When responding, the Server signs the packet with BOTH its Ed25519 and ML-DSA Private Keys.
4. The Client verifies BOTH of the Server's Public Keys. If it's a rogue server, the operation is aborted.

> [!TIP]
> **Symmetric Encryption Rule: No Persistent Shared Secrets**
> To avoid the severe risks associated with a VPS compromise, the system strictly forbids the use of **persistent (long-term) shared symmetric keys**. However, this does *not* mean "no symmetric encryption at all". For bulk data transfers (which require high performance), the system MUST derive a fresh, ephemeral symmetric session key from this initial asymmetric handshake (similar to TLS). Once the session ends, the ephemeral key is discarded.

> [!NOTE]
> **Implementation Scope (Session Establishment vs. Per-Chunk)**
> There are two potential ways to implement this mutual signing process:
> 1.  **Per-Chunk / Per-Request Signing:** Every single piece of data (e.g., every Restic PUT request or data chunk) is individually signed and verified.
> 2.  **Session Establishment (Pre-Auth):** Mutual signing is only performed once during the initial connection/session establishment phase (e.g., `JOIN` command, ceremony pre-auth).
> 
> **Selected Approach:** The system uses **Option 2 (Session Establishment)**. Signing and verifying every single Restic data chunk (Option 1) with ML-DSA would introduce a massive performance overhead and severely bottleneck backup speeds. Therefore, ML-DSA mutual authentication is strictly enforced only at the gateway/connection initialization level before the data transfer session is established.

### 3.2 Applicable Communication Nodes
This system will be integrated into **all** components communicating over the Tailnet:
*   **Phone ↔ Phone VPS (Coordinator):** Commands sent by the phone are hybrid-signed (Ed25519 + ML-DSA).
*   **PC ↔ PC VPS (Coordinator):** Commands from the PC are hybrid-signed (Ed25519 + ML-DSA).
*   **VPS ↔ VPS (`wg-cross` Tunnel and Dual Vault Ceremony):** The two coordinators (`vault-pc` and `vault-phone`) communicate over WireGuard for the "Dual Vault" cross-signing process. Before sending a signature packet (`SIGN`) to each other, the VPSes perform mutual hybrid authentication (**Ed25519 + ML-DSA**) to verify the communication *genuinely* comes from the other VPS.
    *   *Note on Authenticity vs. Confidentiality:* Adding a hybrid signature at the application layer ensures **authenticity** (preventing forgery/injection), but it does **not** provide **confidentiality**. WireGuard's native key exchange (Curve25519) is susceptible to the "harvest now, decrypt later" quantum threat (traffic recorded today could be decrypted in the future). Hybrid signatures do not solve this specific risk.
    *   *Optional Enhancement (Confidentiality):* If true post-quantum confidentiality is desired against eavesdropping, the network layer itself must be upgraded. This can be achieved optionally by utilizing **NIST FIPS 203 (ML-KEM)** for key exchange, or by implementing WireGuard-specific PQC solutions like **Rosenpass** (which adds a post-quantum key exchange to WireGuard's PSK mechanism).
*   **Client ↔ Self-Hosted Server (RHEL):** The `vault-rhel-gate` application only accepts hybrid-signed packets.
*   **Client ↔ AWS S3 (Lambda Gate):** The Lambda function requires a valid hybrid signature as cryptographic proof of authentication.

## 4. Conclusion (SPA/fwknop Alternative)
This extension serves as a direct, more elegant alternative to the SPA (Single Packet Authorization / fwknop) method. While fwknop attempts to solve the "preventing the server from communicating with a malicious client" scenario by manipulating network-level firewalls (which requires high privileges and C-based daemons), this native auth process solves the exact same problem gracefully at the application layer. Instead of temporary IP whitelisting, it ensures that devices communicate with each other completely independent of their IP addresses or the network they are on, relying **solely on the cryptographic hardware/keys they possess**. Even if the Tailscale network turns into the open internet, the system remains 100% secure.
