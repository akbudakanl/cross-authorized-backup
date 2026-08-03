# PQC & Native Communication Auth Process Changelog

This document summarizes the architectural and cryptographic updates made to the PQC Native Communication Auth Process proposal.

## Changes Made

### 1. `Vault_Extension_PQC_Native_Communication_Auth_Process.md`

*   **Session-Level Authentication Scope:** Clarified the implementation scope of mutual signing by detailing two approaches: per-chunk signing vs. session establishment (pre-auth). Documented the choice of **Session Establishment** to avoid the severe performance bottlenecks of signing every single Restic data chunk with post-quantum cryptography.
*   **Transition to Hybrid Cryptography (Ed25519 + ML-DSA):** Upgraded the cryptographic proposal to a Hybrid Signature model. Documented the rationale (Ed25519 has a longer track record than newer lattice-based cryptography, protecting against unforeseen classical flaws in ML-DSA).
*   **Hybrid Signature Combination Rule:** Explicitly defined a simple, deterministic rule for the hybrid mechanism: **Both signatures must independently verify.** If either signature is missing or fails verification, the authentication is rejected.
*   **Symmetric Encryption Clarification:** Clarified that the security rule is **"No Persistent Shared Secrets"** (to prevent keys being compromised on a compromised VPS), not a ban on symmetric encryption. Outlined that ephemeral symmetric session keys derived from the hybrid handshake are required and safe for high-performance bulk data transfer.
*   **Authenticity vs. Confidentiality in WireGuard:** Corrected the quantum threat model for the `wg-cross` tunnel. Clarified that application-layer ML-DSA signatures only protect against forgery (authenticity), not the "harvest now, decrypt later" threat of WireGuard's Curve25519 key exchange.
*   **Optional Post-Quantum Confidentiality (Rosenpass/ML-KEM):** Documented that if post-quantum confidentiality is required for the WireGuard tunnel, upgrading the network layer to use **NIST FIPS 203 (ML-KEM)** or implementing **Rosenpass** should be considered as an optional enhancement.
*   **Headscale Zero-Trust Alignment:** Documented that moving authentication to the application layer natively mitigates the lack of Tailnet Lock in alternative VPN backplanes like Headscale, closing a documented security gap.
*   **Library Maturity & Vetting (Don't Roll Your Own Crypto):** Added a new section recommending robust implementations of ML-DSA to prevent custom cryptographic code:
    *   **Go Standard Library:** Highlighted Go 1.27's `crypto/mldsa` package (with MLDSA44/65/87) for future-proof, standard library support.
    *   **Cloudflare CIRCL:** Recommended Cloudflare's `circl` library as a production-grade, highly-vetted alternative for immediate experimentation.

> [!TIP]
> The updated proposal now balances post-quantum protection, performance, and long-term cryptographic stability by using a hybrid signature scheme and clear boundaries between authenticity and confidentiality.
