# Security Policy

This document explains how to privately report a vulnerability in the
Cross-Authorized Backup project, what issues are in scope, and what information
to include so the report can be acted on efficiently.

> [!CAUTION]
> **If you arrived here via GitHub's "Report a vulnerability" form - please
> stop and send an encrypted e-mail instead.**
> GitHub's advisory channel does not provide end-to-end encryption. Encrypted
> e-mail is the preferred and more private channel for this project.
> Instructions are in the [Preferred channel](#preferred-channel--encrypted-e-mail) section below.
> Only use this form if encrypted e-mail is genuinely not an option for you.

---

## Reporting a Vulnerability

> [!IMPORTANT]
> **Do not open a public GitHub issue for security vulnerabilities.**
> Public disclosure before a fix is available undermines the threat model this
> project is built on and may expose adopters before they can respond.

### Preferred channel - Encrypted e-mail

Send your report to the contact address listed on the maintainer's GitHub
profile. 

> [!NOTE]
> End-to-end encryption is required. Use PGP to encrypt before sending.

  [F46C 0F0B D707 0F79 907E 4D85 25D5 F85B 8362 7D9D](https://keys.openpgp.org/search?q=security.unplanned639@passinbox.com)

  Fingerprint: verify against the key fetched from the keyserver above before
  encrypting. Do not send sensitive details unencrypted.

### Fallback - GitHub Private Security Advisories

> [!WARNING]
> **Please try encrypted e-mail first.** This channel does not provide
> end-to-end encryption. Your report is confidential within GitHub's
> infrastructure but is not cryptographically protected against GitHub itself.

Only use this if encrypted e-mail is genuinely not an option for you:

1. Go to the **Security** tab of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the advisory form and submit.

---

## Response Expectations

| Milestone | Target |
|---|---|
| Acknowledgement of receipt | Within **72 hours** |
| Initial triage and severity assessment | Within **7 days** |
| Coordinated disclosure timeline agreed | Within **30 days** of triage |

These are best-effort targets for an experimental project maintained
individually. If you have not received an acknowledgement within 72 hours,
please follow up once through the same private channel.

---

## Scope

The following are **in scope** for security reports:

### Authorization and session logic
- Weaknesses in the cross-authorization flow that allow a single endpoint to
  unilaterally mint a fresh backup session without participation from the
  opposing compartment.
- Logic flaws in session deadline enforcement, issuance-slot accounting, or
  fail-closed behaviors.
- Flaws in successful-completion-triggered S3 session containment and the
  signed close-signaling protocol.

### Cryptographic boundaries
- Protocol-level weaknesses in Ed25519 or ML-DSA / FIPS 204 authorization
  signatures (e.g., signature malleability, key reuse, improper domain
  separation).
- Flaws in ephemeral session-bound symmetric key derivation or injection via
  MMDS that could lead to persistent shared secrets.
- Weaknesses in the hybrid Ed25519 + ML-DSA transition scheme that allow an
  attacker to satisfy one leg and bypass the dual-validation requirement.
- Issues with the optional ML-KEM / FIPS 203 or Rosenpass tunnel
  confidentiality layer.

### Trust-boundary violations
- Paths through which a compromised PC or phone compartment can influence the
  opposing compartment's authorization or close decision beyond what the model
  explicitly permits.
- IPC or network-layer attacks between MicroVM boundaries (Firecracker / Kata)
  despite the zero-vsock, network-only IPC constraint.

### Credential and IAM controls
- Weaknesses in AWS short-lived credential issuance or role-session revocation
  that could allow credential reuse beyond the intended session window.
- Bypasses of the daily fail-closed issuance limits enforced at the Lambda or
  RHEL gate.
- S3 append-only or object-lock misconfigurations that would allow a
  compromised endpoint to delete or overwrite backup data.

### Detection and credential-custody plane
- Design-level gaps that would allow an advanced attacker to reliably suppress
  detection events without triggering the independent credential-custody
  controls - particularly bypasses that do not rely on prior knowledge of
  custom site-specific thresholds (which are explicitly user-defined and
  therefore out of scope per the project's Kerckhoffs's principle note).

### Restic repository and storage layer
- Client-side encryption weaknesses that could expose backup data
  confidentiality when the restic repository is stored in S3.

---

## Out of Scope

The following are **not** in scope for security reports to this project:

- Vulnerabilities in third-party dependencies (restic, Tailscale, AWS services,
  Firecracker/Kata, Rosenpass) - report those to the upstream projects.
- Physical access attacks that defeat the boot chain or hardware trust root
  before the system reaches the TOFU clean-state baseline - the threat model
  explicitly assumes a trusted initial provisioning state.
- Detection-evasion techniques that rely entirely on knowledge of a specific
  adopter's custom detection thresholds - the project intentionally defers
  threshold customization to each deployer (see the Detection Philosophy
  section in `README.md`).
- Theoretical quantum attacks on Ed25519 using a Cryptographically Relevant
  Quantum Computer - the PQC migration path is already documented and tracked
  in `README.md`; reports that only restate this known limitation will be
  closed as informational.
- General best-practice recommendations unrelated to a demonstrable weakness in
  the design.
- Vulnerabilities that require the attacker to already control both the PC
  **and** the phone compartment simultaneously - this condition is outside the
  stated threat model.

---

## What to Include in Your Report

A useful report contains enough information for the maintainer to reproduce,
triage, and assess the issue without needing extensive follow-up questions.
Include as much of the following as is applicable:

### Description
A clear explanation of the vulnerability: what it is, where it exists in the
architecture, and why it matters.

### Affected component
Which part of the design is affected - for example: Lambda authorization gate,
RHEL credential-custody daemon, cross-compartment close protocol, MMDS
injection path, restic encryption boundary, and so on.

### Attack scenario
A concrete scenario describing:
- **Attacker starting conditions** (e.g., "the PC compartment is fully
  compromised post-provisioning, phone is clean")
- **Steps taken** by the attacker
- **What the attacker achieves** (e.g., mints an unauthorized backup session,
  corrupts a restic repository without triggering detection, extends the
  session window past its hard deadline)

### Supporting material
Any of the following that strengthen the report:
- Proof-of-concept protocol traces, crafted payloads, or pseudocode
- Relevant excerpts from the architecture or threat-model documents
  (`docs/core/`) with annotations
- References to related CVEs, academic papers, or prior art if the weakness is
  a known class of vulnerability applied to this design

### Impact assessment (your view)
Your assessment of severity: confidentiality, integrity, or availability impact;
whether exploitation requires physical access, network position, or only
software-level compromise; and whether the attack is realistic against the
stated threat model.

### Suggested mitigation (optional)
If you have a concrete suggestion for how the design could address the issue,
include it - but a report without a suggested fix is equally welcome and will
not be deprioritized.

---

## Coordinated Disclosure

This project follows a **coordinated disclosure** approach:

1. The vulnerability is confirmed and a fix or documented mitigation is
   prepared.
2. A disclosure timeline is agreed between the reporter and the maintainer
   (target: 90 days from initial report, shorter for actively exploited or
   critical issues).
3. The advisory is published alongside the fix, with full credit to the
   reporter unless they prefer to remain anonymous.

If no response is received within 14 days of the agreed publication date, the
reporter is free to disclose at their discretion.

---

## Recognition

This is a personal research project without a formal bug-bounty program.
Researchers who responsibly disclose valid vulnerabilities will be credited by
name (or handle, or anonymously - your choice) in the published advisory and
in the project's change record.

---

## A Note on the Nature of This Project

Cross-Authorized Backup is an **experimental, pre-deployment reference
architecture** - not a finished product. The codebase and design documents are
published to advance understanding of dual-control backup authorization and
post-quantum credential boundaries, not as a turnkey solution.

Security reports that identify genuine weaknesses in the architectural model
are especially valuable during this phase, and will be taken seriously even if
the finding is against a design assumption rather than a specific line of code.
