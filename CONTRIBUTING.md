# Contributing Guidelines & Governance

Thank you for your interest in contributing to the **Cross-Authorized Backup** project. 

Because this project serves as a high-assurance, threat-model-driven reference architecture, code and documentation contributions must adhere to strict governance and security guidelines.

---

## 1. Development & Branching Workflow

To maintain the integrity of the `main` baseline, direct commits or pushes to the primary branch are strictly disabled via GitHub Repository Rulesets.

1. **Fork or Branch:** Create a dedicated topic branch for your work (e.g., `feature/pqc-kem-tunnel`, `fix/lambda-timeout`, `docs/threat-model-update`).
2. **Atomic Commits:** Keep commits modular, descriptive, and scoped to a single logical change.
3. **Pull Requests:** Submit all changes against the `main` branch via a Pull Request (PR).

---

## 2. Operational Governance & Single-Maintainer Model

### Current Status: Single-Maintainer Pre-Deployment Phase
This repository is currently maintained by a single developer. To balance operational viability with zero-trust branch protection practices, the following governance protocol is enforced:

* **PR Requirement:** All modifications—including minor documentation fixes—must pass through the Pull Request pipeline. Direct `main` pushing is prohibited to ensure full auditability via PR history.
* **Approval Ruleset Adaptation:** During the single-maintainer phase, strict multi-party approval requirements are adapted (e.g., self-merge or bypass configurations are utilized where GitHub prevents single-user approval loops).
* **Future Transition:** As the project moves into campus-network testing and additional co-maintainers join, multi-party review and mandatory independent code owner approvals (`CODEOWNERS`) will be strictly enforced at the ruleset level without exceptions.

---

## 3. Pull Request Requirements

Before a PR can be merged, it must meet the following criteria:

* **Architectural Consistency:** Changes must explicitly align with the threat boundaries, TOFU state assumptions, and zero-trust principles defined in `docs/core/Threat Modeling/Vault_Threat_Model_and_Risk_Register.md`.
* **No Unsolicited Scope Expansion:** Architectural alterations or new protocol implementations must be discussed prior to PR submission.
* **Clean History:** Commits should be logical and clean. Commits may be squashed upon merging to maintain a deterministic project history.
* **Conversation Resolution:** All review comments and discussions must be marked as resolved.

---

## 4. Security Findings

Do **not** use Pull Requests or public issues to report potential security vulnerabilities or threat-model bypasses. Please refer to [`SECURITY.md`](SECURITY.md) for instructions on submitting private security disclosures
