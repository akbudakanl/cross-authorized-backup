# Detection — Directory Index

This directory contains the Vault project's detection documentation. The two
documents here serve complementary purposes and are designed to be read in
sequence.

---

## Reading Order

| Order | Document | Purpose |
|-------|----------|---------|
| **1** | [Vault_Post_Install_Detection_and_Credential_Custody.md](Vault_Post_Install_Detection_and_Credential_Custody.md) | **Reference implementation.** Describes the specific AWS-side detection plane, alert mechanisms, canary patterns, credential custody rules, and acceptance tests that form the project's baseline detection layer. After reading this document you will understand *what* the detection system monitors, *where* each detector lives, and *how* it is deployed. |
| **2** | [Vault_Detection_Design_Methodology.md](Vault_Detection_Design_Methodology.md) | **Generative methodology.** Provides a repeatable eight-step process for turning the reference implementation into a personal, structurally-different detection layer. After applying this document you will have your own private calibration, signal weighting, and canary placement — artifacts that live outside this repository. |

A reader who completes both documents in order progresses through three levels:

```text
Level 1 — "Which events matter and why?"
         (Post-Install Detection, Sections 1–3)

Level 2 — "How is each detector built and tested?"
         (Post-Install Detection, Sections 4–13+)

Level 3 — "How do I derive my own non-public detection layer?"
         (Design Methodology, Steps A–H)
```

---

## Important Note on Detection Design

> [!IMPORTANT]
> The detection system in this project is designed as a reference and
> intentionally left simple. It is crucial for security that users develop
> their own unique signal/behavioral detection systems tailored to their
> environments.

### Kerckhoffs's Principle and Detection: Why They Diverge

In security engineering, the fundamental relationship between a system's
security and keeping structural details secret (security-by-obscurity) is
resolved by Kerckhoffs's principle.

For cryptographic systems, the golden rule is this: a system's security should
rely not on the secrecy of the design, but on the secrecy of the key.
Accordingly, we can divide the layers in this project into two:

* **Key/identity-based layers** (Ed25519 cross-signing, TOTP MFA, IAM
  session-scoped credentials, S3 Object Lock): Even if the architecture is
  entirely public, as long as the real private keys, TOTP seeds, session
  tokens, and ARN/account IDs are not in the repository, these layers
  theoretically remain solid. Even if the attacker knows the protocol, they can
  do nothing without the key. This holds true as long as the content in the
  publicly shared documentation remains generic and actual config values such
  as hostnames, IPs, ARNs, and threshold numbers are not included.

* **Detection layer:** Here, the situation is structurally different because
  most anomaly detection relies to some extent on "the attacker not knowing the
  rules" — which is a form of obscurity. If the reference detection solutions
  in this project are used identically as provided in the sample blueprint, an
  attacker who knows which events trigger the EventBridge/Lambda stack, the
  debounce duration, and the threshold logic of the dual-presence gatekeeper
  can design a behavior that stays below these specific rules. This is a
  classic problem known as "detection evasion via ruleset disclosure" — highly
  discussed in red team/blue team literature.

The sensitivity that must be shown regarding the uniqueness of detection
systems is crucial not for opportunistic attackers, but for sophisticated
attackers who have read the system's full blueprint from open sources or from
the documentation on the victim's device.

### Why Kerckhoffs's Principle Cannot Be Directly Applied to Detection

Kerckhoffs's principle was designed for cryptography, where security relies on
computational impossibility: even if the algorithm is known, the key space is
so large that brute force remains practically impossible in the real world. In
other words, saying "let the algorithm be public" relies on the assumption that
"the key space is already large enough; secrecy is not needed."

In detection systems, this assumption collapses because there is no "key
space" — there is a finite, deterministic logic. If a rule says "3 failed
logins in 5 minutes → alert", the attacker does not need to brute force; they
simply need a basic analysis: "make 2 attempts in 6 minutes." As soon as the
rule is known, the rule's blind spot can be mathematically derived. Here,
secrecy is not "additional security" in the cryptographic sense, but becomes
one of the primary defense components. This is why individual modification
(deviating from generic documentation) is the correct deduction.

### Industry Practice: Public Logic, Private Calibration

Are large organizations a complete black box? No — and this might be
surprising. In the industry, the trend is exactly the opposite:

* MITRE ATT&CK — the attack tactic/technique matrix is entirely public, and
  organizations map their coverage against it.
* SigmaHQ — platform-agnostic SIEM rules are shared open-source on GitHub,
  directly used by thousands of organizations.
* Elastic Detection Rules, Splunk Security Content — the rule sets of major
  vendors are also generally in public repos.

So, the "rule logic" is generally not secret. What is kept secret is something
else:

* Specific threshold/calibration values (tuning specific to the organization's
  own environment)
* Correlation/ML model weights
* Which rules are active and their prioritization (which 80 rules out of 500
  Sigma rules a SOC activates is its own defense signature)
* Honeypot/canary placements
* Runbook/escalation procedures (internal documentation, never goes public)

In other words, the real industry model is not "security through obscurity": it
is **public detection logic + private calibration + private context**.

### Why Multi-Signal Systems Are More Resilient

Single threshold = single alert; a one-dimensional optimization problem for the
attacker. Knowing the single parameter and staying below it is enough.

In a multi-signal/behavioral system, if an alert relies on a weighted
combination of N different signals (time, location, device fingerprint, access
speed, data volume, sequence pattern), the attacker's problem turns into an
N-dimensional optimization. The combination space grows exponentially — and the
critical point is this: the relative weights of the signals and the scoring
function can be kept secret. This is the closest thing to the role of a "key"
in cryptography — even if the architecture is public, the weights/model
parameters can remain private. Thus, a multi-signal system allows you to
transition to a security model closer to Kerckhoffs's logic: let the structure
be known, let the parameters be unknown.

Furthermore, behavioral systems generally measure deviation from a baseline
(z-score, moving average + standard deviation) rather than a static threshold.
Since the baseline is a different and drifting value over time for each
system/user, it is difficult for the attacker to build a "one-size-fits-all"
evasion strategy — they need to know the target's specific baseline, which is
generally not public.

### How to Structure It — Concrete Architecture

* **Correlation engine:** Produce an alert from a sequence of events, not a
  single event. E.g., "unusual location" + "unusual time" + "unusual data
  volume" together trigger an alert; none of them alone.
* **Weighted anomaly score:** Assign a weight to each signal, produce an alert
  when the total score passes the threshold. Keep weights in a private config,
  separate from the code.
* **Adaptive threshold:** Instead of a static number, use a rolling window
  (last 30 days average ± std dev) — there is no fixed number as a
  "threshold", but a constantly shifting reference.
* **Honeytoken / canary:** Plant fake credentials, fake endpoints, fake files.
  Touching these is a 100% definite signal. The existence of this mechanism can
  be mentioned, but its location is never documented — this is the cleanest
  example of the separation between architecture and parameter.
* **Slight randomization:** Add small randomness to some timing/threshold
  parameters so the attacker cannot build a deterministic evasion strategy.

---

> [!WARNING]
> **REMINDER:** The detection system in this project is designed as a reference.
> It is highly recommended to develop unique behavioral detection metrics or at
> least personally update the security thresholds. See
> [Vault_Detection_Design_Methodology.md](Vault_Detection_Design_Methodology.md)
> for the complete process.
