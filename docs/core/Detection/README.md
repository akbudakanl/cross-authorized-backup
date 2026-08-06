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
| **3** | [Vault_Incident_Response_Roadmap.md](Vault_Incident_Response_Roadmap.md) | **Post-containment continuation.** Picks up where §21/§6A.7 of the Post-Install document stop — eradication validation, recovery gating, and post-incident review. |

A reader who completes both documents in order progresses through three levels:

```text
Level 1 — "Which events matter and why?"
         (Post-Install Detection, Sections 1–3)

Level 2 — "How is each detector built and tested?"
         (Post-Install Detection, Sections 4–13+)

Level 3 — "How do I derive my own non-public detection layer?"
         (Design Methodology, Steps A–H)

Level 4 — "Containment worked. Now what?"
         (Incident Response Roadmap, Sections 1–7)
```

---

## Detection Technique Coverage

The reference implementation deliberately combines two detection paradigms in a
way that matches the structural properties of this specific system. Understanding
why each was chosen — and where anomaly-based detection would add genuine value
— helps calibrate what to prioritize when personalizing the detection layer.

### Event-Driven Detection: Well-Covered

The AWS-side detection plane is event-driven by design, and this is the right
choice for the signals this system produces:

| Detector | Trigger |
|---|---|
| VaultSlotWatch | DynamoDB Stream INSERT — fires on slot consumption |
| VaultStsWatch | CloudTrail → EventBridge — fires on `AssumeRole` |
| VaultCompletionPolicyWatch | CloudTrail → EventBridge — fires on `PutRolePolicy` |
| VaultAuditWatch | Scheduled poll — compares audit log against actor allowlist |
| Canary / honeytoken | File/credential access — 100% binary tripwire |

Event-driven detection is appropriate here because the highest-value security
events in this architecture are **discrete, low-frequency, and binary**: a slot
was consumed or it was not; a config mutation occurred or it did not; a canary
was touched or it was not. There is no continuous behavioral stream to model —
one backup session per day per device is the expected workload, and deviations
from that pattern are already structurally constrained by the authorization
model (dual-signature gates, issuance limits, fixed deadlines).

### Anomaly-Based Detection: Intentionally Limited in the Reference

The reference implementation is almost entirely rule/threshold-based rather
than anomaly/statistical-based. This is a deliberate trade-off, not an
oversight, and it is appropriate for this scale.

Anomaly-based detection requires a baseline — a history of "normal" behavior
against which current observations are compared. For a system with highly
predictable, low-volume patterns (one backup per day, two devices, fixed IAM
role boundaries), the signals most worth monitoring are binary rather than
continuous, and a baseline adds implementation complexity without proportional
security value for those signals.

There is also a practical second-order benefit: the Methodology document
(Steps C and F) specifically points users toward adaptive/statistical baselines
as the most Kerckhoffs-adjacent option available for detection — the baseline
becomes a drifting, private value that an attacker cannot recover from the
public architecture. **This is left as the user's own private implementation
precisely because a published reference baseline would itself become a public
attack map** — the same disclosure problem that applies to thresholds and
weights applies equally to what a "normal" session looks like.

### Where Anomaly-Based Detection Adds Genuine Value

There is one category of signals in this architecture where statistical anomaly
detection would fit naturally and is not covered by the reference
implementation: **session behavioral signals**.

* **Backup session duration** — a session that takes substantially longer or
  shorter than historical sessions for the same device/data volume is a
  behavioral anomaly that threshold-based detection cannot capture without a
  fixed, published number.
* **Data volume per session** — a significant deviation from rolling historical
  volume (measured in z-score terms) is a meaningful signal, particularly for
  detecting exfiltration-style behavior that deliberately stays below a fixed
  ceiling.
* **Timing of slot consumption within the day** — if sessions historically
  begin within a consistent window and one begins far outside that window, the
  deviation is a signal worth surfacing even if the session is otherwise
  structurally valid.

These signals are mentioned in the Methodology document's Step A (timing
relationships, negative signals) as examples of signals the reference file did
not use but that your own deployment may warrant. If you implement any of them,
the resulting baseline belongs in your private configuration, not in any
version-controlled file derived from this repository.

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

## Known Gaps and Extension Opportunities

The following are areas where the reference implementation deliberately stops
short and where a motivated user should invest effort first. These are not
design failures — they are places where a published reference value would
recreate the disclosure problem this directory exists to address, or where the
complexity-to-value ratio is only favorable once you have real deployment data.

### Session Behavioral Signals (Highest Priority Gap)

The reference implementation has no anomaly detector for **backup session
behavior**. All session-level signals are currently structural (did
authorization succeed or fail?) rather than behavioral (did the session behave
the way past sessions have?).

Three signals in particular are well-suited to z-score-based anomaly detection
and are absent from the reference:

* **Session duration** — "this backup normally takes N minutes; this one took
  3× that." A session that runs abnormally long may indicate data exfiltration
  appended to a legitimate backup, interference with the restic process, or
  network-level manipulation. A session that terminates abnormally fast may
  indicate premature abortion or a suppressed failure.

* **Data volume per session** — "this device's backup is normally Y GB; this
  one transferred 10× that." A volume spike that stays below a hard ceiling
  (which an attacker who has read the reference file would know) is invisible to
  threshold-based detection but visible to a rolling baseline. This is
  specifically the class of signal that z-score detection exists to catch.

* **Slot consumption timing within the day** — "sessions for this device
  historically start within a consistent window; today's started six hours
  outside that window." A structurally valid session (all signatures present,
  slot available) that occurs at an anomalous time is worth surfacing
  independently of its structural validity.

These signals are implied by the Methodology document's Step A categories
("timing relationships between individually unremarkable events", "negative
signals") but have no corresponding reference detector. Implementing them
requires a few weeks of baseline data first — the rolling window is meaningless
until you have real session history to compute it from. The resulting baseline
parameters belong in private configuration, not in any version-controlled file
in this repository.

### VaultAuditWatch: Scheduled Poll vs. Adaptive Window

The current VaultAuditWatch runs on a fixed five-minute schedule with a fixed
lookback window. This is structurally fine but is the clearest example of a
timing parameter that (a) is documented publicly and (b) could be improved by
personalization. The schedule interval and the lookback multiplier are exactly
the calibration values the Methodology's Step D table calls out as belonging in
private config. Changing them from their reference values is one of the
lowest-effort, highest-signal personalizations available.

### Correlation Across Independent Detectors

The reference detectors operate independently: VaultSlotWatch fires on
slot consumption; VaultAuditWatch fires on config mutation. Neither knows what
the other has seen. A correlation layer that asks "did an anomalous Tailscale
config mutation occur within N minutes of a slot consumption?" would be a
stronger combined signal than either detector alone, because it requires
defeating two independent components simultaneously. The Methodology's Step C
(conjunctive correlation) and Step B (independence analysis) describe exactly
this pattern. No reference implementation exists for it because the correlation
window and the identity of the "anomalous" config event are both calibration
parameters that should not be published.

### Incident Response: Eradication, Recovery, and Post-Incident Activity (Structural Gap)

The Post-Install Detection document already defines Containment-level first response per alert (§21, §6A.7). What is not yet defined is what happens after containment: eradication validation (confirming root cause is actually removed, not merely contained), a recovery gate (what must hold true before Vault operations resume), and post-incident review (root-cause writeup and resulting detection-rule updates). Unlike the three gaps above — which deepen the existing Identification-phase detectors — this gap spans a different NIST SP800-61 phase boundary and is tracked separately in Vault_Incident_Response_Roadmap.md.

---

> [!WARNING]
> **REMINDER:** The detection system in this project is designed as a reference.
> It is highly recommended to develop unique behavioral detection metrics or at
> least personally update the security thresholds. See
> [Vault_Detection_Design_Methodology.md](Vault_Detection_Design_Methodology.md)
> for the complete process.
