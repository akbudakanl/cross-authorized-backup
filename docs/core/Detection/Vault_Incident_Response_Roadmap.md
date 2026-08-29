# VAULT - INCIDENT RESPONSE ROADMAP

## Eradication, Recovery, and Post-Incident Activity

---

## 1. Scope and phase boundary

This document begins where the Post-Install Detection document stops.

```text
Already defined (Post-Install Detection §2, §21, §6A.7):
  - Alert severity model (INFO / CRITICAL)
  - First response matrix - immediate containment actions per alert type
  - Auth-failure-specific response (AUTH_TOKEN_REJECT, PEER_SIGNATURE_INVALID,
    WATCHER BLIND)
  - Operator rule: preserve evidence, then contain, then repair

Not yet defined (this document):
  - How "preserve evidence" is actually done, consistently, across alert types
  - How you confirm the "repair" step actually removed the root cause
    (Eradication)
  - What must be true before Vault operations resume (Recovery)
  - What happens after the incident is over (Post-Incident Activity)
  - When you are allowed to call an incident closed
```

Per NIST SP800-61, the Post-Install document covers Identification and the
opening move of Containment. This document covers the remainder of
Containment, Eradication, Recovery, and Post-Incident Activity.

> [!IMPORTANT]
> This document does not replace §21 or §6A.7. When responding to a live
> alert, start there. Use this document once the immediate containment step
> is done and you are deciding what happens next.

---

## 2. Evidence handling standard

Every alert block in the Post-Install document says some version of "preserve
the logs." This section makes that instruction concrete and consistent
instead of restating it per alert.

### 2.1 What counts as evidence

```text
CloudTrail event records (raw JSON, not console screenshots)
Lambda execution logs for the triggering detector and any detector that
  fired in the same window
DynamoDB item state at time of alert (export, do not just read)
Tailscale audit log entries for the relevant actor/time window
Coordinator and watcher journal entries (journalctl, not just the alert line)
Network-level evidence where applicable (ss output, connection source IPs)
```

### 2.2 Where evidence lives

```text
Evidence never stays only on the compartment that generated it.
Export to a location outside both VPS compartments before doing anything
  else - a local encrypted volume on a device that was not part of the
  suspected incident, not a third VPS in the same trust boundary.
Timestamp the export directory with the alert time and detector name,
  not the export time.
```

### 2.3 Retention

```text
Minimum retention: until the incident is formally closed (Section 6) plus
  one full post-incident review cycle.
Do not delete evidence to "clean up" while eradication status is still
  Suspected or Unconfirmed.
Evidence from closed incidents that fed a detection-rule or documentation
  change should be kept indefinitely as the record of why that change
  exists.
```

### 2.4 Integrity

```text
Prefer exports that include a hash or checksum of the export itself.
If exporting CloudTrail/Lambda logs manually, record the export command
  and timestamp alongside the export - the chain of custody is you,
  and an unrecorded manual step is a gap in that chain.
```

---

## 3. Eradication criteria

"Rotate/rebuild" is not eradication by itself - it is the mechanism.
Eradication is confirmed when the checklist for the relevant category is
fully true. Categories below map to the alert families already defined in
Post-Install Detection §21 and §6A.7.

### 3.A Credential or identity compromise

*(expiry actor wrong-target mutation, unexpected STS caller, AUTH_TOKEN_REJECT
threshold, PEER_SIGNATURE_INVALID/PEER_PAYLOAD_INVALID)*

```text
[ ] The specific credential, token, or key implicated has been rotated -
    not just the account/role it belongs to.
[ ] The old credential's issuance/authorization path has been checked for
    other uses in the same window (was it used anywhere else before
    rotation?).
[ ] Evidence review shows no second, independent path the attacker could
    have used to re-establish the same access (e.g., a second stored copy
    of the same key, a second trust relationship).
[ ] If the credential lived on a specific VPS/device, that compartment's
    other secrets are reviewed for co-location exposure, not assumed clean
    by association.
[ ] The rotation itself is verified to have propagated - old credential
    confirmed rejected, not just confirmed reissued.
```

### 3.B Unexpected privileged action, compromise not yet confirmed

*(unexplained slot consumption, unexpected completion-policy mutation)*

```text
[ ] The action has an explanation that is independently verifiable
    (not just "I probably did that") - e.g., corroborated by a second log
    source or a device you have physical access to.
[ ] If no explanation is found: escalate to 3.A and treat the owning
    credential as compromised rather than leaving this category open
    indefinitely.
[ ] Slot/policy state has been reconciled to a known-good value, not left
    in whatever state the unexplained action produced.
```

### 3.C Detection blind spots

*(DETECTION BLIND, WATCHER BLIND)*

```text
[ ] Root cause of the blind window is identified (scheduler failure,
    identity federation failure, API unavailability, etc.) - not just
    "it's reporting again now."
[ ] The blind window itself has been manually reviewed using an
    independent evidence source for that period (you cannot trust the
    blind detector's own silence as evidence nothing happened).
[ ] A repeat of the same root cause is either fixed or has a documented
    residual-risk acceptance (see Post-Install §24 style).
```

### 3.D Root or administrative compromise

*(AWS root activity)*

```text
[ ] Root password and MFA rotated from a clean, independently verified
    device.
[ ] Every active credential/session issued during the suspected window
    has been enumerated and revoked, not just the one that triggered the
    alert.
[ ] CloudTrail reviewed for the full account, not just the Vault-scoped
    resources, since root-level compromise is not bounded by Vault's own
    IAM boundaries.
```

---

## 4. Recovery / resumption gate

Post-Install §22 is a checklist for signing off a *new deployment*. This is
its counterpart for signing off *resuming operations after an incident*. Do
not resume normal Vault sessions until every applicable item is true.

```text
[ ] Eradication checklist for the relevant category (Section 3) is fully
    checked, not partially.
[ ] All evidence for this incident has been exported per Section 2 before
    any state was reset or logs aged out.
[ ] The specific detector(s) involved in identifying this incident have
    been re-verified functional (run the relevant acceptance test from
    Post-Install §22, not assumed working because it worked before).
[ ] Any rotated credential/key has been confirmed live end-to-end with a
    real (not synthetic) low-stakes operation before resuming normal use.
[ ] No open item from Section 3 is in "Suspected" or "Unconfirmed" state.
[ ] You have written - even briefly - what you believe happened, before
    resuming. If you cannot write one sentence explaining the root cause,
    you are not ready to resume; you are ready to accept unknown risk,
    which is a different decision and should be made consciously, not by
    default.
```

---

## 5. Post-incident activity

Complete this after Section 4 is fully checked, not before. Use it as a
template - fill it in per incident, real or simulated (Section 7).

```text
Incident ID / date:
Detector(s) that fired:
Time from event to first alert:
Time from alert to containment action:
Time from containment to eradication confirmed (Section 3):
Root cause (one paragraph, plain language):
What worked:
What did not work, or was slower than it should have been:
Detection changes made as a result (threshold, new signal, new correlation):
Documentation changes made as a result (this file, Post-Install doc, README):
Residual risk accepted, if any, and why:
```

Any change this produces to a threshold, weight, or baseline value belongs
in private configuration per the Design Methodology's public/private
boundary (Step D) - not copied verbatim into this file if doing so would
recreate the disclosure problem the Detection README addresses.

---

## 6. Incident closure criteria

An incident is closed when all of the following are true:

```text
[ ] Section 4 (Recovery / resumption gate) is fully checked.
[ ] Section 5 (Post-incident activity) is filled in, even briefly.
[ ] Any detection or documentation change identified in Section 5 has
    either been made, or has been explicitly deferred with a reason
    (not silently dropped).
[ ] You have made an explicit decision - "closed" is a statement you make,
    not a state that happens when you stop thinking about the incident.
```

In a single-operator project there is no second reviewer to sign off. The
discipline this section enforces is writing the closure decision down
instead of letting the incident fade out unresolved.

---

## 7. Practice log - tabletop walkthroughs

Real incidents are (hopefully) rare. This section exists so that eradication
and recovery decision-making is not exercised for the first time during an
actual compromise. Run at least one scenario end-to-end using Sections 3–6,
and log it here exactly as if it happened, using the Section 5 template.

```text
Scenario log:
  [none run yet]

Suggested first scenario:
  Post-Install §21 "expiry actor performed non-expiry/wrong-target
  mutation" - chosen first because it has the clearest existing first
  response steps to build on, and touches Sections 3.A, 4, and 5 without
  requiring the root-compromise assumptions of 3.D.
```

---

*Cross-references: Post-Install Detection §2 (severity model), §21 (first
response matrix), §6A.7 (auth-failure response), §22 (deployment acceptance
checklist), §24 (security limits - do not overclaim). Design Methodology
Step D (public/private calibration boundary).*
