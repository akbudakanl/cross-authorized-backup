---
status: pending
---
# Extension: Phase-Liveness Gating (Mid-Session Mutual Termination)

> **Status: pending - deferred.** Requires measured calibration data before any
> decision. See the operator review checklist at the end of this file.

## 1. Problem statement

The core baseline's stated practical goal includes a property the documented
mechanics deliberately do not implement: continuous mutual liveness during a
transfer. Today, once a dual-signed proof opens a session, a brief control-socket
loss does **not** revoke the issued STS credential or close an open RHEL backend
(guide §23.4 pairing notes; threat model T-01/T-11 residuals). Mid-session abuse by
malware sharing the window is therefore bounded only by successful-completion
containment (S3) or the signed one-hour deadline (both legs) - up to ~60 minutes
regardless of whether the opposite primary is still present.

## 2. Design

Signed liveness attestations across the existing `wg-cross` link, gating the same
admission points that CLOSE already controls:

```text
During any active s3/rhel session:
  each coordinator periodically (default 30 s) emits to its peer over wg-cross:

    PHASE_LIVE <target> <shared_session_expires_at> <seq>

Validation mirrors the existing CLOSE-payload rules exactly:
  exact peer WireGuard source IP
  peer VPS Ed25519 signature
  target == own role, phase match
  session_expires_at == currently active shared deadline
  freshness <= 90 s, strictly increasing seq (replay rejected)

Enforcement points:
  S3 leg   : the exact-host proxy admits traffic only while the counter-signal
             from the opposite VPS is fresh (grace G seconds); expiry closes
             admission for new and existing tunnels
  RHEL leg : the local gate's hard-stop timer is refreshed only by valid dual
             attestations relayed through the coordinators; the persisted signed
             deadline remains the final ceiling either way

Re-admission: if attestations resume before the deadline, the proxy reopens within
the SAME session window (not REVOKED); restic's same-credential retry resumes the
transfer. Nothing is revoked unless snapshot+lock-release evidence completes.
```

Security properties:

* A compromised endpoint cannot forge the opposite attestation (no key).
* `PHASE_LIVE` carries no issuance authority - it cannot open, extend, reset, or
  mint anything; abuse ceiling is denial of service, identical in kind to the
  already-accepted `CLOSE_PEER` fail-safe DoS.
* Opening guarantees are untouched: dual signatures, live phases, slots, MFA.

## 3. Honest gain assessment

This shrinks the mid-session residual in T-01/T-07/T-11 from "≤ 1 hour" to
"≤ grace period" for the specific case where the clean peer goes dark mid-window.
It does NOT change who can open sessions, and it adds nothing against an endpoint
that stays online (the endpoint itself is always inside its own window). Treat it
as incremental tightening toward the stated goal - worthwhile, not transformative.

## 4. Trade-offs and known hazards (must be resolved, not ignored)

```text
Availability coupling   peer Wi-Fi/Doze drop now kills the other leg after grace.
Finish-skew hazard      the phone typically finishes earlier and closes its phase;
                        naive strict liveness would truncate every long PC delta.
                        Resolution options (choose one):
                          (a) phases persist until both sides pass the completion
                              barrier (S3 workflow already serializes; extend to RHEL)
                          (b) grace sized above max observed inter-device skew
Flapping                hysteresis: reopen requires K consecutive valid attestations
New DoS surface         peer can kill own-compartment session by dropping out;
                        accepted class (same as CLOSE_PEER veto-free containment)
Clock/threshold drift   all checks bind to the shared signed deadline, never to
                        wall-clock comparisons between hosts
```

## 5. Prerequisites

* Two weeks of representative paired-session measurements: per-device transfer
  durations, finish-time deltas, typical transient disconnect lengths.
* A recorded decision on resolution option (a) vs (b) above and on grace G.
* Coordinator and proxy source trees updated together (protocol change).

## 6. Install / migration (outline on adoption)

1. Implement `PHASE_LIVE` emission/validation in both coordinators (reuse the
   CLOSE payload validator verbatim; add sequence tracking).
2. Gate proxy admission on counter-signal freshness; add structured events for
   liveness-expiry closures distinct from DONE/deadline closures.
3. Extend the RHEL gate timer-refresh path for dual attestations.
4. Update both daily workflows if option (a) is chosen (phase lifetime extends past
   local completion until the barrier passes).
5. Day-zero negative tests: forged/wrong-deadline/stale/replayed PHASE_LIVE all
   rejected and alarmed as `PEER_PAYLOAD_INVALID`; peer silence beyond grace closes
   admission; resume-within-window continues the same backup without new issuance;
   suppressing attestations cannot extend anything past the persisted deadline.

## 7. Removal / rollback

Revert coordinator/proxy/gate binaries to the prior tagged versions and restore the
workflow scripts. Rollback restores the deadline-bounded residual exactly; no
repository, credential, or slot state changes irreversibly.

## 8. Threat-model delta (apply only on adoption)

* I-06/I-07 semantics extended: mid-session containment gains a liveness bound in
  addition to completion revocation and the signed deadline. The sentence "brief
  control-socket loss alone does not revoke..." is replaced by the grace-bounded
  wording.
* T-01/T-07/T-11 residuals tightened as described in §3.
* New accepted DoS: peer-initiated early termination (documented alongside the
  existing `CLOSE_PEER` acceptance rationale).
* Change-log entry template:
  `YYYY-MM-DD | LIVENESS | Signed PHASE_LIVE attestations gate S3/RHEL admission
  mid-session (grace Ns); deadline remains final ceiling.`

## Operator review checklist (decide before adopting)

```text
[ ] Enforcement scope: S3-only, or S3 + RHEL gate refresh?
[ ] Finish-skew resolution: option (a) barrier-held phases vs (b) oversized grace?
[ ] Grace duration G and hysteresis K, from measured data (not guessed).
[ ] Accept the peer-initiated DoS residual explicitly in the register.
[ ] Confirm the two-week measurement prerequisite is satisfied first.
```
