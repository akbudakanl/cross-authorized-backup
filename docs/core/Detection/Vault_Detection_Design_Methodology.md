# VAULT - DETECTION DESIGN METHODOLOGY
## Deriving a Personal, Non-Public Detection Layer from a Public Reference Blueprint

> **Status:** companion process document to
> `Vault_Post_Install_Detection_and_Credential_Custody.md`.
>
> **What this document is:** a repeatable *method* for turning a published detection
> reference into a personal, structurally-different detection layer.
>
> **What this document is not:** a list of specific thresholds, weights, window sizes,
> resource names, or canary locations to adopt. Any such list would itself become a
> second public ruleset the moment this file is committed. The output of applying this
> method belongs in a private notebook, a private config store, or your own head - never
> in the same repository as this file.

---

## 0. Why this document exists

`Vault_Post_Install_Detection_and_Credential_Custody.md` already states the core
problem clearly: the detection plane described there is a **reference**, and using it
verbatim gives a sophisticated attacker who has read the same public repo a finite,
derivable blind spot. The fix is not to stop publishing detection architecture - the
industry norm (MITRE ATT&CK, SigmaHQ, Elastic Detection Rules) is the opposite - the fix
is to separate **structure** (safe to publish) from **calibration and placement**
(must be private and personal).

This document is the missing middle step between "I understand that principle" and "I
have my own detection plane." It is a **generator**, not an **answer key**. Read it,
apply it to your own copy of the reference file, and produce artifacts that live outside
version control.

---

## 1. Read the reference file as a signal inventory, not a rulebook

The first mistake is treating the reference document as a deployment checklist to
execute top-to-bottom. Instead, read it once purely to extract **where the architecture
already produces a fact that could be true or false** - every such fact is a candidate
signal, independent of whether the reference file turns it into an alert.

A working method for this pass:

1. For every component in the architecture, ask: *"What does this component assume
   about who/what is allowed to touch it?"* The reference file already answers this
   for each piece - an exact-device coordinator, a bounded IAM role, a fixed Caddy
   source IP, a single expected `rest-server` credential holder. Each assumption is a
   **structural signal**: a boolean-ish fact about expected identity, expected caller,
   or expected sequence, independent of any numeric tuning.
2. For every structural signal, ask: *"Is there a numeric or time-based parameter
   attached to how this is evaluated?"* Debounce windows, lookback intervals, retry
   thresholds, poll cadences - these are **calibration signals**. They ride on top of a
   structural signal but are not the same thing.
3. Separately catalog **who currently learns about a violation**: in-guest process,
   host-side process, an out-of-band AWS watcher, a human via SNS. This is the
   **observation layer** for each signal, and it matters independently of the signal
   itself - a signal observed only by the component that might be compromised is worth
   less than one observed from outside that component's control boundary.

Do this extraction exercise yourself, on your own copy, before touching Part 2. The
value of the exercise is in doing it, not in reading a pre-made list - a pre-made list
of "here are the eleven signals in this file" would just be a second, more convenient
public ruleset.

---

## 2. The generative process

Eight steps. Apply them per-detector, not once for the whole system - each detector in
the reference plane (slot-consumption watcher, config-audit watcher, STS caller
watcher, coordinator/RHEL auth-failure watchers, MicroVM zero-tolerance layer, canaries,
egress logging) is a separate exercise with a separate output.

### Step A - Signal harvesting

Beyond the pass in Part 1, actively look for signals the reference file did **not**
use, because your environment differs from the generic one it was written for. Sources
worth checking systematically:

- Anything your infrastructure already logs for operational reasons but doesn't
  currently feed into security alerting (systemd journal fields, provider billing
  anomalies, DNS resolver logs, package-manager transaction logs).
- Timing relationships between two events that are individually unremarkable but
  jointly unusual (e.g., an expected daily process that normally takes N minutes and
  this time took a very different amount of time).
- Negative signals - the *absence* of an expected periodic event (a heartbeat that
  stops) is as much a signal as the presence of an unexpected one, and it's a category
  the reference file already uses once (`poll blindness`) but is worth deliberately
  re-deriving for your own components rather than copying only that one instance.

### Step B - Independence analysis

Group every signal by **what would have to be compromised to falsify it**. This is the
generalization of the reference file's own Layer 1 / Layer 2 pattern (in-guest
best-effort vs. host-side absolute truth): a guest-reported signal and a host-observed
signal about the same event are not two confirmations of one fact, they are one fact
observed from two independence classes, and only the host-side one survives a guest
compromise.

For every signal you harvested in Step A, ask one question: *"If the component this
signal describes were fully compromised, could that same compromise suppress or fake
this signal?"* If yes, the signal needs a paired out-of-band observation before it can
be trusted as authoritative - exactly the reasoning the reference file applies to
justify why the host-side network-namespace check (Layer 2) cannot be skipped even
though the in-guest check (Layer 1) is faster.

Signals that pass through genuinely separate trust domains (e.g., an AWS-side watcher
observing control-plane events versus a VPS-local watcher observing its own journal) are
your strongest building blocks, because defeating both requires compromising two
different security boundaries, not one.

### Step C - Aggregation function design

This is where "single threshold = single alert" becomes "weighted combination of
independent signals." You are not picking numbers here - you are picking a **shape**
for how signals combine. Three shapes, with tradeoffs:

- **Weighted linear scoring.** Each signal contributes a score; sum against a threshold.
  Simple to reason about and to audit later, but a determined attacker who recovers the
  weights (through repeated probing or through the same disclosure problem the
  reference file describes) can still solve a linear system. Best suited to signals
  where you want graceful degradation - a lot of mildly-unusual activity should count
  for something even if no single input is disqualifying.
- **Conjunctive correlation.** Alert only when signals from two or more independence
  classes (per Step B) co-occur within a window. Harder for an attacker to reason about
  because the requirement is combinatorial rather than additive, but a false-negative
  risk exists if legitimate simultaneous conditions never happen to co-occur during
  testing.
- **Adaptive/statistical baseline.** Compare current behavior to a rolling
  per-deployment history (moving average and spread) rather than a fixed number. The
  practical benefit is that the "threshold" is now a private, drifting value that
  exists only in your own historical data - nobody reading your public architecture can
  recover it without also having your data.

Which shape (or combination) fits which detector is a judgment call specific to your
deployment's actual traffic patterns - that judgment call, and the resulting
weights/windows, is the private output of this step. Nothing about the choice needs to
leave your private notes.

### Step D - Draw the public/private boundary explicitly

For every detector, produce two lists, kept in two different places:

| Goes in the public repo (structure) | Goes in private config/notes (calibration) |
|---|---|
| Which event sources feed the detector | Exact debounce/lookback/window values |
| The general shape of the aggregation (linear / conjunctive / adaptive) | The actual weights or thresholds |
| The existence of a canary/honeytoken mechanism | The exact path, name, or content of the canary |
| The existence of redundant observation layers | Which specific fields distinguish "expected" from "unexpected" identity |
| Resource *types* used (stream, event bus, scheduled function) | Resource *names* that double as identifiers (table names, topic names, key prefixes) |

The last row matters more than it looks: a resource name that appears verbatim in a
public reference file (a specific DynamoDB table name, SNS topic name, or event-key
prefix pattern) is not just architecture, it is also a literal string an attacker can
search for or fingerprint against - cheap for them, cheap for you to change. Treat
verbatim identifier reuse the same way you'd treat reusing a default password: low
effort to fix, meaningful reduction in exposure.

### Step E - Generalize the redundancy pattern

Take the specific in-guest/host-side pattern from the reference file's MicroVM section
and restate it as a question you ask of **every** detector you design, not just that
one: *"What is the smallest compromise that would let the monitored component lie to
its own detector?"* Then place at least one observation point outside whatever you
identified as that smallest compromise.

This is a design discipline, not a checklist item you complete once. Revisit it any
time you add a new component to the architecture - new components create new "smallest
compromise" boundaries that didn't exist before.

### Step F - Inject personal, non-public entropy

Beyond weights and thresholds, decide where your deployment will simply differ from any
public description in ways that require no architectural change, only a personal
choice made once and kept private:

- Resource naming that doesn't follow an obvious template.
- Canary placement chosen from your own filesystem/namespace conventions rather than
  the illustrative examples in any reference document (illustrative examples exist to
  teach the *pattern* of a plausible-but-fake artifact - reusing the literal example
  defeats the purpose).
- Small, deliberately non-round timing offsets on periodic jobs, so that schedule
  fingerprinting doesn't trivially match a documented default.

None of these require new code. They require treating "what's the default in the
reference doc" as a checklist of things to deliberately change, once, privately.

### Step G - Adversarial self-testing

Before trusting a detector, argue against it the way an attacker who has read your
public architecture (but not your private calibration) would. For each detector, write
down - privately - the answer to: *"Knowing everything that's public about this
detector, what is the minimum-effort behavior that stays under it?"* If you can answer
that question easily, the detector is still leaking too much through its public
structure alone, and you need another pass at Step D or Step C.

The reference file's own acceptance-test sections (bootstrap tests, negative tests,
detector-blind alarms) are a template for *how* to structure this testing discipline -
apply the same rigor to your privately-calibrated version, but keep the actual test
inputs/outputs in your private notes, since a documented negative test is itself a
description of exactly where the boundary sits.

### Step H - Treat calibration as a lifecycle, not a deployment step

Baselines drift, infrastructure changes, and a value that was well-calibrated at
install time decays in relevance. Build a recurring, private review cadence - quarterly
is a reasonable default - that revisits Steps C, D, and F: recompute adaptive baselines
against recent history, confirm resource identifiers haven't leaked into any log output
or ticket that later became public, and rotate canary placement.

---

## 3. Per-detector worksheet template

Copy this table once per detector already present in your architecture (slot-watcher,
config-audit watcher, STS-caller watcher, coordinator/RHEL auth-failure watchers,
MicroVM Layer 1/2, canaries, egress logging). Fill it in your private notes - the empty
template itself is safe to keep alongside your public documentation; the filled version
is not.

```text
Detector name:
Signal source(s) (Step A):
Independence class of each source (Step B):
  - source 1: [in-band / out-of-band] w.r.t. [component]
  - source 2: ...
Aggregation shape chosen (Step C): [linear / conjunctive / adaptive / combination]
Public structure recorded where: [public repo path]
Private calibration recorded where: [private store - NOT in the public repo]
Smallest compromise that could falsify this signal (Step E):
Out-of-band confirmation point for that compromise:
Personal entropy applied (Step F): [naming / placement / timing offset]
Last adversarial self-test date (Step G):
Last calibration review date (Step H):
```

---

## 4. Math toolbox (conceptual - no prescribed values)

These are the building blocks referenced in Step C, explained generically so you can
pick the right tool without this document dictating the actual numbers.

**Adaptive baseline (z-score).** For a metric `x` with rolling mean `μ` and standard
deviation `σ` computed over your own recent history, `z = (x − μ) / σ` expresses how
unusual the current value is relative to *your* deployment's own past, not a fixed
global number. A common practice is to alert past a chosen number of standard
deviations, but which number, and over what window, is precisely the private
calibration this document keeps pointing you toward deciding for yourself.

**Weighted linear score.** `S = Σ (wᵢ · sᵢ)` over normalized per-signal scores `sᵢ` and
weights `wᵢ`. Useful when you want partial credit for multiple mildly-unusual signals to
add up. The weight vector is exactly the "key" in the Kerckhoffs-adjacent framing -
structurally, everyone can know a weighted sum is used; only you know the weights.

**Rule-space entropy (informal).** If an attacker must guess among `k` roughly
equally-likely evasion strategies to stay under your detector, the space they must
search grows with the number of *independent* conditions your aggregation requires
(Step B) - one conjunctive condition doubles their guesswork if it's genuinely
independent of the others, and does nothing if it's redundant with a condition they've
already satisfied. This is the formal justification for prioritizing independence
(Step B) over simply adding more correlated signals.

**Bayesian evidence combination.** Where signals are probabilistic rather than binary,
combining independent detectors' posterior beliefs (rather than raw scores) avoids
double-counting correlated evidence and gives a principled way to express "moderately
confident from three weak signals" versus "certain from one strong signal." Heavier
to implement than a linear score; worth it mainly for detectors with genuinely noisy,
probabilistic inputs rather than crisp expected/unexpected identity checks.

---

## 5. Anti-patterns - things that quietly turn structure into a leaked parameter

- Reusing a reference document's example resource names (table names, topic names, key
  prefixes) verbatim in a real deployment.
- Reusing a reference document's illustrative canary paths or canary content instead of
  choosing your own.
- Reusing exact debounce/lookback/poll-interval values from a reference document without
  changing them.
- Committing your filled-in worksheet (Section 3) to the same public repository as this
  methodology document - a filled worksheet is a calibration record, not a process
  description.
- Publishing your own final weights or thresholds "for transparency" in a project
  changelog, issue tracker, or commit message, even if the main config file itself is
  gitignored - history persists (see the git-history discussion this project has
  already worked through for credentials; the same logic applies to detection
  calibration).
- Assuming a documented negative test is safe to publish. A negative test necessarily
  describes the exact boundary condition a detector uses - treat it with the same
  privacy as the threshold it's testing.

---

## 6. Worked walk-through of the method (structure only, no filled answers)

To make Sections 1–2 concrete, here is the method applied - not completed - to three
pieces already in `Vault_Post_Install_Detection_and_Credential_Custody.md`:

**VaultAuditWatch (Tailscale config-audit anomaly detector).** Step A: the structural
signal is "configuration mutation occurred outside a declared maintenance window."
Step B: this is genuinely out-of-band relative to either VPS, since it observes the
Tailscale control plane via a separate federated identity - strong independence class.
Step C: the reference file already uses a fixed lookback/schedule pair; your private
exercise is deciding whether a fixed schedule is the right shape for your traffic, or
whether an adaptive window fits better. Step D: the schedule interval and the exact
actor-ID allowlist are calibration; the fact that a five-minute-class scheduled Lambda
polls audit logs is structure.

**Local/container canaries (Section 9 family).** Step A: the structural signal is "a
fake credential file was read." Step B: this is *not* independent of the VPS root
compromise it's meant to catch (the reference file says this explicitly) - so per Step
E, it needs an out-of-band forwarding path before it can be trusted as more than an
opportunistic tripwire. Step F: the entire value of a canary depends on its exact
placement being unpublished - this is the clearest possible example in the whole
architecture of "structure public, parameter private."

**MicroVM zero-tolerance auth (Layer 1 / Layer 2).** Step B is already done for you in
the reference text - it names the independence classes explicitly (guest vs. host).
The generative exercise here is Step E applied elsewhere in your architecture: which
other components currently have only a guest-side / in-band detector and are missing
their own Layer 2?

Your own filled version of Section 3's worksheet, for these three detectors and every
other one in your architecture, is the actual deliverable of this methodology - and it
belongs in a private notebook, not in this file or its neighbors.

---

> [!NOTE]
> This document describes a process for producing a personal detection design. It
> deliberately contains no thresholds, weights, resource names, or canary placements of
> its own, because publishing those would recreate the exact disclosure problem this
> document exists to solve. If a future revision of this file starts to contain
> specific numbers, that is a sign it has drifted from methodology into calibration and
> the specific numbers should be moved out before committing.
