---
status: pending
---
# Extension: Hybrid S3 Storage Tiering (Hot Metadata / Cold Data)

> **Status: pending - deliberately deferred.** The operator has paused the project
> and explicitly deferred the architectural decisions below. Nothing in this file is
> adopted; the core guide is intentionally unchanged while this extension is pending.
> The open decision points are collected in the "Operator review checklist" so they
> can be resolved in one sitting later.

## Operator review checklist (decide before adopting)

```text
[ ] Transition delay N for data/: 0 days vs 1 day        (see §2; 1 recommended)
[ ] Adopt the monthly storage-class assertion?           (see §3.1; recommended)
[ ] Adopt the same-day RHEL smoke restore?               (see §3.2; optional/low)
[ ] Confirm rejection of S3 per-transfer data checks      (see §3.3; recommended reject)
```

## 1. Problem statement

The current core guide applies `-o s3.storage-class=DEEP_ARCHIVE` directly on the
backup commands (Section 22.11 and both daily workflows). Restic applies the requested
storage class to **every upload**, including repository metadata: `config/`, `index/`,
`snapshots/`, `keys/`, and `locks/`.

This breaks incremental backups over time. Restic never compares remote data folders;
its delta decision is pure chunk-ID arithmetic against the **index**. Each backup run
must therefore *read* the freshly written index files. The local cache covers previously
seen indexes only, so every run after the first attempts a `GetObject` on cold objects
and fails with `InvalidObjectState`. An all-cold repository is not merely expensive to
verify - its second backup is already structurally broken.

Hybrid tiering is therefore a **correctness prerequisite** for any long-lived Deep
Archive repository, not a cost optimization.

## 2. Design: permanent-hot metadata, lifecycle-cold data

* Remove the three `-o s3.storage-class=DEEP_ARCHIVE` occurrences; uploads land in the
  bucket default (`STANDARD`).
* Add one bucket lifecycle configuration:

```json
{
  "Rules": [
    {
      "ID": "vault-data-to-deep-archive",
      "Filter": { "Prefix": "data/" },
      "Status": "Enabled",
      "Transitions": [
        { "Days": 1, "StorageClass": "DEEP_ARCHIVE" }
      ]
    },
    {
      "ID": "vault-abort-stale-mpu",
      "Filter": {},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 7 }
    }
  ]
}
```

Non-`data/` prefixes receive **no** transition rule and remain `STANDARD`
permanently.

Properties and notes:

* Delta detection is unaffected by data going cold: normal backups read only
  `config/`, `index/`, and transiently `locks/`; `data/` packs are never read until
  restore, `check --read-data`, or prune - none of which run routinely against S3
  (invariant I-13 unchanged).
* Confidentiality is unchanged: metadata objects are client-side restic ciphertext.
  "Readable" means fetchable, not decryptable without the repository password.
* S3 event notifications (snapshot-created, lock-removed) are independent of storage
  class; the completion revoker path is unaffected.
* Lifecycle evaluations run about once per day. A `Days: 0` setting means "eligible
  at the next evaluation", i.e. typically ≤24 h but **not** deterministic at
  sub-day granularity. `Days: 1` guarantees every fresh object stays readable for at
  least ~24–48 h, which matters only if a future control ever needs to read fresh
  data objects. Never couple timing-critical logic to sub-day lifecycle behavior.
* Cost effect: negligible-to-positive. Brief `STANDARD` residence of data before
  transition costs fractions of a cent per GB-day, and Standard PUT request pricing
  is lower than Deep Archive PUT pricing.

## 3. Verification layers considered

### 3.1 Monthly storage-class assertion (recommended, free)

The hybrid design introduces exactly one new failure mode: **silent lifecycle
drift** (rule disabled/edited → either everything stays Standard and costs creep, or
metadata accidentally transitions and backups break). The matching control reads no
cold data and costs nothing:

```text
Monthly operator step (or scripted):
  aws s3api head-object on sampled keys and assert StorageClass:
    data/<object older than 48 h>          -> DEEP_ARCHIVE
    index/, config/, snapshots/, keys/, locks/  -> STANDARD
  Any deviation -> alert (existing notification channels).
```

This replaces the earlier idea of a short post-transfer window for data checks: no
timing coupling, no restore cost, and it targets precisely the fragile piece of the
hybrid design.

### 3.2 Same-day RHEL smoke restore (optional, low priority)

Mechanism: after a successful RHEL-phase backup, take the newest snapshot ID,
deterministically select a few small files (date-seeded) via `ls --json`, restore
them with `restic restore --include` through the append-only rest-server, and compare
SHA-256 against the source. Slot: after `summary_from_json`, before `post_rhel_done`.

Honest assessment: the quarterly staged full-read check already bounds corruption
latency at ≤28 days (average ~14). Same-day smoke restore shortens this for freshly
uploaded packs only; its marginal value is modest, its cost near zero. Defer or adopt
- neither choice affects the security model.

### 3.3 Rejected: S3 per-transfer data verification

Recorded as rejected so it is not revisited:

```text
Transfer-time failure       -> restic exits non-zero; workflow stops          (covered)
In-transit corruption       -> S3 validates ingest checksums; rejects       (covered)
At-rest bit rot in S3       -> effectively nonexistent (durability design)  (covered)
Crypto-layer fault          -> AEAD fails loudly at write, or is a global
                               catastrophic bug no per-transfer check finds (out of scope)
Cold-read economics         -> GDA restore = hours + retrieval fees;
                               violates I-13's routine-read prohibition    (rejected)
```

### 3.4 Out of scope here: source-side anomaly detection

Garbage-in problems (failing phone storage, cloud-sync placeholder stubs, gallery
bugs) are uploaded faithfully by restic and are **invisible to every repo-side check**
including smoke restores, which compare against the possibly-corrupt source. Detection
requires statistical session anomalies (volume/file-count deviations). This is already
catalogued as the highest-priority known gap in
`docs/core/Detection/README.md` ("Session Behavioral Signals") and must be designed
there, not in this extension.

## 4. Prerequisites (on adoption)

* Decision record for each item in the operator review checklist above.
* Administrator workstation access for `put-bucket-lifecycle-configuration`.
* Identification of the three flag sites: Section 22.11 init command, PC daily
  workflow, Phone daily workflow.

## 5. Install / migration

1. Apply the lifecycle configuration to both buckets (`put-bucket-lifecycle-configuration`
   with the JSON above; adjust `Days` per the recorded decision).
2. Remove `-o s3.storage-class=DEEP_ARCHIVE` from Section 22.11 and both daily
   workflow scripts (`bash -n` after edit).
3. Add the §3.1 assertion step to the monthly operator procedure.
4. Day-zero acceptance:

```text
[ ] Consecutive-day incremental backup succeeds end-to-end (fresh index readable).
[ ] get-bucket-lifecycle-configuration lists the exact reviewed rules.
[ ] After >= 48 h, sampled head-object calls show data/=DEEP_ARCHIVE and all
    metadata prefixes=STANDARD.
[ ] Completion revocation still fires (snapshot + lock removal observed).
[ ] Existing repositories remain usable: restic snapshots lists normally.
```

## 6. Removal / rollback

Re-add the storage-class flags, delete the lifecycle configuration, and remove the
assertion step. **Irreversibility notice:** transitions are one-way at the API level.
Objects already transitioned to DEEP_ARCHIVE stay cold unless individually restored
and copied back (hours + fees). Rollback therefore restores the *old behavior for
future writes only*; it does not re-warm existing data, and no repository history is
lost either way.

## 7. Threat-model delta (apply only on adoption)

* No invariant weakened. I-13 wording gains one clarification: GDA receives bulk data
  via lifecycle transition rather than write-time class; routine cold reads remain
  prohibited.
* New asset/risk: lifecycle configuration drift. Mitigation: §3.1 assertion; drift is
  detection-grade (cost creep or availability breakage), not confidentiality.
* T-09: unchanged direction; Standard PUT requests are marginally cheaper than Deep
  Archive PUTs, so the flood-vector bound does not worsen.
* Recovery path availability improves: metadata is instantly fetchable during disaster
  recovery instead of requiring restore-before-index.
* Change-log entry template:
  `YYYY-MM-DD | S3-TIER | Hybrid storage tiering: hot metadata/cold data via lifecycle;
  storage-class flags removed; monthly storage-class assertion added (extension adopted).`

## 8. Documents this extension would touch on adoption

```text
Vault_Zero_Trust_Master_Guide_CORE.md   (§22.11 flag removal, §22.12 lifecycle step,
                                         Part 3 workflow blocks x2, monthly procedure)
Vault_Threat_Model_and_Risk_Register.md (I-13 clarification + change-log entry)
docs/core/Detection/README.md           (no change; cross-reference only)
```
