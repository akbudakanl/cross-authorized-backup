# THE VAULT — 2026-07-16 S3 SUCCESSFUL-COMPLETION CONTAINMENT CHANGELOG

## 1. Reason for this revision

The previous canonical S3 design correctly required two live primary-device phases,
two independent VPS Ed25519 signatures, the requesting device's SSO/MFA, and an unused
device/day slot before fresh STS issuance. However, after legitimate issuance, local
`DONE s3` remained cooperative. A compromised source endpoint could suppress local
`DONE` and retain its already-issued STS/proxy window until the signed one-hour hard
deadline.

This revision preserves the existing dual-device OPEN gate and adds an independent
successful-completion containment path so local `DONE s3` suppression is no longer a
veto after AWS has observed successful repository completion.

## 2. Final security semantics

```text
FRESH S3 OPEN =
  local primary live authenticated s3 phase
  AND opposite primary live authenticated s3 phase
  AND PC-VPS signature
  AND Phone-VPS signature
  AND requesting device SSO/MFA
  AND unused device/day issuance slot

OWN MFA ALONE != FRESH STS ISSUANCE
```

The opposite device is not an always-on preauthorization daemon. Its primary must be
actively participating in the same S3 phase before the opposite VPS signs the fresh
issuance payload.

Successful S3 completion is now inferred independently from the repository event path:

```text
matching snapshots/ ObjectCreated evidence
        AND
later matching locks/ ObjectRemoved evidence
        ↓
exact slot OPEN -> REVOKING
        ↓
immutable completion_revoke_cutoff
        ↓
matching backup-role AWSRevokeOlderSessions inline deny
        ↓
exact slot REVOKED
```

The first stored cutoff is immutable. Event handling is idempotent and tolerates
duplicate/out-of-order S3 delivery. A five-minute reconciliation path checks only a
currently relevant unrevoked slot and refuses to synthesize old completion evidence when
a newer same-device issuance exists.

After its own S3 command succeeds, each clean primary drops local STS environment values,
closes its local cooperative S3 phase, and uses its still-active SSO session only to poll
the shared read-only completion-status Lambda for the opposite device and the exact
shared `calendar_date + session_expires_at`.

When the exact opposite session reaches `REVOKED`, the clean primary authenticates to its
own coordinator and requests:

```text
CLOSE_PEER s3 <own phase token>
```

The local VPS derives the opposite role itself, signs a fresh close-only payload, and
sends it across the existing dedicated `wg-cross` link. The target VPS verifies:

```text
exact peer WireGuard source IP
peer VPS Ed25519 signature
phase == s3
target_role == own role
close lifetime <= 90 seconds
freshness window
session_expires_at == current active shared deadline
```

A valid close can only mark local S3 phase/proxy admission closed. It cannot issue a
proof, mint STS, open RHEL, reset a daily slot, or extend a deadline. A compromised
primary may use its own close credential to cause early denial of service to the opposite
S3 path; this fail-safe DoS residual is accepted instead of giving a compromised target
a containment veto.

## 3. AWS containment components added

```text
Vault-PC-S3-Completion-Revoker
Vault-Phone-S3-Completion-Revoker
Vault-S3-Completion-Status
Vault-PC-S3-Completion-ExecutionRole
Vault-Phone-S3-Completion-ExecutionRole
Vault-S3-Completion-Status-ExecutionRole
Vault-PC-S3-BackupBoundary
Vault-Phone-S3-BackupBoundary
AWSRevokeOlderSessions
2 x S3 snapshot/lock notification configurations
2 x five-minute EventBridge completion reconciliation rules
```

The completion revoker execution roles are device-specific. Each may:

```text
GetItem/UpdateItem on VaultDailyIssuanceSlots
ListBucket on its own bucket for snapshots/* and locks/*
PutRolePolicy on its own exact backup role
write Lambda logs
```

They receive no `sts:AssumeRole`, no S3 object read/write, no opposite bucket, and no
opposite backup-role access.

Before granting `iam:PutRolePolicy`, each backup role receives an exact reviewed
permissions boundary matching its repository/fixed-egress envelope. A compromised
completion revoker can therefore deny its own compartment, but cannot broaden that backup
role beyond the boundary.

## 4. Detection additions

`Vault_Post_Install_Detection_and_Credential_Custody.md` now adds
`VaultCompletionPolicyWatch`.

It observes CloudTrail `PutRolePolicy` calls targeting the two Vault backup roles and
accepts only the exact tuple:

```text
matching completion execution role
matching backup role
policy name == AWSRevokeOlderSessions
```

Unexpected callers or policy names generate a CRITICAL SNS alert. Lambda Errors alarms
and acceptance checks now cover the completion revokers, completion-status function,
completion-policy watcher, and both five-minute reconciliation rules.

## 5. RHEL behavior intentionally unchanged

RHEL does not gain an S3-style repository-event completion plane in this revision.
`DONE rhel` remains an authenticated cooperative early-close signal. The locally verified
dual-signed proof, device/day RHEL opening slot, persisted signed session deadline, and
systemd-managed hard-stop timer remain the RHEL security boundary.

## 6. Residual risk after this revision

The normal successful-completion path is not zero-millisecond. S3 event delivery,
completion-state processing, status polling, signed peer close, and IAM policy propagation
have finite latency.

The clean opposite primary can close target proxy admission after exact AWS completion
state reaches `REVOKED`; this provides a containment layer independent from waiting only
for IAM policy propagation.

If no successful snapshot is created or the successful completion sequence cannot be
established, the session is still an incomplete/failed backup from the system's point of
view. The persisted signed one-hour hard deadline remains the final ceiling.

## 7. Documents changed

```text
Vault_Zero_Trust_Master_Guide_CANONICAL.md
Vault_Threat_Model_and_Risk_Register.md
Vault_Post_Install_Detection_and_Credential_Custody.md
Vault_Extension_Headscale_Control_Plane.md
Vault_Extension_Peer_Relay_Performance.md
Vault_Device_Retirement_and_Migration_Runbook.md
Vault_Deployment_Time_Revalidation_Checklist.md
```

Reviewed and intentionally unchanged because they do not redefine canonical S3 STS
completion semantics:

```text
Vault_Extension_Mutual_Backup.md
Vault_Extension_Capacity_Triggered_Prune_and_Maintenance.md
```

## 8. Executable-block validation performed

The revised embedded executable blocks were extracted from the final Markdown and checked
as follows:

```text
issuance Lambda JavaScript              node --check
completion revoker JavaScript           node --check
completion-status JavaScript            node --check
VaultCompletionPolicyWatch JavaScript   node --check
vault-close-peer.py                     python3 -m py_compile
vault-daily-pc                          bash -n
vault-daily-phone                       bash -n
vault-device-coordinator Go             gofmt + go build
close-payload validation                 go test (target/deadline/freshness/lifetime)
```

All of the above checks passed on the final revised code blocks. The coordinator unit
test accepted a fresh exact-target/exact-deadline close and rejected wrong-target, wrong-
deadline, expired, and greater-than-90-second close payloads.

## 9. Deployment rule

Do not partially apply this revision. The canonical claim that successful S3 completion
is contained before original STS expiration assumes all of the following are deployed and
tested together:

```text
completion row fields in issuance gate
permissions boundaries
both completion revokers
S3 snapshot/lock notifications
five-minute reconciliation
AWSRevokeOlderSessions write path
shared exact-session status Lambda
routine SSO invoke-policy update
coordinator CLOSE/CLOSE_PEER protocol
vault-close-peer helper
both revised daily workflows
completion-policy detection/health checks
negative and propagation tests
```

Until this full set passes the documented day-zero tests, retain the older threat-model
statement: already-issued STS/proxy use may continue until the signed hard deadline.
