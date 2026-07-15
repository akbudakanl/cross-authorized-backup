# VAULT — DEVICE RETIREMENT AND MIGRATION RUNBOOK

**Document type:** canonical operational lifecycle runbook  
**Architecture reference:** 2026-07-16 RHEL 9 BYOL/BYOI + Tailscale Tailnet Lock + outbound-only + no-prune + S3 successful-completion revocation + signed peer close + no-custom-SELinux-policy baseline
**Applies to:** PC and Phone primary-device compartments  
**Purpose:** replace, retire, rebuild, or permanently remove a primary device without weakening cross-authorization, Tailnet Lock, exact-device expiry, daily-slot, or repository-isolation invariants

---

## 0. Scope and security objective

Use this runbook when a PC or Phone is replaced, lost, stolen, rebuilt, suspected compromised, or permanently retired.

A device migration is not merely:

```text
install Tailscale
copy files
continue backup
```

It changes identity bindings used by:

```text
Tailnet Lock membership
exact expected Tailscale NodeID
device-expiry helper
Tailscale audit allowlists
cross-authorization ceremony
phase-token verifier
AWS Identity Center gate + shared read-only completion-status access path
close-only peer S3 authority bound to the device's own phase token/coordinator role
restic repository-secret custody
operator evidence records
```

Security objective:

> A retired, lost, stolen, compromised, or superseded primary must not remain an accepted Vault authorization participant merely because the replacement device works.

---

## 1. Canonical lifecycle principle

Use this order:

```text
freeze old identity
        ↓
preserve required plaintext and recovery material
        ↓
provision replacement as a new identity
        ↓
approve replacement membership explicitly
        ↓
update exact-device bindings
        ↓
run negative tests
        ↓
revoke/remove old identity
        ↓
run a complete synthetic Vault ceremony
```

Do not copy Tailscale state directories, node keys, Tailnet Lock signer state, VPS signing keys, or the opposite device's secrets to the replacement.

A replacement device is a new cryptographic/node identity.

---

## 2. Event classifications

### CLASS A — Planned replacement

Examples:

```text
new laptop
new phone
scheduled SSD replacement
clean OS reinstall with old device still controlled
```

### CLASS B — Lost or destroyed device

Examples:

```text
lost phone
stolen device with compromise unproven
SSD failure
hardware destruction
```

### CLASS C — Suspected or confirmed compromise

Examples:

```text
malware suspected
credential theft suspected
unexpected Tailscale activity
unexpected Vault session evidence
```

Treat all old-device operational secrets as exposed.

### CLASS D — Permanent retirement without replacement

Removing one canonical primary breaks the two-endpoint cross-authorization assumption.

Classify as:

```text
ARCHITECTURE REDESIGN REQUIRED
```

---

## 3. Immediate action matrix

```text
CLASS A
  preserve old device until replacement passes all tests
  never operate both as routine Vault primaries

CLASS B
  expire/revoke old Tailscale node immediately
  inspect detection evidence
  provision replacement as a new identity
  rotate the affected phase token

CLASS C
  stop normal Vault operation
  expire/revoke old Tailscale node immediately
  rotate the affected phase token/verifier
  inspect AWS/Tailscale/RHEL evidence
  do not trust old scripts/configuration as clean

CLASS D
  stop
  do not merely delete the device
  perform architecture redesign
```

---

## 4. Evidence capture

Record:

```text
event date/time
classification
old device role
old hostname/device name
old Tailscale NodeID
old Tailscale IP
old tailnet
Tailnet Lock status
expected expiry actor/client ID
phase-token verifier fingerprint
last successful Vault session ID
last daily-slot date
last known STS issuance event
last known RHEL backend-open event
restic source path
repository-password custody location
```

On a controlled Fedora PC:

```bash
hostnamectl
tailscale version
tailscale status
tailscale ip -4
tailscale lock status
```

Do not commit real NodeIDs, Tailnet IDs, account identifiers, OAuth secrets, phase tokens, or repository passwords to Git.

---

## 5. Freeze normal Vault operation

Before planned migration:

```text
finish or abandon the current Vault ceremony
verify no valid open coordinator session remains
verify no S3 proxy admission remains active
verify the matching RHEL backend is stopped
```

On the matching VPS:

```bash
sudo systemctl status vault-device-coordinator.service --no-pager
sudo systemctl status vault-s3-proxy.service --no-pager
sudo journalctl -u vault-device-coordinator.service -n 200 --no-pager
sudo journalctl -u vault-s3-proxy.service -n 200 --no-pager
```

On RHEL:

```bash
sudo systemctl is-active vault-rhel-pc-rest-server.service || true
sudo systemctl is-active vault-rhel-phone-rest-server.service || true
```

Do not delete daily-slot state to simplify migration testing.

---

## 6. Old-device data handling

### Planned replacement

Copy only the intended source scope:

```text
PC:
  ~/Vault_PC_Ciphertext

Phone:
  ~/Vault_Phone_Ciphertext
```

Do not blindly migrate:

```text
~/.ssh
Tailscale state
browser session stores
AWS CLI SSO cache
shell history
temporary STS credentials
Vault runtime state
```

### Suspected compromise

Preferred approach:

```text
obtain required data through a reviewed recovery path
copy only required non-executable source data
review or scan it before placing it in the canonical Vault source tree
rebuild scripts and configuration from the authoritative guide
```

Do not trust old Vault scripts, systemd user units, Termux widget code, AWS cache, or Tailscale state.

---

## 7. Repository password handling

The canonical RHEL baseline remains ciphertext-only and keyless.

For the affected repository:

```text
retrieve the repository password from authoritative password-manager/offline custody
provision it only to the approved replacement-primary secret path
never place it on RHEL
never place it on vault-pc or vault-phone
never place it in Git
```

Do not merge PC and Phone repository passwords into one shared secret.

---

## 8. Phase-token migration

Each primary owns one independent 256-bit phase token. The matching VPS stores only its SHA-256 verifier.

For all replacement classes, generate a new phase token.

Provision:

```text
new raw phase token → replacement primary only
new verifier → matching VPS only
```

Remove old verifier acceptance.

For CLASS B and CLASS C, the old token is treated as compromised.

Do not accept old and new tokens indefinitely.

---

## 9. Provision replacement Tailscale identity

Install the current reviewed Tailscale client.

Join only the correct tailnet:

```text
replacement PC    → PC tailnet only
replacement Phone → Phone tailnet only
```

Preserve primary inbound policy:

```text
Fedora:
  tailscale set --shields-up=true
  tailscale set --ssh=false

Android:
  Allow incoming connections = OFF
```

Verify:

```bash
tailscale status
tailscale ip -4
```

Record the new exact Tailscale NodeID using the current supported administrative/API procedure.

Do not treat hostname as an exact security identity.

---

## 10. Tailnet Lock admission

Admit the replacement according to current Tailnet Lock procedures.

Before signing, verify:

```text
exact tailnet
device role
new node identity/key
operator-initiated migration
```

Do not disable Tailnet Lock, use a disablement secret for convenience, or make the primary a permanent signing node.

After admission:

```bash
tailscale lock status
```

Verify that the replacement is accepted and the trusted infrastructure signer set is unchanged unless a separate signer migration is being performed.

---

## 11. Update exact-device expiry binding

The canonical Tailscale expiry helper is bound to one exact expected primary NodeID per compartment.

On the matching VPS:

```text
record old expected NodeID
record new expected NodeID
update only the exact configured NodeID binding
preserve exact tailnet binding
preserve fixed expiry endpoint/verb
preserve WIF/OAuth credential separation
```

Do not broaden the helper to expire by hostname, tag, owner, first matching device, or client-supplied NodeID.

Record a new configuration hash after the change.

---

## 12. Update detection identity

Update the affected compartment's expected primary NodeID.

Preserve:

```text
exact expected expiry actor
exact expiry client identity
opposite-tailnet separation
default-deny mutation classification
DETECTION BLIND behavior
```

Do not permanently allowlist both old and new NodeIDs.

Tests:

```text
expected expiry of new NodeID → expected event
unrelated test-node mutation → CRITICAL
old retired NodeID mutation → investigate
```

---

## 13. AWS Identity Center and local AWS state

On the replacement:

```text
install current AWS CLI v2
configure only the matching Vault profile
perform a fresh MFA/SSO login
verify the profile can invoke the matching issuance gate and shared read-only S3 completion-status Lambda only
```

Do not copy AWS SSO cache or temporary STS credentials from the old device.

Do not create static IAM user access keys as a migration shortcut.

Negative tests:

```text
PC replacement cannot invoke Phone issuance gate
Phone replacement cannot invoke PC issuance gate
both replacement profiles can invoke only the shared read-only S3 completion-status Lambda in addition to their own gate
completion-status query with a changed session_expires_at returns ABSENT_OR_SESSION_MISMATCH
primary has no direct S3 data permission before gate issuance
primary cannot AssumeRole directly into backup role
```

---

## 14. Rebuild Vault workflow from authoritative files

Recreate:

```text
canonical source directory
phase helper
close-only peer S3 helper
AWS issuance helper
daily Vault workflow with exact-session S3 completion barrier
systemd user unit on Fedora
Termux workflow/widget on Android
routine secret files with canonical permissions
```

Use the authoritative Git architecture snapshot and current deployment-time revalidation decisions.

Do not rebuild from obsolete FINAL/HARDENED copies or old File Library drafts.

---

## 15. Pre-cutover negative tests

### Inbound prohibition

Verify primary inbound remains disabled and no Vault receiver exists on the replacement.

### Compartment isolation

```text
replacement PC reaches only PC Vault paths
replacement PC cannot reach Phone Vault listeners

replacement Phone reaches only Phone Vault paths
replacement Phone cannot reach PC Vault listeners
```

### Single-endpoint authorization failure

Run only the replacement endpoint's side of the ceremony.

Expected:

```text
no valid dual proof
no S3 credential
no RHEL backend open
```

### Exact-node expiry

Run a synthetic authorized ceremony.

Expected:

```text
matching replacement primary expires
opposite primary does not expire
old NodeID is not selected
unrelated node is not selected
```

### Daily-slot invariant

Verify migration did not create:

```text
a second slot namespace
a second Lambda issuance path
a reset endpoint
an old-device bypass
```

### S3 completion containment and one-hour deadline

Verify:

```text
session_expires_at remains fixed
activity does not slide the deadline
own MFA with opposite primary absent -> no dual proof and no fresh STS issuance
snapshot creation alone -> completion state is not REVOKED
snapshot + later lock removal -> exact slot reaches REVOKED with immutable cutoff
old STS is denied after role-session revocation propagation before original Expiration
replacement can poll opposite exact-session status through the shared read-only Lambda
clean replacement can request signed CLOSE_PEER for the opposite role after exact status REVOKED
target local DONE suppression cannot veto that S3 proxy-admission close
wrong-deadline/expired close payload is rejected
incomplete/no-snapshot session still cannot exceed the signed one-hour ceiling
RHEL DONE remains early close only; suppressed RHEL DONE cannot exceed the signed ceiling
```

---

## 16. Cutover

After the replacement passes the required tests:

```text
1. stop routine Vault use on old device
2. record final old-device evidence
3. expire old Tailscale node
4. revoke/remove old node using the current official procedure
5. verify Tailnet Lock state
6. ensure expiry helper is pinned only to the new NodeID
7. ensure detection expects only the new NodeID
8. remove old phase-token verifier acceptance
9. verify only the new verifier is active
10. run one complete synthetic cross-authorized ceremony
```

The canonical model has one current PC primary and one current Phone primary.

Multiple interchangeable primaries require a separate security review.

---

## 17. Old-device retirement

### Controlled old device

After successful cutover:

```text
sign out of AWS/SSO
remove Vault AWS profile/cache used only by the device
remove phase token
remove restic repository password
remove Vault workflow files
remove Tailscale node from accepted membership
verify it is no longer accepted by locked peers
```

Then use an appropriate secure erase/reinstall/disposal procedure for the storage technology.

Ordinary file deletion is not claimed to sanitize SSD/flash media.

### Lost or stolen device

Server-side actions are primary:

```text
expire/revoke Tailscale node
remove node from accepted membership
rotate affected phase token
update exact NodeID binding
update detection state
review configuration audit
review daily slots
review STS AssumeRole evidence
review RHEL gate/backend evidence
```

### Suspected compromise

Expected affected boundaries:

```text
phase token              → assume exposed; rotate
repository password      → affected source repository may be exposed
active STS credential    → possible during a live authorized session
AWS SSO/browser session  → possible
plaintext source         → exposed

VPS Ed25519 signing key  → not normally stored on primary
Tailscale expiry secret  → not normally stored on primary
Tailnet Lock signer key  → primary should not be canonical signer
```

Rotate based on actual trust-boundary exposure.

---

## 18. Restic repository continuity

A device replacement does not automatically create a new repository.

For the same logical PC or Phone backup lineage:

```text
reuse the same matching restic repository
use the same repository password
preserve bucket/repository compartment
```

Record the migration date.

After the first replacement backup:

```bash
restic snapshots
restic check
```

For S3 Deep Archive, preserve the canonical cold-storage procedure; do not perform routine full cold-data checks as if it were hot storage.

A fundamentally new logical source requires a security review before reusing the repository identity.

---

## 19. RHEL implications

Primary-device migration does not require changing the canonical RHEL trust model.

RHEL remains:

```text
RHEL 9
SELinux Enforcing
ciphertext-only
keyless
no unattended restic maintenance
PC and Phone repository isolation
append-only ingestion
backends disabled at boot
signed one-hour opening
rootless Podman
```

Migration does not require:

```text
copying restic passwords to RHEL
adding a custom SELinux policy
running sepolicy generate
running audit2allow
disabling SELinux
switching to rootful/privileged Podman
merging PC and Phone containers
```

The no-custom-SELinux-policy baseline continues to rely on standard RHEL/Podman SELinux policy, dedicated service identities, DAC separation, systemd confinement, rootless Podman, and explicit repository bind mounts.

Rerun the canonical hardening and repository-isolation checks after migration.

---

## 20. VPS RHEL 9 BYOL/BYOI implications

`vault-pc` and `vault-phone` remain separate RHEL 9 BYOL/BYOI compartments.

If the VPS remains trusted, update only:

```text
phase-token verifier
expected primary NodeID
detection expected-primary state
affected service evidence/configuration hashes
```

Preserve:

```text
SELinux Enforcing
coordinator user = vaultcoord
S3 proxy user = vaultproxy
DAC separation
NoNewPrivileges
systemd sandboxing
root-owned exact-device expiry helper
separate per-tailnet expiry credential
```

The no-custom-SELinux-policy baseline does not require a dedicated local SELinux domain for coordinator or S3 proxy.

Do not generate one during device migration.

---

## 21. Tailnet Lock signer warning

Primary migration is not signer migration.

Canonical primaries are not required signing nodes.

If the old primary appears as a trusted Tailnet Lock signer:

```text
STOP
```

Investigate architecture drift before continuing.

Use the current official Tailnet Lock key-removal/revocation procedure. Do not assume deleting a signer node resolves every signing-key trust question.

---

## 22. Permanent removal of one endpoint

Permanently removing one endpoint without replacement breaks the canonical cross-authorization assumption.

Do not solve this by:

```text
hard-coding the missing signature
copying one endpoint's approval capability to the other
making one VPS sign twice
creating a static second signature
disabling dual-proof verification
```

Classify as:

```text
ARCHITECTURE REDESIGN REQUIRED
```

Possible future models such as a hardware approval factor, offline second signer, approval device, or independent control compartment require a separate threat-model review.

---

## 23. Migration acceptance checklist

```text
EVENT
[ ] Event classified A/B/C/D.
[ ] Old role and old NodeID recorded.
[ ] Last known Vault/AWS/RHEL activity reviewed.

DATA
[ ] Only intended source scope migrated.
[ ] No old Tailscale state copied.
[ ] No AWS SSO cache copied.
[ ] No temporary STS credential copied.
[ ] Repository password retrieved from authoritative custody.
[ ] Repository password absent from RHEL/VPS/Git.

PHASE TOKEN
[ ] New 256-bit phase token generated.
[ ] Raw token exists only on replacement primary.
[ ] SHA-256 verifier exists only on matching VPS.
[ ] Old verifier acceptance removed.

TAILSCALE
[ ] Replacement joined only the correct tailnet.
[ ] New exact NodeID recorded.
[ ] Primary inbound remains disabled.
[ ] Tailnet Lock admission completed.
[ ] Primary is not a canonical signer.
[ ] Old node expired/revoked/removed after cutover.

EXACT EXPIRY
[ ] Helper pinned to new exact NodeID.
[ ] Helper cannot select old NodeID.
[ ] Helper cannot accept client-supplied NodeID.
[ ] Synthetic ceremony expires replacement primary only.

DETECTION
[ ] Expected primary NodeID updated.
[ ] Expected expiry actor remains exact.
[ ] Old NodeID is not permanently allowlisted.
[ ] Unexpected mutation test generates CRITICAL.
[ ] Detection-blind behavior remains valid.

AWS
[ ] AWS CLI configured fresh.
[ ] Matching Identity Center profile only.
[ ] Fresh MFA/SSO flow tested.
[ ] No static IAM user key created.
[ ] Replacement cannot invoke opposite issuance gate.
[ ] Replacement can invoke shared read-only completion-status Lambda and wrong-deadline query fails closed.
[ ] Replacement cannot AssumeRole directly.
[ ] Daily-slot/completion-state invariant unchanged.
[ ] Matching backup-role permissions boundary remains attached.
[ ] No credential-refresh loop introduced.

RHEL
[ ] RHEL remains ciphertext-only.
[ ] RHEL stores no repository password.
[ ] SELinux remains Enforcing.
[ ] No custom Vault SELinux policy added.
[ ] Rootless Podman isolation unchanged.
[ ] PC/Phone repository isolation passes.
[ ] Hard-stop still follows signed deadline.

SESSION
[ ] Single endpoint alone cannot open AWS even when its own MFA succeeds.
[ ] Single endpoint alone cannot open RHEL.
[ ] Dual ceremony succeeds.
[ ] Successful S3 completion reaches REVOKED only after snapshot + later lock removal.
[ ] Old STS is denied after completion revocation propagation before original Expiration.
[ ] Clean opposite primary can close target S3 admission through signed CLOSE_PEER without target DONE.
[ ] Wrong-session/expired close payload is rejected.
[ ] Signed one-hour ceiling remains fixed for incomplete/no-snapshot fallback.
[ ] RHEL DONE closes early only.
[ ] Suppressed RHEL DONE cannot extend deadline.

CUTOVER
[ ] Old primary is no longer accepted as a Vault participant.
[ ] Only one current primary identity exists for the role.
[ ] First replacement backup succeeds.
[ ] Snapshot continuity reviewed.
[ ] Evidence/configuration hashes updated.
```

Decision:

```text
all required checks pass
    → MIGRATION COMPLETE

old device remains accepted by identity/expiry/detection paths
    → NO-GO

one endpoint permanently removed without replacement
    → ARCHITECTURE REDESIGN REQUIRED

suspected compromise with unrotated phase token
    → NO-GO

migration appears to require custom SELinux policy for canonical services
    → STOP; investigate baseline drift/runtime incompatibility
```

---

## 24. Post-migration evidence record

Record:

```text
migration date
classification
old NodeID
new NodeID
tailnet
new phase-token verifier fingerprint
expiry-helper configuration hash
coordinator configuration hash
detection expected-primary configuration hash
Tailscale version
replacement OS/version
last old-device event reviewed
first successful replacement session ID
first successful S3 backup timestamp
first successful RHEL backup timestamp
one-hour deadline test result
old node removal confirmation
Tailnet Lock status confirmation
```

Do not record raw secrets.

---

## 25. Final security statement

A device replacement is complete only when:

> the new primary can participate in the canonical cross-authorized ceremony, and the old primary can no longer exercise the identity bindings that made it a valid Vault participant.

Successful file copying is not the migration acceptance criterion.

The security boundary is the identity and authorization cutover.
