---
status: integrated
---
# Extension: S3 Request Quota Proxy (In-Session Flood Containment)

> **Integrated into the Core baseline on 2026-08-25 as Section 23.6A of**
> **`../core/Vault_Zero_Trust_Master_Guide_CORE.md`.** That section is the normative
> specification and its calibrated quota values (8000/400/12000) supersede the
> provisional defaults below. This document is preserved for its problem analysis and
> the rejected-alternatives record.

## Problem statement

Within a legitimate dual-signed one-hour session, malware controlling the requesting
endpoint shares the already-issued STS credential and the exact-host CONNECT proxy path.
Because the current proxy is a **blind CONNECT relay**, it sees only aggregate bytes:
it cannot count individual S3 requests. A deliberate adversary can therefore emit
millions of minimal-size `PutObject` requests inside the one-hour window. Storage volume
is irrelevant in this attack (Deep Archive storage is priced per GB-month); the bill is
driven by **per-request charges**. Delayed budget containment (up to 8–24 h telemetry
lag) does not prevent this, and a second device/day ceremony can occur before the budget
deny attaches.

Operator constraints fixed for this extension:

* Total S3 cost exposure from any single-day compromise must stay **below USD 2**.
* No paid AWS detection features (CloudWatch request metrics are rejected).
* The one-hour `DurationSeconds` / role maximum session duration is retained unchanged.
* Credentials remain in client-process memory only; the proxy must never hold,
  re-sign, or alter AWS authorization material.
* Backup payloads remain opaque: the proxy must not gain access to plaintext data
  (restic encrypts client-side, so HTTP bodies are already ciphertext).

## Why this design - and the rejected alternatives

| Alternative | Verdict |
|---|---|
| CloudWatch S3 request metrics + alarm + kill Lambda | Rejected: recurring cost; operator declined paid detection. |
| S3 Server Access Logs parsed by scheduled Lambda | Rejected as primary: log delivery latency is best-effort with no SLA (minutes to hours); cannot promise bounded containment. Usable as a supplementary detector, never as the guarantee. |
| Bucket policy `s3:ObjectSizeLessThan` deny on `data/*` | Rejected: a floor large enough to matter financially also denies legitimate small restic pack files (availability loss, burned slot); a floor small enough to be safe is trivially flooded with floor-sized objects. |
| Shorten STS `DurationSeconds` | Rejected by operator decision: the 3600 s ceiling stays. |
| Reverse proxy that re-signs requests with VPS-held credentials | Rejected: violates the keyless/custody model (AWS credentials must never leave the endpoint process). |
| **TLS-terminating counting forward proxy (selected)** | The proxy ends the client-facing TLS session with its own certificate, inspects only HTTP **metadata** (method, path prefix, Content-Length, request count), enforces quotas, and relays every request byte-for-byte to the real S3 endpoint over a freshly verified upstream TLS connection. SigV4 signatures are computed by the client against `s3.<region>.amazonaws.com` and are forwarded untouched, so AWS validation is unaffected. |

## Security properties

* **Credential custody unchanged.** The `Authorization` header and all SigV4 material
  pass through verbatim; the proxy holds no AWS credentials and cannot mint, extend, or
  reuse authority.
* **Confidentiality unchanged.** HTTP bodies are restic ciphertext; the proxy gains
  visibility only into request metadata (operation, repository-relative path, object
  size, timing) - a strictly weaker view than the modeled full-VPS-root compromise.
* **Deterministic economic bound.** Request-count quotas convert the flood vector from
  "bounded only by time" to "bounded by a fixed number".
* **Fail-closed behavior.** Malformed HTTP, unexpected methods, wrong CONNECT targets,
  HTTP/2 ALPN negotiation attempts (restricted to `http/1.1`), and quota exhaustion all
  result in connection teardown and a structured log event. Availability of the S3 leg
  is lost; nothing else is affected.
* **Scoped trust.** The Vault-issued proxy CA is trusted **only** by the Vault backup
  processes via environment variables (`SSL_CERT_FILE` for restic). The operating
  system trust store is never modified; this is enforced by a negative test.
* **Upstream integrity.** The upstream TLS connection to AWS is verified against the
  real AWS CA; the proxy performs no content rewriting.

## 1. Prerequisites

* The Section 23.6 exact-host S3 CONNECT proxy is deployed and passing its tests on
  both `vault-pc` and `vault-phone`.
* A Go build workstation exists (same trust level as the coordinator build process).
* Measured daily request counts exist for at least two representative weeks (enable
  `OBSERVE_ONLY=true` first; see calibration below).
* An out-of-band distribution channel for the proxy CA certificate (password manager
  or offline media) is available, matching the existing provisioning discipline.

## 2. Install / migration

### 2.1 Generate the per-VPS proxy CA and leaf certificates

Run independently on each VPS. Each compartment gets its own CA; neither CA is shared.

```bash
sudo install -d -o root -g root -m 700 /etc/vault-s3-proxy/tls

# CA (ECDSA P-256; valid 10 years)
sudo openssl ecparam -name prime256v1 -genkey \
  -noout -out /etc/vault-s3-proxy/tls/ca.key
sudo openssl req -new -x509 -key /etc/vault-s3-proxy/tls/ca.key \
  -subj "/CN=Vault S3 Proxy CA (pc)" -days 3650 \
  -out /etc/vault-s3-proxy/tls/ca.crt

# Leaf certificate for the exact S3 regional endpoints used by the workflows
sudo openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout /etc/vault-s3-proxy/tls/leaf.key \
  -subj "/CN=s3.us-east-1.amazonaws.com" \
  -out /tmp/leaf.csr
cat > /tmp/leaf.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:s3.us-east-1.amazonaws.com,DNS:s3.amazonaws.com
EOF
sudo openssl x509 -req -in /tmp/leaf.csr \
  -CA /etc/vault-s3-proxy/tls/ca.crt -CAkey /etc/vault-s3-proxy/tls/ca.key \
  -CAcreateserial -days 365 -extfile /tmp/leaf.ext \
  -out /etc/vault-s3-proxy/tls/leaf.crt
rm -f /tmp/leaf.csr /tmp/leaf.ext
sudo chmod 600 /etc/vault-s3-proxy/tls/ca.key /etc/vault-s3-proxy/tls/leaf.key
```

Distribute **only `ca.crt`** to the owning primary device as
`~/.config/vault-secrets/vault-proxy-ca.crt` (mode `0644`; it is public material).
Never place a VPS CA private key on a primary device.

### 2.2 Configure quotas

`/etc/vault-s3-proxy/quotas.env` (mode `0640`, owned root):

```text
OBSERVE_ONLY=false
SESSION_MAX_REQUESTS=5000
SESSION_METADATA_MAX_REQUESTS=300
DAY_MAX_REQUESTS=8000
SESSION_MAX_BYTES=68719476736          # 64 GiB; keep consistent with byte policy
DAY_STATE_PATH=/var/lib/vault-s3-proxy/state
ALLOWED_ENDPOINTS=s3.us-east-1.amazonaws.com:443
```

Classification rules enforced by the proxy:

```text
CONNECT target != ALLOWED_ENDPOINTS           -> DENY
PUT / POST to data/*                          -> DATA class     (SESSION_MAX_REQUESTS)
PUT / POST / DELETE to non-data prefixes      -> META class     (SESSION_METADATA_MAX_REQUESTS)
GET / HEAD / List-type                        -> READ class     (SESSION_MAX_REQUESTS)
any other method                              -> DENY + event
quota exhausted                               -> close tunnel + event + refuse
                                                 further tunnels until phase close
```

Rationale for defaults: a normal daily delta issues a few hundred requests; 5,000 gives
roughly an order of magnitude of headroom while capping the worst-case flood at
5,000 × ~USD 0.00002–0.00005/request ≈ **USD 0.10–0.25 per session**. The documented
calendar-boundary worst case allows at most two issuance windows per day, plus one
further ceremony that may precede budget-deny attachment: the absolute documented
ceiling is ≈ 3 sessions ≈ **USD 0.30–0.75**, i.e. below the USD 2 requirement even for
a fully malicious maximal-rate client.

### 2.3 Deploy

1. Build the proxy v2 binary on the build workstation; record its SHA-256 alongside the
   other frozen artifacts (Section H6 discipline).
2. Install as the same dedicated service identity (`vaultproxy`) with the same systemd
   sandbox as the §23.6 unit; only `ExecStart`, the TLS directory mount, and the
   writable state path differ.
3. Create `/var/lib/vault-s3-proxy/state` (owned `vaultproxy`, mode `0700`).
4. On each primary device, extend the existing proxy-scoped environment block in the
   daily workflow - the block that already exports and unsets `HTTPS_PROXY` around the
   restic S3 call:

   ```bash
   export SSL_CERT_FILE="$HOME/.config/vault-secrets/vault-proxy-ca.crt"
   # ... restic S3 invocation ...
   unset SSL_CERT_FILE
   ```

   Do **not** export it outside the restic S3 scope, and do not install the CA into the
   system trust store.

### 2.4 Calibration (mandatory before enforcement)

Run the v2 proxy with `OBSERVE_ONLY=true` for at least two weeks. It logs per-class
request counts without enforcing. Set `SESSION_MAX_REQUESTS` to ≥ 5× the observed
maximum daily count, then flip to enforcement and run the negative tests below.

Initial-seed exception: during a planned bulk seeding week, temporarily raise
`DAY_MAX_REQUESTS` via the documented override file and remove it afterwards. The
override is operator-initiated and recorded in the log; it is not reachable from any
primary device.

## 3. Removal / rollback

1. Restore the previous §23.6 blind CONNECT binary (retained artifact).
2. Remove `SSL_CERT_FILE` lines and `vault-proxy-ca.crt` from both primaries.
3. Archive and delete `/etc/vault-s3-proxy` and the state directory on each VPS.
4. Run the standard §23.9 positive S3 transfer test.

Rollback restores the earlier property set exactly: the request-flood residual returns,
and no data, history, or cryptographic state changes irreversibly.

## 4. Threat-model delta

Apply this section to `Vault_Threat_Model_and_Risk_Register.md` when enabling the
extension; revert the entries on rollback.

**New assets**

* Per-compartment proxy CA private key (`vault-pc` / `vault-phone`, never shared).
  Compromise yields metadata-level interception of that compartment's Vault S3 sessions
  only - strictly narrower than the already-modeled full-VPS-root loss in T-03.
* Per-device quota state files (integrity-relevant; tampering is a local-root concern).

**Modified invariants** - none of I-01 … I-16 is weakened. Enforcement of I-06/I-07
residuals is tightened: in-session S3 request volume becomes bounded by configuration
instead of only by the signed deadline. I-09's enforcement point is unchanged (fixed
egress `/32`, now with request-level accounting at the same host).

**Changed threat register entries**

* T-07 / T-11: residual shrinks - a stolen or suppressed-DONE session can no longer
  issue unlimited requests inside the window; it hits the session quota.
* T-09: upgraded from "documented residual" to "bounded" while the extension is
  enabled. Revert to the residual wording if rolled back.

**New residual risks (accepted)**

* A parser defect in the proxy causes fail-closed denial of the S3 leg only
  (availability, not confidentiality or authorization).
* A false-positive quota trip burns the day's S3 issuance slot (existing fail-closed
  semantics); mitigation is the 5× calibration margin and observe-first rollout.
* Mis-provisioning the CA into a system-wide trust store would widen endpoint trust;
  the scoped `SSL_CERT_FILE` mechanism and its negative test exist precisely to make
  this detectable.

## Acceptance tests (day-zero)

```text
[ ] Positive: real dual-ceremony backup completes through the v2 proxy; SigV4 accepted
    by S3 (signature forwarded verbatim).
[ ] Positive: completion revocation still fires (snapshot + lock removal observed).
[ ] Negative: CONNECT to any non-allowlisted endpoint is denied and logged.
[ ] Negative: malformed request bytes on an established tunnel drop the connection and
    raise one structured event.
[ ] Negative: HTTP/2 ALPN offer is refused; only http/1.1 is negotiated.
[ ] Negative: with SESSION_MAX_REQUESTS temporarily set to 20, a synthetic flood is cut
    off mid-session; no snapshot completes; the slot burns as designed; RHEL leg
    unaffected.
[ ] Negative: META cap trips on a synthetic snapshots/-prefix flood without consuming
    the DATA allowance.
[ ] Negative: a client launched WITHOUT SSL_CERT_FILE fails the TLS handshake against
    the proxy (proves the system trust store was never modified).
[ ] Rollback: blind-proxy restore passes the §23.9 positive test.
```

> [!NOTE]
> Status is `pending`. Adoption requires the personal architecture audit sign-off,
> two weeks of `OBSERVE_ONLY` calibration data, and a recorded quota decision. Do not
> enable enforcement on unmeasured defaults.
