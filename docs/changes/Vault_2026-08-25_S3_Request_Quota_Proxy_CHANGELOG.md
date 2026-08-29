# THE VAULT - 2026-08-25 S3 REQUEST QUOTA PROXY CHANGELOG

## 1. Reason for this revision

The Section 23.6 exact-host S3 proxy is a blind CONNECT relay: it sees aggregate bytes
but never individual requests. Within a legitimate dual-signed one-hour window, a
compromised endpoint controlling the client stack can therefore emit millions of
minimal-size `PutObject` requests. The bill in this attack is driven by per-request
pricing, not storage volume, so byte-level visibility cannot bound it. Budget
containment is delayed telemetry (8–24 h) and a second device/day ceremony can land
before the deny attaches.

Operator constraints fixed for this revision:

* Total S3 exposure from any compromise sequence must stay below USD 2.
* No paid AWS detection features are used.
* The one-hour STS ceiling is retained unchanged.
* AWS credentials remain in client-process memory only; the proxy never holds,
  re-signs, or alters authorization material.
* Backup payloads stay opaque end-to-end (restic ciphertext).

## 2. Final security semantics

The Section 23.6 binary is superseded by a counting TLS-terminating forward proxy:

```text
client-facing TLS     Vault-issued leaf certificate for the exact regional endpoint;
                      one CA per compartment; trusted ONLY via SSL_CERT_FILE inside
                      the restic S3 env block - never via the OS trust store
upstream TLS          fresh connection to the real endpoint, verified against the
                      normal system CA bundle; all bytes relayed verbatim
visibility            HTTP metadata only (method, path prefix, size headers, timing);
                      bodies are restic ciphertext end-to-end
quotas                SESSION_MAX_REQUESTS = 8000 (tripwire)
                      SESSION_METADATA_MAX_REQUESTS = 400
                      DAY_MAX_REQUESTS = 12000 (persisted Istanbul-day bound)
exhaustion            tunnel close + structured event + refusal until phase close
```

Economic bound at adversarial maximum:

```text
worst flood day            <= USD 0.24..0.60   (12000 requests x pessimistic pricing)
budget-lag window          <= 2 issuance days before the deny attaches
documented absolute bound  <= USD 0.48..1.20   (< USD 2 requirement)

legitimate headroom        normal delta = hundreds of requests; heavy day = low
                           thousands; >= 4x margin under the session cap; bulk
                           seeding uses a temporary operator-only override
```

False-positive failure mode: an over-tight cap stops only the S3 leg mid-run. No
snapshot completes, the daily slot burns (existing fail-closed semantics), RHEL
continues independently, and no corruption is possible because restic snapshots are
atomic.

## 3. Core components added

```text
Vault_Zero_Trust_Master_Guide_CORE.md Section 23.6A (normative contract)
per-compartment ECDSA P-256 proxy CA + regional-endpoint leaf certificates
/etc/vault-s3-proxy/quotas.env with OBSERVE_ONLY mode
/var/lib/vault-s3-proxy/state persisted day counters
SSL_CERT_FILE scoping in both daily workflows and both one-time init blocks
new Definition-of-Done line for the calibrated quota proxy
```

## 4. Threat-model changes

* T-09 Controls gain the counting proxy; Residual/Status now describe the flood
  vector as bounded once the validation gate is recorded.
* Change log entry `2026-08-25 | S3-QUOTA` added.
* The per-compartment proxy CA private key joins the conservatively modeled loss set
  of a full VPS root compromise (T-03): its abuse yields metadata-level interception
  of that compartment's Vault S3 sessions only, strictly narrower than capabilities
  already assumed of VPS root.
* None of I-01 … I-16 is weakened. I-06/I-07 residuals tighten: in-session S3 request
  volume becomes configuration-bounded instead of deadline-bounded only.

## 5. Validation performed

Performed during this revision:

```text
design review against I-01..I-16                no invariant weakened
contract review against operator constraints    free / 1 h duration / custody intact
quota bound arithmetic                          documented above
```

Explicitly **not yet performed** (deployment gate):

```text
v2 binary implementation                        gofmt + go vet + go build
full negative matrix from Section 23.6A         required before any deployment
two-week OBSERVE_ONLY calibration               required before caps are enforced
binary SHA-256 recording per H6                 required before any deployment
```

## 6. Deployment rule

Do not partially apply this revision. Until the v2 binary passes `gofmt`, `go vet`,
`go build`, every Section 23.6A negative test, and two weeks of observe-mode
calibration, retain the Section 23.6 blind relay unchanged and treat the in-session
request-flood vector as an open residual exactly as T-09 states. After the gate,
enforcement may be enabled compartment-by-compartment; symmetric application across
both compartments is expected but each upgrade is independently reversible.

## 7. Documents changed

```text
Vault_Zero_Trust_Master_Guide_CORE.md              (23.6A, DoD, workflow env blocks)
Vault_Threat_Model_and_Risk_Register.md            (T-09, change log)
PROJECT_STATUS.md                                  (AWS Model decision bullet)
docs/extensions/Vault_Extension_S3_Request_Quota_Proxy.md   (status -> integrated;
   preserved for problem analysis and rejected-alternatives record)
docs/extensions/README.md                          (index row -> integrated)
```
