# VAULT EXTENSION — REPLACE TAILSCALE CONTROL PLANES WITH HEADSCALE
================================================================================

## 1. Purpose and security decision

The canonical Vault guide uses **two independent Tailscale tailnets with Tailnet Lock**.
This extension replaces those managed coordination planes with **two independent
Headscale control planes**, one on `vault-pc` and one on `vault-phone`.

This is not a cosmetic VPN-provider switch. It deliberately trades one security
property for another:

```text
TAILSCALE BASELINE
  Tailnet Lock
    -> coordination-plane-only rogue membership is cryptographically rejected

  exact-device expiry
    -> Tailscale API helper
    -> OAuth credential with devices:core
    -> broader API authority than "expire exactly this device"

HEADSCALE EXTENSION
  no Tailnet Lock
    -> compromised Headscale control plane can manipulate membership / network maps

  exact-device expiry
    -> local Headscale CLI/database authority
    -> no Tailscale OAuth expiry credential
    -> exact locally selected node is expired
```

The Headscale model is architecturally elegant for **session revocation and least
privilege**, but weaker against a **control-plane-only membership compromise**. The
canonical cross-VPS Ed25519 authorization for AWS and RHEL remains mandatory because
it is independent from either control plane.

### What does not change

Do not modify these canonical invariants:

```text
2 VPS total: vault-pc + vault-phone
2 security compartments
2 VPS Ed25519 signing private keys
cross-VPS signed ceremony payloads
2 Lambda daily S3 gates
2 daily S3 issuance slots
2 S3 backup roles
2 S3 buckets
2 fixed S3 egress /32 restrictions
AWS-side snapshot + later lock-removal S3 completion revocation
2 device-specific completion revokers + read-only completion-status Lambda
backup-role permissions boundaries and AWSRevokeOlderSessions cutoff policy
signed cross-VPS CLOSE_PEER S3 admission shutdown over wg-cross
RHEL local dual-signature verification
RHEL per-repository daily slots
RHEL signed hard one-hour deadline
outbound-only primary devices
no-prune baseline
```

The extension changes only the coordination/control-plane implementation and exact
primary-node expiry mechanism.

---

## 2. Supported deployment shapes

Use exactly two independent Headscale instances:

```text
PC COMPARTMENT
==============
PC
vault-pc
RHEL-PC tailscaled instance
        |
        v
https://pc-control.example.net
Headscale on vault-pc

PHONE COMPARTMENT
=================
Phone
vault-phone
RHEL-Phone tailscaled instance
        |
        v
https://phone-control.example.net
Headscale on vault-phone
```

**Never replace the two Tailscale tailnets with one shared Headscale instance.** A
single Headscale compromise would then control membership for both primary compartments
and would recreate the shared failure domain that the two-VPS redesign removed.

### VPS count

This extension still needs exactly:

```text
2 VPS
```

No third VPS is introduced.

### Public IPv4 count

A minimal Headscale baseline does **not** self-host DERP. Headscale can load the default
public DERP map, so the recommended transport order remains:

```text
direct UDP / WireGuard
        |
        | if direct path fails
        v
public DERP relay from the configured DERP map
```

Therefore, under a provider that permits the same VPS address to serve HTTPS and be the
actual outbound S3 egress, one stable public IPv4 per VPS can be sufficient:

```text
vault-pc   stable public IPv4
vault-phone stable public IPv4
```

Always measure the real S3 proxy egress address rather than assuming the inbound VPS
address is also the outbound address:

```bash
curl -4 https://checkip.amazonaws.com
```

Record the measured address in the canonical AWS `aws:SourceIp` policy for the matching
backup role.

---

## 3. Enable from day zero or migrate later

### 3.1 Select Headscale from day zero

If this extension is chosen before the canonical Tailscale baseline is installed, treat
this document as a replacement for the master guide's Tailscale control-plane, Tailnet
Lock, managed-control-plane enrollment, and Tailscale API expiry-helper steps.

Keep every non-control-plane canonical component unchanged. In particular, still build
the two VPS signing keys, cross-VPS ceremony, Lambda daily gates, separate roles/buckets,
fixed egress proxies, AWS-side snapshot-plus-later-lock-removal completion revokers,
shared read-only exact-session status Lambda, backup-role permissions boundaries,
signed `CLOSE_PEER` cross-VPS S3 close messages, RHEL local dual-signature gate, signed
hard deadline, and outbound-only primary devices.

For a day-zero Headscale installation:

1. apply the Section 20 threat-model delta before enrolling the first primary;
2. install the two independent Headscale instances in Sections 4–10;
3. enroll exactly the three expected nodes per compartment in Sections 11–12;
4. install the explicit-default-deny policies in Section 13;
5. install local exact-node expiry in Section 14;
6. use the canonical/public DERP-map transport baseline; do not add Peer Relay unless
   its separate extension decision test later justifies it;
7. complete every Section 16 acceptance test before initializing a Vault repository.

Do not first create one shared Headscale instance and plan to split it later. Two
independent control planes are a day-zero invariant for this extension.

### 3.2 Migrate an existing canonical Tailscale installation later

When adding this extension to a running canonical deployment, use the change window and
migration sequence below. Keep the existing Tailscale tailnets intact until each
Headscale compartment passes its negative tests and exact-node expiry test. Remove the
Tailscale OAuth expiry credential only after the matching local Headscale expiry path is
proven.

## 3A. Preconditions and change window

Before migrating an existing Tailscale installation:

1. Finish or abandon the current Vault session.
2. Verify no S3 proxy tunnel is active.
3. Verify both RHEL rest-server backends are stopped.
4. Preserve the current canonical guide and threat model.
5. Export the current Tailscale node identities only for rollback documentation; do not
   copy Tailnet Lock disablement secrets onto the VPSs.
6. Take a provider snapshot of `vault-pc` and `vault-phone` if the VPS provider offers
   immutable rollback snapshots.
7. Record the current RHEL namespace layout and current Tailscale state directories.

On both primary devices, confirm the current baseline is closed:

```bash
tailscale status
```

On RHEL:

```bash
sudo systemctl is-active vault-rhel-pc-rest-server.service || true
sudo systemctl is-active vault-rhel-phone-rest-server.service || true
```

Both backend services must be inactive before control-plane migration.

---

## 4. DNS names and RHEL firewalld worksheet

Choose two different DNS names:

```text
pc-control.example.net      -> vault-pc public IPv4
phone-control.example.net   -> vault-phone public IPv4
```

The canonical Vault VPSs are RHEL 9 BYOL/BYOI hosts and use firewalld. Caddy is the
public HTTPS reverse proxy for this extension.

Install Caddy using the Caddy project's official CentOS/RHEL package path. The official
Caddy documentation uses the project's COPR namespace for this package:

```bash
sudo dnf install -y dnf-plugins-core
sudo dnf copr enable @caddy/caddy
sudo dnf install -y caddy

caddy version
rpm -q caddy
```

The Caddy package installs systemd units but does not need to be enabled until the
Headscale Caddyfile in Section 8 is ready.

Then on each VPS add only the extension's public HTTPS ports to the already active
`drop` zone:

```bash
sudo firewall-cmd --permanent --zone=drop --add-service=http
sudo firewall-cmd --permanent --zone=drop --add-service=https
sudo firewall-cmd --reload

sudo firewall-cmd --zone=drop --list-all
sudo firewall-cmd --zone=drop --list-rich-rules
```

The canonical SSH and UDP/51830 `wg-cross` rich rules remain unchanged.

Do **not** open UDP/40000 here. That belongs only to the Peer Relay extension.

Do **not** open a self-hosted DERP listener here. Self-hosted DERP is not the Headscale
baseline for this project.

## 5. Install Headscale on both RHEL 9 VPSs

Use the same reviewed stable Headscale release on both VPSs. This extension is written
for **Headscale 0.29.2 or a later reviewed 0.29.x patch release**.

The Headscale project currently documents DEB packages as its integrated package path.
The RPM repository commonly referenced for Fedora/RHEL is community-maintained. For this
Vault security boundary, do **not** make a third-party COPR repository part of the
canonical control-plane supply chain.

Use the Headscale project's **official standalone release binary** and manage the
service/user/unit explicitly.

### 5.1 Create the service account

On each VPS:

```bash
sudo useradd \
  --system \
  --home-dir /var/lib/headscale \
  --create-home \
  --user-group \
  --shell /usr/sbin/nologin \
  headscale 2>/dev/null || true

sudo install -d -o headscale -g headscale -m 750 /var/lib/headscale
sudo install -d -o root -g headscale -m 750 /etc/headscale
```

### 5.2 Download the official architecture-matching release binary

Determine the RHEL architecture:

```bash
uname -m
```

Map it deliberately:

```text
x86_64  -> HEADSCALE_ARCH=amd64
aarch64 -> HEADSCALE_ARCH=arm64
```

Set the reviewed release:

```bash
HEADSCALE_VERSION='0.29.2'

case "$(uname -m)" in
  x86_64)  HEADSCALE_ARCH='amd64' ;;
  aarch64) HEADSCALE_ARCH='arm64' ;;
  *) echo "Unsupported architecture for this guide" >&2; exit 1 ;;
esac
```

Download the exact official release asset:

```bash
curl -fL \
  "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${HEADSCALE_ARCH}" \
  -o "/tmp/headscale"

sudo install -o root -g root -m 0755 /tmp/headscale /usr/local/bin/headscale
/usr/local/bin/headscale version
```

Verify that the reported version is exactly the reviewed version. Preserve the downloaded
asset SHA-256 in the operator deployment record and compare it with the release evidence
you reviewed before production.

Do not upgrade one control plane several minor versions ahead of the other. Review the
Headscale upgrade path/changelog and move both compartments deliberately.

### 5.3 Create the explicit RHEL systemd unit

Create `/etc/systemd/system/headscale.service`:

```ini
[Unit]
Description=Headscale coordination server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=headscale
Group=headscale
ExecStart=/usr/local/bin/headscale serve
WorkingDirectory=/var/lib/headscale
Restart=on-failure
RestartSec=5s

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

ReadOnlyPaths=/etc/headscale
ReadWritePaths=/var/lib/headscale

[Install]
WantedBy=multi-user.target
```

Do not add an empty capability set or a speculative syscall filter merely to improve a
score before the full Headscale OIDC, map, policy, DERP-map, and reconnect tests run.

Enable only after Section 6 configuration exists:

```bash
sudo systemctl daemon-reload
sudo systemctl enable headscale.service
```

## 6. Configure the two Headscale instances

The two instances use the same structure but **different URLs, databases, Noise keys,
OIDC clients, users, node sets and local expiry state**.

### 6.1 `vault-pc` configuration

Create `/etc/headscale/config.yaml` on `vault-pc`:

```yaml
server_url: https://pc-control.example.net
listen_addr: 127.0.0.1:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
trusted_proxies:
  - 127.0.0.1/32

noise:
  private_key_path: /var/lib/headscale/noise_private.key

prefixes:
  v4: 100.64.10.0/24
  v6: fd7a:115c:a1e0:10::/64
  allocation: sequential

derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: true
  update_frequency: 3h

node:
  expiry: 0

database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true

policy:
  mode: file
  path: /etc/headscale/policy.hujson

dns:
  magic_dns: true
  base_domain: pc.vault.internal
  override_local_dns: false
  nameservers:
    global: []

log:
  level: info
  format: text

unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
```

### 6.2 `vault-phone` configuration

Create the same file on `vault-phone`, changing only compartment-specific values:

```yaml
server_url: https://phone-control.example.net
listen_addr: 127.0.0.1:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
trusted_proxies:
  - 127.0.0.1/32

noise:
  private_key_path: /var/lib/headscale/noise_private.key

prefixes:
  v4: 100.64.20.0/24
  v6: fd7a:115c:a1e0:20::/64
  allocation: sequential

derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: true
  update_frequency: 3h

node:
  expiry: 0

database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true

policy:
  mode: file
  path: /etc/headscale/policy.hujson

dns:
  magic_dns: true
  base_domain: phone.vault.internal
  override_local_dns: false
  nameservers:
    global: []

log:
  level: info
  format: text

unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
```

Validate configuration permissions:

```bash
sudo chown root:headscale /etc/headscale/config.yaml
sudo chmod 640 /etc/headscale/config.yaml
sudo chown -R headscale:headscale /var/lib/headscale
headscale configtest
```

`headscale configtest` must exit successfully. Compare any rejected field with the exact `config-example.yaml` from the same reviewed Headscale release tag as `HEADSCALE_VERSION`; the standalone binary path does not install Debian package documentation under `/usr/share/doc`. Do not guess configuration fields across versions.

Start Headscale on each VPS:

```bash
sudo systemctl enable --now headscale
sudo systemctl status headscale --no-pager
sudo journalctl -u headscale -n 100 --no-pager
```

Stop if Headscale is not listening only on the expected loopback address.

---

## 7. Preserve browser-mediated MFA with Authelia/OIDC

The canonical Vault expects the primary-device enrollment/sign-in ceremony to require
browser-mediated authentication rather than a reusable pre-auth key stored on the
primary device.

Use a separate OIDC client in each compartment:

```text
Headscale PC OIDC client     -> only pc-control.example.net
Headscale Phone OIDC client  -> only phone-control.example.net
```

Never use one OIDC client secret on both VPSs.

If your Authelia deployment already exists on each VPS, create a dedicated client with
an exact callback URL matching the Headscale documentation for the installed version.
Generate different random client secrets:

```bash
openssl rand -base64 48
```

Store the secret root-only in the matching VPS configuration/secret mechanism.

Add the matching OIDC section to `/etc/headscale/config.yaml` according to the exact
0.29.2 schema you installed. The values must be compartment-specific. Conceptually:

```yaml
oidc:
  only_start_if_oidc_is_available: true
  issuer: https://auth-pc.example.net
  client_id: headscale-pc
  client_secret_path: /etc/headscale/oidc-client-secret
  scope:
    - openid
    - profile
    - email
```

and independently on the Phone side:

```yaml
oidc:
  only_start_if_oidc_is_available: true
  issuer: https://auth-phone.example.net
  client_id: headscale-phone
  client_secret_path: /etc/headscale/oidc-client-secret
  scope:
    - openid
    - profile
    - email
```

Because OIDC config fields may change between Headscale minors, compare these names with
the exact tagged example configuration before restarting.

Protect the secret:

```bash
sudo chown root:headscale /etc/headscale/oidc-client-secret
sudo chmod 640 /etc/headscale/oidc-client-secret
sudo systemctl restart headscale
sudo journalctl -u headscale -n 100 --no-pager
```

Perform one deliberate failed MFA/sign-in test and verify the existing Authelia alerting
path behaves as documented for your environment.

---

## 8. Put Caddy in front of Headscale

On `vault-pc`, add:

```caddyfile
pc-control.example.net {
    reverse_proxy 127.0.0.1:8080
}
```

On `vault-phone`:

```caddyfile
phone-control.example.net {
    reverse_proxy 127.0.0.1:8080
}
```

Validate and start/reload the packaged Caddy service:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
sudo systemctl status caddy --no-pager
sudo journalctl -u caddy -n 100 --no-pager
```

From an external network:

```bash
curl -I https://pc-control.example.net
curl -I https://phone-control.example.net
```

A valid TLS response is required. Do not bypass certificate validation in Tailscale
clients.

---

## 9. Bootstrap with a deny-all policy

Before enrolling the primary devices, use a policy that grants no Vault application
reachability.

Create `/etc/headscale/policy.hujson` on each VPS:

```hujson
{
  "groups": {},
  "tagOwners": {},
  "acls": []
}
```

Protect and restart:

```bash
sudo chown root:headscale /etc/headscale/policy.hujson
sudo chmod 640 /etc/headscale/policy.hujson
sudo systemctl restart headscale
```

Do not begin with `autogroup:member -> *:*` or an equivalent convenience rule. The
whole point of the two compartments is to avoid ambient lateral reachability.

---

## 10. Create one Headscale user per compartment

On `vault-pc`:

```bash
sudo -u headscale headscale users create vault-pc
sudo -u headscale headscale users list
```

On `vault-phone`:

```bash
sudo -u headscale headscale users create vault-phone
sudo -u headscale headscale users list
```

The names are local to different Headscale databases. They are not evidence of shared
identity or a shared tailnet.

---

## 11. Migrate the PC compartment

The PC compartment contains only:

```text
PC
vault-pc
RHEL-PC tailscaled instance
```

### 11.1 `vault-pc` joins its own Headscale

On the VPS, point the local Tailscale client at its local public Headscale URL:

```bash
sudo tailscale logout || true
sudo tailscale up \
  --login-server=https://pc-control.example.net \
  --hostname=vault-pc \
  --accept-routes=false \
  --advertise-exit-node=false \
  --ssh=false
```

Complete the browser/OIDC flow as required.

### 11.2 PC joins

On Fedora:

```bash
sudo tailscale logout || true
sudo tailscale up \
  --login-server=https://pc-control.example.net \
  --hostname=vault-pc-primary \
  --accept-routes=false \
  --advertise-exit-node=false \
  --ssh=false

sudo tailscale set --shields-up=true
sudo tailscale set --ssh=false
```

The browser flow must require the expected OIDC/MFA path.

### 11.3 RHEL-PC instance joins

The canonical RHEL guide already runs two separate `tailscaled` instances. For the
PC namespace, use the PC instance's daemon socket:

```bash
sudo tailscale --socket=/run/tailscale-pc/tailscaled.sock logout || true
sudo tailscale --socket=/run/tailscale-pc/tailscaled.sock up \
  --login-server=https://pc-control.example.net \
  --hostname=vault-rhel-pc \
  --accept-routes=false \
  --advertise-exit-node=false \
  --ssh=false
```

Complete the enrollment flow.

Now list nodes on `vault-pc`:

```bash
sudo -u headscale headscale nodes list --output json | jq .
```

Exactly the expected three Vault nodes should be present before application policy is
opened.

---

## 12. Migrate the Phone compartment

Repeat the same process against the Phone control plane.

### 12.1 `vault-phone`

```bash
sudo tailscale logout || true
sudo tailscale up \
  --login-server=https://phone-control.example.net \
  --hostname=vault-phone \
  --accept-routes=false \
  --advertise-exit-node=false \
  --ssh=false
```

### 12.2 Android Phone

In the Tailscale app, use the custom control-server/login-server option supported by the
installed client build and enroll against:

```text
https://phone-control.example.net
```

Use hostname:

```text
vault-phone-primary
```

Keep **Allow incoming connections** disabled.

### 12.3 RHEL-Phone instance

```bash
sudo tailscale --socket=/run/tailscale-phone/tailscaled.sock logout || true
sudo tailscale --socket=/run/tailscale-phone/tailscaled.sock up \
  --login-server=https://phone-control.example.net \
  --hostname=vault-rhel-phone \
  --accept-routes=false \
  --advertise-exit-node=false \
  --ssh=false
```

On `vault-phone`:

```bash
sudo -u headscale headscale nodes list --output json | jq .
```

Again, exactly the expected three nodes should be present.

---

## 13. Install explicit-default-deny Headscale policies

The exact IPs are assigned by the two independent Headscale pools. Record them first.

On each VPS:

```bash
sudo -u headscale headscale nodes list
```

Create a narrow policy. Example PC compartment policy; replace addresses with actual
Headscale addresses:

```hujson
{
  "hosts": {
    "pc": "100.64.10.1",
    "vault-pc": "100.64.10.2",
    "rhel-pc": "100.64.10.3"
  },
  "acls": [
    {
      "action": "accept",
      "src": ["100.64.10.1/32"],
      "dst": [
        "100.64.10.2:8888",
        "100.64.10.2:8891",
        "100.64.10.3:8000"
      ]
    },
    {
      "action": "accept",
      "src": ["100.64.10.3/32"],
      "dst": ["100.64.10.2:8891"]
    }
  ]
}
```

Phone compartment example:

```hujson
{
  "hosts": {
    "phone": "100.64.20.1",
    "vault-phone": "100.64.20.2",
    "rhel-phone": "100.64.20.3"
  },
  "acls": [
    {
      "action": "accept",
      "src": ["100.64.20.1/32"],
      "dst": [
        "100.64.20.2:8888",
        "100.64.20.2:8891",
        "100.64.20.3:8000"
      ]
    },
    {
      "action": "accept",
      "src": ["100.64.20.3/32"],
      "dst": ["100.64.20.2:8891"]
    }
  ]
}
```

The canonical coordinator/proxy port numbers in your copy of the master guide are the
authority. If that guide uses a different port, use the guide's actual port rather than
blindly pasting the examples above.

### Negative policy requirements

The policy must not create:

```text
PC -> Phone
Phone -> PC
PC -> RHEL-Phone
Phone -> RHEL-PC
vault-pc -> primary plaintext listener
vault-phone -> primary plaintext listener
RHEL-PC -> PC inbound application service
RHEL-Phone -> Phone inbound application service
```

Primary Shields Up / Android incoming-off remains required even when the Headscale
policy is correct.

---

## 14. Replace the Tailscale API expiry helper with local exact-node expiry

The canonical Tailscale guide uses an OAuth-backed exact-device helper as a compensating
control around the broad `devices:core` scope. In this extension the helper is removed
and replaced with a local Headscale command path.

### 14.1 Record the exact primary node identity

On `vault-pc`:

```bash
sudo -u headscale headscale nodes list --output json | \
  jq '.[] | {id, name, given_name, ip_addresses}'
```

Record:

```text
PC_PRIMARY_HEADSCALE_NODE_ID
PC_PRIMARY_HEADSCALE_NAME
PC_PRIMARY_HEADSCALE_IPV4
```

On `vault-phone`, record:

```text
PHONE_PRIMARY_HEADSCALE_NODE_ID
PHONE_PRIMARY_HEADSCALE_NAME
PHONE_PRIMARY_HEADSCALE_IPV4
```

Node ID is the actual local expiry target. Name and IP are independent guardrails.

### 14.2 Stop the Tailscale API helper

On each VPS:

```bash
sudo systemctl disable --now vault-tailscale-expire-primary.path 2>/dev/null || true
sudo systemctl disable --now vault-tailscale-expire-primary.service 2>/dev/null || true
```

Do **not** delete the files until the new local expiry path passes the acceptance test.

### 14.3 Install the exact-node Headscale helper

Install `/usr/local/sbin/vault-headscale-expire-primary` on `vault-pc`:

```bash
sudo tee /usr/local/sbin/vault-headscale-expire-primary >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

INTENT='/var/lib/vault-device/expiry.intent'
STATE='/var/lib/vault-device/headscale-expiry.state'
LOCK='/run/vault-headscale-expire-primary.lock'

EXPECTED_ID='REPLACE_PC_PRIMARY_HEADSCALE_NODE_ID'
EXPECTED_NAME='REPLACE_PC_PRIMARY_HEADSCALE_NAME'
EXPECTED_IP='REPLACE_PC_PRIMARY_HEADSCALE_IPV4'
HEADSCALE='/usr/bin/headscale'

exec 9>"$LOCK"
flock -n 9 || exit 0

[ -s "$INTENT" ] || exit 0

INTENT_IP="$(sed -n 's/^ip=//p' "$INTENT")"
[ -n "$INTENT_IP" ] || {
  echo 'CRITICAL: expiry intent contains no ip=' >&2
  exit 1
}

[ "$INTENT_IP" = "$EXPECTED_IP" ] || {
  echo "CRITICAL: expiry intent IP $INTENT_IP is not expected primary $EXPECTED_IP" >&2
  exit 1
}

JSON="$($HEADSCALE nodes list --output json)"
MATCH_COUNT="$(printf '%s' "$JSON" | python3 - "$EXPECTED_ID" "$EXPECTED_NAME" "$EXPECTED_IP" <<'PY'
import json, sys
expected_id, expected_name, expected_ip = sys.argv[1:]
nodes = json.load(sys.stdin)
count = 0
for n in nodes:
    nid = str(n.get('id', ''))
    name = n.get('name') or n.get('given_name') or ''
    ips = n.get('ip_addresses') or []
    if nid == expected_id and name == expected_name and expected_ip in ips:
        count += 1
print(count)
PY
)"

[ "$MATCH_COUNT" = '1' ] || {
  echo "CRITICAL: exact primary identity matched $MATCH_COUNT Headscale nodes" >&2
  exit 1
}

INTENT_SHA="$(sha256sum "$INTENT" | awk '{print $1}')"
printf 'intent_sha256=%s\nstatus=attempting\n' "$INTENT_SHA" > "$STATE"
chmod 600 "$STATE"
sync "$STATE"

# The helper never accepts a caller-supplied node ID. The target is fixed above.
$HEADSCALE node expire -i "$EXPECTED_ID"

printf 'intent_sha256=%s\nstatus=expired\n' "$INTENT_SHA" > "$STATE"
chmod 600 "$STATE"
sync "$STATE"
rm -f "$INTENT"
EOF

sudo chown root:root /usr/local/sbin/vault-headscale-expire-primary
sudo chmod 700 /usr/local/sbin/vault-headscale-expire-primary
```

Install the same helper on `vault-phone` with the exact Phone node constants.

### Why the helper checks ID + name + IP

The local Headscale CLI has broad administrative authority. The safety property here is
not that Headscale itself is least-privileged; it is that the Vault expiry helper has no
input grammar capable of selecting an arbitrary node.

The helper verifies:

```text
persisted Vault expiry intent IP
        == expected primary IPv4

AND exact Headscale node ID
AND exact Headscale name
AND expected IPv4 belongs to that exact node
AND exactly one node matches
```

Only then does it run the fixed command:

```text
headscale node expire -i <COMPILED/CONFIGURED EXPECTED PRIMARY ID>
```

A caller cannot supply a URL, HTTP method, device ID, hostname or arbitrary Headscale
subcommand.

### 14.4 systemd path unit

Install `/etc/systemd/system/vault-headscale-expire-primary.path`:

```ini
[Unit]
Description=Watch for Vault primary-node expiry intent

[Path]
PathExists=/var/lib/vault-device/expiry.intent
Unit=vault-headscale-expire-primary.service

[Install]
WantedBy=multi-user.target
```

Install `/etc/systemd/system/vault-headscale-expire-primary.service`:

```ini
[Unit]
Description=Expire the exact Vault primary Headscale node
After=headscale.service
Requires=headscale.service

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/vault-headscale-expire-primary
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vault-device /run
NoNewPrivileges=true
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-headscale-expire-primary.path
```

### 14.5 Remove the Tailscale OAuth expiry credential only after success

After the new helper passes the test in Section 16:

```bash
sudo systemctl disable --now vault-tailscale-expire-primary.path 2>/dev/null || true
sudo rm -f /etc/vault-tailscale/oauth-client-id
sudo rm -f /etc/vault-tailscale/oauth-client-secret
sudo rm -f /usr/local/sbin/vault-tailscale-expire-primary.py
sudo rm -f /etc/systemd/system/vault-tailscale-expire-primary.*
sudo systemctl daemon-reload
```

Revoke/delete the corresponding OAuth client in the Tailscale admin interface for the
old tailnet.

The Headscale threat-model delta is not complete while a forgotten `devices:core`
credential remains valid.

---

## 15. Update the canonical VPS coordinator assumptions

The cross-VPS coordinator, signature keys, session deadline state and AWS/RHEL proof
formats do not change.

Only replace the node-expiry backend call:

```text
Tailscale exact-device expiry helper
        |
        v
Headscale local exact-node expiry helper
```

Do not allow the coordinator to invoke arbitrary Headscale commands. The coordinator
must continue to express only one persistent intent:

```text
expire my exact primary after the signed Vault session closes/expires
```

The root-owned path helper translates that narrow intent into the one fixed Headscale
expiry command.

---

## 15A. S3 completion close is control-plane-provider independent

Replacing Tailscale with Headscale does **not** replace the S3 successful-completion
containment path. `CLOSE_PEER s3` is authenticated with the Vault VPS Ed25519 signing
keys and transported over the dedicated `wg-cross` link; it is not authorized by
Tailscale Tailnet Lock, Headscale ACL state, or the node-expiry mechanism.

After migration, rerun the canonical tests proving:

```text
own MFA + opposite primary absent -> no fresh S3 issuance
snapshot alone -> not REVOKED
snapshot + later lock removal -> REVOKED + AWSRevokeOlderSessions
old STS denied after IAM propagation
clean opposite primary sees exact-session REVOKED and closes target proxy via CLOSE_PEER
wrong-deadline/expired CLOSE rejected
```

Headscale local exact-node expiry remains a separate session-hygiene mechanism. Do not
misdescribe it as STS revocation or as the peer-close authorization factor.

## 16. Day-zero acceptance tests

Run these tests on both compartments before enabling real backup.

### Test H-01 — exactly three expected nodes

```bash
sudo -u headscale headscale nodes list --output json | jq 'length'
```

Expected:

```text
3
```

Investigate any unexpected node. Do not merely delete it and continue without
understanding how it enrolled.

### Test H-02 — primary inbound prohibition

From `vault-pc`, attempt a new connection to an arbitrary PC port that has no canonical
return connection:

```bash
nc -zvw3 PC_HEADSCALE_IP 22
```

The Vault architecture must not rely on a reachable primary listener. PC Shields Up
must remain enabled.

Repeat the equivalent negative test in the Phone compartment.

### Test H-03 — cross-compartment isolation

PC tailnet nodes must not resolve or reach Phone Headscale addresses. Phone tailnet
nodes must not reach PC Headscale addresses.

There is no shared Headscale control plane and no subnet route bridging the two.

### Test H-04 — DERP fallback on restrictive Wi-Fi

On the real restrictive Wi-Fi network:

```bash
tailscale netcheck
tailscale status
tailscale ping VAULT_PC_HEADSCALE_IP
```

If direct UDP fails, a relayed connection is acceptable. The authorization system does
not change based on transport type.

Never add a direct-to-S3 or public-RHEL bypass because the network forces DERP.

### Test H-05 — exact local expiry

With no real Vault data transfer running, create a test expiry intent containing the
exact expected primary IP:

```bash
sudo install -d -o root -g root -m 700 /var/lib/vault-device
printf 'ip=%s\n' 'EXPECTED_PRIMARY_HEADSCALE_IPV4' | \
  sudo tee /var/lib/vault-device/expiry.intent >/dev/null
sudo chmod 600 /var/lib/vault-device/expiry.intent
```

Observe:

```bash
sudo journalctl -u vault-headscale-expire-primary.service -f
sudo -u headscale headscale nodes list
```

Expected:

```text
only the exact primary node expires
vault-pc/vault-phone VPS remains enrolled
matching RHEL instance remains enrolled
expiry.intent is removed only after successful local expiry
```

Reauthenticate the primary through the normal OIDC/MFA flow.

### Test H-06 — malformed intent fails closed

Write a wrong IP:

```bash
printf 'ip=100.64.255.254\n' | \
  sudo tee /var/lib/vault-device/expiry.intent >/dev/null
```

The helper must fail and leave the intent/state for investigation. It must not select a
nearby node or expire a node by hostname-only matching.

### Test H-07 — one compromised Headscale control plane is not enough for AWS/RHEL

Use a test node in only the PC Headscale compartment. Even if policy is deliberately
broadened for the test, the test node must not obtain:

```text
Phone-VPS Ed25519 proof
PC daily Lambda issuance without the valid Phone-VPS signature
RHEL-PC backend opening without both valid VPS signatures
Phone bucket role
```

Restore the explicit-default-deny policy immediately after the test.

---

## 17. Upgrades and configuration backup

Back up only what is required to rebuild the control plane. Protect control-plane
backups as sensitive infrastructure data.

On each VPS, include:

```text
/etc/headscale/config.yaml
/etc/headscale/policy.hujson
/var/lib/headscale/db.sqlite
/var/lib/headscale/private.key
/var/lib/headscale/noise_private.key
OIDC client configuration/secret through the approved secret-backup process
```

Do not put these files into either primary plaintext Vault scope.

Before a Headscale upgrade:

```bash
sudo systemctl stop headscale
sudo cp -a /var/lib/headscale "/root/headscale-backup-$(date +%F-%H%M%S)"
sudo cp -a /etc/headscale "/root/headscale-config-backup-$(date +%F-%H%M%S)"
sudo systemctl start headscale
```

Review the release changelog and tagged config example. Test on one non-Vault staging
instance if a release changes policy, DERP, OIDC or node expiry semantics.

Never perform a control-plane upgrade during an active Vault session.

---

## 18. Add the Peer Relay extension later if needed

The Headscale baseline intentionally does not open public Peer Relay UDP.

Measure real backup performance first. If direct UDP fails and default DERP throughput
cannot finish a realistic backup delta inside the signed one-hour Vault session, apply:

```text
Vault_Extension_Peer_Relay_Performance.md
```

Use Headscale 0.29.2 or a later reviewed release with policy grants/application
capability support required by Peer Relay.

Do not self-host DERP merely because you self-host the control plane. Peer Relay and
self-hosted DERP are separate decisions.

---

## 19. Revert to the canonical Tailscale + Tailnet Lock baseline

Rollback is a planned migration, not `tailscale logout` on random nodes.

### Phase 1 — freeze

1. No active Vault session.
2. S3 proxies have no active tunnels.
3. Both RHEL backends stopped.
4. Preserve Headscale databases/configuration for forensic rollback.

### Phase 2 — recreate/verify the two independent Tailscale tailnets

Return to the canonical topology:

```text
PC tailnet:
  PC
  vault-pc
  RHEL-PC

Phone tailnet:
  Phone
  vault-phone
  RHEL-Phone
```

Enable Tailnet Lock and establish the canonical signer set before opening Vault access.
Remember that Android is not used as a signing node in the canonical plan.

### Phase 3 — migrate every node

Remove custom Headscale login-server configuration and re-enroll every node into the
matching Tailscale tailnet.

Verify exact Tailscale node IDs and IPs before configuring the expiry helper.

### Phase 4 — reinstall exact-device Tailscale expiry helper

Create one separate OAuth credential per tailnet with the documented `devices:core`
scope and exact helper tag/constraints from the canonical guide.

Reinstall the root-owned helper exactly as documented in the master. Do not invent a
broader general-purpose Tailscale API wrapper.

### Phase 5 — Tailnet Lock acceptance

Sign only the expected nodes. Verify an unsigned test node receives no locked-tailnet
connectivity.

### Phase 6 — remove Headscale only after negative tests pass

After the canonical day-zero tests pass:

```bash
sudo systemctl disable --now headscale
```

Revoke old OIDC clients if they are no longer used and remove obsolete public DNS
records only after rollback records are preserved.

---

## 20. Threat-model delta

When this extension is enabled, update `Vault_Threat_Model_and_Risk_Register.md`:

```text
EXT-HEADSCALE ENABLED

T-04 changes from:
  Tailscale coordination-plane compromise cannot insert an unsigned node accepted by
  locked peers because Tailnet Lock is an independent membership signature layer.

to:
  Headscale control-plane compromise can manipulate node admission, network maps and
  policy for the affected compartment. Primary Shields Up / Android incoming-off limits
  new inbound application connections, and Headscale alone does not rewrite the local
  restic source path or read primary plaintext. However, unauthorized membership is a
  meaningful residual risk and can be chained with another endpoint/service flaw.

T-06 is removed for the affected compartment:
  the Tailscale devices:core OAuth credential no longer exists.

Replacement expiry risk H-01:
  root/local Headscale administrative authority is broad. The Vault helper constrains
  its own grammar to one exact preconfigured node ID after exact ID+name+IP checks, but
  a full VPS root compromise can still directly administer the local Headscale instance.

Invariants I-01 through I-14 otherwise remain in force.
```

When reverting to Tailscale, restore the canonical T-04 and T-06 entries and mark
`EXT-HEADSCALE DISABLED` in the threat-model change log.

---

## 21. Final decision rule

Choose this extension when the following statement is more important to you:

> The Vault's server-side session revocation should use local exact-node authority and
> should not retain a broad Tailscale devices:core OAuth credential.

Stay on the canonical Tailscale baseline when this statement is more important:

> A coordination-plane-only compromise should not be able to introduce an unsigned node
> that locked peers accept, and Tailscale-hosted DERP should remain a provider-operated relay
> surface rather than a Vault VPS listener.

For this project, the second statement is why Tailscale remains the canonical default.

## HARDENING COMPATIBILITY DELTA

This extension is subordinate to the canonical master guide's
`PART 2A: PRODUCTION SERVICE CONFINEMENT — SYSTEMD AND PODMAN HARDENING`.

Rules:

```text
do not broaden Fedora's canonical single-source backup binding
do not replace rootless Podman with rootful/privileged Podman
do not disable SELinux labeling to fix an extension error
do not apply a generic SystemCallFilter to network/control-plane services without tests
rerun the hardening acceptance matrix after enabling or removing this extension
```

Any extension-specific service, listener, or container must receive its own least-
privilege review. A lower `systemd-analyze security` score never overrides the
extension's authorization, deadline, rollback, or isolation invariants.

### Headscale-service hardening note

Headscale is the control plane and has network, state-database, and coordination needs.
Do not apply the empty-capability profile from the custom Go coordinator blindly to
`headscale.service`. Keep Headscale's state/config paths explicit, run it as its dedicated
service identity, and inspect `systemd-analyze security headscale.service`.

The local `vault-headscale-expire-primary.service` is narrower. Apply the same generic
custom-helper hardening principles as the canonical Tailscale expiry helper:
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, kernel protection,
`PrivateDevices`, `RestrictSUIDSGID`, `LockPersonality`, `RestrictRealtime`,
`SystemCallArchitectures=native`, a narrow address-family set, and explicit read/write
paths.

Do not weaken the canonical coordinator service identity, DAC permissions, systemd
sandbox, or cross-VPS signing controls during a Tailscale-to-Headscale migration.

## 21. RHEL 9 SELinux boundary for the Headscale extension

The host must remain SELinux Enforcing:

```bash
getenforce
```

Expected:

```text
Enforcing
```

The canonical Headscale extension does **not** require the operator to create a custom
SELinux policy module for the standalone Headscale binary. Do not run
`sepolicy generate --init`, auto-load `audit2allow` output, or make a new Headscale
domain permissive as part of this guide.

Headscale is instead constrained by:

```text
dedicated headscale Unix user/group
/etc/headscale read-only in the systemd mount namespace
/var/lib/headscale as the declared writable state path
NoNewPrivileges
ProtectSystem=strict
ProtectHome=yes
PrivateDevices
kernel/control-group protections
restricted address families
firewalld public-listener policy
Caddy as the separate public HTTPS edge
```

The fact that a custom standalone daemon may appear in `unconfined_service_t` is not
treated as a production failure in this baseline. No per-daemon SELinux MAC claim is
made.

SELinux still protects the host according to the RHEL targeted policy and remains
mandatory. Do not disable SELinux or relabel broad trees to make Headscale work.

After install or upgrade, rerun:

```bash
getenforce
systemctl show headscale.service \
  -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome
sudo systemd-analyze security headscale.service
sudo firewall-cmd --zone=drop --list-all
sudo journalctl -u headscale -b --no-pager
```

Then rerun the extension's OIDC, node-registration, policy, map-delivery,
exact-node-expiry, restart, and reconnect tests.

A future custom Headscale SELinux policy may be developed as a separate expert-reviewed
hardening extension. It is not a prerequisite for this extension.
