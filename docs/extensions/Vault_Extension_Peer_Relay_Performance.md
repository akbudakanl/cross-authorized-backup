---
status: rejected
---
# VAULT EXTENSION - ADD PEER RELAY ONLY AFTER A MEASURED DERP PERFORMANCE FAILURE
================================================================================

This extension is currently rejected for security reasons, as opening an additional UDP port is not desired at this time. However, it may be reconsidered in the future if the current DERP solution leads to transfer speed degradation caused by the "TCP meltdown" problem.

## 1. Purpose

The core Vault transport order is:

```text
direct WireGuard / UDP when available
        |
        | direct path fails
        v
managed/public DERP relay over the available relay path
```

This is deliberately conservative. The two Vault VPSs do not expose a public Peer Relay
listener by default.

Apply this extension only when a **realistic backup delta on the real restrictive
network** proves that DERP throughput cannot finish reliably inside the Vault's signed
one-hour session ceiling, while UDP to a chosen VPS relay port is actually available.

Peer Relay changes transport performance and public attack surface. It does **not**
replace:

```text
cross-VPS Ed25519 authorization
daily AWS issuance slots
separate S3 roles and buckets
fixed S3 egress /32 restrictions
AWS-side snapshot + later lock-removal S3 completion revocation
read-only exact-session completion status
signed cross-VPS CLOSE_PEER S3 admission shutdown
backup-role permissions boundaries
RHEL local dual-signature gate
signed hard one-hour deadline
primary inbound prohibition
```

---

## 2. Decision tree before installing

Run the test from the actual campus/restrictive Wi-Fi, not from a home network.

```text
A. Can the primary establish a direct UDP path to its own VPS/RHEL peer?
   YES -> keep direct. Peer Relay is unnecessary.
   NO  -> continue.

B. Does DERP complete a representative backup delta comfortably inside one hour?
   YES -> keep DERP. Peer Relay is unnecessary.
   NO  -> continue.

C. Can the client send UDP to <OWN_VPS_PUBLIC_IP>:40000?
   NO  -> Peer Relay cannot solve an all-UDP-blocked network. Keep DERP/fail closed.
   YES -> continue.

D. Can the required campus and RHEL source identities be represented by a deliberately
   accepted narrow provider-firewall/firewalld allowlist?
   NO  -> keep DERP. Do not open UDP/40000 broadly for performance.
   YES -> explicitly assess the shared-NAT population behind each allowed campus source.
          If that exposure is accepted, Peer Relay is a reasonable performance extension.
```

The wrong decision is:

```text
UDP blocked -> install Peer Relay
```

Peer Relay itself uses a selected UDP listener. If the network blocks all outbound UDP,
the useful fallback remains DERP.

### 2.1 Enable during the initial rollout

“Day-zero Peer Relay” still means **measure first**. During commissioning, complete the
core direct/managed-DERP transport test with representative backup delta data. If
the Section 2 decision tree reaches D=YES and its shared-NAT exposure is explicitly
accepted in that same rollout window, apply Sections 4–12 before storing irreplaceable data and then rerun the core day-zero negative
tests.

Do not pre-open UDP/40000 or advertise relay capability before the measurement merely
because the extension file exists.

### 2.2 Add later

If the core deployment has already been running, keep the current direct/DERP
transport active while collecting the Section 4 baseline. Apply Peer Relay one
compartment at a time, prove actual Peer Relay selection, then prove DERP fallback by
blocking UDP/40000. The AWS/RHEL authorization and daily-slot state are not migrated;
this extension changes only transport.

Removal is fully documented in Section 13. Removing Peer Relay later must restore the
core `direct -> managed/public DERP` path and close UDP/40000 on both VPSs.

---

## 3. Compatibility

### Core Tailscale baseline

Use a Tailscale client version that supports Peer Relay. The current implementation plan
requires Tailscale **1.86 or later** on the relay and participating clients.

### Headscale extension

If `Vault_Extension_Headscale_Control_Plane.md` is enabled, use Headscale **0.29.2 or a
later reviewed release** with grants/application capability support for Peer Relay.

Do not assume an old Headscale policy parser understands `tailscale.com/cap/relay`.

### Relay platform

The relay in this project is a Linux VPS:

```text
vault-pc    -> relay only for PC compartment
vault-phone -> relay only for Phone compartment
```

Do not create one shared relay for both compartments.

---

## 4. Record a pre-change performance baseline

Use a representative encrypted transfer size. Do not benchmark a 1 MiB file and infer
that a 20 GiB restic run will behave identically.

Before Peer Relay, record:

```text
date/time
network name/location
PC or Phone compartment
Tailscale version
connection type shown by tailscale status/ping
backup delta bytes
total elapsed seconds
average observed throughput
whether the signed one-hour session completed with margin
```

Useful commands on Fedora/Linux:

```bash
tailscale version
tailscale netcheck
tailscale status
tailscale ping VAULT_PC_TAILSCALE_IP
```

For the Phone compartment, inspect the Tailscale app's connection information and VPS
logs in addition to the Phone workflow elapsed time.

Run at least three representative sessions on the target network if practical. A single
congested DERP session is not enough evidence for enabling a new Peer Relay listener.

---

## 5. Measure source identities and create a source-restricted UDP allowlist

This extension uses:

```text
UDP/40000
```

**Do not open UDP/40000 to `0.0.0.0/0`.** Peer Relay is retained as an optional
performance extension, not as justification for an Internet-wide UDP listener on either
Vault VPS.

Before enabling the listener, identify the public source addresses that must actually
reach the matching relay.

### 5.1 Measure the restrictive/campus network

From the real target Wi-Fi, record the observed public IPv4 on several representative
days and, if the campus has materially different locations or SSIDs, from those locations:

```bash
curl -4 https://checkip.amazonaws.com
tailscale netcheck
```

Record:

```text
date/time
SSID / location
observed public IPv4
Tailscale netcheck result
whether UDP/40000 reaches the matching VPS during the controlled test
```

Do not infer the allowlist from the campus name, WHOIS organization, ASN, or the full
address space announced by the institution. Do not whitelist a broad university or ISP
prefix merely because the measured address belongs to it.

The goal is the **smallest empirically justified egress set**. Examples:

```text
one stable NAT egress address       -> one /32
a repeatedly observed small pool    -> the narrow proven CIDR(s) only
widely changing or broad NAT pool    -> do not add a campus Peer Relay rule; keep DERP
```

A shared campus NAT address is not a device identity. Every hostile or compromised host
that exits through an allowed NAT address can also deliver UDP datagrams to the Peer Relay
listener. Treat the entire observed shared-NAT population as part of the network-facing
attack surface.

### 5.2 Add the existing RHEL-home egress identity

The matching RHEL tailnet instance also needs to reach the relay endpoint. Reuse the
already documented and verified RHEL-home public egress identity from the core
firewall/whitelist model. Prefer the exact current `/32` when the home egress address is
stable.

If that address is dynamic, do not broaden the rule to the ISP ASN or a large consumer
prefix. A stale allowlist must fail safely to DERP until the operator reviews and updates
the exact source rule.

### 5.3 Create provider-firewall rules first

At the VPS provider firewall/security-group layer, allow UDP/40000 only from the measured
and accepted source set for the matching compartment. Conceptually:

```text
vault-pc UDP/40000 sources:
  VERIFIED_CAMPUS_EGRESS_CIDR_1   # only if accepted after measurement
  VERIFIED_CAMPUS_EGRESS_CIDR_2   # only if actually observed/required
  RHEL_HOME_PUBLIC_IP/32

vault-phone UDP/40000 sources:
  VERIFIED_CAMPUS_EGRESS_CIDR_1   # only if accepted after measurement
  VERIFIED_CAMPUS_EGRESS_CIDR_2   # only if actually observed/required
  RHEL_HOME_PUBLIC_IP/32

all other IPv4 sources:
  DROP UDP/40000
```

If the campus egress set is too broad, unstable, or operationally unclear, omit all
campus rules. Keep only the RHEL-home source rule and allow campus clients to remain on
DERP.

### 5.4 Mirror the same source allowlist in RHEL firewalld

The core Vault VPSs use firewalld. Examples only; replace every placeholder with
measured values.

On `vault-pc`:

```bash
sudo firewall-cmd --permanent --zone=drop \
  --add-rich-rule='rule family="ipv4" source address="VERIFIED_CAMPUS_EGRESS_CIDR_1" port port="40000" protocol="udp" accept'

sudo firewall-cmd --permanent --zone=drop \
  --add-rich-rule='rule family="ipv4" source address="RHEL_HOME_PUBLIC_IP/32" port port="40000" protocol="udp" accept'

sudo firewall-cmd --reload
sudo firewall-cmd --zone=drop --list-rich-rules
```

Repeat on `vault-phone` with the same empirically accepted source set for that
compartment.

Add additional campus CIDRs only when Section 5.1 evidence justifies them. Do not use:

```bash
# FORBIDDEN IN THIS EXTENSION
sudo firewall-cmd --permanent --zone=drop --add-port=40000/udp
```

That unrestricted port rule admits every source reaching the public interface.

Do not open TCP/40000. Do not open a port range. Do not add UDP/40000 listeners to the
backup RHEL host or either primary device. The RHEL backup host only initiates outbound
UDP toward the matching VPS relay.

## 6. Enable Peer Relay on each VPS

On `vault-pc`:

```bash
sudo tailscale set --relay-server-port=40000
```

On `vault-phone`:

```bash
sudo tailscale set --relay-server-port=40000
```

Verify:

```bash
sudo ss -lunp | grep ':40000'
tailscale status
```

### Static endpoint advertisement

A VPS with a stable public IPv4 should normally have a predictable endpoint. If automatic
endpoint discovery does not advertise the address clients can actually reach, explicitly
advertise the fixed endpoint:

On `vault-pc`:

```bash
sudo tailscale set \
  --relay-server-port=40000 \
  --relay-server-static-endpoints='VAULT_PC_PUBLIC_IP:40000'
```

On `vault-phone`:

```bash
sudo tailscale set \
  --relay-server-port=40000 \
  --relay-server-static-endpoints='VAULT_PHONE_PUBLIC_IP:40000'
```

Replace the placeholders with the real stable public addresses.

Do not advertise the other compartment's address.

---

## 7. Grant relay capability narrowly

Peer Relay requires an application capability grant. The exact policy syntax depends on
whether the core Tailscale control plane or Headscale extension is active, but the
security rule is the same:

```text
PC compartment:
  PC may use vault-pc as its relay
  RHEL-PC may use vault-pc as needed for that compartment
  no Phone-compartment identity is a relay user

Phone compartment:
  Phone may use vault-phone as its relay
  RHEL-Phone may use vault-phone as needed for that compartment
  no PC-compartment identity is a relay user
```

### 7.1 Tailscale grant example

In the PC tailnet policy, add a grant shaped like:

```json
{
  "src": ["PC_IDENTITY_OR_GROUP"],
  "dst": ["VAULT_PC_RELAY_IDENTITY_OR_TAG"],
  "app": {
    "tailscale.com/cap/relay": [{}]
  }
}
```

In the Phone tailnet, independently add:

```json
{
  "src": ["PHONE_IDENTITY_OR_GROUP"],
  "dst": ["VAULT_PHONE_RELAY_IDENTITY_OR_TAG"],
  "app": {
    "tailscale.com/cap/relay": [{}]
  }
}
```

Use the exact user/tag selectors already established by the core policy. Do not
replace a narrow policy with `autogroup:member -> *` merely to make the relay appear.

### 7.2 Headscale grant example

When the Headscale extension is enabled, add the equivalent grant in that compartment's
policy file using the installed 0.29.2 grant syntax:

```hujson
{
  "grants": [
    {
      "src": ["PC_SOURCE_SELECTOR"],
      "dst": ["VAULT_PC_RELAY_SELECTOR"],
      "app": {
        "tailscale.com/cap/relay": [{}]
      }
    }
  ]
}
```

Repeat independently for Phone.

After a Headscale policy edit:

```bash
sudo systemctl restart headscale
sudo journalctl -u headscale -n 100 --no-pager
```

If the parser rejects the `app` grant, stop. Do not weaken the application capability
model into broad packet access as a workaround.

---

## 8. Verify source filtering and listener reachability before using Vault data

On each VPS:

```bash
sudo ss -lunp | grep ':40000'
sudo firewall-cmd --zone=drop --list-rich-rules
sudo tcpdump -ni any udp port 40000
```

Verify the provider firewall and firewalld contain the same accepted source set. There must be
no `0.0.0.0/0` or equivalent unrestricted UDP/40000 allow rule.

From the real restrictive Wi-Fi, run a controlled connection attempt from only the
matching primary.

Expected on `vault-pc` while PC tests:

```text
UDP packets from an explicitly allowed measured campus egress source arrive on 40000
```

Expected on `vault-phone` while Phone tests:

```text
UDP packets from an explicitly allowed measured campus egress source arrive on 40000
```

Also test from the RHEL home path and verify packets arrive from the exact accepted
RHEL-home egress identity.

Then perform a negative source-filter test from a network that is **not** on the allowlist,
for example mobile data or another unrelated Internet connection. The matching VPS must
not admit UDP/40000 from that source.

If the campus source is not stable enough to express as a narrowly accepted set, or UDP
does not arrive from the allowed source and the client remains on DERP, **do not broaden
the firewall to a university ASN, ISP range, or `0.0.0.0/0` to make the test pass**.
Remove the campus rule or the entire extension using Section 13.

---

## 9. Prove the client is using Peer Relay

Use:

```bash
tailscale status
tailscale ping MATCHING_VPS_OR_RHEL_NODE
```

Record the connection type reported by the client. The desired test progression is:

```text
direct unavailable
        v
Peer Relay selected
```

Do not infer relay use merely because UDP/40000 packets exist. A control or probing packet
is not proof that the long-lived data path is relayed through the VPS.

Run the same representative restic backup delta used for the pre-change baseline.

Record:

```text
elapsed time
backup delta bytes
connection type
whether session completed before signed deadline
CPU/RAM on relay VPS
VPS egress/ingress transfer volume
```

The extension is successful only if it solves the operational problem that justified it.

---

## 10. DERP fallback must still work

Peer Relay is not allowed to become a hidden single point of availability failure.

Temporarily block the relay port on the matching VPS during a non-production test:

```bash
sudo firewall-cmd --zone=drop --add-rich-rule='rule priority="-100" family="ipv4" source address="TEST_CLIENT_CURRENT_PUBLIC_IP/32" port port="40000" protocol="udp" reject'
```

Reconnect/test:

```bash
tailscale ping MATCHING_NODE
```

Expected:

```text
Peer Relay becomes unavailable
        v
client falls back to DERP relay when direct is also unavailable
```

The Vault ceremony must still be fail-closed if no transport works.

Remove the temporary runtime deny by supplying the exact same rich-rule text:

```bash
sudo firewall-cmd --zone=drop   --remove-rich-rule='rule priority="-100" family="ipv4" source address="TEST_CLIENT_CURRENT_PUBLIC_IP/32" port port="40000" protocol="udp" reject'

sudo firewall-cmd --zone=drop --list-rich-rules
```

The temporary test rule was not added with `--permanent`; do not add it permanently and
do not add an unrestricted UDP/40000 allow rule. Inspect the current rich-rule list
instead of assuming remembered rule state.

---

## 11. Security interpretation

Peer Relay adds a UDP listener on the VPS:

```text
VPS UDP/40000 listener
```

In this extension the listener is **not intentionally Internet-wide reachable**. Provider
firewall and firewalld source rules restrict packets to the empirically accepted source set.
That is a real reduction in exposure, but it is not equivalent to authenticating a
specific primary device.

For a shared campus NAT source:

```text
allowed campus public egress IP
        =
all devices currently exiting through that same accepted NAT identity
```

A malicious campus host behind the same allowed egress can therefore deliver UDP
datagrams to the listener even though it cannot legitimately obtain the narrow
`tailscale.com/cap/relay` permission. The capability grant controls authorized relay use;
it does not turn the source CIDR rule into device authentication.

The additional code path is the Tailscale Peer Relay packet-processing/state-machine path
in `tailscaled`, not a weakness inherent to the UDP protocol itself. Malformed or abusive
network input can still contribute to parser/state/resource-exhaustion risk in any
network-facing implementation. Source filtering reduces which networks can reach that
code path; keeping Tailscale patched and removing an unused listener remain mandatory.

However, the relay capability is a **transport permission**, not a Vault authorization
signature.

Compromise of `vault-pc` Peer Relay still does not provide:

```text
Phone-VPS Ed25519 private key
valid Phone-VPS approval signature
PC daily S3 slot reset
Phone S3 role
RHEL-PC dual-signature authorization
restic repository password
```

Likewise for `vault-phone`.

The security equation remains:

```text
one VPS compromise != two valid VPS signatures
```

unless the attacker separately compromises the other VPS or its signing key.

### WireGuard encryption

Direct, DERP-relayed and Peer-Relay paths remain Tailscale connection types carrying the
tailnet packet path. Peer Relay does not turn restic plaintext into relay-visible
plaintext. The application data is still inside the tailnet's WireGuard-encrypted path;
restic also encrypts repository data before it reaches S3/RHEL.

Do not use this statement to ignore local endpoint compromise: malware on the source can
read the source's plaintext before restic encryption.

---

## 12. Operational monitoring

Add the following checks to monthly infrastructure review:

```bash
# Each relay VPS
sudo ss -lunp | grep ':40000'
sudo firewall-cmd --zone=drop --list-rich-rules
tailscale status
sudo journalctl -u tailscaled --since '30 days ago' | tail -500
```

Record whether Peer Relay was actually used on the target network. Re-check the observed
campus public egress addresses against the approved source rules; do not automatically
widen rules when a new address appears.

If several months of real operation show:

```text
DERP/direct always sufficient
Peer Relay never selected
```

remove this extension. A network-facing listener should not survive merely because it
was once interesting to test.

Review VPS bandwidth accounting. Peer Relay traffic traverses your own VPS and therefore
uses the provider's network allowance; Tailscale-hosted DERP does not make that traffic your VPS
bandwidth bill.

---

### 12.1 Completion containment must survive the transport change

Peer Relay changes packet transport only and does not replace successful-completion
revocation, exact-session status, or signed cross-VPS `CLOSE_PEER`. Rerun the core
completion containment tests after enabling the relay.

## 13. Remove Peer Relay and return to core transport

Removal is intentionally simple and reversible.

### 13.1 Disable relay service advertisement

On both VPSs:

```bash
sudo tailscale set --relay-server-port=''
```

If static endpoints were set, clear them according to the installed client syntax and
verify the node no longer advertises a Peer Relay service.

### 13.2 Remove grants

Delete only the `tailscale.com/cap/relay` grant added by this extension from each
compartment policy.

Do not delete the core S3 proxy/RHEL access grants.

### 13.3 Remove every source-restricted UDP/40000 rule

On each VPS:

```bash
sudo firewall-cmd --zone=drop --list-rich-rules
```

Remove every Peer Relay UDP/40000 rich rule by its exact rich-rule text. Do not assume there is only one campus CIDR or one RHEL rule.

Remove the matching source-restricted provider security-group/network-list rules. Verify
that no unrestricted UDP/40000 rule was ever added and no stale measured-source rule
remains.

Verify:

```bash
sudo ss -lunp | grep ':40000' && echo 'ERROR: relay listener still active' || true
```

### 13.4 Regression test

On restrictive Wi-Fi:

```bash
tailscale ping MATCHING_NODE
```

Expected:

```text
direct if available
otherwise DERP
```

Run a small non-destructive Vault preflight. There must be no direct-to-S3 or public-RHEL
bypass.

---

## 14. Interaction with other extensions

### Mutual Backup extension

The dedicated `wg-mutual` PC↔Phone transfer does not use Peer Relay. It remains a
separate manually activated WireGuard tunnel over the Phone hotspot.

Do not reroute mutual receiver traffic through the two Vault tailnets merely because Peer
Relay exists.

### Prune extension

No interaction with retention semantics. Peer Relay does not authorize forget/prune and
must not make RHEL repository passwords available to a VPS.

### Headscale extension

Supported only on a reviewed Headscale release with Peer Relay grants/application
capability support. The control-plane membership risk described by the Headscale threat
model remains; Peer Relay neither fixes nor worsens Tailnet Lock absence. This extension
does add the source-restricted UDP Peer Relay listener and its associated packet-processing
attack surface to each matching VPS.

---

## 15. Threat-model delta

When enabling this extension, update `Vault_Threat_Model_and_Risk_Register.md`:

```text
EXT-PEER-RELAY ENABLED

New risk PR-01:
  vault-pc and vault-phone run a UDP Peer Relay listener on the selected port. The
  listener is source-restricted at both the VPS provider firewall and host firewalld layer;
  it is not intentionally exposed to 0.0.0.0/0. Relayed bandwidth moves onto the
  operator's VPS/provider path.

Controls:
  one relay per existing compartment; no shared cross-compartment relay; narrow
  tailscale.com/cap/relay grant; fixed single UDP port; no TCP listener added by this
  extension; patched Tailscale client; provider-firewall and firewalld rules use only the
  smallest empirically justified campus egress source set plus the existing verified
  RHEL-home egress identity; no ASN-wide, ISP-wide or Internet-wide allow rule; listener
  retained only after real-network performance validation; cross-VPS Ed25519
  authorization remains independent.

Residual:
  source IP filtering is not device authentication. A malicious or compromised host
  sharing an allowed campus NAT egress can deliver UDP datagrams to the Peer Relay
  listener. A vulnerability or resource-exhaustion bug in the relay/Tailscale packet
  processing path or host can contribute to a VPS compromise or denial of service. One
  compromised VPS still lacks the other VPS signing key and therefore cannot
  independently authorize a new S3 or RHEL window.

T-12 update:
  when direct UDP is unavailable, Peer Relay may be selected before DERP only from
  networks whose measured source identity is admitted to UDP/40000 and from which the
  relay port is actually reachable. Unknown, disallowed, stale-source or all-UDP-blocked
  networks remain on DERP when direct is unavailable.
```

When removing the extension, mark `EXT-PEER-RELAY DISABLED`, remove PR-01 after the
listener, grant and **all source-restricted provider/firewalld rules** are gone, and restore
the core T-12 transport text.

---

## 16. Final activation criterion

Keep Peer Relay only when this sentence is true and supported by measurements:

> On the real restrictive network, direct UDP is unavailable, managed/public DERP cannot
> complete representative Vault backup deltas with acceptable margin inside the signed
> one-hour session, UDP/40000 to the matching Vault VPS is reachable, the required client
> and RHEL source identities can be expressed as a deliberately accepted narrow allowlist,
> the shared-NAT exposure of that allowlist has been explicitly accepted, and Peer Relay
> materially improves measured transfer time.

If the campus egress set is broad, unstable, shared beyond the accepted threat boundary,
or requires ASN/ISP/Internet-wide firewall rules, keep the core direct -> DERP
baseline. Otherwise, Peer Relay may be retained only with the source-restricted rules
documented by this extension.

## HARDENING COMPATIBILITY DELTA

This extension is subordinate to the core master guide's
`PART 2A: PRODUCTION SERVICE CONFINEMENT - SYSTEMD AND PODMAN HARDENING`.

Rules:

```text
do not broaden Fedora's core single-source backup binding
do not replace rootless Podman with rootful/privileged Podman
do not disable SELinux labeling to fix an extension error
do not apply a generic SystemCallFilter to network/control-plane services without tests
rerun the hardening acceptance matrix after enabling or removing this extension
```

Any extension-specific service, listener, or container must receive its own least-
privilege review. A lower `systemd-analyze security` score never overrides the
extension's authorization, deadline, rollback, or isolation invariants.

### Peer Relay hardening note

Peer Relay is a Tailscale transport service with deliberate UDP/network requirements.
Do not paste the core empty `CapabilityBoundingSet=` profile onto the Tailscale
relay service. Keep the source-restricted UDP firewall rules and Tailscale capability
policy as the primary listener boundaries, then inspect the effective vendor/generated
unit after every Tailscale upgrade.

The relay extension must not weaken `vault-device-coordinator.service`,
`vault-s3-proxy.service`, or the exact-device expiry helper merely to make relay traffic
work. If enabling Peer Relay requires such a change, remove Peer Relay and return to
managed DERP while investigating.

### Core relay-host platform

`vault-pc` and `vault-phone` are RHEL 9 BYOL/BYOI hosts with SELinux Enforcing and
firewalld. Peer Relay does not change the RHEL major-version or BYOI architecture
decision. On `E2.1.Micro`, use the x86_64 RHEL image; on `A1.Flex`, use the aarch64
RHEL image.

After enabling or removing Peer Relay, rerun:

```bash
getenforce
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=drop --list-rich-rules
tailscale version
sudo ss -lunp | grep ':40000'
```

Do not disable SELinux or replace firewalld with an independent ruleset flush to make a
relay test pass.
