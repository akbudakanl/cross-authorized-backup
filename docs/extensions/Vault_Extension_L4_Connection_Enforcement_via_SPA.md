# Extension Proposal: Migrating Cross-Sign Gate Enforcement from L7 (Caddy) to L3/L4 (Dynamic Firewall and SPA Support)

## 10. ARCHITECTURAL UPDATE: PROPOSAL REJECTED (Post-Bare-Firecracker)

> [!IMPORTANT]
> **Decision: REJECTED.** This document is no longer an active proposal and is preserved for historical reference only.
> The original rejection decisions for Option A (stateful reconciliation) and Option C (eBPF/XDP) remain in effect. Option B (SPA/fwknop) is also rejected based on the rationale below.

### 10.1 Rejection Rationale

This document was written under the assumption of an architecture where Caddy ran relatively close to the host — in that context, the problem of "the host being exposed to TCP/TLS/HTTP prior to authentication" was real, and SPA was a logical proposal to reduce this exposure.

With the transition to the Bare Firecracker (Path A) architecture, this premise became invalid: Caddy now runs inside its own MicroVM, has no access to the data disk, and TCP/TLS/HTTP parsing takes place entirely within the VM boundary (guest kernel + Go userspace). **The original problem SPA intended to solve (host exposure to pre-auth traffic) was already resolved by the architectural transition**, without needing an additional mechanism.

Furthermore, adding SPA/fwknop creates a **structural inconsistency** with the current architecture: dynamically modifying nftables rules requires `CAP_NET_ADMIN` — which by definition must be performed by a privileged process on the host and cannot be placed inside a guest. Thus, fwknop would become the **sole exception** to the principle followed across the rest of the architecture ("the host never performs raw/untrusted packet parsing") — operating as a root-privileged, C-based component running directly on the host.

Historical precedents (Heartbleed CVE-2014-0160, SACK Panic CVE-2019-11477) confirm that these layers carry a real attack surface — but in this architecture, the affected codebase is already isolated within the Go/VM boundary; adding fwknop does not reduce this risk, but rather introduces a **new and higher-privileged** instance of it to the host.

### 10.2 How is SPA's "Zero Response" Value Proposition Handled?

It comes for free via the ephemeral per-ceremony boot model: MicroVMs exist only during the ceremony window. Outside of the ceremony, a property stronger than SPA's "silent drop of the port" applies — there is simply no VM running behind the port at that time.

### 10.3 Alternative

The goal of device-specific, network-agnostic authentication is addressed in a separate extension (`Vault_Extension_PQC_Native_Communication_Auth_Process.md`) — since Ed25519/ML-DSA signing runs inside Caddy within the VM boundary, it does not expose any new host-level attack surface. This document is archived with reference to that extension.

---

## 1. Context

The current gate design terminates the connection at the application layer:

```
Tailnet peer --SYN--> RHEL:443 --TCP/TLS handshake--> Caddy --HTTP request--> Ed25519 check --> 401 or proxy-to-rest-server
```

This was a deliberate choice: Caddy is memory-safe (Go), extremely mature, and avoids the need for a custom stateful daemon reconciling firewall state against cross-sign validity — a pattern known to be prone to race conditions and lockups when hand-rolled.

This document exists to record why that decision is worth revisiting later, not to argue it was wrong at the time.

## 2. Problem: The Gate Responds Before It Authenticates

Any tailnet peer that has *network reachability* to port 443 (whether through legitimate ACL policy, or through an ACL/tag-manipulation bypass as discussed in the threat model) currently gets a live TCP connection, a completed TLS handshake, and a parsed HTTP request — all *before* the Ed25519 signature is ever checked. Concretely, an attacker with reachability but no valid signature still reaches:

- The TCP/IP stack's connection handling (SYN-ACK, state tracking)
- Go's `crypto/tls` implementation (cipher negotiation, certificate handling, session resumption logic)
- Caddy's HTTP parsing and routing layer
- Any middleware sitting in front of the 401 check

Each of these is a real, if narrow, piece of attack surface exposed to an *unauthenticated* peer. This is a meaningful inconsistency with the rest of the vault's design philosophy: WireGuard itself (the outer layer) never responds to a peer that cannot complete a valid Noise handshake — there is no TCP-equivalent "let me look at your request first" step at the WireGuard layer. The Caddy gate currently does not hold itself to that same standard: it is fail-closed on *authorization*, but not on *reachability*.

The design goal of this proposal is to close that gap: make the port itself unreachable (no SYN-ACK at all) to any peer that has not first proven possession of a valid, fresh cross-sign, regardless of what Tailscale ACL/tag state currently says.

## 3. Options Considered

### 3.1 Option A — Custom Stateful nftables Reconciliation Agent (Rejected, correctly)

A daemon that continuously watches cross-sign state and reconciles nftables rules to match. This was the original design considered and rejected. The rejection reasoning holds up: continuous state reconciliation between an external event source and firewall rule state is a well-known source of race conditions (a rule added/removed at the wrong moment relative to a connection attempt, rules left stale after a crash, etc.), and it adds a second piece of custom, unaudited logic on top of an already-flagged audit backlog item (`wg-cross`). **Not recommended.**

### 3.2 Option B — Single Packet Authorization (SPA) — Recommended

SPA is a much narrower pattern than Option A, and avoids the specific failure mode that motivated rejecting it. Instead of continuously reconciling state, a small, single-purpose daemon does exactly one thing:

1. Listens on a UDP port with a default-DROP policy on the real service port (443) from the tailnet interface.
2. Receives one authenticated "knock" packet (HMAC or Ed25519-signed, with a timestamp + nonce for replay protection).
3. If valid, inserts **one** time-bounded ACCEPT rule for that source address on port 443 (e.g., 30–60 second TTL, enough for the real connection to complete).
4. Rule expires automatically via a kernel-level timeout (nftables supports timed set elements natively — no external cleanup process required, which removes a whole class of "cleanup daemon crashed, rule never removed" failure).

The base nftables policy for 443 on the tailnet interface stays DROP at all times. The only thing that changes is a narrow, auto-expiring exception, added by a single-purpose verifier that does no continuous reconciliation and holds no persistent state beyond the kernel's own timed set.

This is a materially different reliability profile than Option A:

| | Option A (rejected) | Option B (SPA) |
|---|---|---|
| State model | Continuous reconciliation | One-shot, per-knock |
| Failure mode on crash | Rules may drift from true state | No new pinholes open; existing state unaffected |
| Cleanup mechanism | External (fragile) | Kernel-native rule timeout |
| Custom crypto surface | New, hand-rolled | Can reuse mature tooling (`fwknop`) or existing Ed25519 material |

**fwknop** (`fwknop.org`) is a mature, independently-used SPA implementation with ~15+ years of production use, HMAC/GPG-based knock verification, and native nftables/iptables integration. Using it (rather than writing a custom SPA daemon) keeps this addition off the growing "custom crypto to audit" list — it is a well-trodden, external, replaceable component rather than another home-grown protocol next to `wg-cross`.

### 3.3 Option C — eBPF/XDP Packet Filtering (Not recommended at this stage)

Kernel-level filtering at the XDP hook, before the packet reaches connection tracking, is the most performant and arguably most "correct" long-term answer. It is also the most complex to implement correctly for a custom signature-verification use case, has the least mature off-the-shelf tooling for this specific pattern, and would add another significant piece of low-level, hard-to-audit code to a single-maintainer project that has already flagged its existing custom protocol as top audit priority. Worth revisiting only after (a) the `wg-cross` audit is complete, and (b) SPA has been running successfully for a meaningful period.

## 4. Recommended Architecture

```
Tailnet peer                         RHEL host
     |                                   |
     |--- UDP knock (Ed25519-signed) --->|  fwknop-server (or minimal SPA daemon)
     |                                   |     verifies signature + nonce/timestamp
     |                                   |     inserts nftables ACCEPT rule, TTL 45s
     |                                   |
     |--- TCP SYN :443 ----------------->|  now reaches Caddy (previously: silently dropped)
     |<-- SYN-ACK, TLS, HTTP ----------->|
     |                                   |  Caddy still performs its own Ed25519 401 check
```

Important: **the existing Caddy-level Ed25519 check should be kept, not removed.** SPA becomes an additional, independent layer in front of it, not a replacement — belt-and-suspenders. If the SPA daemon ever has a bug, Caddy's own check is still there; if Caddy's check ever has a bug, the SPA layer means an unauthenticated peer never reached it in the first place.

## 5. Benefits

- **Removes the pre-auth attack surface entirely** for unauthenticated peers: no TCP handshake, no TLS handshake, no HTTP parsing happens without a prior valid knock. Go's TLS stack and Caddy's HTTP stack are only ever exposed to peers who have already proven possession of a valid signature.
- **No response to reconnaissance.** A port scan or an ACL-bypass attacker probing 443 gets nothing — not even a closed-port RST, if configured as DROP rather than REJECT. This matches the vault's existing "don't reveal what exists" posture at the WireGuard layer.
- **Independent of ACL/tag state.** This is the most important property given the tag-manipulation discussion: the SPA gate does not consult Tailscale ACLs or tags at all. A successful tag-manipulation bypass that grants network reachability still hits a silently-dropping port, because reachability and authentication are no longer the same question.
- **Brings the RHEL vault backend to parity** with the "no response without authentication" bar already set by WireGuard at the outer layer — closes a real internal inconsistency rather than introducing a new concept.

## 6. Costs and Friction (honest accounting)

- **New component to maintain.** fwknop (or equivalent) becomes a new piece of software with its own patch cadence, own logs to monitor, own potential CVEs. Small footprint, but not zero.
- **The SPA daemon itself is pre-auth-reachable by definition** — it must parse untrusted UDP packets from any tailnet peer before authentication. This is inherent to the pattern (something has to be first), which is exactly why using a mature, widely-scrutinized implementation (fwknop) instead of hand-rolled parsing matters here.
- **Coordination with the existing cross-sign flow.** Right now cross-sign presumably happens as part of/immediately before the Caddy request. Introducing SPA means the vault-pc/vault-ph coordinator needs to fire the "knock" at the right moment — likely immediately after a successful Ed25519 cross-sign completes, before attempting the HTTPS connection. This is a real integration point, not just a firewall config change.
- **TTL tuning.** Too short a TTL risks legitimate connections racing the rule expiry under load or network jitter; too long a TTL widens the exposure window unnecessarily. Needs testing under realistic conditions (including degraded network scenarios, since your setup already deals with CGNAT/relay paths).
- **UDP knock spoofing/replay** must be handled correctly (timestamp window + nonce cache) — again, a strong argument for fwknop's already-hardened implementation over a custom one.
- **Two independent auth checks to keep in sync conceptually** (SPA signature + Caddy's own Ed25519 check). Not a security cost, but an operational one — a key rotation, for example, now needs to be applied consistently in two places.

## 7. What This Does NOT Solve

For completeness, this proposal is scoped narrowly. It does not address:

- Container escape from rest-server (already independently mitigated via `--network=none`-style isolation, seccomp, and read-only rootfs — a separate, already-strong layer).
- The single-physical-host / shared-kernel compartmentalization limitation (tracked separately).
- Anything about the AWS/S3 side of the architecture.

## 8. Suggested Rollout Plan

1. **Pilot on SSH first**, not on 443. SSH-via-fwknop is the single most common and best-documented fwknop use case, which makes it a low-risk way to validate the operational pattern (knock timing, TTL behavior, logging, integration with existing monitoring) before touching the backup data path.
2. **Extend to 443/rest-server** only after the SSH pilot has run uneventfully for a reasonable period (suggest: at least one full review cycle in your existing testing/audit rhythm).
3. **Keep Caddy's own Ed25519 check permanently**, even after SPA is in place — defense in depth, not replacement.
4. **Do not build Option A** (continuous reconciliation agent) or **Option C** (eBPF) at this time; both add complexity disproportionate to the current maintenance capacity of a single-maintainer project, and Option B already closes the gap that motivated this proposal.

## 9. Open Questions for Future Decision

- Reuse existing Ed25519 material for the knock itself, or run fwknop with its own independent key material (simpler integration, but a second key hierarchy to manage)?
- Where does the SPA daemon run — same namespace as Caddy, or a separate, even more restricted namespace, given it is now the first thing an unauthenticated packet touches?
- Should knock validation and TTL/rule insertion be logged to the same audit pipeline as `VaultAuditWatch`, so a burst of failed knocks (brute-force / fuzzing attempts) triggers the same class of alerting as tag-manipulation does today?
