# VAULT EXTENSION — MUTUAL ENCRYPTED PC↔PHONE BACKUP
================================================================================

## 1. What this extension changes

The canonical master is outbound-only: PC and Phone never run Vault receivers and never
accept a Vault application connection from the other primary. This extension deliberately
adds one encrypted restic repository copy in the opposite primary device:

```text
PC plaintext
  └── restic -> Phone stores encrypted PC repository

Phone plaintext
  └── restic -> PC stores encrypted Phone repository
```

This extension does **not** merge the two Tailscale tailnets and does not change the
AWS/RHEL cross-VPS authorization system. The new primary-to-primary data path uses a
separate, manually activated WireGuard tunnel over the Phone hotspot. That tunnel exists
only for this extension and carries only the two sequential restic REST transfers.

### Security cost

The baseline invariant “primary devices expose no Vault listener” becomes false while a
receiver window is active. A compromised source endpoint gains a legitimate application
path to the opposite primary receiver. The receiver remains append-only, protocol-gated,
authenticated, and open only sequentially, but the attack edge is **mitigated rather
than eliminated**.

Apply the threat-model delta in Section 16 before enabling this extension.

## 2. Compatibility matrix

```text
Canonical Tailscale baseline        compatible
Headscale control-plane extension   compatible
Peer Relay extension                unrelated; mutual path uses its own WireGuard tunnel
Prune extension                     compatible, but Section 14 intersection rules apply
```

## 3. Install now vs add later

The installation procedure is the same whether enabled on day zero or years later.
When adding later, first complete one healthy canonical S3 + RHEL backup from both
sources and record the success markers. The mutual repositories are additional copies;
do not destroy or rename the canonical source directories.

When removing later, follow Section 15. Do not simply stop using the scripts while
leaving receiver services, firewall rules, htpasswd files, and tunnel keys active.

## 4. Paths and identities

Use these extension-only paths:

```text
PC source plaintext:       ~/Vault_PC_Ciphertext
Phone source plaintext:    ~/Vault_Phone_Ciphertext

PC receives Phone repo:    ~/Vault_Mutual_Phone_Repo
Phone receives PC repo:    ~/Vault_Mutual_PC_Repo

WireGuard:
  Phone 10.77.0.1/24
  PC    10.77.0.2/24
  UDP/51840 on Phone hotspot underlay

REST/TLS:
  Phone receiver https://10.77.0.1:8000/
  PC receiver    https://10.77.0.2:8000/
```

Do not reuse the canonical Tailscale addresses, RHEL repository paths, or S3 bucket
names for this extension.

## 5. Install packages

PC/Fedora:

```bash
sudo dnf install -y wireguard-tools podman caddy httpd-tools par2cmdline restic rclone
mkdir -p ~/Vault_Mutual_Phone_Repo
mkdir -p ~/.config/vault-mutual/{wireguard,tls,rest-server,caddy}
mkdir -p ~/.local/log/vault-mutual ~/bin
chmod 700 ~/.config/vault-mutual
```

Phone/Termux:

```bash
pkg update
pkg install -y restic caddy wireguard-tools termux-api python openssl netcat-openbsd
mkdir -p ~/Vault_Mutual_PC_Repo
mkdir -p ~/.config/vault-mutual/{wireguard,tls,rest-server,caddy}
mkdir -p ~/.shortcuts ~/.local/log/vault-mutual ~/bin
chmod 700 ~/.config/vault-mutual
```

Install the same reviewed `rest-server` version used by the canonical RHEL build. On
Fedora the extension runs it in rootless Podman. On Termux install the matching ARM64
binary in `$PREFIX/bin/rest-server` and verify:

```bash
rest-server --version
restic version
caddy version
```

## 6. Create the dedicated WireGuard tunnel

### 6.1 Generate keys

PC:

```bash
umask 077
wg genkey | tee ~/.config/vault-mutual/wireguard/private.key \
  | wg pubkey > ~/.config/vault-mutual/wireguard/public.key
wg genpsk > ~/.config/vault-mutual/wireguard/mutual.psk
chmod 600 ~/.config/vault-mutual/wireguard/private.key \
  ~/.config/vault-mutual/wireguard/mutual.psk
cat ~/.config/vault-mutual/wireguard/public.key
```

Phone:

```bash
umask 077
wg genkey | tee ~/.config/vault-mutual/wireguard/private.key \
  | wg pubkey > ~/.config/vault-mutual/wireguard/public.key
chmod 600 ~/.config/vault-mutual/wireguard/private.key
cat ~/.config/vault-mutual/wireguard/public.key
```

Transfer the two public keys freely. Transfer the single PC-generated `mutual.psk` to
the Phone through a confidential administrative channel and store it at the same path,
mode `600`.

### 6.2 PC config

```bash
PC_PRIV="$(cat ~/.config/vault-mutual/wireguard/private.key)"
PHONE_PUB="PHONE_MUTUAL_WG_PUBLIC_KEY"
PSK="$(cat ~/.config/vault-mutual/wireguard/mutual.psk)"

cat > ~/.config/vault-mutual/wireguard/wg-mutual.conf <<EOF
[Interface]
PrivateKey = ${PC_PRIV}
Address = 10.77.0.2/24

[Peer]
PublicKey = ${PHONE_PUB}
PresharedKey = ${PSK}
AllowedIPs = 10.77.0.1/32
Endpoint = 192.168.43.1:51840
PersistentKeepalive = 25
EOF
chmod 600 ~/.config/vault-mutual/wireguard/wg-mutual.conf
```

The Android hotspot gateway varies. The PC start helper updates the peer endpoint from
the current default route every run.

### 6.3 Phone config

```bash
PHONE_PRIV="$(cat ~/.config/vault-mutual/wireguard/private.key)"
PC_PUB="PC_MUTUAL_WG_PUBLIC_KEY"
PSK="$(cat ~/.config/vault-mutual/wireguard/mutual.psk)"

cat > ~/.config/vault-mutual/wireguard/wg-mutual.conf <<EOF
[Interface]
PrivateKey = ${PHONE_PRIV}
Address = 10.77.0.1/24
ListenPort = 51840

[Peer]
PublicKey = ${PC_PUB}
PresharedKey = ${PSK}
AllowedIPs = 10.77.0.2/32
EOF
chmod 600 ~/.config/vault-mutual/wireguard/wg-mutual.conf
```

Import the Phone config into the Android WireGuard implementation you actually use.
The extension assumes the Phone hotspot is enabled and the PC is the hotspot client.
Do not expose UDP/51840 on an Internet-facing router.

### 6.4 PC tunnel helpers

```bash
cat > ~/bin/vault-mutual-wg-up <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CONF="$HOME/.config/vault-mutual/wireguard/wg-mutual.conf"
sudo wg-quick up "$CONF" 2>/dev/null || true
GW_IP="$(ip route | awk '/^default / {print $3; exit}')"
PHONE_PUB="$(awk '/^PublicKey/ {print $3; exit}' "$CONF")"
[ -n "$GW_IP" ] || { echo 'No hotspot default gateway found' >&2; exit 1; }
sudo wg set wg-mutual peer "$PHONE_PUB" endpoint "${GW_IP}:51840"
ping -c 1 -W 3 10.77.0.1 >/dev/null
EOF

cat > ~/bin/vault-mutual-wg-down <<'EOF'
#!/usr/bin/env bash
sudo wg-quick down "$HOME/.config/vault-mutual/wireguard/wg-mutual.conf" 2>/dev/null || true
EOF
chmod 700 ~/bin/vault-mutual-wg-up ~/bin/vault-mutual-wg-down
```

## 7. Create a private CA and server certificates

Create the CA on the PC and keep the CA private key in the authoritative password
manager/offline recovery set after issuance:

```bash
cd ~/.config/vault-mutual/tls
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj '/CN=VaultMutualCA/O=Vault'
chmod 600 ca.key
```

PC receiver certificate:

```bash
openssl genrsa -out pc-server.key 4096
openssl req -new -key pc-server.key -out pc-server.csr \
  -subj '/CN=vault-mutual-pc/O=Vault'
printf '%s\n' 'subjectAltName = IP:10.77.0.2' > pc-server-ext.cnf
openssl x509 -req -days 3650 -in pc-server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out pc-server.crt -extfile pc-server-ext.cnf
chmod 600 pc-server.key
```

Phone receiver certificate:

```bash
openssl genrsa -out phone-server.key 4096
openssl req -new -key phone-server.key -out phone-server.csr \
  -subj '/CN=vault-mutual-phone/O=Vault'
printf '%s\n' 'subjectAltName = IP:10.77.0.1' > phone-server-ext.cnf
openssl x509 -req -days 3650 -in phone-server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out phone-server.crt -extfile phone-server-ext.cnf
chmod 600 phone-server.key
```

Transfer to Phone:

```text
ca.crt
phone-server.crt
phone-server.key  (confidential)
```

Store them under `~/.config/vault-mutual/tls/`; Phone private key mode `600`.

After proving both certificates, remove routine access to `ca.key` from the PC working
filesystem or keep it in an offline encrypted administrative location. The daily path
needs only `ca.crt` and the receiver-specific server key/certificate.

## 8. Create two independent HTTP Basic Auth credentials

PC receiver credential, used only by Phone:

```bash
htpasswd -B -c ~/.config/vault-mutual/rest-server/htpasswd vaultphone
chmod 600 ~/.config/vault-mutual/rest-server/htpasswd
```

Phone receiver credential, used only by PC:

```bash
pkg install -y apache2
htpasswd -B -c ~/.config/vault-mutual/rest-server/htpasswd vaultpc
chmod 600 ~/.config/vault-mutual/rest-server/htpasswd
```

Save the two different plaintext passwords in the password manager. Put the PC→Phone
client copy on the PC as:

```text
~/.config/vault-secrets/mutual_phone_htpasswd
```

Put the Phone→PC client copy on the Phone as:

```text
~/.config/vault-secrets/mutual_pc_htpasswd
```

Mode `600`. The server keeps only the bcrypt hash. Never reuse the RHEL htpasswd.

## 9. Configure Caddy protocol gates

The positive allowlist is intentionally narrow. Restic may evolve; run day-zero backup,
snapshots, and staged-check tests after restic upgrades. Do not replace the matcher with
an unrestricted reverse proxy merely to fix a new client error.

PC `~/.config/vault-mutual/caddy/Caddyfile`:

```caddyfile
https://10.77.0.2:8000 {
    tls /home/YOUR_PC_USER/.config/vault-mutual/tls/pc-server.crt /home/YOUR_PC_USER/.config/vault-mutual/tls/pc-server.key
    @restic {
        method GET POST HEAD DELETE
        path /*
    }
    handle @restic {
        reverse_proxy 127.0.0.1:18080
    }
    respond 403
}
```

Phone `~/.config/vault-mutual/caddy/Caddyfile`:

```caddyfile
https://10.77.0.1:8000 {
    tls /data/data/com.termux/files/home/.config/vault-mutual/tls/phone-server.crt /data/data/com.termux/files/home/.config/vault-mutual/tls/phone-server.key
    @restic {
        method GET POST HEAD DELETE
        path /*
    }
    handle @restic {
        reverse_proxy 127.0.0.1:18080
    }
    respond 403
}
```

Replace `YOUR_PC_USER`. Validate:

```bash
caddy validate --config ~/.config/vault-mutual/caddy/Caddyfile
```

The rest-server remains authoritative for append-only mutation semantics. The Caddy
matcher is defense in depth, not a replacement for `--append-only`.

## 10. Build the PC rootless rest-server container

```bash
mkdir -p ~/.config/vault-mutual/container
cat > ~/.config/vault-mutual/container/Containerfile <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache curl tar
ARG RSERVER_VERSION=0.13.0
RUN curl -fsSL "https://github.com/restic/rest-server/releases/download/v${RSERVER_VERSION}/rest-server_${RSERVER_VERSION}_linux_amd64.tar.gz" \
 | tar -xz -C /usr/local/bin rest-server
ENTRYPOINT ["rest-server"]
EOF
podman build -t vault-mutual-rest-server:0.13.0 ~/.config/vault-mutual/container
```

Start/stop helpers:

```bash
cat > ~/bin/vault-mutual-pc-receiver-start <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
! pgrep -f 'vault-mutual-phone-receiver-marker' >/dev/null 2>&1 || {
  echo 'Another mutual receiver marker is active' >&2; exit 1;
}
podman rm -f vault-mutual-pc-receiver 2>/dev/null || true
podman run -d --name vault-mutual-pc-receiver \
  --network=host --userns=keep-id \
  -v "$HOME/Vault_Mutual_Phone_Repo:/data:Z" \
  -v "$HOME/.config/vault-mutual/rest-server/htpasswd:/htpasswd:ro,Z" \
  vault-mutual-rest-server:0.13.0 \
  --path /data --htpasswd-file /htpasswd --append-only \
  --listen 127.0.0.1:18080
caddy start --config "$HOME/.config/vault-mutual/caddy/Caddyfile"
ss -lnt | grep -q '10.77.0.2:8000'
echo '[+] PC mutual receiver open for Phone only'
EOF

cat > ~/bin/vault-mutual-pc-receiver-stop <<'EOF'
#!/usr/bin/env bash
caddy stop 2>/dev/null || true
podman stop vault-mutual-pc-receiver 2>/dev/null || true
podman rm vault-mutual-pc-receiver 2>/dev/null || true
EOF
chmod 700 ~/bin/vault-mutual-pc-receiver-*
```

PC firewall: allow the receiver only from Phone WireGuard `/32` and only while the
WireGuard interface exists. A permanent rich rule scoped to the source `/32` is:

```bash
sudo firewall-cmd --permanent --zone=drop \
  --add-rich-rule='rule family="ipv4" source address="10.77.0.1/32" port port="8000" protocol="tcp" accept'
sudo firewall-cmd --reload
```

Do not allow hotspot LAN ranges.

## 11. Phone receiver widgets

```bash
cat > ~/.shortcuts/Vault\ Mutual\ Phone\ Receiver\ Start.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
termux-wake-lock 2>/dev/null || true
pkill -f 'rest-server.*18080' 2>/dev/null || true
rest-server \
  --path "$HOME/Vault_Mutual_PC_Repo" \
  --htpasswd-file "$HOME/.config/vault-mutual/rest-server/htpasswd" \
  --append-only \
  --listen 127.0.0.1:18080 \
  --log "$HOME/.local/log/vault-mutual/phone-rest-server.log" &
caddy start --config "$HOME/.config/vault-mutual/caddy/Caddyfile"
nc -z -w3 10.77.0.1 8000
termux-toast 'Phone mutual receiver OPEN for PC' 2>/dev/null || true
EOF

cat > ~/.shortcuts/Vault\ Mutual\ Phone\ Receiver\ Stop.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
caddy stop 2>/dev/null || true
pkill -f 'rest-server.*18080' 2>/dev/null || true
termux-wake-unlock 2>/dev/null || true
termux-toast 'Phone mutual receiver CLOSED' 2>/dev/null || true
EOF
chmod 700 ~/.shortcuts/Vault\ Mutual\ Phone\ Receiver\ *.sh
```

Use the Android firewall/VPN implementation to keep the WireGuard tunnel disabled except
for a mutual session. The receiver is not a background service.

## 12. Initialize and operate the sequential transfer

### 12.1 Initialize PC repository on Phone

1. Enable Phone hotspot.
2. Connect PC to the hotspot.
3. Enable the Phone `wg-mutual` profile.
4. Run `~/bin/vault-mutual-wg-up` on PC.
5. Start the Phone receiver widget.
6. On PC:

```bash
export RESTIC_PASSWORD="$(cat ~/.config/vault-secrets/own_restic_pw)"
PHONE_HTTP_PW="$(cat ~/.config/vault-secrets/mutual_phone_htpasswd)"
PHONE_AUTH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' "$PHONE_HTTP_PW")"
export RESTIC_REPOSITORY="rest:https://vaultpc:${PHONE_AUTH}@10.77.0.1:8000/"
export RESTIC_CACERT="$HOME/.config/vault-mutual/tls/ca.crt"
restic init --repository-version 2
restic snapshots
unset RESTIC_REPOSITORY RESTIC_PASSWORD PHONE_HTTP_PW PHONE_AUTH
```

7. Stop the Phone receiver. Do not open the PC receiver yet until the listener check
   proves Phone receiver is closed.

### 12.2 Initialize Phone repository on PC

Start PC receiver, then on Phone:

```bash
export RESTIC_PASSWORD="$(cat ~/.config/vault-secrets/own_restic_pw)"
PC_HTTP_PW="$(cat ~/.config/vault-secrets/mutual_pc_htpasswd)"
PC_AUTH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' "$PC_HTTP_PW")"
export RESTIC_REPOSITORY="rest:https://vaultphone:${PC_AUTH}@10.77.0.2:8000/"
export RESTIC_CACERT="$HOME/.config/vault-mutual/tls/ca.crt"
restic init --repository-version 2
restic snapshots
unset RESTIC_REPOSITORY RESTIC_PASSWORD PC_HTTP_PW PC_AUTH
```

Stop PC receiver and bring the mutual tunnel down after the initialization test.

### 12.3 Complete PC send script

```bash
cat > ~/bin/vault-mutual-pc-send <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG="$HOME/.local/log/vault-mutual/$(date +%Y%m%d-%H%M%S)-pc-send.log"
export RESTIC_PASSWORD="$(cat "$HOME/.config/vault-secrets/own_restic_pw")"
PW="$(cat "$HOME/.config/vault-secrets/mutual_phone_htpasswd")"
AUTH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' "$PW")"
export RESTIC_REPOSITORY="rest:https://vaultpc:${AUTH}@10.77.0.1:8000/"
export RESTIC_CACERT="$HOME/.config/vault-mutual/tls/ca.crt"
nc -z -w3 10.77.0.1 8000 || { echo 'Phone receiver is not open' >&2; exit 1; }
restic backup "$HOME/Vault_PC_Ciphertext" --json 2>&1 | tee "$LOG"

STATE="$HOME/.local/state/vault"
mkdir -p "$STATE"
WEEK="$(date +%G-W%V)"
if [ "$(cat "$STATE/mutual-pc-check-week" 2>/dev/null || true)" != "$WEEK" ]; then
  STAGE="$(cat "$STATE/mutual-pc-check-stage" 2>/dev/null || echo 1)"
  case "$STAGE" in 1|2|3|4) ;; *) STAGE=1 ;; esac
  restic check --read-data-subset="${STAGE}/4"
  echo $(( (STAGE % 4) + 1 )) > "$STATE/mutual-pc-check-stage"
  echo "$WEEK" > "$STATE/mutual-pc-check-week"
fi
unset RESTIC_REPOSITORY RESTIC_PASSWORD PW AUTH
EOF
chmod 700 ~/bin/vault-mutual-pc-send
bash -n ~/bin/vault-mutual-pc-send
```

### 12.4 Complete Phone send widget

```bash
cat > ~/.shortcuts/Vault\ Mutual\ Phone\ Send.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
termux-wake-lock 2>/dev/null || true
LOG="$HOME/.local/log/vault-mutual/$(date +%Y%m%d-%H%M%S)-phone-send.log"
export RESTIC_PASSWORD="$(cat "$HOME/.config/vault-secrets/own_restic_pw")"
PW="$(cat "$HOME/.config/vault-secrets/mutual_pc_htpasswd")"
AUTH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' "$PW")"
export RESTIC_REPOSITORY="rest:https://vaultphone:${AUTH}@10.77.0.2:8000/"
export RESTIC_CACERT="$HOME/.config/vault-mutual/tls/ca.crt"
nc -z -w3 10.77.0.2 8000 || { termux-toast 'PC receiver not open'; exit 1; }
restic backup "$HOME/Vault_Phone_Ciphertext" --json 2>&1 | tee "$LOG"
STATE="$HOME/.local/state/vault"
mkdir -p "$STATE"
WEEK="$(date +%G-W%V)"
if [ "$(cat "$STATE/mutual-phone-check-week" 2>/dev/null || true)" != "$WEEK" ]; then
  STAGE="$(cat "$STATE/mutual-phone-check-stage" 2>/dev/null || echo 1)"
  case "$STAGE" in 1|2|3|4) ;; *) STAGE=1 ;; esac
  restic check --read-data-subset="${STAGE}/4"
  echo $(( (STAGE % 4) + 1 )) > "$STATE/mutual-phone-check-stage"
  echo "$WEEK" > "$STATE/mutual-phone-check-week"
fi
unset RESTIC_REPOSITORY RESTIC_PASSWORD PW AUTH
termux-wake-unlock 2>/dev/null || true
EOF
chmod 700 ~/.shortcuts/Vault\ Mutual\ Phone\ Send.sh
bash -n ~/.shortcuts/Vault\ Mutual\ Phone\ Send.sh
```

### 12.5 Exact operator sequence

Run mutual backup **after** the canonical S3/RHEL workflows complete:

```text
1. Enable Phone hotspot; connect PC.
2. Enable Phone wg-mutual.
3. PC: vault-mutual-wg-up.
4. Phone: Start Phone Receiver.
5. PC: vault-mutual-pc-send.
6. Phone: Stop Phone Receiver.
7. PC verifies 10.77.0.1:8000 is CLOSED.
8. PC: vault-mutual-pc-receiver-start.
9. Phone: Vault Mutual Phone Send.
10. PC: vault-mutual-pc-receiver-stop.
11. PC verifies 10.77.0.2:8000 is CLOSED.
12. PC: vault-mutual-wg-down; disable Phone wg-mutual.
```

Never overlap both receivers. A premature Enter/tap does not count as proof: use `nc`
or `ss` checks before opening the opposite receiver.

## 13. PAR2 and external HDD maintenance introduced by this extension

PAR2 is **not** for S3 Deep Archive. It protects the locally available ciphertext pack
files of `~/Vault_Mutual_Phone_Repo` and its external-HDD mirror.

Install 8% parity for each pack that lacks parity:

```bash
PHONE_REPO="$HOME/Vault_Mutual_Phone_Repo"
find "$PHONE_REPO/data" -type f -name '*.par2' -print0 | while IFS= read -r -d '' p; do
  [ -f "${p%.par2}" ] || rm -f -- "$p"
done
find "$PHONE_REPO/data" -type f ! -name '*.par2' -print0 | while IFS= read -r -d '' pack; do
  [ -f "${pack}.par2" ] || par2create -r8 -n1 "${pack}.par2" "$pack"
done
```

Mirror to an external HDD only when mounted at the operator-approved path:

```bash
EXT=/mnt/external/Vault_Mutual_Phone_Repo
rclone sync "$PHONE_REPO" "$EXT" --checksum --progress
rclone check "$PHONE_REPO" "$EXT" --one-way --checksum --exclude '*.par2'
```

The source-side weekly `1/4` checks in the two send scripts provide a complete content
read approximately every four successful weeks. PAR2 is raw-byte repair capability for
the PC/HDD-hosted Phone repository; restic check is keyed repository verification. They
are different controls.

### If a pack is reported corrupt

```bash
cd "$HOME/Vault_Mutual_Phone_Repo/data/SHARD"
par2 verify PACKFILE.par2
par2 repair PACKFILE.par2
```

Then the Phone source, which owns the repository password, must run a full or staged
restic check against the repaired repository during a controlled PC receiver window.
Do not declare recovery successful based only on PAR2.

## 14. Interaction with the prune extension

Without the prune extension, mutual repositories remain keep-all-history and PAR2 is
incremental.

If `Vault_Extension_Capacity_Triggered_Prune_and_Maintenance.md` is also enabled, local
mutual repositories add new maintenance trust requirements:

```text
PC pruning its local Phone repository needs the Phone restic repository password.
Phone pruning its local PC repository needs the PC restic repository password.
```

Do not store the opposite repository password permanently on the opposite primary by
default. For manual local maintenance, retrieve it from the password manager, keep it in
RAM, perform structural check -> reviewed duration-window forget -> prune -> staged
content check, then unset it. After prune/repack, rebuild PAR2 for the PC-hosted Phone
repository before mirroring to HDD.

The RHEL unattended prune trust decision is separate and documented only in the prune
extension.

## 15. Remove this extension and return to outbound-only

Removal restores the baseline only if all receiver/network capability is removed.

1. Complete a healthy canonical PC and Phone S3 + RHEL backup.
2. Decide whether to retain the two mutual ciphertext repositories as offline archives
   or erase them. Their data is encrypted; deletion is an operator retention decision.
3. Stop both receiver services and prove ports `10.77.0.1:8000` and `10.77.0.2:8000`
   are closed.
4. Disable/delete the Phone `wg-mutual` profile.
5. PC: `~/bin/vault-mutual-wg-down`.
6. Remove PC firewalld rule for source `10.77.0.1/32` TCP/8000.
7. Delete/disable the mutual Caddy configs and receiver scripts/widgets.
8. Delete `mutual_phone_htpasswd` and `mutual_pc_htpasswd` client files.
9. Remove WireGuard private keys/PSK from both devices if the extension will not return.
10. Remove server private keys after any retained mutual repository has been moved to an
    offline archive and no receiver will be reopened.
11. Remove mutual steps from operator shortcuts.
12. Re-run canonical day-zero negative tests: no primary Vault listener; no PC↔Phone
    application data path.
13. Apply the threat-model rollback below.

Deleting the mutual repository copies does not affect canonical RHEL or S3 repositories.

## 16. Threat-model delta

When enabling, append:

```text
EXT-MUTUAL ENABLED
Baseline I-01/I-02 modified: primary devices now expose a temporary Vault receiver over
a dedicated manual WireGuard tunnel. Exactly one receiver may be open at a time.

New risk M-01:
  compromised source endpoint has a legitimate application path to the opposite primary
  receiver during its sequential window.
Controls:
  dedicated non-Tailscale WireGuard tunnel; optional PSK; phone-hotspot underlay;
  receiver bound only to 10.77.0.x; server-authenticated private-CA TLS; Caddy positive
  protocol gate; independent htpasswd; append-only rest-server; sequential receiver
  exposure; no SSH; no shared repository password at rest.
Residual:
  direct primary-to-primary application edge is mitigated, not eliminated.

New asset:
  PC-hosted Phone ciphertext repository and Phone-hosted PC ciphertext repository.

New maintenance controls:
  weekly 1/4 source-side restic read check; PAR2 8% for PC/HDD-hosted Phone repo; HDD
  checksum mirror.
```

When removing, mark M-01 `removed` only after both receiver listeners, firewall rule,
tunnel profile/keys, client htpasswd copies, and operator scripts are removed and the
canonical outbound-only negative tests pass.

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

### Mutual-backup hardening note

This extension intentionally adds receiver services to the primary devices and therefore
changes the baseline "no Vault receiver on primaries" property. The receiver process
must see only the **encrypted mutual repository destination**, its exact htpasswd/TLS
material, and its own runtime/log paths. It must not receive a bind of the ordinary home
tree or the canonical plaintext source folder.

On Fedora, retain rootless Podman and require:

```text
--read-only
--cap-drop=all
--security-opt=no-new-privileges
no --privileged
SELinux label separation enabled
```

The mutual receiver's repository volume is the only writable persistent data mount.
Because this extension's Phone receiver runs under Termux rather than systemd, the
canonical systemd section does not create a false claim of equivalent Phone-side process
sandboxing. That asymmetry is part of this extension's residual risk.

## CANONICAL RHEL 9 VPS PLATFORM NOTE

This extension does not change either Vault VPS operating system. `vault-pc` and
`vault-phone` remain RHEL 9 BYOL/BYOI hosts with SELinux Enforcing, firewalld, and the
master guide's dedicated service users, DAC boundaries, and systemd hardening. The extension's separate Phone-hotspot
WireGuard path does not justify opening an additional public listener on either RHEL VPS.
