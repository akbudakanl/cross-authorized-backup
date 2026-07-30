# EXTENSION: AUTOMATED CORRUPTION DIAGNOSTICS & SELF-HEALING

> **NOTE:** This extension plan is approved and its core concepts (out-of-band diagnostic signaling and parsing principles) are integrated directly into the Canonical master guide. This file serves as the detailed reference for the diagnostic architecture.

================================================================================

## 1. What this extension changes

The canonical master guide is designed for Zero Trust backup where the server never has the decryption keys. If data corruption (bit-rot) occurs on the RHEL server, the `restic check` running on the client will fail. However, because the client does not have SSH access to the server, it cannot directly trigger a diagnostic tool like `par2` on the server.

This extension introduces an **Out-of-Band (OOB) Diagnostic Workflow**:
1.  **Client Parsing:** The client parses the output of a failed `restic check` to extract the IDs of corrupted packs.
2.  **Restic Find:** The client automatically runs `restic find --pack <ID>` to identify exactly which files are affected, logging the damage.
3.  **OOB Signaling:** The client sends a new `DIAGNOSE rhel` signal via its VPS. The VPS signs this and sends it over the existing `wg-cross` tunnel to the RHEL server, requiring zero new open ports.
4.  **Autonomous Server Healing:** The RHEL server receives the signed signal and autonomously starts a local systemd service (`vault-diagnostics.service`). This service runs `par2 verify` and `par2 repair`, securely logging the results.

### Security cost

There is no loss of Zero Trust. The client still has no shell access to the server. It can only trigger a rigidly defined, static diagnostic script on the server using the existing cryptographic signaling path.

## 2. Parsing Output Warning and Fallback Instructions

> [!WARNING]
> **Restic Check Parsing Reliability**
> This workflow relies on `awk` and `grep` to parse the `stdout/stderr` of the `restic check` command. Restic's standard error format is generally stable, but future updates could change how pack IDs are formatted or reported during a corruption event.
> 
> **Testing Required:** You must test this workflow on your current Restic version by simulating a failure before relying on it in production.
> 
> **How to Remove/Disable Parsing:**
> If a future Restic update breaks the parser (causing false positives or missing corrupted packs), you should revert to standard execution. Remove the complex parsing block from your daily send script and replace it with a simple execution:
> ```bash
> # Fallback to standard check
> restic check --read-data-subset="1/4" || {
>     echo "CRITICAL: Restic check failed. Please run restic find manually and trigger server PAR2."
>     exit 1
> }
> ```
> Then, manually run `restic find --pack <ID>` using the IDs printed to the console.

## 3. Workflow Steps

### Step A: The Client-Side Bash Parser
When `restic check` fails, the script captures the output, extracts 64-character pack IDs, and runs `restic find`:

```bash
CHECK_OUTPUT=$(restic check --read-data-subset="${STAGE}/4" 2>&1)
CHECK_EXIT=$?

if [ $CHECK_EXIT -ne 0 ]; then
    echo "CORRUPTION DETECTED. Parsing affected files..."
    # Extract pack IDs (64 character hex strings)
    PACK_IDS=$(echo "$CHECK_OUTPUT" | grep -ioE 'pack [0-9a-f]{64}' | awk '{print $2}')
    
    for PACK in $PACK_IDS; do
        echo "Files affected by corrupted pack $PACK:" >> ~/vault-corruption-report.log
        restic find --pack "$PACK" >> ~/vault-corruption-report.log
    done
    
    # Trigger VPS out-of-band signal (e.g., via a local helper script)
    vault-diagnose-helper
fi
```

### Step B: The VPS Coordinator Command
The custom VPS coordinator is updated to accept `DIAGNOSE rhel <token>`. Upon receiving this, the VPS signs a payload `DIAGNOSE RHEL_PC <timestamp>` and sends it to the RHEL server over the `wg-cross` WireGuard tunnel.

### Step C: RHEL Autonomous Diagnostic Service
The RHEL gate verifies the signature. If valid, it starts `vault-pc-diagnostics.service` instead of a backup backend.

`/etc/systemd/system/vault-pc-diagnostics.service`:
```ini
[Unit]
Description=Vault PC Autonomous Diagnostics (PAR2)
ConditionPathExists=/var/lib/vault-rhel/repos/pc

[Service]
Type=oneshot
User=vaultpc
Group=vaultpc
WorkingDirectory=/var/lib/vault-rhel/repos/pc/data
ExecStart=/bin/bash -c "for f in */*.par2; do par2 verify $f || par2 repair $f; done"
StandardOutput=file:/var/log/vault-diagnostics/pc-diagnostics.log
StandardError=inherit
```

Following the autonomous repair, the operator must manually run a full `restic check` on the client to cryptographically verify the repair's success.
