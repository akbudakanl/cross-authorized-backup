---
status: rejected
---
# VAULT EXTENSION — CAPACITY-TRIGGERED PRUNE AND PERMANENT RETENTION MAINTENANCE
================================================================================

This extension has been rejected for security reasons and its contents are not included in the Core master guide.

## 1. Purpose

The core master intentionally begins in no-prune/keep-all-history mode. This
extension is the documented trust-model migration when real measured repository growth
shows that the current RHEL storage lifecycle cannot sustain keep-all history.

The recommended automatic trigger is the core RHEL **85% hard ingestion guard**.
The operator may choose to migrate earlier after a documented capacity review, but must
not install destructive maintenance merely because prune exists.

This extension applies to the hot RHEL repositories. It does **not** add routine
maintenance to Glacier Deep Archive S3. Do not add PAR2, `check --read-data-subset`,
forget, or prune to the cold S3 daily path; archive packs still require the AWS restore
workflow before ordinary reads.

### Irreversible warning

The software/configuration change can be removed later, but snapshot history deleted by
`forget` and physically reclaimed by `prune` cannot be reconstructed from that
repository. “Rollback” means stop future destructive retention and remove maintenance
keys; it does not resurrect deleted history.

## 2. Baseline checks that remain before and after this extension

The core source devices already perform a Saturday-anchored staged
`check --read-data-subset=n/4` cycle against their own hot RHEL repository: `1/4`,
`2/4`, `3/4`, `4/4`, then repeat. If a Saturday is missed, the pending stage runs on
the first later successful RHEL transfer; the stage number advances only after a
successful check. Keep that source-owned keyed verification.

The prune extension adds RHEL-local maintenance safety checks because RHEL will now hold
the repository passwords and perform local destructive operations. The RHEL checks do
not replace the source-device checks.

## 3. Security decision: RHEL becomes a trusted decryption-capable maintenance node

Baseline:

```text
RHEL root compromise -> encrypted repository bytes, no source repository passwords
```

After this extension:

```text
RHEL root compromise -> PC repo + PC password AND Phone repo + Phone password
                      -> both RHEL copies are decryptable
```

This is a major trust-model change. The two passwords are needed for unattended local
`forget`, `prune`, `unlock`, and keyed checks.

**Egress requirement:** if the RHEL provider/gateway/network cannot enforce a trusted
egress policy that prevents arbitrary Internet exfiltration by a root-compromised RHEL
host, do not enable unattended prune for personal data. Use one of these alternatives:

```text
A. stay on keyless no-prune and expand/migrate storage;
B. perform manual maintenance with passwords entered locally from the password manager
   and never stored on RHEL;
C. restrict the decryption-capable RHEL backup scope to separately selected work data.
```

Do not hide this choice in a shell script.

## 4. Activation decision

Use the core capacity log and `data_added_packed` history. At 70% review the
90-day growth slope. At 80% begin storage/retention preparation. At 85% stop ingestion.

For the documented approximately 237 GiB filesystem and 25–30 GiB OS/runtime reserve,
the roadmap estimates roughly 171–176 GiB repository budget before the 85% guard. With
about 40 GiB initial total repository load, the remaining growth room is roughly
131–136 GiB; spread over 48 months this corresponds to about 2.73–2.83 GiB/month.
These are planning numbers, not disk guarantees. Replace them with actual `df`/`du`
measurements.

### 4.1 Enable this extension from day zero

The core recommendation is **not** to do this for the documented approximately
40 GiB workload. Day-zero prune deliberately accepts a decryption-capable RHEL and
destructive maintenance before measured capacity pressure proves that the extra trust
is necessary.

If the operator nevertheless selects permanent retention from the first installation:

1. apply the threat-model delta in Section 12 **before** copying either repository
   password to RHEL;
2. finish the core RHEL repository initialization and one successful source-owned
   backup for each repository;
3. install the root-only maintenance credentials in Section 6;
4. skip the emergency `%85` freeze narrative because there is no full-disk incident yet;
5. run the Section 7 structural check and retention dry-run against the first real
   snapshot set;
6. install the permanent weekly maintenance in Section 8.

Do **not** run the low-free-space first-migration command merely because this extension
was enabled on day zero. `prune --max-repack-size 0` is the conservative first migration
choice when free space is already constrained. On a healthy empty/new filesystem, use
the normal scheduled maintenance path after the human-reviewed retention policy has
been verified.

Once day-zero retention is selected and destructive maintenance begins, treat the system
as permanently in the prune/retention trust model. Do not describe it as the core
keyless RHEL baseline.

### 4.2 Add this extension later

This is the recommended lifecycle for the core guide:

```text
no-prune baseline
        ↓
capacity logs + data_added_packed trend
        ↓
70% review / 80% prepare
        ↓
85% hard stop, or documented earlier migration decision
        ↓
Sections 5–9 of this extension
```

When adding later, preserve the pre-migration capacity evidence and perform the first
migration repository-by-repository. Never copy maintenance passwords to RHEL weeks or
months before the actual migration “for convenience”; doing so changes the threat model
before the extension is active.

## 5. Freeze at the migration boundary

At the 85% trigger:

```text
PC S3/RHEL daily workflow        STOP
Phone S3/RHEL daily workflow     STOP
RHEL PC backend                  STOP
RHEL Phone backend               STOP
No new snapshots                 until migration completes
```

S3 is stopped only to keep the operator's backup state simple during the emergency
maintenance window; S3 Deep Archive itself is not pruned by this extension.

Verify:

```bash
sudo systemctl stop vault-rhel-pc-rest-server.service \
  vault-rhel-phone-rest-server.service
sudo systemctl is-active vault-rhel-pc-rest-server.service || true
sudo systemctl is-active vault-rhel-phone-rest-server.service || true
sudo ss -lnt | grep -E ':(8001|8002) ' && {
  echo 'STOP: a RHEL listener is still present' >&2; exit 1;
} || true

sudo du -sb /var/lib/vault-rhel/repos/pc
sudo du -sb /var/lib/vault-rhel/repos/phone
sudo du -sb /var/lib/vault-rhel/repos
sudo df -P /var/lib/vault-rhel/repos
```

Save the output as `BEFORE` capacity evidence.

## 6. Install maintenance credentials deliberately

Create a root-only directory:

```bash
sudo install -d -o root -g root -m 700 /etc/vault-rhel-maintenance
sudo install -m 600 /dev/null /etc/vault-rhel-maintenance/restic-password-pc
sudo install -m 600 /dev/null /etc/vault-rhel-maintenance/restic-password-phone
```

Paste the PC source repository password into `restic-password-pc` and the Phone source
repository password into `restic-password-phone`. Each file contains exactly the
password and one final newline. Verify permissions without printing secrets:

```bash
sudo stat -c '%U %G %a %n' /etc/vault-rhel-maintenance/restic-password-*
sudo test -s /etc/vault-rhel-maintenance/restic-password-pc
sudo test -s /etc/vault-rhel-maintenance/restic-password-phone
```

Expected owner/mode: `root root 600`.

Do not copy either password to a VPS or Lambda. Do not grant the rootless rest-server
containers access to these files. Local maintenance executes after the receiver services
are stopped.

## 7. First migration: repository-by-repository human-reviewed procedure

Set variables on RHEL:

```bash
PC_REPO=/var/lib/vault-rhel/repos/pc
PHONE_REPO=/var/lib/vault-rhel/repos/phone
PC_PW=/etc/vault-rhel-maintenance/restic-password-pc
PHONE_PW=/etc/vault-rhel-maintenance/restic-password-phone
```

Perform the entire sequence for one repository before starting the other.

### 7.1 Structural check before destructive work

PC example:

```bash
sudo env RESTIC_PASSWORD_FILE="$PC_PW" restic -r "$PC_REPO" snapshots
sudo env RESTIC_PASSWORD_FILE="$PC_PW" restic -r "$PC_REPO" check
```

If `check` fails, **do not run forget or prune**. Investigate corruption/recovery first.
Phone is symmetric.

### 7.2 Human-reviewed duration-window dry-run

```bash
sudo env RESTIC_PASSWORD_FILE="$PC_PW" restic -r "$PC_REPO" forget \
  --keep-within-daily 7d \
  --keep-within-weekly 42d \
  --keep-within-monthly 6m \
  --keep-within-yearly 4y \
  --dry-run | tee /root/vault-pc-first-retention-dry-run.txt
```

Inspect:

```text
newest known-good snapshot remains
expected host/path grouping
no unexpected future timestamps
no suspicious dense snapshot burst replacing legitimate recovery points
retention windows match 7d / 42d / 6m / 4y
```

The first dry-run is a human security checkpoint because a compromised sender can create
malicious/suspicious snapshots and manipulate snapshot timing patterns.

### 7.3 Apply the exact reviewed forget policy

```bash
sudo env RESTIC_PASSWORD_FILE="$PC_PW" restic -r "$PC_REPO" forget \
  --keep-within-daily 7d \
  --keep-within-weekly 42d \
  --keep-within-monthly 6m \
  --keep-within-yearly 4y
```

Do not change the policy between dry-run and actual forget.

### 7.4 First low-free-space prune

At an 85% migration trigger, scratch space is deliberately scarce. Use:

```bash
sudo env RESTIC_PASSWORD_FILE="$PC_PW" \
  restic -r "$PC_REPO" prune --max-repack-size 0
```

The first migration prioritizes reclaiming fully unreferenced packs with minimal repack
scratch demand. It is not an “optimal compaction” contest.

Then:

```bash
sudo env RESTIC_PASSWORD_FILE="$PC_PW" restic -r "$PC_REPO" check
```

Repeat Sections 7.1–7.4 for the Phone repository with `PHONE_REPO`/`PHONE_PW`.

### 7.5 Capacity validation

```bash
sudo du -sb /var/lib/vault-rhel/repos/pc
sudo du -sb /var/lib/vault-rhel/repos/phone
sudo du -sb /var/lib/vault-rhel/repos
sudo df -P /var/lib/vault-rhel/repos
```

Save as `AFTER` evidence and compare with `BEFORE`. Migration is not considered complete
merely because restic exited zero; the capacity objective must be measured.

## 8. Install permanent weekly maintenance after first migration

Once retention migration has happened, retention mode is permanent unless the operator
explicitly chooses to stop future pruning and accepts renewed growth. Do not wait for
another 85% emergency before the next prune.

Install `/usr/local/sbin/vault-rhel-retention-maintenance`:

```bash
sudo tee /usr/local/sbin/vault-rhel-retention-maintenance >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/vault-rhel-retention-maintenance.log
STATE=/var/lib/vault-rhel/maintenance
mkdir -p "$STATE"
chmod 700 "$STATE"

maintain() {
  local label="$1" repo="$2" pwfile="$3"
  local stage_file="$STATE/${label}.deep-check-stage"
  local week_file="$STATE/${label}.maintenance-week"
  local week
  week="$(date +%G-W%V)"

  if [ "$(cat "$week_file" 2>/dev/null || true)" = "$week" ]; then
    echo "$(date -Iseconds) [$label] already maintained in $week" >> "$LOG"
    return 0
  fi

  systemctl is-active --quiet "vault-rhel-${label}-rest-server.service" && {
    echo "$(date -Iseconds) [$label] REFUSE: backend active" >> "$LOG"
    return 1
  }

  env RESTIC_PASSWORD_FILE="$pwfile" restic -r "$repo" unlock || true

  if ! env RESTIC_PASSWORD_FILE="$pwfile" restic -r "$repo" check >>"$LOG" 2>&1; then
    echo "$(date -Iseconds) [$label] structural check failed; no destructive operation" >> "$LOG"
    return 1
  fi

  # Retention classification remains duration-window based.
  if ! env RESTIC_PASSWORD_FILE="$pwfile" restic -r "$repo" forget \
      --keep-within-daily 7d \
      --keep-within-weekly 42d \
      --keep-within-monthly 6m \
      --keep-within-yearly 4y >>"$LOG" 2>&1; then
    echo "$(date -Iseconds) [$label] forget failed; prune not run" >> "$LOG"
    return 1
  fi

  if ! env RESTIC_PASSWORD_FILE="$pwfile" restic -r "$repo" prune >>"$LOG" 2>&1; then
    echo "$(date -Iseconds) [$label] prune failed" >> "$LOG"
    return 1
  fi

  stage="$(cat "$stage_file" 2>/dev/null || echo 1)"
  case "$stage" in 1|2|3|4) ;; *) stage=1 ;; esac
  if ! env RESTIC_PASSWORD_FILE="$pwfile" restic -r "$repo" \
      check --read-data-subset="${stage}/4" >>"$LOG" 2>&1; then
    echo "$(date -Iseconds) [$label] deep check ${stage}/4 failed; markers not advanced" >> "$LOG"
    return 1
  fi

  echo $(( (stage % 4) + 1 )) > "$stage_file"
  echo "$week" > "$week_file"
  echo "$(date -Iseconds) [$label] maintenance complete; deep-check ${stage}/4" >> "$LOG"
}

maintain pc /var/lib/vault-rhel/repos/pc \
  /etc/vault-rhel-maintenance/restic-password-pc
maintain phone /var/lib/vault-rhel/repos/phone \
  /etc/vault-rhel-maintenance/restic-password-phone

du -sb /var/lib/vault-rhel/repos >> "$LOG"
df -P /var/lib/vault-rhel/repos >> "$LOG"
EOF
sudo chown root:root /usr/local/sbin/vault-rhel-retention-maintenance
sudo chmod 700 /usr/local/sbin/vault-rhel-retention-maintenance
sudo bash -n /usr/local/sbin/vault-rhel-retention-maintenance
```

The script is weekly/catch-up by state, not “Saturday or never.” The systemd timer may
run Saturday, but a missed powered-off window is completed on the next timer/manual run.

Create service:

```bash
sudo tee /etc/systemd/system/vault-rhel-retention-maintenance.service >/dev/null <<'EOF'
[Unit]
Description=Vault RHEL duration-window retention maintenance
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vault-rhel-retention-maintenance
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/vault-rhel-maintenance
ReadWritePaths=/var/lib/vault-rhel /var/log
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
```

Create timer:

```bash
sudo tee /etc/systemd/system/vault-rhel-retention-maintenance.timer >/dev/null <<'EOF'
[Unit]
Description=Weekly Vault RHEL retention maintenance

[Timer]
OnCalendar=Sat 12:00
Persistent=true
RandomizedDelaySec=10m
Unit=vault-rhel-retention-maintenance.service

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vault-rhel-retention-maintenance.timer
systemctl list-timers vault-rhel-retention-maintenance.timer
```

`Persistent=true` causes systemd to run a missed timer after the host next starts. The
script's week marker prevents duplicate same-week destructive maintenance.

## 9. Integrate the 85% guard after migration

After enough space is reclaimed, re-enable core backend gating. Keep the 70/80/85
monitoring. In permanent retention mode, 85% remains a hard stop; it now means regular
maintenance or the chosen retention policy is no longer sufficient and storage/scope
must be reviewed.

Do not disable the guard because prune exists.

## 10. PAR2 and the monthly staged check

The core outbound-only baseline has no local PC↔Phone ciphertext repository, so
there is no PAR2 target on a primary device. The RHEL hot repositories continue to be
verified by the source devices' weekly `1/4` checks, producing an approximately monthly
full read cycle.

If the Mutual Backup extension is also enabled, its PC-hosted Phone repository and HDD
mirror retain the PAR2 workflow. A prune repacks/removes pack files, so after pruning a
mutual local repository:

```text
remove orphaned .par2 files
create PAR2 for new/repacked pack files
run source-owned restic staged/full check
mirror the post-maintenance state to HDD
```

Do not generate PAR2 for Deep Archive S3.

## 11. Stopping future prune and returning to a keyless RHEL posture

This rollback is **forward-looking only**. Deleted history stays deleted.

1. Stop/disable the maintenance timer and service.
2. Run one final `restic check` for both repositories while passwords still exist.
3. Securely remove both `/etc/vault-rhel-maintenance/restic-password-*` files.
4. Verify no password copy exists in environment files, systemd credentials, shell
   history, backups, or root scripts.
5. Remove or archive the maintenance script/unit/timer.
6. Re-run core keyless-RHEL verification.
7. Continue new backups in no-prune mode from the current retained repository state.
8. Update the threat model: RHEL is no longer decryption-capable after key removal, but
   historical snapshot deletion from the prune period is irreversible.

Example:

```bash
sudo systemctl disable --now vault-rhel-retention-maintenance.timer
sudo rm -f /etc/vault-rhel-maintenance/restic-password-pc \
  /etc/vault-rhel-maintenance/restic-password-phone
sudo find /etc /var/lib/vault-rhel /usr/local/sbin -xdev -type f \
  -iname '*restic*password*' -print
```

Do not use `shred` as a guaranteed SSD secure-erasure claim. The storage encryption and
host decommission procedure govern remanence.

## 12. Threat-model delta

When enabled:

```text
EXT-PRUNE ENABLED
I-11 modified: RHEL is no longer keyless. It is a trusted decryption-capable maintenance
node because both source repository passwords are stored root-only for unattended local
maintenance.

New risk P-01:
  RHEL root compromise can decrypt both RHEL repository copies.
Controls:
  trusted gateway/provider egress restriction required for personal data; root-only
  password files; maintenance runs only with both ingestion backends stopped; no password
  on rest-server containers/VPS/AWS; independent S3 copies remain.
Residual:
  root can read keys and repository bytes; confidentiality depends on RHEL host and
  egress boundary.

I-14 modified:
  keep-all-history is replaced by permanent duration-window retention after migration.
Policy:
  daily 7d / weekly 42d / monthly 6m / yearly 4y.

New irreversible state:
  snapshots removed by forget/prune cannot be restored from the affected repository.
```

When future pruning is disabled and passwords are removed, mark P-01 mitigated back to
the keyless-RHEL confidentiality posture, but record that prior retention deletion is
historical and irreversible.

## ANNEX A — PRESERVED CAPACITY ROADMAP

The following operator roadmap is preserved as the quantitative decision record for this
extension.

---

# Vault Keep-All-Snapshots: 4 Yıllık Kapasite Yol Haritası

## Amaç

Bu belge, `Vault_Zero_Trust_Master_Guide_NO_PRUNE.md` içindeki **GFS/forget/prune olmadan bütün snapshot geçmişini koruyan** üretim modu için kapasite ve gelecekteki retention-migration karar rehberidir.

**Güncel karar:** Sistem no-prune modunda başlar ve gerçek kullanım verisiyle çalışır. Kapasite sorunu ortaya çıkmadan retention karmaşıklığı geri getirilmez. RHEL repository filesystem'i %85 hard ingestion guard seviyesine ulaşırsa yeni ingestion durur ve belgelenmiş retention migration uygulanır. Bu, “prune gerekecek mi?” sorusunu yıllar önceden tahmin etmek yerine gerçek repository büyümesiyle cevaplamayı amaçlar.

Hedef kullanım profili:

- yaklaşık **40 GB başlangıç verisi**;
- ağırlıklı fotoğraf/video gibi oluşturulup nadiren değiştirilen kişisel veri;
- Markdown notları ve kaynak kod gibi sık değişen fakat küçük dosyalar;
- Cloud Security / DevSecOps eğitimi için Terraform, Ansible, Kubernetes YAML, Vagrantfile, script ve küçük proje dosyaları;
- seçilmiş küçük veritabanı ve PCAP/log örnekleri;
- yaklaşık **4 yıllık** kullanım süresi;
- RHEL repository filesystem'i için rehberdeki **%85 hard ingestion guard**.

Bu belge fiyat garantisi veya mutlak kapasite garantisi değildir. Asıl karar verisi, ilk 90 günden itibaren gerçek repository büyüme eğimidir.

---

## 1. 237 GiB görünen disk için kapasite bütçesi

Windows'ta yaklaşık `237 GB` görünen 256 GB sınıfı SSD, RHEL kurulduğunda partition/layout ayrıntılarına göre benzer büyüklükte bir filesystem sunabilir. Rehberdeki guard `df /var/lib/vault-rhel/repos` mantığıyla **repository dizininin bulunduğu gerçek filesystem'in kullanım yüzdesini** ölçer; üreticinin kutu üzerinde yazdığı `256 GB` sayısına doğrudan yüzde uygulamaz.

237 GiB varsayımıyla:

| Eşik | Toplam filesystem kullanımı |
|---|---:|
| %70 | 165.9 GiB |
| %80 | 189.6 GiB |
| %85 | 201.45 GiB |

Planlama amacıyla RHEL + paketler + Podman storage + log/cache için **25–30 GiB** rezerv ayırırsak repository'lere %85 guard öncesinde yaklaşık **171.45–176.45 GiB** kalır.

> Bu 25–30 GiB bir RHEL garantisi değil, muhafazakâr planlama payıdır. İlk kurulumdan sonra gerçek `df -h` ve `du` değerleriyle değiştirilmelidir.

---

## 2. 40 GiB başlangıç verisi tek kez RHEL'e gidiyorsa

Toplam iki repository'nin başlangıçtaki fiziksel veri yükü yaklaşık 40 GiB kabul edilirse:

| Hedef eşik | 30 GiB OS rezerviyle büyüme payı | 25 GiB OS rezerviyle büyüme payı | 48 aya bölünmüş aylık ortalama |
|---|---:|---:|---:|
| %70 warning | 95.9 GiB | 100.9 GiB | yaklaşık 2.00–2.10 GiB/ay |
| %80 urgent review | 119.6 GiB | 124.6 GiB | yaklaşık 2.49–2.60 GiB/ay |
| %85 hard guard | 131.45 GiB | 136.45 GiB | yaklaşık 2.74–2.84 GiB/ay |

### Pratik yorum

Dört yıl boyunca repository fiziksel büyümen ortalama:

- **≤1 GiB/ay:** çok rahat; 48 ayda yaklaşık +48 GiB.
- **1–2 GiB/ay:** rahat; 48 ayda +48–96 GiB.
- **2–2.5 GiB/ay:** izlenmeli; dört yıllık sonunda 136–160 GiB civarı repository yüküne yaklaşabilirsin.
- **>2.5 GiB/ay sürekli:** no-prune mimarisini 90 günlük trend üzerinden yeniden değerlendirmek gerekir.

40 GiB'yi gerçek hayatta ondalık `GB` olarak söylüyorsan bu yaklaşık 37.3 GiB'dir; burada 40 GiB kabul etmek biraz muhafazakâr davranır.

---

## 3. Karşılaştırma senaryosu: aynı 40 GiB iki repository'de duplicate olsaydı

Restic deduplication **repository içindedir**. PC ve phone RHEL repository'leri birbirine karşı deduplicate olmaz.

**Bu kullanıcının mevcut durumu değildir; doğrulanan başlangıç toplamı yaklaşık 40 GiB'dır.** Bu bölüm yalnız yanlış scope/duplicate oluşursa kapasite etkisini göstermek için tutulur.

Aynı 40 GiB koleksiyon iki bağımsız repository'ye giderse başlangıç yaklaşık 80 GiB olabilir:

| Hedef eşik | 30 GiB OS rezerviyle büyüme payı | 25 GiB OS rezerviyle büyüme payı | 48 aya bölünmüş aylık ortalama |
|---|---:|---:|---:|
| %70 warning | 55.9 GiB | 60.9 GiB | yaklaşık 1.16–1.27 GiB/ay |
| %80 urgent review | 79.6 GiB | 84.6 GiB | yaklaşık 1.66–1.76 GiB/ay |
| %85 hard guard | 91.45 GiB | 96.45 GiB | yaklaşık 1.91–2.01 GiB/ay |

Bu nedenle ilk gerçek backup'tan sonra RHEL'de iki repository'nin toplam fiziksel büyüklüğünü ölçmek kritik:

```bash
sudo du -sh /var/lib/vault-rhel/repos/pc
sudo du -sh /var/lib/vault-rhel/repos/phone
sudo du -sh /var/lib/vault-rhel/repos
sudo df -h /var/lib/vault-rhel/repos
```

---

## 4. Sürekli değişen Markdown ve kod dosyaları no-prune için sorun mu?

### Kısa cevap

**Evet, her yeni sürüm geçmiş veri olarak repository'de kalır; fakat küçük Markdown/kod dosyalarında mutlak disk maliyeti genellikle düşüktür.**

Restic'in tasarımında:

- 512 KiB'den küçük dosyalar bölünmeden tek blob olarak saklanır;
- daha büyük dosyalar content-defined chunking ile 512 KiB–8 MiB arası blob'lara bölünür ve ortalama yaklaşık 1 MiB blob hedeflenir;
- değiştirilmiş büyük dosyalarda yalnız yeni/değişmiş blob'ların eklenmesi amaçlanır;
- repository v2 veri ve tree blob'larında zstd sıkıştırmasını destekler.

Bu nedenle küçük bir `.md` dosyasını her gün değiştirmek eski sürümlerin tutulduğu anlamına gelir, ancak dosyanın kendisi küçük olduğu için kapasite etkisi de küçüktür.

### Dört yılda günlük benzersiz churn matematiği

1,461 günlük dört yıllık dönem için, **her gün repository'ye gerçekten yeni ve benzersiz olarak eklenen ham değişmiş içerik** yaklaşık şöyle birikir:

| Günlük unique churn | 4 yılda ham historical churn |
|---|---:|
| 0.1 MiB/gün | 0.14 GiB |
| 1 MiB/gün | 1.43 GiB |
| 5 MiB/gün | 7.13 GiB |
| 10 MiB/gün | 14.27 GiB |
| 25 MiB/gün | 35.67 GiB |
| 50 MiB/gün | 71.34 GiB |
| 100 MiB/gün | 142.68 GiB |

Örnek:

- 100 KiB Markdown notunun her gün tamamen farklı bir blob üretmesi bile dört yılda yaklaşık **143 MiB ham sürüm geçmişi** demektir.
- Toplam 1 MiB yeni kod/not içeriğinin her gün gerçekten benzersiz hâle gelmesi dört yılda yaklaşık **1.43 GiB** yapar.
- Asıl tehlike 50–100 MiB/gün sürekli benzersiz değişimdir; bu artık Markdown/kaynak kod profili değil, büyük mutable artefact profilidir.

Sıkıştırma nedeniyle düz metin ve kaynak kodun fiziksel `data_added_packed` değeri ham churn'den daha düşük olabilir. Kapasite planında sabit bir “kod %X sıkışır” oranı varsayma; gerçek JSON summary değerini ölç.

---

## 5. Asıl riskli dosya türleri

Aşağıdakiler aylar boyunca sürekli değişirse no-prune repository'yi hızlı büyütebilir:

```text
*.qcow2
*.vmdk
raw VM disk images
büyük mutable database files
uzun süre açık kalan *.pcap / *.pcapng captures
sürekli append edilen büyük loglar
container image tar exports
build artefacts
ISO images
package/provider/dependency caches
```

### DevSecOps için önerilen scope

**Vault'a dahil et:**

- `.md` notlar;
- source code;
- `.git` repository bilgisi, gerçekten yerel tarihçeyi korumak istiyorsan;
- `Dockerfile`, `Containerfile`, Compose dosyaları;
- Terraform `.tf` ve `.tfvars` içinden secret olmayanlar;
- `.terraform.lock.hcl`;
- Ansible playbook/role'ları;
- Kubernetes YAML/Helm chart'ları;
- Vagrantfile;
- CI/CD config;
- küçük ve anlamlı DB dump'ları;
- seçilmiş/etiketlenmiş PCAP örnekleri;
- rapor, ödev ve proje dokümantasyonu.

**Varsayılan olarak Vault dışında tut:**

- `.terraform/` provider cache;
- `.terragrunt-cache/`;
- `node_modules/`;
- `.venv/`, virtualenv cache;
- `target/`, `build/`, `dist/`, `out/`;
- Docker/Podman image export tar'ları;
- indirilebilir ISO'lar;
- yeniden üretilebilir VM diskleri;
- ham, uzun süreli packet capture arşivleri;
- rotate edilmemiş debug logları.

Bir VM'in **tanımı** yedeklenmeli; disposable VM disk image'ı çoğu durumda yedeklenmemeli.

---

## 6. 128 MiB S3 pack hedefi küçük değişiklikleri 128 MiB'a şişirir mi?

**Hayır.** `RESTIC_PACK_SIZE=128` bir **target pack size** ayarıdır; “her değişiklik için 128 MiB padding yap” anlamına gelmez.

Restic blob'ları pack dosyalarında birleştirir. Güncel restic kaynak kodu repository işlemi tamamlanırken “remaining packs” için `Flush` çalıştırıldığını gösterir. Dolayısıyla bir backup çalışması yalnız küçük miktarda yeni blob ürettiyse kalan pack yine kaydedilir; 128 MiB'a sıfır/padding ile doldurulmaz.

Bu nedenle:

```text
2 KiB Markdown değişikliği
    ≠ 128 MiB yeni S3 data pack zorunluluğu
```

Gerçek eklenen veri yeni data/tree blob'ları, encryption/pack header overhead'i ve repository metadata'sıdır.

### 128 MiB ayarının gerçek etkisi

Restic'in varsayılan target pack size değeri 16 MiB; desteklenen maksimum target 128 MiB'dir.

Yeterince yeni veri üreten bir backup'ta kabaca:

```text
40 GiB / 16 MiB  ≈ 2,560 target-sized data packs
40 GiB / 128 MiB ≈   320 target-sized data packs
```

Yani pack'ler iyi doluyorsa data-pack object/PUT sayısı kabaca **8 kat azalabilir**. Bu, S3 object/API request sayısını düşürmek için 128 MiB seçiminin mantığını açıklar.

Fakat günlük değişim yalnız birkaç MiB ise backup sonundaki partial pack flush nedeniyle “128 MiB dolana kadar sekiz gün bekle” davranışı yoktur. Böyle küçük günlük çalışmalarda her backup yine küçük pack/metadata object'ları üretebilir. Bu nedenle 128 MiB ayarı API çağrılarını her workload'da tam sekiz kat azaltmaz.

### Bedeli

Restic'in resmi tuning dokümanına göre pack size büyüdükçe:

- client temp alanı gereksinimi artar;
- backend'e bağlı olarak RAM ihtiyacı benzer şekilde artabilir;
- daha büyük temporary pack'lerin upload sürerken diske flush edilme ihtimali ve SSD write wear artabilir.

Dokümantasyondaki formüle göre gereken minimum temp alanı yaklaşık:

```text
pack size × (backend connection count + 1)
```

Çoğu backend için örnek 5 connection ise:

```text
128 MiB × 6 = yaklaşık 768 MiB minimum temp alanı
64 MiB  × 6 = yaklaşık 384 MiB minimum temp alanı
```

Bu yüzden PC tarafında 128 MiB makul olabilir. Telefon script'inin 64 MiB kullanması, daha sınırlı RAM/temp alanı için daha dengeli bir seçimdir.

---

## 7. 40 GiB başlangıç senaryosu için önerilen dört yıllık yol

### Ay 0 — Baseline

İlk başarılı tam RHEL backup sonrasında:

```bash
sudo du -sb /var/lib/vault-rhel/repos
sudo df -P /var/lib/vault-rhel/repos
```

çıktısını kapasite logunun ilk referans noktası kabul et.

İki repository'nin gerçekten toplam 40 GiB mi, yoksa aynı verinin iki repository'de bulunması nedeniyle 80 GiB'a mı yakın olduğunu burada öğren.

### İlk 90 gün — Ölçüm dönemi

Her session sonunda watchdog zaten:

```text
timestamp,filesystem-used-percent,total-repository-bytes
```

formatında `/var/log/vault-rhel-capacity.csv` kaydı tutar.

90 günlük eğim:

```text
growth_per_month = (repo_bytes_day90 - repo_bytes_day0) / 3
```

### Karar tablosu — 40 GiB başlangıç toplam repository senaryosu

| 90 günlük normalize aylık büyüme | Karar |
|---|---|
| ≤1 GiB/ay | No-prune model çok rahat. Yıllık gözden geçirme yeterli. |
| 1–2 GiB/ay | No-prune mantıklı. Her 6 ay trend kontrolü yap. |
| 2–2.5 GiB/ay | Sarı bölge. Büyük mutable artefact'ları ve duplicate data scope'u incele. |
| 2.5–2.8 GiB/ay | %85 dört yıllık matematik sınırına yaklaşıyorsun. Storage migration planı hazırla. |
| >2.8 GiB/ay | Mevcut 237 GiB / %85 varsayımıyla dört yıllık no-prune hedefi güvenli plan değildir. |

80 GiB başlangıç senaryosunda kritik dört yıllık ortalama yaklaşık **1.9–2.0 GiB/ay** seviyesine düşer.

### Yıl 1

Şunları karşılaştır:

```text
başlangıç repo bytes
yıl 1 repo bytes
90-day rolling growth slope
filesystem % used
```

İlk yıl sonunda repo toplamı 60–70 GiB civarındaysa ve başlangıç 40 GiB ise no-prune seçimi çok rahat görünür.

### %70 warning

Panik veya cleanup yapma.

- Son 90 günlük büyüme eğimini hesapla.
- `du` ile `/pc` ve `/phone` paylarını ayır.
- VM disk, PCAP, log ve cache scope'unu incele.
- Kalan runway'i hesapla:

```text
months_remaining = (85_percent_repo_budget - current_repo_bytes) / average_monthly_growth
```

### %80 urgent review

Artık “ileride bakarım” seviyesi değildir.

- Daha büyük SSD / yeni receiver hazırlığını başlat.
- Repository'yi mevcut ciphertext hâliyle daha büyük storage'a taşımayı planla.
- Yeni bir retention mimarisi düşünüyorsan bunu ayrı threat-model revizyonu olarak tasarla.
- RHEL'e repository passwords kopyalayıp acil receiver-side cleanup yolu açma.

### %85 hard guard

Yeni ingestion durur.

Bu bir hata değil, **retention migration için fail-safe karar sınırıdır**. Güncel operasyon kararı şudur:

1. No-prune modunu %85 hard guard'a kadar kullan.
2. Guard tetiklendiğinde yeni backup kabul etme.
3. Repository'leri ve kaynak anahtarlarını doğrula.
4. Aşağıdaki “Kalıcı Retention Migration” prosedürünü uygula.
5. Migration, `forget` dry-run, gerçek `forget`, düşük-scratch-space `prune` ve `check` başarıyla tamamlanmadan ingestion'ı yeniden açma.

Önemli: `%85`, “birkaç backup daha alıp sonra bakarım” eşiği değildir. `prune` repack sırasında geçici scratch alanına ihtiyaç duyabilir. Restic düşük boş alan senaryolarında `--max-repack-size 0` seçeneğini önerir; yine de güvenli yaklaşım hard guard tetiklendiği anda yazmayı durdurmaktır.

---

## 8. Benim senin kullanım profiline ilişkin değerlendirmem

Sürekli değişen Markdown ve source code **no-prune kararını tek başına bozmaz**. Küçük dosyalarda her sürüm tutulsa bile günlük benzersiz changed-content hacmi düşükse dört yıllık maliyet birkaç GiB veya birkaç on GiB düzeyinde kalabilir.

Senin için esas kapasite kontrol soruları şunlardır:

1. 40 GiB kişisel medya iki RHEL repository'sinde yanlışlıkla duplicate mı?
2. VM disk image'ları backup scope'unda mı?
3. PCAP/log dosyaları rotate/curate ediliyor mu?
4. `data_added_packed` ve RHEL physical-growth slope ayda kaç GiB?

Başlangıçta toplam repository gerçekten yaklaşık 40 GiB ve 90 günlük ölçüm **2 GiB/ay altında** kalıyorsa, dört yıllık no-prune tasarımı senin anlatılan öğrenci/DevSecOps kullanım profilin için mantıklı bir plan olarak görünür.


---

## 9. Kalıcı Operasyon Kararı: Capacity-Triggered Retention

### Karar

Bu Vault kurulumu **no-prune / keep-all-history** modunda başlar.

Amaç, dört yıl boyunca ihtiyaç duyulmayabilecek destructive retention yetkisini ve çapraz repository anahtar paylaşımını sırf teorik bir kapasite endişesi için ilk günden sisteme eklememektir.

Operasyon modeli:

```text
NO-PRUNE DEFAULT
      │
      │ gerçek kullanım
      │ kapasite logları
      │ data_added_packed trendi
      ▼
filesystem < %85
      │
      └── keep all snapshots; forget/prune yok

filesystem >= %85 hard guard
      │
      ▼
INGESTION STOPPED
      │
      ▼
RETENTION MIGRATION
      │
      ▼
GFS-LIKE WEEK / MONTH / YEAR WINDOWS + PRUNE
      │
      ▼
PERMANENT RETENTION MODE
```

This design is a deliberate **deferred complexity** decision:

> Do not add destructive repository privileges to solve capacity until the capacity problem becomes real.

Therefore, using no-prune until 85% does not mean "maintenance is forgotten". The system utilizes the capacity limit as an **architectural migration trigger**.

### Why not revert to no-prune after 85%?

Once a retention migration is performed, old snapshots are removed with `forget`, and unreferenced pack data is physically deleted with `prune`, the keep-all-history past cannot be restored.

Therefore, a migration means:

> Disk pressure is no longer theoretical; the lifecycle of the repository requires permanent retention.

After migration, the system does not bounce back and forth weekly/monthly between no-prune and prune. **Prune + retention becomes the permanent mode of operation.**

The permanent GFS-like target policy in this document is: **7d / 6 weeks / 6 months / 4 years**.

---

## 10. Reinstating the Old Count-Based GFS Exactly

In the old prune guide, there was a policy similar to the following:

```bash
--keep-daily 6 \
--keep-weekly 6 \
--keep-monthly 6 \
--keep-yearly 4
```

This classic count-based GFS approach is understandable; however, it should not be brought back exactly as is within an append-only threat model.

If a backup client compromise occurs, an attacker can append new snapshots. Restic uses snapshot timestamps for retention classification. If the attacker appends fake snapshots that are slightly newer than the legitimate snapshot within the same week/month, policies like `--keep-weekly N` ("keep the newest snapshot in each period") may cause the legitimate snapshots to not be selected during the subsequent `forget` operation.

In this Vault architecture, a sender compromise is included in the threat model. Therefore, a transition to permanent retention must use **duration-window GFS**.

### Recommended GFS-like duration windows

When transitioning to permanent retention mode, the default target should be a tiered history of **7 days / 6 weeks / 6 months / 4 years**. Since the restic duration syntax does not recognize weeks (`w`), 6 weeks is expressed as `--keep-within-weekly 42d`.

First, a dry-run:

```bash
restic forget \
    --keep-within-daily 7d \
    --keep-within-weekly 42d \
    --keep-within-monthly 6m \
    --keep-within-yearly 4y \
    --dry-run
```

Real execution:

```bash
restic forget \
    --keep-within-daily 7d \
    --keep-within-weekly 42d \
    --keep-within-monthly 6m \
    --keep-within-yearly 4y
```

Meaning:

- daily recovery points within the last **7 days**;
- weekly recovery points within the last **6 weeks (42 days)**;
- monthly recovery points within the last **6 months**;
- yearly recovery points within the last **4 years**.

This remains the GFS philosophy, but instead of count-based `--keep-daily/weekly/monthly/yearly N` selections, it uses duration-window bounds relative to the latest snapshot. All four tiers are part of the default permanent migration policy; the daily tier is no longer optional.

---

## 11. Permanent Retention Migration Procedure After %85 Hard Guard

This procedure is not a repository format migration. The existing restic repositories remain exactly as they are. What changes is the repository lifecycle and the maintenance trust model.

### Phase 0 — Freeze

When the hard guard triggers:

```text
PC backup        STOP
Phone backup     STOP
S3 backup        STOP, if the relevant repository is also transitioning to retention
RHEL ingestion   STOP
Cross-device push STOP
```

Do not generate new snapshots.

Do not bypass the Coordinator / Caddy / append-only receiver layers just because the disk is full.

### Phase 1 — Reopen the reference architecture with Prune

Archived reference document:

```text
Vault_Zero_Trust_Master_Guide_PRUNE_CURRENT.md
```

This document is an exact working copy of the old architecture; however, **do not bring back the count-based GFS commands as they were**. Use the script/lifecycle structure as a reference and change the retention commands to the `--keep-within-*` policy detailed in this roadmap.

In permanent retention mode, the secret model changes once again:

```text
PC own restic password
    → stays on PC

Phone own restic password
    → stays on Phone

PC hosted Phone repository maintenance
    → Phone restic password required

Phone hosted PC repository maintenance
    → PC restic password required

RHEL local unattended maintenance
    → PC and Phone RHEL repository passwords required on RHEL
```

Meaning that the "receiver knows no repository key" guarantee of the no-prune model is deliberately weakened with retention migration.

Do not add just a few `prune` commands without explicitly logging this change as a trust-model change in the guide.

### Phase 2 — Repository-level check first

Via a maintenance client possessing its own key for each repository:

```bash
restic check
```

must succeed.

If `check` fails, do not run `forget` or `prune`. Investigate the repository issue first.

### Phase 3 — Retention dry-run

For each repository:

```bash
restic forget \
    --keep-within-daily 7d \
    --keep-within-weekly 42d \
    --keep-within-monthly 6m \
    --keep-within-yearly 4y \
    --dry-run
```

Specifically check in the output:

```text
- does the newest healthy snapshot remain?
- is each repository under the correct host/path group?
- is there any unexpected future timestamp?
- are an unusual number of snapshots clustered in a single day/week?
- is the backup scope correct?
```

If you see an anomalous snapshot list, halt the migration. The purpose of the dry-run is not merely a syntax check; it is a human checkpoint to detect suspicious snapshot patterns generated by a compromised sender.

### Phase 4 — Real forget

After the dry-run is approved, run the same policy without `--dry-run`:

```bash
restic forget \
    --keep-within-daily 7d \
    --keep-within-weekly 42d \
    --keep-within-monthly 6m \
    --keep-within-yearly 4y
```

This step removes snapshot references; do not consider pack space to be physically reclaimed just yet.

### Phase 5 — Controlled prune for low free space

Since this was deferred until the hard guard, the initial prune may start under low free space conditions.

First migration prune:

```bash
restic prune --max-repack-size 0
```

must be used.

This option is used to reduce the additional scratch space required for repack. The goal during the initial migration is not the "most aggressive compaction"; instead, space is safely reclaimed first from completely unreferenced packs.

After the first prune:

```bash
restic check
```

must be run.

If sufficient space has been reclaimed, the normal prune policy can be evaluated during the next scheduled maintenance window.

### Phase 6 — Capacity validation

On the RHEL side:

```bash
sudo du -sb /var/lib/vault-rhel/repos
sudo df -P /var/lib/vault-rhel/repos
```

record the output.

Compare before/after migration:

```text
BEFORE repo bytes
AFTER  repo bytes
BEFORE filesystem %
AFTER  filesystem %
```

A retention migration is not deemed "successful" solely by the command's exit code. The real goal is reclaiming disk space; the physical capacity result must be logged.

### Phase 7 — Permanent maintenance schedule

Once the migration is complete, the old "Saturday/catch-up" concept can be brought back:

```text
Saturday:
    backup phase completed
    receiver append-only ingestion closed
    maintenance credential access opened
    check
    duration-window forget dry-run / policy sanity
    duration-window forget
    prune
    staged deep check
    capacity log
    shutdown / session cleanup
```

Recommended permanent retention policy:

```bash
--keep-within-daily 7d
--keep-within-weekly 42d   # 6 weeks; restic duration syntax lacks `w`
--keep-within-monthly 6m
--keep-within-yearly 4y
```

Because retention was initially reinstated due to capacity pressure, do not run subsequent maintenance in a "prune only when disk reaches 85% again" manner. Once retention mode is entered, scheduled maintenance must proceed regularly; otherwise, you will return to the exact same hard-guard emergency.

---

## 12. Security and Operations Rules for "Waiting Until 85%"

This strategy makes sense alongside the following rules:

1. **The 85% guard must be a true hard stop.** It is not merely a threshold to give the user a warning while continuing backups.
2. **The capacity log must not be deleted.** `/var/log/vault-rhel-capacity.csv` is proof of the growth slope.
3. **During the no-prune period, remote repository passwords must not be copied to receivers.** "I'll prune eventually anyway" is not a justification for applying a future trust model today.
4. **Prune must not be run ad hoc.** Do not open a path for a one-time remote-password paste + prune before completing the migration procedure.
5. **The initial migration dry-run must be reviewed by a human.** Sender compromise is within the threat model.
6. **`--unsafe-recover-no-free-space` is not a normal migration command.** This option is a last-resort recovery path that may leave the repository temporarily unusable; it is not added to the standard `85%` migration procedure.

### Why does this approach make sense for you?

The current validated starting size is approximately **40 GiB total data**.

The conservative repository budget is approximately **171–176 GiB**.

Thus, prior to the 85% hard guard, there is about:

```text
131–136 GiB net repository growth space
```

available.

The 48-month simple average limit is:

```text
131 GiB / 48 ≈ 2.73 GiB/month
136 GiB / 48 ≈ 2.83 GiB/month
```

Therefore, if your actual physical repository growth remains around 1 GiB/month for an extended period, retention migration may not be required for years.

Even within the 2–2.5 GiB/month band, the no-prune system continues to generate a true real-world usage test.

If 85% is reached, it is then known that:

> For this user and this actual backup scope, keep-all-history does not align with the lifecycle of the available disk capacity.

At that point, reinstating prune/GFS is no longer a hypothetical optimization, but a measured operational necessity.

---

## 13. Design Note to Preserve When Updating Guide with AI in the Future

Do not lose the context of this decision:

> The no-prune initial mode is not universally based on the claim that "prune is bad". Given the user's approximately 40 GiB of initial data, low expectations for large mutable data, and a four-year usage horizon, this is a security/complexity preference that defers destructive retention privileges until the need arises.

> The `85% hard ingestion guard` is not just disk protection, it is a trust-model migration trigger. If the trigger occurs, remote repository maintenance credentials can be reinstated, and the system can transition into permanent duration-window GFS + prune mode.

> In the future, if capacity, disk, or backup scope changes, this threshold and retention windows must be recalculated. Do not indiscriminately reinstate old count-based `--keep-weekly N / --keep-monthly N / --keep-yearly N` commands into an append-only threat model without understanding the context.

---

## Birincil teknik kaynaklar

- Restic repository design / chunking / blobs / pack format: https://restic.readthedocs.io/en/stable/100_references.html
- Restic backup and deduplication examples: https://restic.readthedocs.io/en/stable/040_backup.html
- Restic tuning parameters and pack size: https://restic.readthedocs.io/en/stable/047_tuning_parameters.html
- Restic current repository source; pack size constants and remaining-pack flush path: https://github.com/restic/restic/blob/master/internal/repository/repository.go
- Restic scripting JSON summary fields: https://restic.readthedocs.io/en/latest/075_scripting.html
- Restic staged `check --read-data-subset=n/t`: https://restic.readthedocs.io/en/latest/045_working_with_repos.html
- Restic forget/prune, append-only security considerations, `--keep-within-*`, and low-free-space prune: https://restic.readthedocs.io/en/stable/060_forget.html

## HARDENING COMPATIBILITY DELTA

This extension is subordinate to the core master guide's
`PART 2A: PRODUCTION SERVICE CONFINEMENT — SYSTEMD AND PODMAN HARDENING`.

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

### Maintenance-service hardening note

When this extension is enabled, `vault-rhel-retention-maintenance.service` becomes a
decryption-capable destructive service. Give it no network requirement by default and
use:

```ini
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
RestrictAddressFamilies=AF_UNIX
UMask=0077

ReadOnlyPaths=/etc/vault-rhel-maintenance
ReadWritePaths=/var/lib/vault-rhel/repos/pc /var/lib/vault-rhel/repos/phone
```

If the installed restic/runtime needs a different local address family for a documented
reason, change only `RestrictAddressFamilies=` after a negative test. The maintenance
service must not receive Internet egress merely because restic supports remote
repositories; this extension operates on the local hot RHEL repository paths.

The two rootless rest-server containers must remain unable to read
`/etc/vault-rhel-maintenance`.

## CORE RHEL 9 PLATFORM NOTE

The capacity/prune extension changes the trust role of the **backup RHEL host** by adding
decryption-capable maintenance credentials. It does not change `vault-pc` or
`vault-phone`: both VPSs remain RHEL 9 BYOL/BYOI systems with SELinux Enforcing and must
not receive either repository password.

If the backup RHEL host and the two VPSs are on different RHEL 9 minor releases during
an update window, treat their systemd/SELinux policy tests independently. Do not copy a
locally generated SELinux module from one host role to another merely because all three
systems are RHEL 9.
