# THE VAULT — POST-INSTALL DETECTION, INCIDENT VISIBILITY, AND CREDENTIAL CUSTODY
================================================================================

> **Status: mandatory production-entry stage for the core Vault baseline.**
>
> Apply this guide **after** completing
> `Vault_Zero_Trust_Master_Guide_CORE.md`
> and its day-zero correctness tests, but **before** treating the system as production.
> This is not one of the four architecture extensions. It does not change the backup
> topology. It adds an independent detection plane, alert health checks, evidence
> retention, and explicit custody rules for break-glass, human-admin, and machine
> credentials.
>
> Read `Vault_Threat_Model_and_Risk_Register.md` first. This guide adds the detection
> invariants and risks referenced there.

## 1. What this guide is trying to achieve

> [!NOTE]
> Adding a sufficient amount of log files to the system and providing instructions for auditing them is also of vital importance from a detection perspective.
>
> **The detection system in this project is a reference implementation.** For the
> full discussion on why Kerckhoffs's principle diverges from detection design,
> why individual modification is a primary defense component, and how to derive
> your own non-public detection layer, see the
> [Detection directory README](README.md) and
> [Vault_Detection_Design_Methodology.md](Vault_Detection_Design_Methodology.md).


The core Vault already tries to **prevent** one compromised endpoint or one
compromised VPS from independently creating a new AWS/RHEL backup window. Prevention is
not the same as visibility. A broad credential such as Tailscale `devices:core`, an
unexpected daily-slot consume, or an unexpected `AssumeRole` attempt should be noisy
outside the component that might be compromised.

The detection plane is therefore placed in AWS, outside both Vault VPSs:

```text
                        AWS DETECTION PLANE

VaultDailyIssuanceSlots --DynamoDB Stream--> VaultSlotWatch --SNS--> operator

CloudTrail AssumeRole ----EventBridge------> VaultStsWatch  --SNS--> operator

CloudTrail PutRolePolicy --EventBridge--> VaultCompletionPolicyWatch --SNS--> operator

VPS coordinator journal ---> VaultAuthFailureWatch ---> Roles Anywhere ---> SNS

S3 snapshots/ + locks/ ----> device completion revokers
                                   |
                                   +--> exact slot OPEN/REVOKING/REVOKED
                                   +--> AWSRevokeOlderSessions
EventBridge rate(5 min) ----------> reconciliation

EventBridge Scheduler (5 min)
             |
             v
      VaultAuditWatch Lambda
             |
      AWS GetWebIdentityToken
             |
      Tailscale WIF token exchange
             |
      logs:configuration:read ONLY
             |
     +-------+--------+
     |                |
 PC tailnet logs   Phone tailnet logs
     |                |
     +-------+--------+
             |
       default-deny rules
             |
             +-- unexpected mutation --> SNS CRITICAL
             +-- poll blindness -------> SNS CRITICAL
```

The design deliberately prefers **duplicate alerts over silently lost alerts**. A security
watcher may therefore send the same message twice after a retry. Do not “fix” this by
marking an event processed before the notification is published.

### Detection is not prevention

This guide does **not** turn `devices:core` into an expire-only credential. If its
long-lived OAuth client secret is stolen, the credential's real Tailscale API scope is
still broad. The exact-device helper prevents ordinary coordinator/helper misuse; the
AWS watcher makes configuration mutation outside the expected behavior visible.

Likewise, an alert is not a kill switch. The existing dual-signature gates, live
participation from both primaries for fresh S3 OPEN, daily slots, fixed S3 egress,
AWS-side snapshot-plus-later-lock-removal completion revocation, clean-opposite signed
peer close, one-hour deadline, separate buckets/roles, RHEL local verification, and
budget deny remain the preventive/containment layers.

The completion revokers are **not part of this detection plane** merely because they run
in AWS. They are preventive/containment components from the core master. This guide
adds visibility around their Lambda health and around the privileged
`iam:PutRolePolicy` transition they are expected to perform.

---

## 2. Alert severity and operator rule

Use one SNS Standard topic named:

```text
VaultCriticalSecurityAlerts
```

Subscribe an email address that is **not dependent on either Vault VPS**. Confirm the SNS
subscription before continuing.

Severity meanings:

```text
INFO
  expected or explicitly declared maintenance event

CRITICAL
  privileged action has no expected Vault explanation
  OR the detector itself is blind
  OR an issuance/slot event happened when you did not initiate a session
  OR repeated phase-token rejection crosses the documented threshold
  OR one invalid cross-VPS signature/exact-session payload is observed
```

**Operator rule:** a CRITICAL alert is never auto-dismissed because “the backup still
works.” First preserve evidence, then contain, then repair.

Create the topic:

```bash
export AWS_REGION="us-east-1"
export VAULT_ALERT_TOPIC_ARN="$(aws sns create-topic \
  --region "$AWS_REGION" \
  --name VaultCriticalSecurityAlerts \
  --query TopicArn --output text)"

echo "$VAULT_ALERT_TOPIC_ARN"

aws sns subscribe \
  --region "$AWS_REGION" \
  --topic-arn "$VAULT_ALERT_TOPIC_ARN" \
  --protocol email \
  --notification-endpoint 'YOUR_ALERT_EMAIL@example.com'
```

Open the confirmation email and confirm it. Then run:

```bash
aws sns publish \
  --region "$AWS_REGION" \
  --topic-arn "$VAULT_ALERT_TOPIC_ARN" \
  --subject '[VAULT TEST] SNS path' \
  --message 'Vault security alert path test.'
```

Do not continue until the test arrives.

---

# PART I — AWS-SIDE DETECTION PLANE
================================================================================

## 3. Create the shared detection-state table

The existing issuance table remains:

```text
VaultDailyIssuanceSlots
```

Create a separate state table for poll cursors, event fingerprints, health counters, and
short operator-declared maintenance windows:

```bash
export DETECTION_STATE_TABLE="VaultDetectionState"

aws dynamodb create-table \
  --region "$AWS_REGION" \
  --table-name "$DETECTION_STATE_TABLE" \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

aws dynamodb wait table-exists \
  --region "$AWS_REGION" \
  --table-name "$DETECTION_STATE_TABLE"

aws dynamodb update-time-to-live \
  --region "$AWS_REGION" \
  --table-name "$DETECTION_STATE_TABLE" \
  --time-to-live-specification 'Enabled=true,AttributeName=ttl_epoch'
```

This table is **not** an authorization database. Deleting an event fingerprint must not
open AWS or RHEL. Its loss causes duplicate/repeated alerts and detector-health noise,
not additional backup authority.

Expected key families:

```text
EVENT#<sha256>       processed Tailscale audit event; TTL 7 days
HEALTH#pc            PC tailnet poll health
HEALTH#phone         Phone tailnet poll health
MAINTENANCE#pc       optional temporary admin-change window
MAINTENANCE#phone    optional temporary admin-change window
```

---

## 4. Daily-slot consumption alert — VaultSlotWatch

### Why use DynamoDB Streams instead of only CloudTrail

The security event we care about is not merely “Lambda was invoked.” The high-signal
state transition is:

```text
both VPS proofs passed
        AND
S3#PC#YYYY-MM-DD or S3#PHONE#YYYY-MM-DD was atomically inserted
```

The existing Lambda already creates that row only after proof validation and before the
single `AssumeRole` attempt. A DynamoDB Stream therefore observes the business-security
state directly.

### 4.1 Enable a stream on the existing slot table

```bash
export SLOT_TABLE="VaultDailyIssuanceSlots"

aws dynamodb update-table \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE" \
  --stream-specification StreamEnabled=true,StreamViewType=NEW_IMAGE

export SLOT_STREAM_ARN="$(aws dynamodb describe-table \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE" \
  --query 'Table.LatestStreamArn' --output text)"

echo "$SLOT_STREAM_ARN"
```

### 4.2 Create the Lambda execution role

```bash
cat > /tmp/vault-detection-lambda-trust.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
JSON

aws iam create-role \
  --role-name Vault-SlotWatch-ExecutionRole \
  --assume-role-policy-document file:///tmp/vault-detection-lambda-trust.json

aws iam attach-role-policy \
  --role-name Vault-SlotWatch-ExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

export SLOT_WATCH_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-SlotWatch-ExecutionRole \
  --query 'Role.Arn' --output text)"
```

Give it only SNS publish to the Vault topic. DynamoDB Streams is read through the Lambda
event-source mapping service integration; the role also needs the standard stream read
actions:

```bash
cat > /tmp/vault-slot-watch-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeStream",
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
        "dynamodb:ListStreams"
      ],
      "Resource": "$SLOT_STREAM_ARN"
    },
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "$VAULT_ALERT_TOPIC_ARN"
    }
  ]
}
JSON

aws iam put-role-policy \
  --role-name Vault-SlotWatch-ExecutionRole \
  --policy-name VaultSlotWatchMinimum \
  --policy-document file:///tmp/vault-slot-watch-policy.json
```

### 4.3 Package and deploy VaultSlotWatch

Create `index.mjs` with the following complete source:

```javascript
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

const sns = new SNSClient({});
const topicArn = process.env.TOPIC_ARN;
if (!topicArn) throw new Error('TOPIC_ARN is required');

export const handler = async (event) => {
  const failures = [];
  for (const record of event.Records ?? []) {
    if (record.eventName !== 'INSERT') continue;
    const image = record.dynamodb?.NewImage ?? {};
    const pk = image.pk?.S ?? '';
    if (!/^S3#(PC|PHONE)#\d{4}-\d{2}-\d{2}$/.test(pk)) continue;

    const ceremonyId = image.ceremony_id?.S ?? 'unknown';
    const consumedAt = image.consumed_at?.S ?? 'unknown';
    const [, device, date] = pk.split('#');
    const subject = `[VAULT] ${device} daily slot consumed`;
    const message = [
      'Vault security event: an S3 daily issuance slot was consumed.',
      '',
      `Device: ${device}`,
      `Calendar date (Europe/Istanbul): ${date}`,
      `Consumed at (UTC): ${consumedAt}`,
      `Ceremony ID: ${ceremonyId}`,
      `DynamoDB stream event ID: ${record.eventID ?? 'unknown'}`,
      '',
      'If you did not initiate a joint Vault session, treat this as CRITICAL.',
      'Do not delete the daily slot. Preserve evidence and begin the incident runbook.'
    ].join('\n');

    try {
      // Deliberately publish before any dedupe state. A duplicate alert is safer than
      // a silently lost security event if SNS succeeds but later state persistence fails.
      await sns.send(new PublishCommand({ TopicArn: topicArn, Subject: subject, Message: message }));
    } catch (error) {
      failures.push({ itemIdentifier: record.dynamodb?.SequenceNumber ?? record.eventID });
      console.error('slot alert publish failed', record.eventID, error?.name, error?.message);
    }
  }
  return { batchItemFailures: failures };
};
```

Package with an explicit AWS SDK dependency rather than relying on a runtime-bundled SDK
version:

```bash
mkdir -p ~/vault-slot-watch && cd ~/vault-slot-watch
# Save the code above as index.mjs.
cat > package.json <<'JSON'
{
  "type": "module",
  "dependencies": {
    "@aws-sdk/client-sns": "^3.0.0"
  }
}
JSON
npm install --omit=dev
zip -qr /tmp/vault-slot-watch.zip index.mjs package.json package-lock.json node_modules

aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name VaultSlotWatch \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$SLOT_WATCH_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-slot-watch.zip \
  --timeout 20 \
  --memory-size 128 \
  --environment "Variables={TOPIC_ARN=$VAULT_ALERT_TOPIC_ARN}"
```

Create the stream trigger with partial batch failure reporting:

```bash
aws lambda create-event-source-mapping \
  --region "$AWS_REGION" \
  --function-name VaultSlotWatch \
  --event-source-arn "$SLOT_STREAM_ARN" \
  --starting-position LATEST \
  --batch-size 10 \
  --function-response-types ReportBatchItemFailures
```

### 4.4 Acceptance test

Do **not** insert a fake row into the production slot table for today's real device/day
key. Use an obviously non-matching key first and confirm no alert:

```bash
aws dynamodb put-item \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE" \
  --item '{"pk":{"S":"TEST#SLOTWATCH"}}'
```

Then use a historical date that cannot affect a current ceremony:

```bash
aws dynamodb put-item \
  --region "$AWS_REGION" \
  --table-name "$SLOT_TABLE" \
  --item '{
    "pk":{"S":"S3#PC#2000-01-01"},
    "ceremony_id":{"S":"00000000000000000000000000000000"},
    "consumed_at":{"S":"2000-01-01T00:00:00.000Z"}
  }'
```

Expected: one email whose subject contains `PC daily slot consumed`.

Delete only the two **test** rows:

```bash
aws dynamodb delete-item --region "$AWS_REGION" --table-name "$SLOT_TABLE" \
  --key '{"pk":{"S":"TEST#SLOTWATCH"}}'
aws dynamodb delete-item --region "$AWS_REGION" --table-name "$SLOT_TABLE" \
  --key '{"pk":{"S":"S3#PC#2000-01-01"}}'
```

**Never delete today's real `S3#PC#...` or `S3#PHONE#...` row to make a backup retry.**

---

## 5. Tailscale configuration-audit anomaly detector — VaultAuditWatch

### 5.1 What the detector can and cannot see

Tailscale configuration audit logs are server-side configuration mutation logs. They
contain the action, actor, target, event time, and relevant old/new values. They are
always enabled and cannot be disabled. They are not packet-flow logs and they do not
record failed identity-provider login attempts.

The watcher is intentionally designed around this rule:

> The `devices:core` expiry actor may perform exactly one class of mutation: update the
> exact primary node's `KEY_EXPIRY_TIME`, near a matching Vault daily-slot window.
> Any other mutation by that actor is CRITICAL.

The watcher also defaults other unallowlisted configuration mutations to CRITICAL after
production. Before an intentional admin change, create a short maintenance record as
shown later. A detector that silently learns arbitrary new admin behavior is not useful
for this threat model.

### 5.2 Do not store another Tailscale API secret in Lambda

Use **Tailscale Workload Identity Federation (WIF)**. The Lambda execution role requests
a five-minute AWS-signed OIDC JWT with `sts:GetWebIdentityToken`; Tailscale validates the
issuer/audience/subject and returns a short-lived API token with only:

```text
logs:configuration:read
```

No Tailscale client secret is stored in Lambda environment variables, Secrets Manager,
or the source package.

### 5.3 Enable AWS outbound identity federation

Run once for the AWS account:

```bash
aws iam enable-outbound-web-identity-federation
aws iam get-outbound-web-identity-federation-info
```

Record the AWS OIDC issuer URL shown by the command.

### 5.4 Create the AuditWatch Lambda role

```bash
aws iam create-role \
  --role-name Vault-AuditWatch-ExecutionRole \
  --assume-role-policy-document file:///tmp/vault-detection-lambda-trust.json

aws iam attach-role-policy \
  --role-name Vault-AuditWatch-ExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

export AUDIT_WATCH_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-AuditWatch-ExecutionRole \
  --query 'Role.Arn' --output text)"
export AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

echo "$AUDIT_WATCH_ROLE_ARN"
```

The AWS `sub` claim represents the principal that requested the token. For a Lambda
role session, configure the Tailscale federated identity subject narrowly for this role
session pattern:

```text
arn:aws:sts::<AWS_ACCOUNT_ID>:assumed-role/Vault-AuditWatch-ExecutionRole/*
```

Tailscale supports `*` in subject claim matching. Do not use `*` for the whole AWS
account or `arn:aws:sts::*:assumed-role/*`.

### 5.5 Create one read-only Tailscale federated identity in each tailnet

In the **PC tailnet** admin console:

```text
Trust credentials
  -> Credential
  -> OpenID Connect
  -> Issuer: AWS / the account-specific AWS OIDC issuer
  -> Subject: arn:aws:sts::<ACCOUNT>:assumed-role/Vault-AuditWatch-ExecutionRole/*
  -> Scope: logs:configuration:read ONLY
  -> Description: Vault AuditWatch PC
```

Record:

```text
PC_TS_CLIENT_ID
PC_TS_AUDIENCE
```

The Client ID and Audience are not secrets.

Repeat in the **Phone tailnet**, producing:

```text
PHONE_TS_CLIENT_ID
PHONE_TS_AUDIENCE
```

Do not give either federated identity `devices:core`, `all`, `auth_keys`, policy write,
Tailnet Lock write, DNS write, or any other scope.

### 5.6 Restrict AWS token issuance to exactly the two Tailscale audiences

After you have the two generated audiences:

```bash
cat > /tmp/vault-audit-wif-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:GetWebIdentityToken",
    "Resource": "*",
    "Condition": {
      "ForAnyValue:StringEquals": {
        "sts:IdentityTokenAudience": [
          "PC_TS_AUDIENCE_HERE",
          "PHONE_TS_AUDIENCE_HERE"
        ]
      },
      "StringEquals": {
        "sts:SigningAlgorithm": "RS256"
      },
      "NumericLessThanEquals": {
        "sts:DurationSeconds": 300
      }
    }
  }]
}
JSON
```

Replace the two audience placeholders exactly, then add DynamoDB/SNS access:

```bash
export SLOT_TABLE_ARN="arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/VaultDailyIssuanceSlots"
export DETECTION_STATE_TABLE_ARN="arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${DETECTION_STATE_TABLE}"

cat > /tmp/vault-audit-storage-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem"],
      "Resource": "$SLOT_TABLE_ARN"
    },
    {
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
      "Resource": "$DETECTION_STATE_TABLE_ARN"
    },
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "$VAULT_ALERT_TOPIC_ARN"
    }
  ]
}
JSON

aws iam put-role-policy \
  --role-name Vault-AuditWatch-ExecutionRole \
  --policy-name VaultAuditWatchWIF \
  --policy-document file:///tmp/vault-audit-wif-policy.json

aws iam put-role-policy \
  --role-name Vault-AuditWatch-ExecutionRole \
  --policy-name VaultAuditWatchStateAndAlerts \
  --policy-document file:///tmp/vault-audit-storage-policy.json
```

### 5.7 Bootstrap exact actor IDs from known-good events

The detector pins **IDs**, not display names.

You need:

```text
PC_EXPIRY_ACTOR_ID
PHONE_EXPIRY_ACTOR_ID
PC_EXPIRY_CLIENT_ID    devices:core OAuth Client ID from core setup
PHONE_EXPIRY_CLIENT_ID devices:core OAuth Client ID from core setup
PC_USER_ACTOR_ID       optional but recommended
PHONE_USER_ACTOR_ID    optional but recommended
```

Perform one supervised core Vault session on a day you can observe closely. In each
Tailscale admin console open **Logs** and inspect:

1. the exact node-key expiry produced by the root-owned exact-device expiry helper;
2. the primary user's normal re-authentication event.

Record the immutable actor `id` values and exact primary node target IDs. Confirm the
expiry event targets the same NodeID documented by the core guide and changes
`KEY_EXPIRY_TIME`. Also copy each core expiry OAuth credential's **Client ID** (not
the secret) as `PC_EXPIRY_CLIENT_ID` / `PHONE_EXPIRY_CLIENT_ID`.

The `devices:core` trust credential's API access-token creation itself is audit logged
with the trust credential Client ID as actor. AuditWatch therefore treats token creation
by the exact expiry Client ID as expected only near a matching daily-slot window. Token
creation at another time is CRITICAL. AuditWatch's own WIF token exchange also creates
a read-only API access token; its exact WIF Client ID is explicitly allowlisted so the
detector does not alarm on its own five-minute polling token.

### 5.8 Deploy VaultAuditWatch

Create `index.mjs` with this complete source:

```javascript
import crypto from 'node:crypto';
import { STSClient, GetWebIdentityTokenCommand } from '@aws-sdk/client-sts';
import {
  DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand
} from '@aws-sdk/client-dynamodb';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

const region = process.env.AWS_REGION;
const stateTable = process.env.STATE_TABLE;
const slotTable = process.env.SLOT_TABLE;
const topicArn = process.env.TOPIC_ARN;
const lookbackMinutes = Number(process.env.POLL_LOOKBACK_MINUTES ?? '10');
const expiryWindowMinutes = Number(process.env.EXPIRY_WINDOW_MINUTES ?? '75');
const healthFailThreshold = Number(process.env.HEALTH_FAIL_THRESHOLD ?? '2');

const tails = [
  {
    name: 'pc', tailnet: process.env.PC_TAILNET_ID,
    clientId: process.env.PC_TS_CLIENT_ID, audience: process.env.PC_TS_AUDIENCE,
    primaryNodeId: process.env.PC_PRIMARY_NODE_ID,
    expiryActorId: process.env.PC_EXPIRY_ACTOR_ID,
    expiryClientId: process.env.PC_EXPIRY_CLIENT_ID,
    userActorId: process.env.PC_USER_ACTOR_ID ?? ''
  },
  {
    name: 'phone', tailnet: process.env.PHONE_TAILNET_ID,
    clientId: process.env.PHONE_TS_CLIENT_ID, audience: process.env.PHONE_TS_AUDIENCE,
    primaryNodeId: process.env.PHONE_PRIMARY_NODE_ID,
    expiryActorId: process.env.PHONE_EXPIRY_ACTOR_ID,
    expiryClientId: process.env.PHONE_EXPIRY_CLIENT_ID,
    userActorId: process.env.PHONE_USER_ACTOR_ID ?? ''
  }
];

for (const value of [region, stateTable, slotTable, topicArn]) {
  if (!value) throw new Error('AWS_REGION, STATE_TABLE, SLOT_TABLE and TOPIC_ARN are required');
}
for (const t of tails) {
  for (const [k, v] of Object.entries(t)) {
    if (['userActorId'].includes(k)) continue;
    if (!v) throw new Error(`missing ${t.name}.${k}`);
  }
}

const sts = new STSClient({ region, maxAttempts: 2 });
const ddb = new DynamoDBClient({ region });
const sns = new SNSClient({ region });

function isoDateInIstanbul(date) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Istanbul', year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(date);
  const m = Object.fromEntries(parts.map((p) => [p.type, p.value]));
  return `${m.year}-${m.month}-${m.day}`;
}

function previousIstanbulDate(date) {
  return isoDateInIstanbul(new Date(date.valueOf() - 24 * 60 * 60 * 1000));
}

function eventFingerprint(tail, log) {
  const raw = [tail.name, log.eventGroupID, log.action, log.eventTime,
    log.actor?.id, log.target?.id, log.target?.type, log.target?.property].join('|');
  return crypto.createHash('sha256').update(raw).digest('hex');
}

async function publish(severity, title, lines) {
  await sns.send(new PublishCommand({
    TopicArn: topicArn,
    Subject: `[VAULT ${severity}] ${title}`.slice(0, 100),
    Message: [`Severity: ${severity}`, ...lines].join('\n')
  }));
}

async function exchangeToken(t) {
  const identity = await sts.send(new GetWebIdentityTokenCommand({
    Audience: [t.audience],
    SigningAlgorithm: 'RS256',
    DurationSeconds: 300
  }));
  if (!identity.WebIdentityToken) throw new Error('AWS STS returned no WebIdentityToken');

  const body = new URLSearchParams({ client_id: t.clientId, jwt: identity.WebIdentityToken });
  const response = await fetch('https://api.tailscale.com/api/v2/oauth/token-exchange', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  if (!response.ok) throw new Error(`Tailscale token exchange HTTP ${response.status}`);
  const data = await response.json();
  if (!data.access_token) throw new Error('Tailscale token exchange returned no access_token');
  return data.access_token;
}

async function fetchLogs(t, token, start, end) {
  const url = new URL(`https://api.tailscale.com/api/v2/tailnet/${encodeURIComponent(t.tailnet)}/logging/configuration`);
  url.searchParams.set('start', start.toISOString());
  url.searchParams.set('end', end.toISOString());
  const response = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error(`Tailscale audit API HTTP ${response.status}`);
  const data = await response.json();
  if (!Array.isArray(data.logs)) throw new Error('Tailscale audit API returned invalid logs payload');
  return data.logs;
}

async function slotConsumedNear(t, eventTime) {
  const date = new Date(eventTime);
  const dates = [isoDateInIstanbul(date), previousIstanbulDate(date)];
  for (const day of dates) {
    const pk = `S3#${t.name.toUpperCase()}#${day}`;
    const result = await ddb.send(new GetItemCommand({
      TableName: slotTable, Key: { pk: { S: pk } }, ConsistentRead: true
    }));
    const consumed = result.Item?.consumed_at?.S;
    if (!consumed) continue;
    const start = new Date(consumed).valueOf();
    const eventMs = date.valueOf();
    if (eventMs >= start - 60_000 && eventMs <= start + expiryWindowMinutes * 60_000) return true;
  }
  return false;
}

async function maintenanceActive(t, eventTime) {
  const result = await ddb.send(new GetItemCommand({
    TableName: stateTable, Key: { pk: { S: `MAINTENANCE#${t.name}` } }, ConsistentRead: true
  }));
  const until = Number(result.Item?.expires_epoch?.N ?? '0') * 1000;
  return until > new Date(eventTime).valueOf();
}

function isAccessTokenCreateBy(actorId, log) {
  return log.actor?.id === actorId &&
    log.target?.type === 'API_KEY' &&
    log.action === 'CREATE';
}

function isExactExpiry(t, log) {
  return log.actor?.id === t.expiryActorId &&
    log.target?.type === 'NODE' &&
    log.target?.id === t.primaryNodeId &&
    log.action === 'UPDATE' &&
    log.target?.property === 'KEY_EXPIRY_TIME';
}

function isNormalPrimaryReauth(t, log) {
  if (!t.userActorId || log.actor?.id !== t.userActorId) return false;
  if (log.target?.type !== 'NODE' || log.target?.id !== t.primaryNodeId) return false;
  return (log.action === 'UPDATE' && log.target?.property === 'KEY_EXPIRY_TIME') ||
    log.action === 'LOGIN';
}

function isTailscaleService(log) {
  return log.actor?.type === 'SERVICE' || /tailscale service/i.test(log.actor?.displayName ?? '');
}

async function alreadyProcessed(fingerprint) {
  const result = await ddb.send(new GetItemCommand({
    TableName: stateTable, Key: { pk: { S: `EVENT#${fingerprint}` } }, ConsistentRead: true
  }));
  return Boolean(result.Item);
}

async function markProcessed(fingerprint, log) {
  const ttl = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
  await ddb.send(new PutItemCommand({
    TableName: stateTable,
    Item: {
      pk: { S: `EVENT#${fingerprint}` },
      event_time: { S: log.eventTime ?? new Date().toISOString() },
      ttl_epoch: { N: String(ttl) }
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  })).catch((error) => {
    if (error?.name !== 'ConditionalCheckFailedException') throw error;
  });
}

async function healthSuccess(t) {
  const key = { pk: { S: `HEALTH#${t.name}` } };
  const prior = await ddb.send(new GetItemCommand({ TableName: stateTable, Key: key, ConsistentRead: true }));
  const oldFails = Number(prior.Item?.fail_count?.N ?? '0');
  await ddb.send(new UpdateItemCommand({
    TableName: stateTable, Key: key,
    UpdateExpression: 'SET fail_count = :z, last_success = :now REMOVE last_error',
    ExpressionAttributeValues: { ':z': { N: '0' }, ':now': { S: new Date().toISOString() } }
  }));
  if (oldFails >= healthFailThreshold) {
    await publish('INFO', `${t.name} Tailscale audit polling recovered`, [
      `Tailnet: ${t.tailnet}`, `Previous consecutive failures: ${oldFails}`
    ]);
  }
}

async function healthFailure(t, error) {
  const result = await ddb.send(new UpdateItemCommand({
    TableName: stateTable, Key: { pk: { S: `HEALTH#${t.name}` } },
    UpdateExpression: 'ADD fail_count :one SET last_failure = :now, last_error = :err',
    ExpressionAttributeValues: {
      ':one': { N: '1' }, ':now': { S: new Date().toISOString() },
      ':err': { S: `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`.slice(0, 900) }
    },
    ReturnValues: 'ALL_NEW'
  }));
  const fails = Number(result.Attributes?.fail_count?.N ?? '1');
  if (fails === healthFailThreshold || fails % 12 === 0) {
    await publish('CRITICAL', `${t.name} DETECTION BLIND: audit polling failed`, [
      `Tailnet: ${t.tailnet}`, `Consecutive failures: ${fails}`,
      `Error: ${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`,
      'The Tailscale mutation detector is blind. Investigate before trusting silence.'
    ]);
  }
}

async function classifyAndAlert(t, log) {
  // AuditWatch creates a short-lived read-only API token on every WIF exchange.
  // Tailscale records token creation with the trust credential Client ID as actor.
  if (isAccessTokenCreateBy(t.clientId, log)) {
    return { severity: 'EXPECTED', reason: 'AuditWatch read-only WIF access token creation' };
  }

  // The devices:core expiry OAuth client must mint its short-lived API token only
  // near a matching Vault daily-slot window. Token minting at any other time is noisy.
  if (isAccessTokenCreateBy(t.expiryClientId, log)) {
    const inWindow = await slotConsumedNear(t, log.eventTime);
    if (inWindow) return { severity: 'EXPECTED', reason: 'expiry helper access token creation inside slot window' };
    return { severity: 'CRITICAL', reason: 'devices:core OAuth access token created outside a matching daily-slot window' };
  }

  if (isExactExpiry(t, log)) {
    const inWindow = await slotConsumedNear(t, log.eventTime);
    if (inWindow) return { severity: 'EXPECTED', reason: 'exact primary expiry inside slot window' };
    return { severity: 'CRITICAL', reason: 'exact expiry actor used outside a matching daily-slot window' };
  }

  if (log.actor?.id === t.expiryActorId) {
    return { severity: 'CRITICAL', reason: 'devices:core expiry actor performed a non-expiry or wrong-target mutation' };
  }

  if (isNormalPrimaryReauth(t, log)) return { severity: 'EXPECTED', reason: 'primary user re-authentication' };
  if (isTailscaleService(log)) return { severity: 'EXPECTED', reason: 'Tailscale service event' };
  if (await maintenanceActive(t, log.eventTime)) return { severity: 'INFO', reason: 'operator-declared maintenance window' };

  return { severity: 'CRITICAL', reason: 'unallowlisted tailnet configuration mutation' };
}

async function processTailnet(t, now) {
  const token = await exchangeToken(t);
  const start = new Date(now.valueOf() - lookbackMinutes * 60_000);
  const logs = await fetchLogs(t, token, start, now);

  logs.sort((a, b) => String(a.eventTime).localeCompare(String(b.eventTime)));
  for (const log of logs) {
    const fingerprint = eventFingerprint(t, log);
    if (await alreadyProcessed(fingerprint)) continue;

    const verdict = await classifyAndAlert(t, log);
    if (verdict.severity === 'CRITICAL' || verdict.severity === 'INFO') {
      await publish(verdict.severity, `${t.name} tailnet mutation: ${verdict.reason}`, [
        `Tailnet: ${t.tailnet}`,
        `Event time: ${log.eventTime ?? 'unknown'}`,
        `Action: ${log.action ?? 'unknown'}`,
        `Actor ID: ${log.actor?.id ?? 'unknown'}`,
        `Actor: ${log.actor?.displayName ?? log.actor?.loginName ?? 'unknown'}`,
        `Target type: ${log.target?.type ?? 'unknown'}`,
        `Target ID: ${log.target?.id ?? 'unknown'}`,
        `Target property: ${log.target?.property ?? 'none'}`,
        `Event group ID: ${log.eventGroupID ?? 'unknown'}`,
        `Reason: ${verdict.reason}`,
        '',
        verdict.severity === 'CRITICAL'
          ? 'Preserve evidence, revoke the implicated trust credential if applicable, and begin the incident runbook.'
          : 'This event occurred during an explicit maintenance window. Review it against the maintenance change record.'
      ]);
    }

    // Publish first, then mark processed. If state persistence fails after an alert,
    // the next overlapping poll may send a duplicate. Duplicate security mail is
    // intentionally preferred over a silent loss.
    await markProcessed(fingerprint, log);
  }
  await healthSuccess(t);
}

export const handler = async () => {
  const now = new Date();
  const errors = [];
  for (const t of tails) {
    try {
      await processTailnet(t, now);
    } catch (error) {
      console.error('audit poll failed', t.name, error?.name, error?.message);
      errors.push({ tailnet: t.name, error: error?.message ?? String(error) });
      try { await healthFailure(t, error); } catch (healthError) {
        console.error('health failure handling failed', t.name, healthError);
      }
    }
  }
  if (errors.length) throw new Error(`audit polling failed: ${JSON.stringify(errors)}`);
  return { ok: true, checked: tails.map((t) => t.name) };
};
```

Package dependencies:

```bash
mkdir -p ~/vault-audit-watch && cd ~/vault-audit-watch
# Save the code above as index.mjs.
cat > package.json <<'JSON'
{
  "type": "module",
  "dependencies": {
    "@aws-sdk/client-dynamodb": "^3.0.0",
    "@aws-sdk/client-sns": "^3.0.0",
    "@aws-sdk/client-sts": "^3.0.0"
  }
}
JSON
npm install --omit=dev
zip -qr /tmp/vault-audit-watch.zip index.mjs package.json package-lock.json node_modules
```

Create the function. Replace every placeholder with the exact values from your two
tailnets and core deployment:

```bash
aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name VaultAuditWatch \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$AUDIT_WATCH_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-audit-watch.zip \
  --timeout 60 \
  --memory-size 256 \
  --reserved-concurrent-executions 1 \
  --environment 'Variables={
AWS_REGION=us-east-1,
STATE_TABLE=VaultDetectionState,
SLOT_TABLE=VaultDailyIssuanceSlots,
TOPIC_ARN=VAULT_ALERT_TOPIC_ARN,
POLL_LOOKBACK_MINUTES=10,
EXPIRY_WINDOW_MINUTES=75,
HEALTH_FAIL_THRESHOLD=2,
PC_TAILNET_ID=PC_TAILNET_ID,
PC_TS_CLIENT_ID=PC_TS_CLIENT_ID,
PC_TS_AUDIENCE=PC_TS_AUDIENCE,
PC_PRIMARY_NODE_ID=PC_PRIMARY_NODE_ID,
PC_EXPIRY_ACTOR_ID=PC_EXPIRY_ACTOR_ID,
PC_EXPIRY_CLIENT_ID=PC_EXPIRY_CLIENT_ID,
PC_USER_ACTOR_ID=PC_USER_ACTOR_ID,
PHONE_TAILNET_ID=PHONE_TAILNET_ID,
PHONE_TS_CLIENT_ID=PHONE_TS_CLIENT_ID,
PHONE_TS_AUDIENCE=PHONE_TS_AUDIENCE,
PHONE_PRIMARY_NODE_ID=PHONE_PRIMARY_NODE_ID,
PHONE_EXPIRY_ACTOR_ID=PHONE_EXPIRY_ACTOR_ID,
PHONE_EXPIRY_CLIENT_ID=PHONE_EXPIRY_CLIENT_ID,
PHONE_USER_ACTOR_ID=PHONE_USER_ACTOR_ID
}'
```

Because shell quoting a large environment map is error-prone, the recommended production
method is to save a JSON file and use `--cli-input-json` or `update-function-configuration`
with a generated environment JSON. Never put a Tailscale access token or OAuth secret in
that file; only IDs and audiences are stored.

### 5.9 Schedule every five minutes

Use EventBridge Scheduler:

```bash
aws scheduler create-schedule \
  --region "$AWS_REGION" \
  --name VaultAuditWatchEvery5Minutes \
  --schedule-expression 'rate(5 minutes)' \
  --flexible-time-window '{"Mode":"OFF"}' \
  --target '{
    "Arn":"VAULT_AUDIT_WATCH_FUNCTION_ARN",
    "RoleArn":"SCHEDULER_INVOKE_ROLE_ARN"
  }'
```

Create the scheduler invoke role with trust principal
`"scheduler.amazonaws.com"` and permission only:

```text
lambda:InvokeFunction
Resource: exact VaultAuditWatch function ARN
```

Do not grant Scheduler permission to invoke either issuance gate.

### 5.10 Why ten-minute lookback with a five-minute schedule

Poll windows intentionally overlap:

```text
run 12:00 -> inspect 11:50–12:00
run 12:05 -> inspect 11:55–12:05
```

`EVENT#<fingerprint>` state suppresses already-processed events. Overlap tolerates a
late scheduler run and audit-log publication delay. Tailscale documents no maximum audit
log inclusion delay; it says inclusion occurs within seconds in practice. Therefore the
correct promise is:

> expected detection latency = five-minute polling cadence plus Tailscale audit-log
> ingestion delay; not a guaranteed five-minute upper bound.

### 5.11 Detector-blind alarm

`VaultAuditWatch` stores consecutive poll failures independently for `pc` and `phone`.
At two consecutive failures it sends:

```text
[VAULT CRITICAL] <tailnet> DETECTION BLIND
```

It repeats every 12 failed polls and sends an INFO recovery message after polling works
again. Silence from a failed detector is not treated as evidence of safety.

Also create a CloudWatch alarm on the Lambda's own `Errors` metric:

```text
Namespace: AWS/Lambda
Metric: Errors
FunctionName: VaultAuditWatch
Threshold: >= 1
Period: 5 minutes
Evaluation periods: 1
Alarm action: VaultCriticalSecurityAlerts
```

The function intentionally throws if either tailnet poll fails, so CloudWatch and the
in-function health state provide two visibility paths.

### 5.12 Intentional Tailscale admin changes

Before an intentional PC-tailnet configuration change, create a short maintenance
record. Example: 20 minutes from now.

```bash
UNTIL=$(( $(date +%s) + 1200 ))
aws dynamodb put-item \
  --region "$AWS_REGION" \
  --table-name "$DETECTION_STATE_TABLE" \
  --item "{\"pk\":{\"S\":\"MAINTENANCE#pc\"},\"expires_epoch\":{\"N\":\"$UNTIL\"},\"reason\":{\"S\":\"planned Tailnet Lock signer rotation\"}}"
```

For Phone use `MAINTENANCE#phone`.

The watcher still sends INFO for unallowlisted mutations during the window. The window
does not alter Tailscale permissions and does not suppress evidence. It only changes
severity from CRITICAL to INFO.

Do not create a 24-hour or permanent maintenance window.

### 5.13 Negative tests

After deployment, perform all of these:

```text
[ ] exact helper expiry after a real daily slot -> no CRITICAL
[ ] exact helper expiry outside slot window on a test/maintenance day -> CRITICAL
[ ] rename a non-production test node without maintenance -> CRITICAL
[ ] create 20-minute maintenance window and rename test node -> INFO
[ ] temporarily break one Tailscale WIF audience -> after two polls DETECTION BLIND
[ ] restore WIF audience -> INFO recovery
```

Do not delete or modify a production primary node merely to test an alarm.

---

## 6. STS backup-role caller validation — VaultStsWatch

The issuance Lambda is supposed to be the **only** principal that calls `AssumeRole` for
the corresponding backup role. Watch this at AWS control-plane level.

### 6.1 Reuse or create a CloudTrail management-event trail

If the AWS account already has an organization/account trail that records management
events, reuse it. Otherwise create one in the CloudTrail console:

```text
Trail name: VaultSecurityTrail
Management events: Read + Write
Data events: NONE by default
Insights: optional
S3 log bucket: dedicated CloudTrail log bucket
```

Do **not** enable S3 object-level data events merely for this Vault detector. They are a
different, higher-volume/cost category and the current control is about STS management
events.

### 6.2 Create the StsWatch execution role

```bash
aws iam create-role \
  --role-name Vault-StsWatch-ExecutionRole \
  --assume-role-policy-document file:///tmp/vault-detection-lambda-trust.json

aws iam attach-role-policy \
  --role-name Vault-StsWatch-ExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

cat > /tmp/vault-sts-watch-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sns:Publish",
    "Resource": "$VAULT_ALERT_TOPIC_ARN"
  }]
}
JSON

aws iam put-role-policy \
  --role-name Vault-StsWatch-ExecutionRole \
  --policy-name VaultStsWatchMinimum \
  --policy-document file:///tmp/vault-sts-watch-policy.json

export STS_WATCH_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-StsWatch-ExecutionRole \
  --query 'Role.Arn' --output text)"
```

### 6.3 Deploy VaultStsWatch

Create `index.mjs`:

```javascript
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

const sns = new SNSClient({});
const topicArn = process.env.TOPIC_ARN;
const sendExpected = (process.env.SEND_EXPECTED_STS ?? 'false').toLowerCase() === 'true';

const expected = new Map([
  [process.env.PC_BACKUP_ROLE_ARN, process.env.PC_GATE_ROLE_ARN],
  [process.env.PHONE_BACKUP_ROLE_ARN, process.env.PHONE_GATE_ROLE_ARN]
].filter(([role, actor]) => role && actor));

if (!topicArn || expected.size !== 2) throw new Error('TOPIC_ARN and four role ARN variables are required');

function callerRoleArn(detail) {
  return detail?.userIdentity?.sessionContext?.sessionIssuer?.arn ?? '';
}

export const handler = async (event) => {
  const detail = event.detail ?? {};
  const roleArn = detail.requestParameters?.roleArn ?? '';
  if (!expected.has(roleArn)) return { ignored: true };

  const expectedCaller = expected.get(roleArn);
  const actualCaller = callerRoleArn(detail);
  const ok = actualCaller === expectedCaller;

  if (!ok || sendExpected) {
    const severity = ok ? 'INFO' : 'CRITICAL';
    await sns.send(new PublishCommand({
      TopicArn: topicArn,
      Subject: `[VAULT ${severity}] STS AssumeRole ${ok ? 'expected' : 'unexpected caller'}`,
      Message: [
        `Severity: ${severity}`,
        `Event time: ${event.time ?? detail.eventTime ?? 'unknown'}`,
        `Target backup role: ${roleArn}`,
        `Expected caller role: ${expectedCaller}`,
        `Actual caller role: ${actualCaller || 'unknown'}`,
        `Source IP: ${detail.sourceIPAddress ?? 'unknown'}`,
        `CloudTrail event ID: ${detail.eventID ?? 'unknown'}`,
        '',
        ok
          ? 'Expected Vault gate activity.'
          : 'Unexpected principal attempted to assume a Vault backup role. Treat as CRITICAL and begin the incident runbook.'
      ].join('\n')
    }));
  }
  return { ok, roleArn, actualCaller };
};
```

Package:

```bash
mkdir -p ~/vault-sts-watch && cd ~/vault-sts-watch
# Save code as index.mjs.
cat > package.json <<'JSON'
{
  "type": "module",
  "dependencies": {
    "@aws-sdk/client-sns": "^3.0.0"
  }
}
JSON
npm install --omit=dev
zip -qr /tmp/vault-sts-watch.zip index.mjs package.json package-lock.json node_modules
```

Retrieve the four ARNs from the core deployment and create the function:

```bash
export PC_GATE_ROLE_ARN="$(aws iam get-role --role-name Vault-PC-S3-Gate-ExecutionRole --query Role.Arn --output text)"
export PHONE_GATE_ROLE_ARN="$(aws iam get-role --role-name Vault-Phone-S3-Gate-ExecutionRole --query Role.Arn --output text)"
export PC_BACKUP_ROLE_ARN="$(aws iam get-role --role-name Vault-PC-S3-BackupRole --query Role.Arn --output text)"
export PHONE_BACKUP_ROLE_ARN="$(aws iam get-role --role-name Vault-Phone-S3-BackupRole --query Role.Arn --output text)"

aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name VaultStsWatch \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$STS_WATCH_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-sts-watch.zip \
  --timeout 20 \
  --memory-size 128 \
  --environment "Variables={TOPIC_ARN=$VAULT_ALERT_TOPIC_ARN,PC_GATE_ROLE_ARN=$PC_GATE_ROLE_ARN,PHONE_GATE_ROLE_ARN=$PHONE_GATE_ROLE_ARN,PC_BACKUP_ROLE_ARN=$PC_BACKUP_ROLE_ARN,PHONE_BACKUP_ROLE_ARN=$PHONE_BACKUP_ROLE_ARN,SEND_EXPECTED_STS=false}"
```

### 6.4 Create the EventBridge rule

Use this event pattern, replacing the two backup role ARNs literally:

```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "source": ["aws.sts"],
  "detail": {
    "eventSource": ["sts.amazonaws.com"],
    "eventName": ["AssumeRole"],
    "requestParameters": {
      "roleArn": [
        "PC_BACKUP_ROLE_ARN",
        "PHONE_BACKUP_ROLE_ARN"
      ]
    }
  }
}
```

Target `VaultStsWatch`. Add the normal Lambda resource-based permission allowing
`events.amazonaws.com` to invoke this exact function from this exact rule ARN.

Expected behavior:

```text
PC backup role assumed by PC gate execution role       -> accepted
Phone backup role assumed by Phone gate execution role -> accepted
any other caller                                       -> SNS CRITICAL
```

Set `SEND_EXPECTED_STS=true` temporarily for one acceptance test if you want one INFO
email for a normal session, then set it back to `false`.

### 6.5 Completion-revocation IAM caller validation — VaultCompletionPolicyWatch

A healthy completed S3 backup causes one device-specific completion revoker to update
only the matching backup role's inline policy named:

```text
AWSRevokeOlderSessions
```

Because the revoker holds a narrow `iam:PutRolePolicy` primitive, watch every
`PutRolePolicy` call that targets either Vault backup role. Expected pairs are:

```text
Vault-PC-S3-BackupRole
  <- Vault-PC-S3-Completion-ExecutionRole
  <- policy name exactly AWSRevokeOlderSessions

Vault-Phone-S3-BackupRole
  <- Vault-Phone-S3-Completion-ExecutionRole
  <- policy name exactly AWSRevokeOlderSessions
```

Create the function with the existing `Vault-StsWatch-ExecutionRole`; that role already
has Lambda logging plus SNS publish only. The watcher itself needs no IAM write access.

Create `index.mjs`:

```javascript
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

const sns = new SNSClient({});
const topicArn = process.env.TOPIC_ARN;
const sendExpected = (process.env.SEND_EXPECTED_COMPLETION_POLICY ?? 'false').toLowerCase() === 'true';
const expected = new Map([
  ['Vault-PC-S3-BackupRole', process.env.PC_COMPLETION_ROLE_ARN],
  ['Vault-Phone-S3-BackupRole', process.env.PHONE_COMPLETION_ROLE_ARN],
].filter(([, actor]) => actor));

if (!topicArn || expected.size !== 2) throw new Error('missing TOPIC_ARN or completion role ARNs');

function callerRoleArn(detail) {
  return detail?.userIdentity?.sessionContext?.sessionIssuer?.arn ?? '';
}

export const handler = async (event) => {
  const detail = event.detail ?? {};
  const roleName = detail.requestParameters?.roleName ?? '';
  if (!expected.has(roleName)) return { ignored: true };

  const policyName = detail.requestParameters?.policyName ?? '';
  const actualCaller = callerRoleArn(detail);
  const expectedCaller = expected.get(roleName);
  const ok = policyName === 'AWSRevokeOlderSessions' && actualCaller === expectedCaller;

  if (!ok || sendExpected) {
    const severity = ok ? 'INFO' : 'CRITICAL';
    await sns.send(new PublishCommand({
      TopicArn: topicArn,
      Subject: `[VAULT ${severity}] completion revocation policy ${ok ? 'expected' : 'unexpected mutation'}`,
      Message: [
        `Severity: ${severity}`,
        `Event time: ${event.time ?? detail.eventTime ?? 'unknown'}`,
        `Target role: ${roleName}`,
        `Policy name: ${policyName || 'unknown'}`,
        `Expected caller role: ${expectedCaller}`,
        `Actual caller role: ${actualCaller || 'unknown'}`,
        `Source IP: ${detail.sourceIPAddress ?? 'unknown'}`,
        `CloudTrail event ID: ${detail.eventID ?? 'unknown'}`,
        '',
        ok
          ? 'Expected Vault successful-completion role-session revocation update.'
          : 'Unexpected inline-policy mutation targeted a Vault backup role. Preserve evidence and contain before reopening Vault sessions.'
      ].join('\n')
    }));
  }
  return { ok, roleName, policyName, actualCaller };
};
```

Package and deploy:

```bash
mkdir -p ~/vault-completion-policy-watch && cd ~/vault-completion-policy-watch
# Save the code above as index.mjs.
cat > package.json <<'JSON'
{
  "type": "module",
  "dependencies": {
    "@aws-sdk/client-sns": "^3.0.0"
  }
}
JSON
npm install --omit=dev
node --check index.mjs
zip -qr /tmp/vault-completion-policy-watch.zip \
  index.mjs package.json package-lock.json node_modules

export PC_COMPLETION_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-PC-S3-Completion-ExecutionRole \
  --query Role.Arn --output text)"
export PHONE_COMPLETION_ROLE_ARN="$(aws iam get-role \
  --role-name Vault-Phone-S3-Completion-ExecutionRole \
  --query Role.Arn --output text)"

aws lambda create-function \
  --region "$AWS_REGION" \
  --function-name VaultCompletionPolicyWatch \
  --runtime nodejs22.x \
  --handler index.handler \
  --role "$STS_WATCH_ROLE_ARN" \
  --zip-file fileb:///tmp/vault-completion-policy-watch.zip \
  --timeout 20 \
  --memory-size 128 \
  --environment "Variables={TOPIC_ARN=$VAULT_ALERT_TOPIC_ARN,PC_COMPLETION_ROLE_ARN=$PC_COMPLETION_ROLE_ARN,PHONE_COMPLETION_ROLE_ARN=$PHONE_COMPLETION_ROLE_ARN,SEND_EXPECTED_COMPLETION_POLICY=false}"
```

Create an EventBridge rule for CloudTrail IAM events whose exact target role name is one
of the two Vault backup roles:

```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "source": ["aws.iam"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["PutRolePolicy"],
    "requestParameters": {
      "roleName": [
        "Vault-PC-S3-BackupRole",
        "Vault-Phone-S3-BackupRole"
      ]
    }
  }
}
```

Target `VaultCompletionPolicyWatch`. Add the ordinary Lambda resource-based permission
for `events.amazonaws.com` restricted to this exact rule ARN.

Temporarily set `SEND_EXPECTED_COMPLETION_POLICY=true` for one synthetic successful
completion test. Confirm one INFO message shows the matching completion execution role
and exact `AWSRevokeOlderSessions` policy name, then set it back to `false`. A human
administrator, gate role, opposite completion role, different policy name, or unknown
caller targeting either backup role is CRITICAL.

---

## 6A. Coordinator authorization-failure detector — VaultAuthFailureWatch

### Why this detector exists

The core coordinator rejects a wrong device phase token and rejects invalid
cross-VPS close/signature payloads. A 256-bit random phase token and Ed25519 signing key
are not realistically brute-forced by online guessing. However, repeated authorization
failures are still a high-signal indication of one of the following:

```text
compromised primary probing its own coordinator
stale/incorrect secret after a migration
unexpected tailnet member reaching the coordinator
malformed automation repeatedly exercising the authorization boundary
attempted cross-VPS signature/payload forgery
```

The goal is therefore **visibility, not cryptographic rate-limit theater**. Do not weaken
the token or signing design because an alarm exists, and do not describe this watcher as
making a weak secret safe.

This watcher is installed by the mandatory post-install profile rather than the master
architecture guide because it does not grant, extend, revoke, or close a Vault session.
It observes authorization failures and publishes alerts.

### 6A.1 Event policy

Use the following event classes:

```text
AUTH_TOKEN_REJECT
  wrong local device phase token
  threshold: 5 events from one source IP in 60 seconds -> CRITICAL
  threshold: 20 events from one source IP in 10 minutes -> CRITICAL

AUTH_PROTOCOL_REJECT
  malformed/unsupported coordinator command
  threshold: 20 events from one source IP in 10 minutes -> CRITICAL

PEER_SIGNATURE_INVALID
  cross-VPS Ed25519 verification failure
  threshold: 1 event -> CRITICAL

PEER_PAYLOAD_INVALID
  signed peer-close payload has wrong target, deadline, freshness, lifetime,
  core encoding, or other exact-session semantics
  threshold: 1 event -> CRITICAL
```

A single wrong phase token is not immediately CRITICAL because a stale local secret,
operator mistake, or incomplete device migration can produce one failure. An invalid
cross-VPS signature or exact-session payload is different: normal operation should not
produce it, so one event is high signal.

Never log:

```text
phase token candidate
stored phase-token verifier
Ed25519 private key material
full STS credential
restic repository password
```

Log only the event class, source IP, local coordinator role, command class, and time.

### 6A.2 Add structured security events to the coordinator

The core coordinator currently returns protocol rejection text to the caller. During
this mandatory detection stage, add structured journal events to the same reviewed Go
source before rebuilding it.

Add this helper near the other coordinator helpers:

```go
func securityEvent(event, sourceIP, command, detail string) {
	log.Printf(
		"VAULT_SECURITY event=%q source_ip=%q command=%q detail=%q",
		event,
		sourceIP,
		command,
		detail,
	)
}
```

At both local token-rejection branches, log only the command class; do **not** interpolate
`fields[2]` or any token bytes:

```go
if !s.authenticateToken(fields[2]) {
	securityEvent("AUTH_TOKEN_REJECT", sourceIP, strings.ToUpper(fields[0]), "local phase token rejected")
	_, _ = io.WriteString(conn, "REJECT token\n")
	return
}
```

Before the generic malformed-command rejection, record:

```go
securityEvent("AUTH_PROTOCOL_REJECT", sourceIP, "UNKNOWN", "unexpected coordinator command shape")
_, _ = io.WriteString(conn, "REJECT expected JOIN <s3|rhel> <token> or CLOSE_PEER s3 <token>\n")
return
```

At cross-VPS signature verification failures, emit:

```go
securityEvent("PEER_SIGNATURE_INVALID", sourceIP, "PEER", "cross-vps Ed25519 verification failed")
```

At exact-session peer payload validation failures caused by target, deadline, freshness,
lifetime, core encoding, or equivalent payload-semantic mismatch, emit:

```go
securityEvent("PEER_PAYLOAD_INVALID", sourceIP, "PEER", "cross-vps payload semantics rejected")
```

Keep the existing rejection/error return. Logging is additive and must not convert a
rejection into success.

Reformat, build, and restart exactly as in the core coordinator install section:

```bash
gofmt -w /usr/local/src/vault-device-coordinator/main.go
cd /usr/local/src/vault-device-coordinator
go build ./...
sudo systemctl restart vault-device-coordinator.service
sudo systemctl is-active vault-device-coordinator.service
```

Confirm that ordinary successful Vault use does not emit `VAULT_SECURITY`:

```bash
sudo journalctl -u vault-device-coordinator.service --since '-15 min' --no-pager \
  | grep 'VAULT_SECURITY' || true
```

`journalctl` can read service journal entries and can emit JSON records for machine
processing. The watcher below consumes the coordinator unit's journal stream; it does
not scrape human-formatted console output.

### 6A.3 Create two SNS-publish-only IAM roles with IAM Roles Anywhere

The VPSs run outside AWS. Do not place an IAM user's long-lived access key on either
VPS merely to publish security alerts.

Use IAM Roles Anywhere with one X.509 workload certificate per VPS. AWS exchanges the
certificate-backed signature for temporary AWS credentials. Create two separate roles:

```text
Vault-AuthFailureWatch-PC-PublishRole
Vault-AuthFailureWatch-Phone-PublishRole
```

Each role receives only:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sns:Publish",
    "Resource": "VAULT_ALERT_TOPIC_ARN"
  }]
}
```

Do not grant:

```text
sts:AssumeRole
lambda:InvokeFunction
dynamodb:*
iam:*
s3:*
tailscale API authority
```

Use one Roles Anywhere profile per VPS and constrain each profile to its matching role.
Issue one leaf certificate for `vault-pc` and one for `vault-phone`. Keep the CA private
key outside both VPSs. Store only the matching leaf certificate/private key on each VPS.

Recommended VPS paths:

```text
/etc/vault-auth-watch/rolesanywhere.crt
/etc/vault-auth-watch/rolesanywhere.key
```

Permissions:

```bash
sudo install -d -o root -g root -m 700 /etc/vault-auth-watch
sudo chown root:root /etc/vault-auth-watch/rolesanywhere.crt \
  /etc/vault-auth-watch/rolesanywhere.key
sudo chmod 600 /etc/vault-auth-watch/rolesanywhere.crt \
  /etc/vault-auth-watch/rolesanywhere.key
```

Install the current reviewed AWS Roles Anywhere credential helper from the official AWS
release/documentation path and place it at:

```text
/usr/local/libexec/aws_signing_helper
```

Configure a root-only AWS profile on `vault-pc`:

```bash
sudo install -d -o root -g root -m 700 /root/.aws
sudo tee /root/.aws/config >/dev/null <<'EOF_AWS'
[profile vault-auth-watch]
region = AWS_REGION
credential_process = /usr/local/libexec/aws_signing_helper credential-process --certificate /etc/vault-auth-watch/rolesanywhere.crt --private-key /etc/vault-auth-watch/rolesanywhere.key --trust-anchor-arn PC_TRUST_ANCHOR_ARN --profile-arn PC_ROLES_ANYWHERE_PROFILE_ARN --role-arn PC_AUTH_FAILURE_PUBLISH_ROLE_ARN
EOF_AWS
sudo chmod 600 /root/.aws/config
```

Use the Phone-specific trust-anchor/profile/role values on `vault-phone`.

Test the identity:

```bash
sudo AWS_PROFILE=vault-auth-watch aws sts get-caller-identity
```

The returned ARN must contain only the matching AuthFailureWatch publish role. Then test
one explicit SNS publication:

```bash
sudo AWS_PROFILE=vault-auth-watch aws sns publish \
  --region "$AWS_REGION" \
  --topic-arn "$VAULT_ALERT_TOPIC_ARN" \
  --subject '[VAULT TEST] AuthFailureWatch publisher' \
  --message 'VaultAuthFailureWatch publish-only path test.'
```

Possession of a VPS leaf certificate/private key can therefore create alert spam if that
VPS is root-compromised, but the role cannot open Vault sessions, mint backup STS,
change IAM policy, read/write S3, or disable the AWS detection plane. A root-compromised
VPS can also suppress its local journal/watcher; this detector is primarily for the
single-compromised-primary and unexpected-access cases, not a claim of independent
visibility after full root compromise of the observing VPS.

### 6A.4 Install the journal aggregation watcher

Install:

```bash
sudo tee /usr/local/libexec/vault-auth-failure-watch.py >/dev/null <<'PY'
#!/usr/bin/env python3
import collections
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Deque, Dict, Tuple

PREFIX = "VAULT_SECURITY "
EVENT_RE = re.compile(
    r'event="(?P<event>[A-Z_]+)" source_ip="(?P<source>[^"]*)" '
    r'command="(?P<command>[^"]*)" detail="(?P<detail>[^"]*)"'
)

TOPIC_ARN = os.environ["VAULT_ALERT_TOPIC_ARN"]
AWS_REGION = os.environ["AWS_REGION"]
COMPARTMENT = os.environ["VAULT_COMPARTMENT"]
AWS_PROFILE = "vault-auth-watch"

@dataclass(frozen=True)
class Rule:
    count: int
    window: int

RULES = {
    "AUTH_TOKEN_REJECT": (Rule(5, 60), Rule(20, 600)),
    "AUTH_PROTOCOL_REJECT": (Rule(20, 600),),
    "PEER_SIGNATURE_INVALID": (Rule(1, 1),),
    "PEER_PAYLOAD_INVALID": (Rule(1, 1),),
}

history: Dict[Tuple[str, str], Deque[float]] = collections.defaultdict(collections.deque)
last_alert: Dict[Tuple[str, str, int, int], float] = {}


def publish(event: str, source: str, command: str, detail: str, rule: Rule, observed: int) -> None:
    dedupe_key = (event, source, rule.count, rule.window)
    now = time.time()
    # Duplicate alerts are safer than silence, but avoid one email per rejected packet.
    if now - last_alert.get(dedupe_key, 0) < 900:
        return

    subject = f"[VAULT CRITICAL] {event} on {COMPARTMENT}"
    message = (
        f"Vault authorization boundary alert\n"
        f"compartment={COMPARTMENT}\n"
        f"event={event}\n"
        f"source_ip={source}\n"
        f"command={command}\n"
        f"detail={detail}\n"
        f"observed={observed}\n"
        f"threshold={rule.count}\n"
        f"window_seconds={rule.window}\n"
        f"operator_action=preserve evidence, verify source identity, and freeze Vault sessions if unexplained\n"
    )

    subprocess.run(
        [
            "aws", "sns", "publish",
            "--profile", AWS_PROFILE,
            "--region", AWS_REGION,
            "--topic-arn", TOPIC_ARN,
            "--subject", subject,
            "--message", message,
        ],
        check=True,
        timeout=30,
    )
    last_alert[dedupe_key] = now


def process(message: str) -> None:
    if not message.startswith(PREFIX):
        return
    match = EVENT_RE.search(message)
    if not match:
        return

    event = match.group("event")
    source = match.group("source") or "unknown"
    command = match.group("command")
    detail = match.group("detail")
    rules = RULES.get(event)
    if not rules:
        return

    now = time.time()
    key = (event, source)
    q = history[key]
    q.append(now)
    max_window = max(rule.window for rule in rules)
    while q and q[0] < now - max_window:
        q.popleft()

    for rule in rules:
        observed = sum(1 for ts in q if ts >= now - rule.window)
        if observed >= rule.count:
            try:
                publish(event, source, command, detail, rule, observed)
            except Exception as exc:
                print(f"VaultAuthFailureWatch publish failure: {exc}", file=sys.stderr, flush=True)


def main() -> int:
    proc = subprocess.Popen(
        [
            "journalctl",
            "-u", "vault-device-coordinator.service",
            "-f", "-n", "0",
            "-o", "json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        try:
            record = json.loads(line)
            process(str(record.get("MESSAGE", "")))
        except json.JSONDecodeError:
            continue
    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
PY

sudo chown root:root /usr/local/libexec/vault-auth-failure-watch.py
sudo chmod 750 /usr/local/libexec/vault-auth-failure-watch.py
sudo python3 -m py_compile /usr/local/libexec/vault-auth-failure-watch.py
```

Create the environment file on `vault-pc`:

```bash
sudo tee /etc/vault-auth-watch/watch.env >/dev/null <<EOF_ENV
AWS_REGION=${AWS_REGION}
VAULT_ALERT_TOPIC_ARN=${VAULT_ALERT_TOPIC_ARN}
VAULT_COMPARTMENT=pc
EOF_ENV
sudo chown root:root /etc/vault-auth-watch/watch.env
sudo chmod 600 /etc/vault-auth-watch/watch.env
```

Use `VAULT_COMPARTMENT=phone` on `vault-phone`.

Install the service:

```bash
sudo tee /etc/systemd/system/vault-auth-failure-watch.service >/dev/null <<'UNIT'
[Unit]
Description=Vault coordinator authorization-failure watcher
After=network-online.target vault-device-coordinator.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/vault-auth-watch/watch.env
ExecStart=/usr/bin/python3 /usr/local/libexec/vault-auth-failure-watch.py
Restart=always
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=no
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now vault-auth-failure-watch.service
sudo systemctl is-active vault-auth-failure-watch.service
```

The service requires journal read access and the root-only Roles Anywhere leaf key. It
has no write requirement outside ordinary systemd runtime state. `ProtectKernelLogs=no`
is deliberate because journal access must remain functional; do not broaden other
sandbox settings to solve a logging mistake.

### 6A.5 Add watcher-health visibility

A dead authorization watcher must not fail silently. Add a systemd `OnFailure` handler
that publishes a CRITICAL message through the same publish-only profile.

Install:

```bash
sudo tee /usr/local/libexec/vault-auth-watch-failed >/dev/null <<'SH'
#!/usr/bin/env bash
set -euo pipefail

exec aws sns publish \
  --profile vault-auth-watch \
  --region "${AWS_REGION:?}" \
  --topic-arn "${VAULT_ALERT_TOPIC_ARN:?}" \
  --subject "[VAULT CRITICAL] AuthFailureWatch blind on ${VAULT_COMPARTMENT:?}" \
  --message "VaultAuthFailureWatch service failed on compartment=${VAULT_COMPARTMENT}. Treat authorization-failure visibility as blind until repaired."
SH
sudo chown root:root /usr/local/libexec/vault-auth-watch-failed
sudo chmod 750 /usr/local/libexec/vault-auth-watch-failed
```

Create:

```bash
sudo tee /etc/systemd/system/vault-auth-failure-watch-alert@.service >/dev/null <<'UNIT'
[Unit]
Description=Alert when VaultAuthFailureWatch fails

[Service]
Type=oneshot
EnvironmentFile=/etc/vault-auth-watch/watch.env
ExecStart=/usr/local/libexec/vault-auth-watch-failed
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
UMask=0077
UNIT
```

Add to `[Unit]` in `vault-auth-failure-watch.service`:

```ini
OnFailure=vault-auth-failure-watch-alert@%n.service
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart vault-auth-failure-watch.service
```

Also extend the detector-health review table in Section 7 with:

```text
vault-auth-failure-watch.service   inactive/failed -> SNS CRITICAL through OnFailure
```

The OnFailure path shares the same VPS and Roles Anywhere leaf credential, so a full VPS
root compromise can blind both. This limitation is recorded in the threat model. It does
not weaken the existing AWS-side SlotWatch, StsWatch, AuditWatch, completion-policy
watcher, or Lambda health alarms.

### 6A.6 Negative and threshold tests

From the expected primary in the matching tailnet, send five deliberately wrong token
attempts within 60 seconds to the coordinator listener. Use a generated fake value; do
not print or paste the real phase token:

```bash
FAKE_TOKEN="$(openssl rand -hex 32)"
for i in $(seq 1 5); do
  printf 'JOIN s3 %s\n' "$FAKE_TOKEN" | nc -w 2 VAULT_COORDINATOR_IP VAULT_COORDINATOR_PORT || true
  sleep 2
done
unset FAKE_TOKEN
```

Expected:

```text
all five requests rejected
no DynamoDB daily slot inserted
no Lambda issuance
no STS credential returned
no S3 proxy admission opened
coordinator journal contains AUTH_TOKEN_REJECT without token bytes
one VaultAuthFailureWatch CRITICAL alert arrives
```

Inspect:

```bash
sudo journalctl -u vault-device-coordinator.service --since '-5 min' --no-pager \
  | grep 'VAULT_SECURITY'

sudo journalctl -u vault-auth-failure-watch.service --since '-5 min' --no-pager
```

Then perform one wrong-token attempt only and wait more than 60 seconds. It must be
rejected but must not independently trigger the five-in-60-seconds alert.

For cross-VPS validation, use the core unit-test harness to feed one invalid
signature and one exact-session payload mismatch. Do not test this by modifying a
production VPS private key. Each synthetic event must create an immediate CRITICAL alert.

Finally stop the watcher deliberately:

```bash
sudo systemctl stop vault-auth-failure-watch.service
sudo systemctl start vault-auth-failure-watch.service
```

A normal manual stop may not exercise `OnFailure`. For the acceptance test, temporarily
replace `ExecStart` with `/usr/bin/false`, run `systemctl daemon-reload`, start the unit,
verify the CRITICAL blind alert, then restore the reviewed `ExecStart` and restart the
service.

### 6A.7 Incident response for authorization-failure alerts

```text
AUTH_TOKEN_REJECT threshold
  freeze new Vault ceremonies if unexplained
  identify the source Tailnet node/IP
  verify whether a migration or stale secret explains the failures
  if not explained, treat the source primary as suspected compromised
  expire/revoke that primary node and rotate its phase token/verifier
  preserve coordinator and watcher journals
  inspect SlotWatch/StsWatch for any nearby issuance event

PEER_SIGNATURE_INVALID or PEER_PAYLOAD_INVALID
  stop new Vault ceremonies in both compartments
  preserve both VPS coordinator journals
  verify wg-cross peer identity and current VPS public signing keys
  inspect recent VPS administrator access and provider-console events
  do not rotate only one log field and continue
  follow the VPS signing-key compromise/migration procedure if unexplained

WATCHER BLIND
  treat brute-force/authorization-failure visibility as unavailable
  existing authorization prevention still applies
  repair the watcher and Roles Anywhere publish path
  inspect the missing interval manually before resuming normal operation
```

Do not interpret a token-guess alarm as evidence that the attacker is close to finding a
256-bit token. It is evidence that an authorization boundary is being exercised
abnormally.

## 7. Gate, completion, and detector health alarms

Create CloudWatch alarms on:

```text
Vault-PC-S3-Gate                    Errors >= 1 / 5 min -> SNS
Vault-Phone-S3-Gate                 Errors >= 1 / 5 min -> SNS
Vault-PC-S3-Completion-Revoker      Errors >= 1 / 5 min -> SNS
Vault-Phone-S3-Completion-Revoker   Errors >= 1 / 5 min -> SNS
Vault-S3-Completion-Status          Errors >= 1 / 5 min -> SNS
VaultCompletionPolicyWatch          Errors >= 1 / 5 min -> SNS
VaultAuditWatch                     Errors >= 1 / 5 min -> SNS
VaultSlotWatch                      Errors >= 1 / 5 min -> SNS
VaultStsWatch                       Errors >= 1 / 5 min -> SNS
```

An issuance-gate error may represent invalid proof, daily-slot collision, STS failure,
or a deployment bug. A completion-revoker error may represent malformed/out-of-window
S3 evidence, DynamoDB transition failure, S3 reconciliation failure, or failure to write
or finalize the exact role-session revocation policy. The alarms do not decide incident
cause; they prevent an ambiguous authorization or containment path from failing silently.

Also monitor EventBridge Scheduler invocation failures for `VaultAuditWatchEvery5Minutes`
and EventBridge invocation failures for both core five-minute completion reconcile
rules. If you use a dead-letter queue for either path, alert on messages arriving there.
A daily workflow that reaches the signed deadline while waiting for the opposite exact
session to become `REVOKED` is itself an operational containment incident; preserve the
slot row and completion Lambda logs rather than deleting state.

---

## 8. AWS root-activity alert

There is no such thing as “S3 root access” as a separate credential. The **AWS account
root user is account-wide authority** and should be almost never used.

Add an EventBridge rule for CloudTrail events where:

```text
userIdentity.type = Root
```

Send every match to `VaultCriticalSecurityAlerts` with subject:

```text
[VAULT CRITICAL] AWS ROOT USER ACTIVITY
```

The operator must have a written reason for every root event. Root use is rare enough
that false-positive fatigue is not an acceptable excuse.


---

## 6B. RHEL local-gate authorization-failure detector — VaultRhelAuthFailureWatch

`VaultAuthFailureWatch` on the two Vault VPSs covers phase-token and cross-VPS
coordinator rejection events. It does not observe requests that reach the independent
RHEL local dual-signature gate. Complete the detection boundary by instrumenting
`vault-rhel-gate` and deploying a separate watcher on the RHEL backup host.

This is a mandatory production-entry step. It does not grant or revoke backup authority
and does not change the RHEL daily-slot or hard-stop behavior.

### 6B.1 Events and alert policy

Emit the following structured journal records from `vault-rhel-gate.service`:

```text
RHEL_PROOF_SIGNATURE_INVALID
  one invalid PC-VPS or Phone-VPS Ed25519 signature
  -> CRITICAL immediately

RHEL_PROOF_PAYLOAD_INVALID
  signature encoding is valid but target/date/nonce/freshness/session semantics fail
  -> CRITICAL immediately

RHEL_DONE_TOKEN_REJECT
  invalid authenticated early-close token
  -> 5 from the same source in 60 seconds: WARN
  -> 20 from the same source in 10 minutes: CRITICAL

RHEL_PROTOCOL_REJECT
  malformed JSON, oversized body, wrong method/path, or structurally invalid request
  -> 20 from the same source in 10 minutes: CRITICAL
```

A single malformed HTTP request is not automatically a security incident. A single
cryptographic proof failure is high signal because normal Vault operation should never
send a bundle with an invalid infrastructure signature.

Never log:

```text
raw proof signatures
raw core payload
DONE token
repository password
restic credentials
Tailscale node keys
```

Log only the event type, source address, target compartment, and a bounded reason code.

### 6B.2 Add structured security logging to the RHEL gate

Patch the core `/usr/local/src/vault-rhel-gate/main.go` source and rebuild the
existing binary. Add these helpers:

```go
func requestSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func rhelSecurityEvent(event, source, target, reason string) {
	log.Printf(
		"VAULT_RHEL_SECURITY event=%q source_ip=%q target=%q reason=%q",
		event,
		source,
		target,
		reason,
	)
}
```

The source file already imports `net`; do not add a second import. Keep reason values
from a fixed vocabulary rather than copying attacker-controlled input.

In `openHandler`, log protocol parsing failures:

```go
source := requestSource(r)

if r.Method != http.MethodPost || r.URL.Path != "/__vault_gate" {
	rhelSecurityEvent("RHEL_PROTOCOL_REJECT", source, kind, "wrong_method_or_path")
	http.NotFound(w, r)
	return
}
```

Use bounded reason codes for body/JSON errors:

```go
rhelSecurityEvent("RHEL_PROTOCOL_REJECT", source, kind, "invalid_body")
rhelSecurityEvent("RHEL_PROTOCOL_REJECT", source, kind, "invalid_json")
```

Do not return the internal cryptographic verification error directly to the client.
Classify it locally:

```go
p, err := s.verifyBundle(bundle, expectedTarget(kind))
if err != nil {
	event := "RHEL_PROOF_PAYLOAD_INVALID"
	reason := "proof_semantics_rejected"

	switch {
	case strings.Contains(err.Error(), "signature encoding"):
		event = "RHEL_PROOF_SIGNATURE_INVALID"
		reason = "signature_encoding_invalid"
	case strings.Contains(err.Error(), "signature verification failed"):
		event = "RHEL_PROOF_SIGNATURE_INVALID"
		reason = "signature_verification_failed"
	}

	rhelSecurityEvent(event, source, kind, reason)
	jsonResponse(w, http.StatusForbidden, map[string]any{
		"ok": false,
		"error": "authorization proof rejected",
	})
	return
}
```

In `doneHandler`, record invalid early-close attempts without logging the token:

```go
source := requestSource(r)

if r.Method != http.MethodPost || r.URL.Path != "/__vault_done" {
	rhelSecurityEvent("RHEL_PROTOCOL_REJECT", source, kind, "wrong_done_method_or_path")
	http.NotFound(w, r)
	return
}

if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.DoneToken) != 64 {
	rhelSecurityEvent("RHEL_DONE_TOKEN_REJECT", source, kind, "invalid_done_token_shape")
	jsonResponse(w, http.StatusBadRequest, map[string]any{
		"ok": false,
		"error": "invalid done token",
	})
	return
}
```

At the existing constant-time DONE-token comparison failure, add:

```go
rhelSecurityEvent("RHEL_DONE_TOKEN_REJECT", source, kind, "done_token_mismatch")
```

Then rebuild and restart:

```bash
cd /usr/local/src/vault-rhel-gate
sudo gofmt -w main.go
sudo go test ./...
sudo go build -trimpath -ldflags='-s -w' -o vault-rhel-gate main.go
sudo install -o root -g root -m 0755 vault-rhel-gate /usr/local/sbin/vault-rhel-gate
sudo systemctl restart vault-rhel-gate.service
sudo systemctl --no-pager --full status vault-rhel-gate.service
```

Before replacing the production binary, preserve a root-owned rollback copy:

```bash
sudo install -o root -g root -m 0755 \
  /usr/local/sbin/vault-rhel-gate \
  /usr/local/sbin/vault-rhel-gate.pre-auth-watch
```

### 6B.3 Workload identity and minimum AWS permission

Do not copy either VPS's Roles Anywhere private key or certificate to RHEL.

Create a third, RHEL-specific X.509 leaf certificate and a separate IAM Roles Anywhere
profile/role. The role must have exactly one AWS data-plane permission:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sns:Publish",
    "Resource": "VAULT_ALERT_TOPIC_ARN"
  }]
}
```

It must not permit:

```text
sts:AssumeRole
iam:*
lambda:InvokeFunction
dynamodb:*
s3:*
tailscale administration
```

Store the RHEL leaf private key root-only and configure the Roles Anywhere credential
helper exactly as in Section 6A, but use distinct names:

```text
role:     Vault-RHEL-AuthFailure-PublishRole
profile:  Vault-RHEL-AuthFailure-PublishProfile
cert:     /etc/vault-auth-watch/rhel-leaf.crt
key:      /etc/vault-auth-watch/rhel-leaf.key
```

Compromise of this identity can publish alert spam to the exact topic; it cannot open,
extend, or revoke a Vault backup session.

### 6B.4 Install the RHEL watcher

Reuse the reviewed `vault-auth-failure-watch.py` implementation from Section 6A, but
install a separate configuration and systemd instance with:

```text
VAULT_COMPARTMENT=rhel
VAULT_JOURNAL_UNIT=vault-rhel-gate.service
VAULT_JOURNAL_PREFIX=VAULT_RHEL_SECURITY
```

Add these rules to its fixed rule table:

```python
"RHEL_DONE_TOKEN_REJECT": (
    Rule(5, 60, "WARN"),
    Rule(20, 600, "CRITICAL"),
),
"RHEL_PROTOCOL_REJECT": (
    Rule(20, 600, "CRITICAL"),
),
"RHEL_PROOF_SIGNATURE_INVALID": (
    Rule(1, 1, "CRITICAL"),
),
"RHEL_PROOF_PAYLOAD_INVALID": (
    Rule(1, 1, "CRITICAL"),
),
```

Use a separate persistent cursor/state path:

```text
/var/lib/vault-auth-failure-watch/rhel-state.json
```

Create:

```text
vault-rhel-auth-failure-watch.service
vault-rhel-auth-failure-watch-failure.service
```

The failure unit publishes:

```text
VaultRhelAuthFailureWatch service failed.
Treat RHEL local authorization-failure visibility as blind until repaired.
```

Do not make `vault-rhel-gate.service` depend on the watcher. Detection failure must
create a loud blind-state alert and operational stop condition, not make the local gate
silently inherit an additional availability dependency.

### 6B.5 Acceptance tests

Perform these tests before production:

```text
[ ] One malformed gate request creates RHEL_PROTOCOL_REJECT but no CRITICAL alert.
[ ] Twenty malformed requests from one source inside ten minutes create one CRITICAL alert.
[ ] Five invalid DONE tokens inside sixty seconds create WARN.
[ ] Twenty invalid DONE tokens inside ten minutes create CRITICAL.
[ ] One proof with a modified signature creates RHEL_PROOF_SIGNATURE_INVALID and immediate CRITICAL.
[ ] One correctly signed proof with a modified target/deadline creates RHEL_PROOF_PAYLOAD_INVALID and immediate CRITICAL.
[ ] Journal records contain no raw proof, signature, DONE token, or repository credential.
[ ] Disabling the watcher triggers its failure/blindness notification path.
[ ] The RHEL Roles Anywhere identity can publish only to the exact security SNS topic.
[ ] The RHEL Roles Anywhere identity cannot invoke Lambda, access S3/DynamoDB, or assume another role.
[ ] A legitimate PC and Phone RHEL ceremony still passes unchanged.
[ ] Daily-slot and signed hard-stop behavior remain unchanged.
```

### 6B.6 Residual risk

RHEL root can alter `vault-rhel-gate` logs, stop the local watcher, or steal the
RHEL-specific publish-only certificate. This detector is therefore independent from a
compromised primary endpoint or either Vault VPS, but not independent from full RHEL
root compromise.

The preventive controls remain the locally verified dual signatures, repository/day
slot, isolated backend, and signed systemd hard-stop. Detection does not replace them.

---

# PART II — OPTIONAL LOCAL TRIPWIRES AND EGRESS VISIBILITY
================================================================================

## 9. Local canary files: optional high-signal tripwire, not primary detection

The idea is valid, but it has a hard limit:

```text
VPS root compromise
  -> root may stop/alter auditd or local forwarding
```

Therefore a canary file is **not** an independent guarantee that root compromise will be
detected. Treat it as a high-signal tripwire for opportunistic discovery.

Use plausible but fake files. Never place real secrets in the canary:

```text
/root/.aws/credentials.bak
/etc/vault/archive/oauth-client.env.old
/var/lib/vault-coordinator/backup/device-admin.env
```

Example:

```bash
sudo install -d -m 700 /etc/vault/archive
sudo sh -c 'cat > /etc/vault/archive/oauth-client.env.old <<"EOF"
TS_CLIENT_ID=tskey-client-FAKEONLY
TS_CLIENT_SECRET=tskey-secret-FAKE-DO-NOT-USE
EOF'
sudo chmod 600 /etc/vault/archive/oauth-client.env.old

sudo auditctl -w /etc/vault/archive/oauth-client.env.old -p r -k vault-canary-read
```

Verify:

```bash
sudo cat /etc/vault/archive/oauth-client.env.old >/dev/null
sudo ausearch -k vault-canary-read -ts recent
```

For production, make the rule persistent in `/etc/audit/rules.d/vault-canary.rules` and
forward audit events off the VPS before alerting. A local script that merely reads local
`audit.log` and emails from the same root-compromisable host is weaker than the AWS
watchers above.

Do not use a third-party callback canary by default. It adds another external trust and
privacy dependency. Reconsider it only if you deliberately want that independent third
party.

### 9.1 Container-level canaries (RHEL rest-server)

If the Advanced RHEL Containment extension is enabled, detect RCE inside the
`rest-server` Podman container by placing fake credential files **inside the container
image** but **outside** the bind-mounted `/data` repository directory:

```text
/.auth-token-master
/.restic-admin-token
```

Legitimate `rest-server` only operates on the `/data` path. Any read access to these
files is evidence of unexpected code execution inside the container.

Monitor with `inotifywait` from a sidecar or host-side process targeting the container's
OverlayFS merged directory:

```bash
inotifywait -m -e access /.auth-token-master
```

The same root-compromise caveat applies: a full host compromise can disable the watcher.
This is a high-signal tripwire for container-scoped RCE, not an independent guarantee.

### 9.2 Network honeypots (RHEL)

Detect lateral movement attempts or automated port scanning within the RHEL environment
by listening on commonly targeted but unused ports:

```text
TCP 22    (if SSH is moved to a non-standard port)
TCP 8080  (common admin/proxy port)
TCP 3389  (RDP — should never be used on RHEL)
```

Use lightweight listeners (netcat or a minimal Python socket) that log and alert on any
connection attempt. The core architecture ensures that the phone and PC never
connect to anything other than the exact Caddy proxy port.

Any connection to a honeypot port is a CRITICAL event.

### 9.3 Cloud canaries (AWS)

Create deceptive AWS resources that the core system never accesses:

```text
S3 bucket:       vault-backup-archive-admin-do-not-delete
DynamoDB table:  VaultMasterKeys
```

Configure CloudTrail to alert on any API call targeting these resources. Because the
core IAM roles are strictly bound to their respective production resources, any
access attempt indicates credential theft or unauthorized AWS account exploration.

### 9.4 DNS canaries (container egress detection)

If the Advanced RHEL Containment extension is enabled, the `rest-server` container
operates with `--network=none` and should never perform DNS lookups.

Log all DNS queries on the RHEL host via `systemd-resolved` or a local DNS sinkhole.
A DNS query originating from a container network namespace (or any unexpected namespace)
indicates a compromised process attempting to download a secondary payload or beacon to a
Command and Control (C2) server.

This signal is strongest when combined with `--network=none`. Without network isolation,
DNS queries from the container are expected and this canary is not useful.

---

## 10. Egress: prevention first, detection second

The correct goal is not “hardcode three Internet IP addresses for the whole VPS.”
Tailscale control/relay infrastructure can change, and a tiny static IP allowlist can
turn a legitimate service change into an outage.

Prefer service/process separation:

```text
vault S3 proxy service user
  -> exact S3 destinations required by the core proxy

cross-VPS WireGuard
  -> exact opposite VPS public IP + exact wg-cross UDP port

expiry helper
  -> Tailscale API HTTPS

tailscaled
  -> Tailscale control/DERP requirements

unrecognized local service/user
  -> no broad outbound permission by default where practical
```

On Linux, `nftables` can combine process UID (`meta skuid`) with destination policy. The
core S3 proxy already narrows application destinations. Add final deny logging with
a prefix such as:

```text
VAULT_EGRESS_DENY
```

Then forward firewall logs to an independent collector before making “C2 connection
attempts are detectable” a formal threat-model claim.

Because provider networking and Tailscale destination resolution vary, this guide does
not include a fake universal three-IP nftables ruleset. Build the egress policy from the
actual two VPS distributions/providers and test Tailscale DERP fallback before enabling
a fail-closed global output policy.

---

# PART III — CREDENTIAL CUSTODY STANDARD
================================================================================

## 11. Stop treating every secret the same

Use three classes:

| Class | Examples | Storage rule |
|---|---|---|
| A — Break-glass/account recovery | AWS root password, root recovery records, Tailscale Tailnet Lock disablement secrets, VPS provider owner recovery codes | Offline/separated; never needed by routine services |
| B — Human admin credentials | Tailscale IdP admin login, AWS Identity Center admin, SSH admin authentication | Interactive; phishing-resistant MFA; short sessions; no machine-readable long-lived secret where avoidable |
| C — Runtime machine secrets | VPS cross-signing private key, unavoidable `devices:core` OAuth client secret | Only the owning compartment; service-scoped delivery; encrypted-at-rest where possible; root compromise remains a known boundary |

A password manager is excellent for many Class A/B records, but **the location of the
password-manager database matters**. Do not place the only break-glass copy inside the
same Vault repository or cloud account whose loss you are trying to recover.

---

## 12. AWS account root user — break-glass only

### 12.1 Terminology

Do not create a conceptual “S3 root credential.” AWS account root can control the entire
AWS account, including IAM, S3, billing, Lambda, DynamoDB, and containment controls.

### 12.2 Password storage

Recommended personal-use layout:

```text
Offline Break-Glass KeePass database
  AWS account root entry
    root email address
    account ID
    unique high-entropy root password
    recovery/contact checklist
    root MFA device inventory
    date last tested
```

Rules:

```text
NOT in the normal Vault working-data folder
NOT in the same AWS account's Secrets Manager as the only copy
NOT in a browser password store synchronized to both primary endpoints by default
NOT in shell history, notes, email drafts, or source repositories
```

Keep two encrypted offline copies of the break-glass database on separate removable
media. Store the two media separately. The database master passphrase should not be
written on the same USB media in plaintext. A sealed paper recovery record stored
separately is acceptable if your physical threat model permits it.

### 12.3 Root MFA

Prefer FIDO/passkey security keys. Register multiple root MFA devices so loss of one
does not force account recovery. A practical personal layout:

```text
Root MFA Key R1 -> physically accessible emergency key
Root MFA Key R2 -> separately stored backup/off-site key
```

Do not keep both backup keys permanently attached to the same keychain or laptop bag.

Protect the root email account with its own phishing-resistant MFA. Keep AWS account
contact phone and email current.

### 12.4 Root access keys

**Do not create them.** If the console shows root access keys, investigate why they
exist and remove them after confirming no legitimate dependency. Routine CLI/API work
must use IAM Identity Center and temporary credentials.

### 12.5 Normal AWS administration

Create a human administrative Identity Center permission set for rare infrastructure
changes. Do not use root and do not use `AdministratorAccess` for daily backup.

Recommended split:

```text
Vault-PC-Gate-Invoke        routine PC backup; invoke PC gate + shared read-only completion status
Vault-Phone-Gate-Invoke     routine Phone backup; invoke Phone gate + shared read-only completion status
Vault-Recovery-Admin        Deep Archive restore / documented incident operations
Vault-Infrastructure-Admin  rare controlled deployment changes
AWS root                    root-only tasks / account recovery only
```

`Vault-Recovery-Admin` should contain only the restore/version/containment actions needed
by the two Vault buckets and the documented incident runbook. Keep its session short and
require browser MFA. Do not make it a disguised permanent AdministratorAccess role.

---

## 13. Tailscale Owner/Admin access

Tailscale does not have a separate Tailscale password. User authentication is delegated
to the chosen identity provider (IdP). Therefore the real admin credential is:

```text
IdP account
  + IdP MFA/passkey/security key
  + Tailscale role assignment
```

For each tailnet:

1. Use an IdP identity whose password is unique and stored in the human-admin password
   manager, not on either VPS.
2. Enable phishing-resistant MFA/passkeys/security keys at the IdP where supported.
3. Store IdP recovery codes in the offline break-glass database.
4. Do not leave the Tailscale admin console signed in indefinitely on both primary
   devices.
5. Review Tailscale configuration audit logs after every intended admin change.

### Tailnet Lock disablement secrets

Tailnet Lock disablement secrets are Class A break-glass secrets. Store them in the
offline break-glass database or print/seal them in a secure physical location.

```text
NEVER on vault-pc
NEVER on vault-phone
NEVER on RHEL
NEVER in Lambda environment variables
NEVER in the same routine password-manager sync path accessible from both primary devices
```

The disablement secret exists specifically to authorize a security-sensitive Tailnet
Lock disable operation. Treat its loss as a major recovery problem and its disclosure as
an incident.

---

## 14. `devices:core` expiry credentials

### 14.1 Best option: eliminate the stored client secret with workload identity

If the VPS provider offers a trustworthy workload OIDC identity that Tailscale WIF can
validate, prefer a separate federated identity per VPS/tailnet and grant only the scope
required by the expiry helper. This removes the long-lived OAuth client secret from disk.

Do not assume every cheap VPS provider exposes a trustworthy workload identity. A public
cloud VM metadata endpoint and a random user-data field are not equivalent.

### 14.2 Generic VPS fallback: systemd service credential

If a long-lived Tailscale OAuth client secret is unavoidable:

```text
PC tailnet devices:core secret    -> vault-pc only
Phone tailnet devices:core secret -> vault-phone only
```

Never reuse one OAuth client across both tailnets.

Prefer `systemd-creds` plus `LoadCredentialEncrypted=` when the VPS OS/systemd version and
TPM2 environment support it. Example concept:

```bash
sudo install -d -o root -g root -m 700 /etc/credstore.encrypted
printf '%s' 'TAILSCALE_OAUTH_SECRET_HERE' | \
  sudo systemd-creds encrypt --name=tailscale_oauth_secret - \
  /etc/credstore.encrypted/vault-expiry-oauth.cred
sudo chmod 600 /etc/credstore.encrypted/vault-expiry-oauth.cred
```

Service unit:

```ini
[Service]
LoadCredentialEncrypted=tailscale_oauth_secret:/etc/credstore.encrypted/vault-expiry-oauth.cred
ExecStart=/usr/local/sbin/vault-expire-exact-primary
```

The helper reads:

```text
$CREDENTIALS_DIRECTORY/tailscale_oauth_secret
```

not an environment variable.

**Security limit:** if `vault-pc` root is already compromised while the helper can use
the credential, the attacker can generally make the machine use/decrypt that runtime
secret. TPM/systemd credential encryption protects offline disk/image theft and careless
secret copying; it does not transform a runtime root compromise into safety.

### 14.3 Minimum fallback when encrypted service credentials are unavailable

Use:

```text
/etc/vault-tailscale/expiry.oauth.client-id
/etc/vault-tailscale/expiry.oauth.secret
```

with:

```bash
sudo chown root:root /etc/vault-tailscale/expiry.oauth.*
sudo chmod 600 /etc/vault-tailscale/expiry.oauth.*
```

Load them with systemd `LoadCredential=` into the helper's credential directory. Do not
export them globally in `/etc/environment`, shell profiles, `.bashrc`, a Docker/Podman
image, cloud-init user-data, source code, or command-line arguments visible in process
inspection.

### 14.4 Rotation

Rotate/revoke immediately after:

```text
VPS rebuild or image exposure
suspected root compromise
secret printed/logged/copied to wrong host
helper redesign that changes trust assumptions
unexpected AuditWatch event by the expiry actor
```

A calendar rotation such as every 6–12 months is an operator hygiene choice, not a
substitute for incident-driven revocation. After rotation, run one supervised expiry and
update the pinned audit actor ID if Tailscale assigns a new actor identity.

---

## 15. Tailscale AuditWatch credential

There is deliberately **no persistent Tailscale audit credential**.

```text
VaultAuditWatch Lambda role
    -> AWS GetWebIdentityToken, <= 300 s
    -> Tailscale token exchange
    -> short-lived logs:configuration:read token
    -> token discarded with Lambda invocation
```

Client IDs and audiences are identifiers, not secrets. The Lambda role permission is
restricted to the exact two audience values and five-minute token lifetime.

This is preferable to placing a 90-day API key or never-expiring OAuth client secret in
Lambda environment variables.

---

## 16. VPS provider owner accounts

The provider control panel can usually reset a VM, open a serial/web console, replace
SSH keys, attach disks, or rebuild the machine. Treat it as a high-value admin plane.

For `vault-pc` and `vault-phone`, the strongest compartment model is:

```text
Provider/account A -> vault-pc
Provider/account B -> vault-phone
```

If both VPSs use one provider owner account, compromise of that account is a shared
failure domain even though the VMs are separate.

For every provider owner account:

```text
unique password
FIDO/passkey MFA where supported
recovery codes in offline break-glass DB
billing/contact email protected with MFA
no reusable provider API token unless automation actually requires it
```

If a provider API token is required, create a compartment-specific scoped token. Do not
store an unrestricted owner API key on either VPS.

Record the provider's serial/web-console recovery procedure in the break-glass database.
That console is the recovery path if SSH authentication is intentionally strict.

---

## 17. VPS SSH administrator authentication

### 17.1 Do not use one ordinary software SSH private key for both VPSs

This is the most important custody rule for the two-VPS architecture.

Bad layout:

```text
PC ~/.ssh/id_ed25519
        |
        +--> root/admin vault-pc
        +--> root/admin vault-phone
```

A PC malware compromise that steals the private key can now reach **both** VPS security
compartments and collapse the cross-VPS assumption.

### 17.2 Preferred layout: FIDO-backed OpenSSH credentials

OpenSSH supports FIDO security-key algorithms such as `ed25519-sk`. Use separate
credentials for the two VPSs.

Strongest compartment layout:

```text
FIDO key A / credential A -> vault-pc admin SSH
FIDO key B / credential B -> vault-phone admin SSH

backup FIDO key A2 -> stored separately
backup FIDO key B2 -> stored separately
```

Generate on the admin workstation:

```bash
ssh-keygen -t ed25519-sk \
  -O verify-required \
  -C 'vault-pc-admin' \
  -f ~/.ssh/vault-pc-admin_sk

ssh-keygen -t ed25519-sk \
  -O verify-required \
  -C 'vault-phone-admin' \
  -f ~/.ssh/vault-phone-admin_sk
```

The local `_sk` private-key handle file is still sensitive metadata and should be mode
`600`, but it is not sufficient to authenticate without the corresponding FIDO
authenticator.

Pragmatic lower-cost option: one physical FIDO token can hold two distinct SSH
credentials. This still protects against malware merely copying a software private key,
but loss/compromise of the physical token becomes a shared failure domain. The security
model should state that compromise explicitly.

### 17.3 Create a named admin user; disable direct root SSH

On each VPS through the provider console or initial trusted setup session:

```bash
sudo useradd -m -s /bin/bash vaultadmin
sudo passwd vaultadmin
sudo usermod -aG wheel vaultadmin      # RHEL-family
# Core Vault VPSs are RHEL 9; use the wheel group. Debian/Ubuntu is no longer the core VPS path.

sudo install -d -o vaultadmin -g vaultadmin -m 700 /home/vaultadmin/.ssh
sudo install -o vaultadmin -g vaultadmin -m 600 /dev/null \
  /home/vaultadmin/.ssh/authorized_keys
```

Install **only the correct VPS public key**:

```text
vault-pc    <- vault-pc-admin_sk.pub
vault-phone <- vault-phone-admin_sk.pub
```

Recommended `sshd_config` hardening after a second console remains available:

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PubkeyAuthOptions touch-required,verify-required
```

Restart/reload SSH only after checking syntax:

```bash
sudo sshd -t
sudo systemctl reload sshd
```

Keep the current session open. From a second terminal, verify the new FIDO-backed login
works before closing the first session.

### 17.4 Separate sudo secrets

Do not use the same sudo password on both VPSs. Store the two sudo passwords in the
human-admin password manager or offline break-glass database, depending on how rarely
you use them.

Do not put either sudo password in an automation script.

### 17.5 SSH host-key fingerprints

After first trusted provisioning, record:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Store the fingerprint in the break-glass record for that VPS/provider account.

Use strict host-key checking from the admin workstation:

```text
Host vault-pc
    HostName PC_VPS_ADMIN_ADDRESS
    User vaultadmin
    IdentityFile ~/.ssh/vault-pc-admin_sk
    IdentitiesOnly yes
    StrictHostKeyChecking yes

Host vault-phone
    HostName PHONE_VPS_ADMIN_ADDRESS
    User vaultadmin
    IdentityFile ~/.ssh/vault-phone-admin_sk
    IdentitiesOnly yes
    StrictHostKeyChecking yes
```

On a VPS rebuild, do not reflexively run `ssh-keygen -R` and accept the next fingerprint.
Verify the new fingerprint through the provider serial/web console first.

---

## 18. Vault VPS cross-signing private keys

These Ed25519 private keys are Class C runtime secrets:

```text
vault-pc private signing key    -> vault-pc only
vault-phone private signing key -> vault-phone only
```

Never place both private keys in one password manager, one RHEL directory, one AWS secret,
or one VPS backup image.

The authoritative recovery model is **rotation, not restoration of a compromised signing
identity**:

```text
VPS lost without compromise
  -> rebuild compartment
  -> generate NEW signing keypair
  -> update opposite VPS/public-key trust, both Lambdas, and RHEL
  -> rerun dual-sign negative tests

VPS suspected compromised
  -> preserve evidence
  -> destroy/rebuild
  -> generate NEW signing keypair
  -> never restore old private signing key
```

If the service can consume systemd credentials, deliver the signing key via
`LoadCredential=` or `LoadCredentialEncrypted=`. Otherwise keep the private key
root/dedicated-service-owned at mode `0400` or `0600` and use systemd sandboxing.

Public keys are not secrets and should be backed up/documented to simplify trust-state
inspection.

---

## 19. Restic repository passwords and device phase tokens

### Restic passwords

Baseline rules remain:

```text
PC source device    -> PC restic password routine copy
Phone source device -> Phone restic password routine copy
RHEL baseline       -> neither password
PC                  -> never stores Phone restic password
Phone               -> never stores PC restic password
```

The password manager is the authoritative human recovery store. Keep an independent
offline encrypted recovery copy if losing the password-manager database would otherwise
make both S3 and RHEL repositories unrecoverable.

Do not put repository passwords in AWS Secrets Manager merely because AWS is available;
that would make AWS account administration a decryption-key recovery path for the same
S3 repositories.

### Phase tokens

Each primary stores only its own raw 256-bit phase token. The owning VPS stores only its
SHA-256 verifier.

Do not create a central file containing:

```text
PC raw phase token
Phone raw phase token
```

and sync it to both devices or both VPSs. That would silently collapse the two-device
role-admission boundary.

---

## 20. Cross-device MFA storage

For the stated single-endpoint-compromise model, this is a reasonable software-only
layout:

```text
PC backup identity TOTP seed    -> Phone only
Phone backup identity TOTP seed -> PC only
```

Do not keep a backup copy of each seed in a password-manager database synchronized back
to the same protected endpoint. That would defeat the separation.

However, prefer phishing-resistant FIDO/passkey factors when available. For AWS root and
high-value admin identities, physical FIDO security keys are the preferred choice.

The cross-device TOTP layout is a compartment strategy; it does not make TOTP
phishing-resistant.

---

# PART IV — INCIDENT RESPONSE AND ROTATION
================================================================================

## 21. First response matrix

### Alert: daily slot consumed and you did not initiate a session

```text
1. Do not delete the DynamoDB slot.
2. Preserve Lambda, DynamoDB, CloudTrail, Tailscale audit, and VPS logs.
3. Disable/contain the affected backup role if budget deny is not already active.
4. Revoke the affected Tailscale expiry trust credential if related events exist.
5. Treat the corresponding endpoint/VPS compartment as suspect.
6. Do not run another ceremony to “test whether it works.”
```

### Alert: expiry actor performed non-expiry/wrong-target mutation

```text
1. Revoke that Tailscale trust credential immediately.
2. Review the previous 90 days of configuration audit logs.
3. Inspect API access-token creation events for the Client ID.
4. Export/preserve the logs outside the VPS.
5. Assume the owning VPS secret may be exposed until disproved.
6. Rebuild/rotate the VPS compartment if root compromise is plausible.
```

### Alert: unexpected caller assumed a Vault backup role

```text
1. Attach/confirm emergency deny on the affected backup role.
2. Review CloudTrail event ID, caller ARN/session issuer, source IP, and related calls.
3. Preserve Lambda and STS logs.
4. Rotate/rebuild the implicated AWS execution path.
5. Validate bucket policy and opposite-role explicit deny before reopening.
```

### Alert: unexpected completion-policy mutation or completion revoker failure

```text
1. Preserve the CloudTrail PutRolePolicy event, completion Lambda logs, exact DynamoDB
   slot row, backup-role inline policies, and permissions-boundary ARN.
2. Confirm whether the caller is the matching device-specific completion execution role
   and the policy name is exactly AWSRevokeOlderSessions.
3. If caller/policy is unexpected, attach or confirm emergency deny on the affected
   backup role and pause Vault sessions.
4. Verify the backup-role permissions boundary is still attached and unchanged.
5. If the exact slot is stuck REVOKING or the daily workflow hit the completion barrier
   deadline, do not delete/rewrite the slot. Repair the revoker/reconcile path and treat
   the old session as potentially usable only up to the core hard ceiling.
6. Re-run snapshot-only, snapshot+later-lock-removal, old-STS-denied, and signed peer-close
   acceptance tests before production resumes.
```

### Alert: DETECTION BLIND

```text
1. Treat silence from Tailscale audit detection as untrusted.
2. Check Scheduler invocation, Lambda Errors, AWS STS outbound identity, WIF client,
   audience, subject rule, and Tailscale audit API availability.
3. If blind state persists, pause discretionary Tailscale admin changes and consider
   pausing Vault sessions until visibility returns.
```

### Alert: AWS root activity

```text
1. Verify whether you personally initiated the exact root-only task.
2. If no: use a clean device, contain the AWS account, rotate root password/MFA as
   appropriate, revoke active credentials, and inspect CloudTrail.
3. Do not investigate from a suspected compromised endpoint.
```

---

## 22. Detection acceptance checklist

Do not sign off production until every item is true:

```text
[ ] VaultCriticalSecurityAlerts SNS test email received.
[ ] VaultDetectionState exists and TTL is enabled on ttl_epoch.
[ ] VaultDailyIssuanceSlots stream is NEW_IMAGE.
[ ] Historical test slot creates a SlotWatch email.
[ ] AuditWatch Lambda stores no Tailscale secret.
[ ] PC WIF identity has logs:configuration:read only.
[ ] Phone WIF identity has logs:configuration:read only.
[ ] AWS GetWebIdentityToken policy allows only the two exact audiences and <=300 s.
[ ] Exact PC/Phone expiry mutation actor IDs, expiry OAuth Client IDs, and primary NodeIDs are pinned.
[ ] Normal primary re-auth does not generate CRITICAL.
[ ] Unallowlisted test-node mutation (including tag manipulation / setTags) generates CRITICAL.
[ ] Broken WIF produces DETECTION BLIND after two polls.
[ ] Restored WIF produces recovery INFO.
[ ] CloudTrail management events are recorded; S3 data events are not enabled by default.
[ ] StsWatch validates exact gate-role -> backup-role pairs.
[ ] CompletionPolicyWatch validates exact completion-role -> own backup-role -> AWSRevokeOlderSessions triples.
[ ] Snapshot-created alone does not mark a slot REVOKED.
[ ] Snapshot-created plus later lock-removal marks the exact slot REVOKED and preserves one immutable cutoff.
[ ] Old STS fails after completion revocation propagation before its original Expiration.
[ ] Both backup-role permissions boundaries are attached and match the reviewed bucket/fixed-egress maximum envelope.
[ ] Completion revokers have no sts:AssumeRole, no S3 object read/write, and no opposite-role/bucket authority.
[ ] Completion-status Lambda is DynamoDB GetItem-only and both routine SSO profiles can invoke it.
[ ] Both five-minute completion reconciliation rules are enabled and target only their matching revoker.
[ ] Signed CLOSE_PEER closes target S3 proxy admission after exact opposite status REVOKED even when target local DONE is suppressed.
[ ] Lambda Errors alarms target the security SNS topic, including completion revokers/status/policy watcher.
[ ] Coordinator security logging emits event class/source/command only and never logs token candidates or secret material.
[ ] Five wrong local phase-token attempts in 60 seconds produce one AuthFailureWatch CRITICAL without consuming a slot or minting STS.
[ ] One isolated wrong-token attempt is rejected but does not independently create the threshold alert.
[ ] One synthetic invalid peer signature produces immediate CRITICAL.
[ ] One synthetic exact-session peer payload mismatch produces immediate CRITICAL.
[ ] vault-pc and vault-phone use separate IAM Roles Anywhere leaf certificates and separate publish roles.
[ ] AuthFailureWatch publish roles have sns:Publish to the exact security topic and no other AWS authorization.
[ ] AuthFailureWatch service failure exercises the documented blind-alert path.
[ ] Root-activity alert exists.
[ ] AWS root has no access keys.
[ ] AWS root password/recovery record is outside the routine Vault data path.
[ ] Multiple root MFA devices are registered; FIDO preferred.
[ ] Tailnet Lock disablement secrets are offline and absent from VPS/RHEL/Lambda.
[ ] vault-pc and vault-phone do not share an ordinary software SSH private key.
[ ] FIDO-backed or otherwise compartment-specific SSH admin credentials are tested.
[ ] Provider owner accounts use unique credentials and phishing-resistant MFA where supported.
[ ] PC and Phone devices:core OAuth clients have their Tag Ownership scoped exclusively to their respective target device tags (e.g., tag:pc-device).
[ ] Cross-VPS signing private keys have never been co-located.
[ ] Incident response contact/checklist is available without decrypting the Vault repositories.
```

---

## 23. Cost expectations

The design intentionally avoids high-volume S3 data-event logging and paid Tailscale log
streaming as baseline requirements.

The five-minute watcher schedule is approximately:

```text
12 runs/hour * 24 * ~30 = ~8,640 AuditWatch invocations/month
```

SlotWatch, StsWatch, and CompletionPolicyWatch run only on low-volume Vault security or
control events. The two completion reconcilers add approximately two more five-minute
Lambda schedules, while normal completion notifications occur only around daily backups.
DynamoDB state remains a few small items and short-TTL fingerprints. SNS email volume
should be tiny in a healthy system.

AWS pricing and free-tier terms can change. Confirm current prices before deployment, but
this architecture is deliberately sized for low-volume Lambda/Scheduler/DynamoDB/SNS
usage rather than a continuously running security VM.

---

## 24. Security limits — do not overclaim

This guide improves detection, not omniscience.

```text
Tailscale audit log:
  server-side and always enabled
  but no documented maximum event-inclusion latency

AuditWatch:
  independent from both VPSs
  but AWS admin compromise can disable it

Local canary:
  high-signal
  but root on the same VPS can attack local audit/forwarding

AWS slot/STS alerts:
  high-signal for Vault issuance
  but not general endpoint malware detection

Completion containment visibility:
  watches Lambda health and exact PutRolePolicy caller/target/name
  but S3 event delivery, client status polling, peer close, and IAM propagation are not
  zero-latency and AWS administrator compromise can disable the plane

Egress controls:
  useful prevention/detection
  but not a substitute for endpoint DLP
```

The intended security statement is:

> Under the single-endpoint or single-VPS compromise assumptions, the most important
> privileged Vault state transitions now either require an independent second signature,
> leave server-side evidence outside the compromised VPS, or both. Detection failure is
> itself surfaced as a security event where practical.

# PART IV — SERVICE-CONFINEMENT VISIBILITY
================================================================================

## 25. Detect hardening drift and confinement failures

The core production baseline now includes systemd and Podman confinement. Detection
must observe **drift and failure**, not merely assume the unit files remain unchanged.

### 17.1 What is security-significant

Treat these as CRITICAL unless they occur inside a declared maintenance window and are
followed by the full hardening acceptance matrix:

```text
Vault unit loses NoNewPrivileges
Vault unit changes ProtectSystem=strict to a weaker value
Fedora Vault unit exposes the whole home directory
Fedora Vault unit gains ~/.ssh, Documents, Pictures, or Downloads bindings
RHEL rest-server gains --privileged
RHEL rest-server loses --read-only
RHEL rest-server loses --cap-drop=all
RHEL rest-server loses no-new-privileges
Vault container gains label=disable or seccomp=unconfined
PC container gains Phone repository/credential bind mounts
Phone container gains PC repository/credential bind mounts
SELinux changes from Enforcing
hardened Vault unit repeatedly fails with EPERM/EACCES after an update
capacity guard can no longer stop the selected backend
RHEL hard-stop can no longer terminate the backend by signed deadline
```

A sandbox denial is not automatically an intrusion. It may be a legitimate software
update that introduced a new runtime need. The security event is that the reviewed
confinement contract no longer matches reality.

### 17.2 Local daily health evidence

On each VPS, install `/usr/local/sbin/vault-hardening-health`:

```bash
#!/usr/bin/env bash
set -euo pipefail

fail=0

must_have() {
  unit="$1"
  key="$2"
  expected="$3"
  actual="$(systemctl show "$unit" -p "$key" --value)"
  if [[ "$actual" != "$expected" ]]; then
    logger -p authpriv.crit -t vault-hardening \
      "$unit drift: $key expected=$expected actual=$actual"
    fail=1
  fi
}

for unit in vault-device-coordinator.service vault-s3-proxy.service; do
  must_have "$unit" NoNewPrivileges yes
  must_have "$unit" ProtectSystem strict
  must_have "$unit" ProtectHome yes
done

exit "$fail"
```

Create `/etc/systemd/system/vault-hardening-health.service`:

```ini
[Unit]
Description=Vault custom-service hardening drift check

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vault-hardening-health
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
```

Create `/etc/systemd/system/vault-hardening-health.timer`:

```ini
[Unit]
Description=Daily Vault service hardening drift check

[Timer]
OnCalendar=daily
Persistent=yes
RandomizedDelaySec=20m
Unit=vault-hardening-health.service

[Install]
WantedBy=timers.target
```

Enable on both VPSs:

```bash
sudo chmod 755 /usr/local/sbin/vault-hardening-health
sudo systemctl daemon-reload
sudo systemctl enable --now vault-hardening-health.timer
sudo systemctl start vault-hardening-health.service
journalctl -t vault-hardening -b --no-pager
```

On RHEL, create a symmetric local checker that verifies the effective settings and the
literal Podman command line in the two backend units. At minimum verify:

```bash
systemctl cat vault-rhel-pc-rest-server.service | grep -F -- '--read-only'
systemctl cat vault-rhel-pc-rest-server.service | grep -F -- '--cap-drop=all'
systemctl cat vault-rhel-pc-rest-server.service | grep -F -- '--security-opt=no-new-privileges'

systemctl cat vault-rhel-phone-rest-server.service | grep -F -- '--read-only'
systemctl cat vault-rhel-phone-rest-server.service | grep -F -- '--cap-drop=all'
systemctl cat vault-rhel-phone-rest-server.service | grep -F -- '--security-opt=no-new-privileges'

getenforce | grep -Fx Enforcing
```

Also inspect the repository mount declarations and fail if the PC unit contains the Phone
repository path or the Phone unit contains the PC repository path.

### 17.3 Journal/SELinux triage after updates

After a systemd, Podman, Caddy, Tailscale, rest-server, kernel, or SELinux policy update:

```bash
sudo journalctl -p warning..alert -b --no-pager
sudo journalctl -u 'vault-*' -b --no-pager
sudo ausearch -m AVC,USER_AVC -ts boot 2>/dev/null || true
```

Do not respond to an AVC by disabling SELinux or container labeling. Identify the exact
service, source/target context, object path, and operation. Reconcile the confinement
contract with the updated software, then rerun the core hardening acceptance matrix.

### 17.4 Alert-plane integration

The AWS-side detector remains independent and authoritative for Tailscale/AWS control
events. Local systemd/SELinux evidence is a separate host signal. Forwarding host
journals to AWS is optional and is **not** required for the current prevention model.

At minimum, the operator must check local hardening health after every relevant software
update and whenever a Vault custom service enters a failed/restart loop. A future remote
log-forwarding extension may publish only structured hardening-health failures to the
existing security alert path; do not give a VPS write authority to detection state that
can suppress AWS-side alerts.

## 26. RHEL 9 VPS platform, service-identity, and sandbox health

The two Vault VPSs are RHEL 9 BYOL/BYOI hosts. Add the following to the monthly
infrastructure review and to every post-update review:

```bash
cat /etc/redhat-release
uname -m
rpm --eval '%{_arch}'
getenforce
sudo subscription-manager status || true
sudo dnf repolist

systemctl show vault-device-coordinator.service \
  -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome

systemctl show vault-s3-proxy.service \
  -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome

sudo -u vaultproxy test ! -r /etc/vault-device/signing-key.pem
sudo -u vaultcoord test ! -r /etc/vault-ts-expiry/config.json
```

You may record native service SELinux contexts for diagnostics:

```bash
ps -eZ | grep vault-device-coordinator || true
ps -eZ | grep vault-s3-proxy || true
```

The core baseline does not require a dedicated custom SELinux domain for those
native Go daemons and does not alert merely because one appears in
`unconfined_service_t`.

CRITICAL local hardening drift:

```text
either VPS is no longer SELinux Enforcing
coordinator no longer runs as vaultcoord
S3 proxy no longer runs as vaultproxy
coordinator gains read access to /etc/vault-ts-expiry
S3 proxy gains read access to /etc/vault-device/signing-key.pem
NoNewPrivileges or strict filesystem sandbox settings are weakened
a local Vault SELinux policy module appears without an explicitly approved extension/change record
RHEL content repositories disappear and security maintenance becomes blind
OCI shape architecture no longer matches the imported RHEL image/record
```

A legitimate RHEL/SELinux policy update may create AVCs for packaged services or
containers. Do not silence them by setting the host permissive, disabling SELinux, or
adding `label=disable`.

For the native coordinator/proxy, do not auto-generate and load a local policy with
`audit2allow`. The core response to a service problem is:

```text
verify DAC ownership and group membership
verify effective systemd unit settings
inspect the exact journal/error
verify packaged/container SELinux labeling when relevant
rerun the Vault negative matrix
```

A future expert-reviewed custom SELinux policy must be introduced as a documented
optional extension, not as an emergency troubleshooting command.

Record the current platform tuple in the operator evidence set:

```text
hostname
OCI shape
RHEL major/minor
architecture
custom image identifier/hash
SELinux mode
coordinator service user
coordinator effective systemd hardening baseline hash
proxy service user
proxy effective systemd hardening baseline hash
Tailscale package version
```

A RHEL 9 -> RHEL 10 migration or x86_64 <-> aarch64 shape migration is a planned
platform migration and must generate a new evidence tuple and hardening baseline.

## 2. MicroVM Intrusion Detection & Zero-Tolerance Authentication

> **Context**: The `rest-server` MicroVM utilizes an ephemeral `.htpasswd` injected dynamically via Firecracker MMDS on every boot. Because this credential is never typed by a human and is exclusively known to the automated Caddy proxy, any `401 Unauthorized` response is deterministically an active compromise attempt, not a typo. 

This zero-tolerance philosophy eliminates the need for classic "N failures in T seconds" (`fail2ban`) thresholds. The threshold is exactly 1. To enforce this, the detection plane operates across two independent layers:

### Layer 1: In-Guest Best-Effort (Fast Response)
The `rest-server` binary is wrapped in a monitoring loop that reads `stderr`. Upon detecting the first `401` or `Unauthorized` log, the wrapper:
1. Writes a `.SECURITY_ALERT_AUTHFAIL` timestamp file to the already-mounted `/data` block device.
2. Immediately executes `poweroff -f` to self-halt the MicroVM and kill any suspicious connections.

### Layer 2: Host-Side Absolute Truth (Slow but Guest-Independent)
> [!IMPORTANT]
> **Why Layer 2 is Mandatory:** The in-guest response (Layer 1) is fast, but it is fundamentally a "best-effort" defense. A deeply compromised guest could theoretically suppress its own logs, prevent the `poweroff`, or avoid writing the alert flag. 
> 
> Therefore, you **MUST NEVER bypass the Host-Side Layer**. It is slow, but it operates outside the guest's control boundary, making it the absolute "source of truth".

The Host-Side Layer relies on two out-of-band checks:
1. **Post-Mortem Flag Inspection**: When the Firecracker process terminates (either naturally, via crash, or via the in-guest halt), the host mounts the data block device and checks for the `.SECURITY_ALERT_AUTHFAIL` flag. If found, a full capacity alarm is raised.
2. **Out-of-Band Network Namespace Observation**: A host-side monitor (e.g., cron or systemd timer) periodically runs `ss -antp` inside the `vault-pc` network namespace to inspect active connections to port 8000. If the source IP does not match the Caddy MicroVM (e.g., `172.16.0.3`), the alarm is triggered immediately. This completely ignores what the guest reports and relies purely on host-level networking truths.
