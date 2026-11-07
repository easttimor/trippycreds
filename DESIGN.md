# TrippyCreds — Design Spec

## Purpose

Generate, track, and detect use of disposable AWS IAM access keys deployed as canary
tokens (honeytokens) for strong attribution of credential leaks. Keys carry zero
permissions; any use at all is the signal. Future credential types (SSH keys, etc.)
are out of scope for v1 but the storage/audit model should not preclude them.

## Account

A dedicated AWS account inside the existing Organization. No other workloads live
here. Admin/operator access is via existing AWS Identity Center (SSO) roles — human
access to the account itself is out of scope for this spec (handled by your existing
Org access patterns); what this spec covers is the console/API this system exposes
on top of that account.

## Tagging strategy

Two distinct tags, both deliberately mundane-looking so they don't read as
"honeypot" to a casual console/tag viewer:

- `ManagedBy = platform-automation` — fixed key/value, applied to **every** canary
  IAM User and every "bait" S3 bucket. Exists purely so Service Control Policies and
  bucket/IAM policies can reference `aws:PrincipalTag/ManagedBy` /
  `aws:ResourceTag/ManagedBy` as a condition key. This is the mechanism for
  defense-in-depth restrictions independent of each user's own inline policy.
- `CostCenter = CC-0000 | CC-<batch-id>` — encodes claim status on canary IAM Users
  only. `CC-0000` means unclaimed/pool. Any other value is a batch identifier
  assigned at claim time. Looks like routine billing/tagging hygiene to anyone
  without the decoder; DynamoDB remains the authoritative, full-detail record —
  this tag exists only so a reconciliation job can diff live IAM state against
  DynamoDB without trusting DynamoDB alone.

No placement description, "what this was used to bait," or other sensitive
metadata ever goes into an IAM tag — that lives in DynamoDB only.

## IAM User & access key lifecycle

Treated as **ephemeral, not declarative** — managed by Python/boto3 tooling
(scripts + Lambda), never by Terraform. Terraform owns everything durable around
them (the table they're recorded in, the trail that watches them, the SCP that
restricts them).

**Naming convention**: plausible service-account style, e.g.
`svc-billing-sync-4f8a2c1e`, `data-export-worker-9b21c3`. Random suffix is a
hex/base32 chunk of a UUID4 — long enough to avoid collisions, no semantic meaning
encoded in the name itself (unlike the tags, which do carry meaning for your
tooling).

**Inline policy per user** (deny-all with one carve-out):
- `Deny *:*` as the baseline (explicit deny wins over everything, including any
  future SCP misconfiguration).
- Explicit `Allow sts:GetCallerIdentity` — lets a leaked-key finder's first,
  near-universal move ("is this key alive?") succeed, which keeps them engaged
  long enough to try more things. Every other call — including
  `iam:CreateAccessKey` on themselves — stays denied. This is important: if
  `CreateAccessKey` were ever allowed, a holder of the leaked key could mint a
  second key for themselves and you'd lose the one-key-one-identity attribution
  guarantee.

**One key per user, enforced structurally**: a user is created with exactly one
access key at provisioning time and the policy denies the user from ever creating
another. No rotation — a "retired" canary is deleted (user + key both), not
rotated. This also sidesteps AWS's secret-key-only-returned-once constraint neatly:
you only ever need to capture the secret at the single moment you create it.

**Batch pre-provisioning / pool model**: because AWS only returns an access key's
secret at `CreateAccessKey` time, "claiming" a key can't call that API on demand —
claiming has to allocate from a pool that was already created. Flow:

1. A batch-create job (Python, run on demand or via a scheduled Lambda) creates N
   IAM Users + access keys, tags each `ManagedBy=platform-automation`,
   `CostCenter=CC-0000`, attaches the deny-all inline policy, and writes a row per
   key to DynamoDB with `status = unclaimed` and no placement metadata yet.
2. `POST /claim` (API Gateway + Lambda, behind Cognito auth) picks **any** unclaimed
   row via a DynamoDB conditional update (`status = unclaimed` → `status = claimed`,
   fails/retries on contention — this is the concurrency-safety mechanism, no
   explicit locking needed), writes the caller-supplied metadata onto that row,
   updates the IAM User's `CostCenter` tag to the new batch id, and returns the key
   material (access key id + secret, read back from DynamoDB — never re-derived).
3. Callers never pick a specific key — "give me one" is the only verb.

**Bulk cleanup**: a purge tool (Python) deletes IAM Users in bulk, scoped to
`status = unclaimed` **only**, by default — so scaling the pool down (e.g. created
5000, decided you only want 1000) never touches a key that's live in the field. A
claimed/placed canary is only ever removed by deliberate, specific deletion.

Deletion is a soft delete at the DynamoDB layer: the IAM User and its access key
are torn down for real, but the row is updated to `status = deleted` (with
`deleted_at`, and `secret_access_key` scrubbed since the key behind it no longer
exists) rather than removed from the table. This keeps a permanent, queryable
record of every canary that ever existed — useful for audit and for explaining a
gap in attribution later ("was this access key ever ours?") — without retaining
secret material that's no longer live. The `status-index` GSI serves this the
same way it serves `unclaimed`/`claimed`.

**IAM's 5,000-user-per-account limit**: not a standard, requestable service
quota — it's a hard ceiling, and it counts every IAM User in the account, not
just canaries. `batch_create` checks `iam:GetAccountSummary` (`Users` vs.
`UsersQuota`) before creating any users, so a batch that would blow through the
limit fails fast with one clear error instead of dying partway through with no
record of how far it got; `create_canary` also catches `LimitExceeded` from
`CreateUser` itself as a fallback, in case headroom was consumed by a
concurrent batch between the check and the call. Both raise the same
`IamUserLimitReachedError`, surfaced as an HTTP 409 by the API and a
non-zero exit by the CLI.

## Storage: DynamoDB

Single table, on-demand billing (no capacity planning needed at this scale).

- PK: `access_key_id`
- Attributes: `iam_username`, `secret_access_key` (captured once, at creation;
  removed once deleted - see "Bulk cleanup" below),
  `status` (`unclaimed` | `claimed` | `deleted`), `batch_id`, `created_at`,
  `created_by`, `claimed_at`, `claimed_by`, `deleted_at`, `deleted_by`,
  `placement_description`, `placed_by`, `environment`/tag-of-your-choosing,
  `distinct_actions_seen` (string set, rolled up by the event pipeline),
  `last_triggered_at`, `trigger_count`. The `*_by` fields are a structured,
  server-derived `actor` (see "Attribution" below) - distinct from `placed_by`,
  which is caller-supplied free text, not a verified identity.
- GSI on `status` (to list unclaimed pool size, list all claimed canaries).
- A second collection/table for raw trigger events (one item per CloudTrail event
  matched to a canary): `access_key_id` (PK), `event_time` (SK), `event_name`,
  `source_ip`, `user_agent`, `error_code`, `aws_region`, raw event id. This is what
  the console renders as a per-canary timeline; `distinct_actions_seen` on the main
  item is a cheap rollup so the console doesn't have to scan the event collection
  just to show "which API actions has this key tried."

### Design decision: `status-index`'s partition key has low cardinality

`status` only ever takes 3 values (`unclaimed`/`claimed`/`deleted`), which means
every GSI read/write for a given status concentrates onto a single logical
partition - a textbook DynamoDB anti-pattern. This is a known, accepted
trade-off, not an oversight: at the scale this runs at (hundreds to low
thousands of canaries, bounded hard by IAM's 5,000-user-per-account ceiling
anyway), on-demand billing's adaptive capacity absorbs it fine, and the simpler
query shape (`list unclaimed`, `claim any unclaimed`) is worth more than the
headroom a sharded key would buy. Revisit (e.g. a calculated `status#<shard>`
key with writes spread across N shards and reads fanned out across all of
them) only if claim-contention or query throttling actually shows up in
practice - don't pre-optimize for a scale this system structurally can't reach.

## Attribution: the `actor` field

Every mutating action (`create_canary`/`batch_create`, `claim`, `purge_unclaimed`,
`trigger_test`) now records *who actually asked for it*, captured server-side -
stored as `created_by`, `claimed_by`, and `deleted_by` on the row (and returned,
not stored, as `triggered_by` for a test-trigger). This is deliberately separate
from `placed_by`, which stays free text the caller supplies about the
placement itself (e.g. a team name) and is never verified against anything.
For a system whose entire value proposition is attribution, trusting a
free-text field for "who did this" was a gap worth closing.

`actor` is a small, source-agnostic shape: `{"type": ..., "id": ..., "email": ...}`.
Two sources exist today, both built in `trippycreds/actor.py`:

- **Console (Lambda/API Gateway)**: `{"type": "cognito_user", "id": <sub>, "email": ...}`,
  read from the *verified* JWT claims API Gateway's Cognito authorizer attaches
  to `requestContext.authorizer.jwt.claims` - never from the request body, so a
  caller can't spoof who they are.
- **CLI**: `{"type": "aws_principal", "id": <arn>}`, from `sts:GetCallerIdentity`
  against whatever AWS profile the operator is running as - there's no Cognito
  session to read claims from.

This shape is intentionally not Cognito-specific: the plan is eventually to
expose a programmatic/API interface for scripted, non-interactive callers
(CI pipelines, other internal tooling) to do these same actions. Whatever
auth mechanism that ends up using (an API key, a service IAM role via SigV4,
etc.) should populate this same `actor` shape - e.g. `{"type": "api_key", "id": "<key-id>"}` -
rather than growing a parallel attribution field. `iam_lifecycle.py` and the
DynamoDB schema don't need to change at all when that lands; only
`trippycreds/actor.py` and whatever new entry point authenticates the caller do.

## Core infrastructure (Terraform)

Everything below is declarative, in the Terraform root for this account:

- **No dedicated CloudTrail trail — blocked, not just undesired.** The
  original plan was a trail in this account with data events scoped to the
  bait buckets' ARNs. In practice, this Org has a member-account SCP with a
  hard, unconditional `Deny` on `cloudtrail:CreateTrail` (the org already runs
  its own centralized trail elsewhere) — unlike its sibling statement
  restricting `s3:CreateBucket`, this one has no `aws:PrincipalTag` condition
  to tag our way around. So: no trail, which means no data-event detection for
  now. The demo/bait bucket stays in Terraform as a placeholder for whenever
  that becomes possible (an SCP exception, or getting our bait buckets added
  to the org's own trail by whoever manages it).
- **SNS topic**, email subscription(s) now, structured so a Slack subscriber
  (chatbot integration or a Lambda fan-out) can be added later without touching the
  publishing side.
- **DynamoDB table(s)** as above.
- **Detection pipeline, via EventBridge's direct CloudTrail integration** —
  the same free, trail-less mechanism that powers every account's 90-day
  CloudTrail Event History. An EventBridge rule matches `"AWS API Call via
  CloudTrail"` events where `userIdentity.type = IAMUser`, targeting a Lambda
  that receives the CloudTrail record directly (one record per invocation, no
  S3/gunzip step needed) and looks up `userIdentity.accessKeyId` in DynamoDB.
  Two real limitations, both accepted for now: **management events only**
  (data events were never part of this integration, trail or not), and
  **per-region** (an event lands on the bus in the region the call happened
  in; global-service calls like `sts:GetCallerIdentity` always record as
  `us-east-1`, so the single rule there catches our main recon signal, but a
  canary key's denied attempts against a regional service in another region
  wouldn't be caught without replicating the rule into every region). On a
  match: records the raw event, updates the distinct-actions rollup, and
  publishes to SNS.
- **Cognito user pool** — auth for the console and the API. No users provisioned
  yet; you'll enroll people after deploy.
- **CloudFront distribution** fronting an S3-origin SPA (the console
  frontend), served publicly with no edge-level auth. Decided against a
  Lambda@Edge authorizer: it only deploys from `us-east-1`, can't use
  environment variables, and is slow to iterate on — not worth it for a
  static bundle that contains no secrets or data. The SPA is simply inert
  without a valid Cognito session, because every real API call is gated by
  API Gateway's native Cognito authorizer instead.
- **API Gateway + Lambda** backend for the console (list canaries, claim, view
  audit trail, batch-create, purge). Uses API Gateway's **native Cognito User
  Pool authorizer** — no custom Lambda authorizer needed anywhere in this
  path.

Lambda handlers (event-pipeline consumer, API backend) are Python, built from
the same source tree as the ephemeral IAM lifecycle tooling.

## Defense in depth — Service Control Policy (flagged, not yet scoped)

An Org-level SCP restricting any principal tagged `ManagedBy=platform-automation`
to essentially nothing, enforced above IAM, would be a strong backstop against a
future misconfigured inline policy. This requires editing SCPs at the Organization
(management account or delegated admin) — different credentials/scope than the
rest of this Terraform, which only touches the dedicated member account. Proposing
this as a phase-2 item in a separate, small Terraform root once you confirm you
want it and have decided where that root runs from.

## Defense in depth — protecting the DynamoDB tables directly (flagged, needs research)

The SCP above restricts canary *IAM principals*. It does nothing to restrict
who/what can read `canary-keys` directly - and that table holds every live
canary's plaintext `secret_access_key` plus the full placement/attribution
record. Today it's protected only by each Lambda role's own IAM policy
(tag-scoped, least-privilege - see `lambda_api_backend.tf`/`lambda_event_consumer.tf`)
and by nobody else in this account having a reason to touch it. That's
identity-side protection; there's no resource-side backstop if some other
principal in the account (a future broader role, a compromised admin session)
ends up with DynamoDB permissions it shouldn't.

Two ways to add one, both worth evaluating rather than committing to yet:

- **A resource-based policy on the table itself** (AWS added these for
  DynamoDB fairly recently) - explicitly deny every principal except the two
  Lambda roles and the Terraform deploy principal, so it holds even if some
  other role in the account is accidentally over-permissioned.
- **An Organizations-level Resource Control Policy (RCP)** - conceptually the
  resource-side analog of the SCP above, enforced above IAM and (unlike a
  resource policy you manage yourself) binding even against this account's
  own admin/root. Whether RCPs currently cover DynamoDB needs checking against
  current AWS docs before planning around it - unconfirmed as of this
  writing, and likely to change as AWS has been expanding RCP service
  coverage.

Either way, this needs the same Org-management-account access problem flagged
for the SCP above (see "Resolved: SCP timing and scope") if the RCP route is
the one taken.

## Repo layout (proposed)

```
trippycreds/
  terraform/           # core infra: cloudtrail, sns, dynamodb, cognito,
                        # cloudfront+s3, api gateway, eventbridge rule
  lambdas/              # python handlers: event-pipeline consumer, api backend
                        # (built/zipped, referenced by terraform)
  tooling/              # python: batch-create pool, purge unclaimed, any CLI helpers
  console/              # SPA frontend source, built output uploaded to the S3 origin
```

## Resolved: SCP timing and scope

SCP deferred to a later phase. All Terraform and tooling built now targets only
the dedicated member account, using a principal that lives in that account — it
has no Org-management-account access and won't be used to write the SCP. That
work happens later, from the management account, with different credentials
entirely.

## Backlog

- **Per-claim notification subscriptions.** Right now every claimer shares the
  single SNS topic/subscription list, so everyone gets alerted on every
  canary's trigger. Let the claim form optionally subscribe just the claimer
  (or a address they specify) to triggers on *their* canary only — likely an
  SNS filter policy keyed on an attribute set at claim time (e.g.
  `placed_by`), or a per-claim topic/subscription created on demand.
- **Honeypot resources with broader-than-today permissions, contained by
  SCP.** Considering adding actual bait resources (e.g. S3 buckets) and
  widening a canary's own inline policy beyond `sts:GetCallerIdentity` to
  allow a few more reconnaissance-shaped calls (`s3:ListBuckets` and
  similar) — right now the deny-all policy cuts the interaction off after
  one call, so there's no visibility into what a holder would try next.
  The containment has to move up a layer for this to be safe: the
  account-level SCP (see "Defense in depth" above) would need to be the
  thing holding the line, scoped so none of the added permissions can
  ever reach outside this dedicated account, rather than relying on each
  inline policy alone. Gives real insight into post-compromise behavior
  instead of just "was this key used at all."
- **TODO: no CloudWatch alarm on the `api_backend` Lambda.** `monitoring.tf`
  alarms on the `event_consumer` Lambda's errors and its DLQ depth, but
  nothing watches the console/API Lambda - if claim/batch-create/purge start
  erroring, nobody gets paged. Add an `Errors` alarm (and probably `Throttles`,
  given the API Gateway 30s integration cap) mirroring the existing
  `event_consumer_errors` alarm.
- **TODO: Terraform state is local-only.** No S3+DynamoDB (or Terraform Cloud)
  backend configured - `terraform/terraform.tfstate` lives only on whoever's
  machine last ran `apply`, gitignored, with no locking and no durability
  beyond the local `.backup` file. Fine solo; blocks a second operator ever
  running `apply` safely, and risks losing state entirely if that machine's
  disk doesn't make it. Migrate to a remote backend before more than one
  person touches this.
