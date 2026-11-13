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
  IAM User and every "bait" S3 bucket, and (via Terraform's provider-level
  `default_tags`) also to this account's own infrastructure principals, e.g. the
  two Lambda execution roles in `lambda_api_backend.tf`/`lambda_event_consumer.tf`.
  That overlap turned out to matter: this is also the tag/value the *Org's own*
  existing central SCP keys its `s3:CreateBucket` exception on, which is almost
  certainly why this value was picked in the first place. Originally documented
  here as the mechanism for the canary-lockdown SCP below - it isn't anymore (see
  that section for why), precisely because it's shared with non-canary principals.
  Left in place for the Org-SCP carve-out it already serves; don't repurpose it as
  a condition key for anything that must match canary IAM Users *only*.
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

## Cross-account service claims

Lets an explicitly trusted AWS principal - e.g. a build server's CodeBuild
service role, in a different account entirely - claim a canary directly
through an API, with no operator in the loop. The motivating case: a CI
pipeline that should inject a fresh canary into every host or config bundle
it provisions, without a human running `claim` by hand each time.

**Two separate authorization layers, deliberately.** AWS proves *who signed
the request*; DynamoDB decides *whether that identity is allowed to do
anything*. Concretely:

- **AWS layer**: the request is SigV4-signed by the caller's own IAM
  credentials and hits a dedicated API endpoint with `AWS_IAM` authorization.
  API Gateway verifies the signature and attaches the caller's ARN to the
  request before it ever reaches application code - a caller can't spoof
  this any more than a Cognito user can spoof their JWT claims.
- **Application layer**: that verified ARN is looked up in a
  `trusted-principals` DynamoDB table
  (`trippycreds/trusted_principals.py`). No row, a disabled row, or an
  environment mismatch all mean "no" - identical in spirit to the rest of
  this system's philosophy (AWS enforces identity, DynamoDB is the
  authoritative record of who's allowed to do what with it).

Registering a new trusted build server is a DynamoDB write (via the
console's "Trusted principals" panel, or `register-principal`/
`list-principals`/`disable-principal` on the CLI) - never a Terraform apply
and never an IAM trust-policy edit. That's the whole point: onboarding a
new caller shouldn't require redeploying infrastructure.

### What the trusted role itself needs - and what it doesn't

Easy thing to get backwards: **this is not an `sts:AssumeRole` trust
relationship.** The trusted build server's role is never assumed *into* the
trippycreds account, and trippycreds never gets a trust-policy edit for a
new caller - that alternative was considered and rejected (see below). The
role keeps its own identity, in its own account, and simply signs a request
with it.

That means the only AWS-side permission the trusted role needs is one
`execute-api:Invoke` statement, scoped to the one resource it's allowed to
call:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "execute-api:Invoke",
    "Resource": "arn:aws:execute-api:<region>:<trippycreds-account-id>:<service-api-id>/prod/POST/service/claim"
  }]
}
```

(`<service-api-id>` is `terraform output -raw` on the `aws_api_gateway_rest_api.service` resource, or just read off `service_claim_api_url`.) No DynamoDB, Lambda, or S3 permissions, and nothing scoped to resources in the trippycreds account beyond that one API route - the role never touches trippycreds' AWS resources directly. The Lambda behind the API does all the real work, running under *its own* role; the caller's role only has to get a SigV4-signed HTTP request there.

The caller's role also needs a trust policy of its own, but that's about who/what is allowed to assume *that* role in *its own* account (an EC2 instance profile, a CI job, an operator testing by hand) - ordinary same-account IAM, unrelated to trippycreds.

Putting it together, onboarding a new trusted caller is two independent, unrelated actions in two different places:

1. **In the caller's account**: attach the `execute-api:Invoke` policy above to whatever role will do the signing.
2. **In the trippycreds account**: `register-principal --arn <that role's ARN> --label ... [--environment ...]`.

Neither one touches the other account's IAM, and neither is a Terraform apply.

### Why this needs a second, separate API Gateway

The console's existing API (`api_gateway.tf`) is an HTTP API
(`aws_apigatewayv2_api`) with a Cognito JWT authorizer. The natural-looking
alternative - add an `AWS_IAM`-authorized route to that same API - doesn't
work: **HTTP APIs don't support resource policies at all.** Resource
policies are the only mechanism that permits a *cross-account* `AWS_IAM`
caller to invoke anything; without one, a correctly-SigV4-signed request
from another account is still denied before it reaches the "is this ARN
trusted" check. That's a REST-API-only (`aws_api_gateway_rest_api`, "v1")
feature.

So `terraform/rest_api_service.tf` stands up one small, separate REST API
carrying only `POST /service/claim`, with a resource policy of
`Principal: "*"` - intentionally wide open on *who may attempt to invoke*,
because the real gate is the DynamoDB lookup described above, not this
policy. The console's HTTP API is untouched; `lambdas/api_backend/handler.py`
dispatches both APIs' events through the same function, reconstructing a
`"METHOD /path"` route key for the REST API's older (v1) proxy event shape
so the two authorizer types share one dispatch table.

Considered and rejected: a cross-account `sts:AssumeRole` trust instead of
`AWS_IAM` + a resource policy. Trust policies are static IAM resources -
"register an ARN via the console" would then require a Terraform apply per
onboarded principal, defeating the actual requirement.

### The assumed-role ARN normalization gotcha

Almost every real caller here is already role-based (an EC2 instance
profile, an ECS task role, a CodeBuild service role, a cross-account
`AssumeRole`), and API Gateway hands such a caller's identity to us in STS's
"assumed-role" form: `arn:aws:sts::<account>:assumed-role/<role-name>/<session-name>`.
That is *not* the IAM role ARN
(`arn:aws:iam::<account>:role/<role-name>`) an operator would naturally
register, and the session-name suffix is caller-controlled and varies per
call - matching on the raw ARN would never hit. `normalize_principal_arn()`
collapses the STS form back to the bare role ARN on every registry write and
every authorization check, so one registration covers every session that
role ever assumes.

### Scope, deliberately narrow for now

The service API exposes `claim` only - not `batch-create`, `list`, or
`purge-unclaimed`. A registered principal can also be scoped to a single
`environment` value at registration time, so a build server can be
restricted to claiming only for the one environment it actually provisions,
rather than any canary in the pool. Widening the action set, if a real use
case needs it (e.g. a service that also wants to batch-create its own
canaries), is an `allowed_actions` change away - the registry schema already
supports a list of actions per principal, only `handler.py`'s
`_handle_service_claim` enforces `"claim"` specifically today.

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

## Defense in depth — Service Control Policy (applied)

The inline per-user policy (`Deny *:*` plus `Allow sts:GetCallerIdentity`) is the
first line of defense, but it's identity-side only: it holds only as long as
nobody *also* attaches a second, broader policy to a canary user. An SCP backstop
makes that guarantee hold even against a fully compromised account that tries to
do exactly that - SCP effective permissions are the intersection of the identity
policy and the SCP, so an explicit SCP `Deny` wins even over `AdministratorAccess`
attached directly to the user.

**Targeting, and why not the `ManagedBy` tag.** The original idea (see "Tagging
strategy" above) was to key this off `aws:PrincipalTag/ManagedBy=platform-automation`.
Rejected: that tag/value is also stamped onto this account's own Lambda execution
roles (via Terraform's `default_tags`) and is already load-bearing for an
unrelated Org-level SCP carve-out - reusing it here would both break the Lambdas
and risk colliding with that existing exception.

Landed on `aws:PrincipalType` instead, which sidesteps tags entirely. This account
is dedicated to trippycreds and has no other workloads (see "Account" above);
every human/operator path goes through Identity Center (SSO) roles, and both
Lambda roles are, naturally, roles - so **every IAM User this account will ever
have *is* a canary**, structurally, with no tag needed to tell them apart.
`aws:PrincipalType` resolves to `"User"` only for IAM Users (long-lived
access-key credentials) - distinct from `"AssumedRole"` (SSO sessions, both
Lambda roles) and `"Account"` (root) - so it can't be stripped or forged by
whoever's holding a set of canary credentials, unlike a tag.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllIamUsersUselessEvenIfGrantedAdmin",
      "Effect": "Deny",
      "NotAction": "sts:GetCallerIdentity",
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:PrincipalType": "User" }
      }
    }
  ]
}
```

**Applied directly to the trippycreds member account** (not the Org root or an
OU) - the narrowest possible blast radius for a first rollout, consistent with
AWS's own guidance to test org policies at the account level before promoting
them higher. Attached manually via the Org management account's console/CLI,
same as the DynamoDB RCP above; not yet Terraform-codified (same
management-account-credentials gap noted in "Resolved: SCP timing and scope"
below). Revisit promoting it to the OU/root level only if there's ever a second
account that should carry the same guarantee.

**SCP syntax note**: unlike the RCP above, SCPs have no `Principal` element at
all (it's on the SCP "unsupported elements" list - the opposite situation from
RCPs, where `Principal: "*"` is mandatory). `NotAction` is supported in SCPs,
which is what this statement relies on.

## Defense in depth — protecting the DynamoDB tables directly (RCP, applied)

The SCP above (once written) only restricts canary *IAM principals*. It does
nothing to restrict who/what can read `canary-keys` directly - and that table
holds every live canary's plaintext `secret_access_key` plus the full
placement/attribution record. Identity-side protection (each Lambda role's own
tag-scoped IAM policy - see `lambda_api_backend.tf`/`lambda_event_consumer.tf`)
was the only thing guarding it; there was no resource-side backstop if some
other principal in the account (a future broader role, a compromised admin
session) ended up with DynamoDB permissions it shouldn't.

**Resolved**: DynamoDB is on AWS's RCP-supported-services list (confirmed
against the
[official list](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services)
as of Nov 2026 - that list has grown several times since RCPs launched, so
re-check it before assuming a service not named here is covered). An RCP is
the resource-side analog of the SCP above: enforced above IAM, and - unlike a
resource policy you manage yourself - binding even against this account's own
admin/root. Applied manually in the Org management account (not yet
Terraform-codified - same access gap flagged in "Resolved: SCP timing and
scope" below):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceOrgPerimeterDynamoDB",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "dynamodb:*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "<org-id>" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
```

This denies `dynamodb:*` account-wide unless the caller is in our own Org (or
is an AWS service acting on our behalf) - a no-op for the Lambda roles
(same-account, same-org) and for Terraform's deploy principal. It only
actually bites if a resource-based policy is ever attached to one of these
tables granting read access to an external account - e.g. to exfiltrate the
canary registry.

**RCP syntax gotcha, learned the hard way**: RCPs look like SCPs but aren't
the same grammar. The first attempt at this policy came back
`MalformedPolicyDocumentException` ("the provided policy document does not
meet the requirements of the specified policy type") purely because it was
missing `Principal`. Unlike an SCP (which has no `Principal` element at all -
it implicitly covers every principal in the attached account/OU), every RCP
statement **must** include `"Principal": "*"` - you narrow *who* via
`Condition`, never via `Principal` itself. RCPs also don't support
`NotPrincipal` or `NotAction` at all (SCPs support both) - worth remembering
before copy-pasting a statement between policy types, which is exactly how the
first draft here went wrong.

**Not covered by this (or any) RCP**: the cross-account service-claim API's
`Principal: "*"` resource policy (`rest_api_service.tf`, see "Cross-account
service claims" above). `execute-api` is not on the RCP-supported-services
list, so an Org-wide identity perimeter for that endpoint can't be done this
way - it has to be enforced in the API Gateway resource policy itself, with an
`aws:PrincipalOrgID` condition added to the existing `Allow
execute-api:Invoke` statement. Not yet done; tracked in Backlog below.

Added as a complementary, independent layer underneath this RCP: a
resource-based policy on each DynamoDB table itself. See "Resolved:
per-table DynamoDB resource-based policies" below.

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

SCP is written and attached (see "Defense in depth — Service Control Policy"
above) - this is no longer deferred. All Terraform and tooling in this repo still
targets only the dedicated member account, using a principal that lives in that
account; it has no Org-management-account access and was never used to write the
SCP. That part of the original plan held: the SCP was authored and attached
separately, by hand, from the Org management account with different credentials
entirely - not yet Terraform-codified anywhere.

## Resolved: per-table DynamoDB resource-based policies

The Org-level RCP above (see "Defense in depth — protecting the DynamoDB
tables directly") only restricts principals *outside* this Org. It does
nothing about a same-org principal - an over-permissioned role, a
compromised admin session - reading `canary-keys`, `canary-events` or
`trusted-principals` directly via an ordinary identity policy; identity and
resource policies are combined with OR (an Allow from either side grants
access) unless a policy carries an explicit Deny, and there was no
resource-based policy on the tables themselves to provide one.

Resolved in `terraform/dynamodb_resource_policy.tf`: each of the three
tables now gets its own `aws_dynamodb_resource_policy` - a single `Deny
dynamodb:*` statement, scoped via `Condition: StringNotLike
aws:PrincipalArn` to everyone *except* that table's expected principals
(the Lambda roles that already have narrow, resource-scoped identity
policies for it - see `lambda_api_backend.tf`/`lambda_event_consumer.tf`/
`lambda_reconciler.tf` - plus `trippycreds-deploy` for Terraform and the
CLI). `trusted-principals` is included too, even though the RCP writeup
above only named the other two - a role that could write there could
register itself as a trusted cross-account claimant, which is its own kind
of sensitive.

Two deliberate choices worth flagging:
- **`aws:PrincipalArn` + `StringNotLike`, not `NotPrincipal` with literal
  role ARNs.** `NotPrincipal` resolves role ARNs to their internal unique ID
  at policy-save time, so a role deleted and recreated under the same
  name/ARN would silently fall out of the allow-list. `aws:PrincipalArn` is
  a live string match, so it keeps working across role recreation.
- **`trippycreds-admin` (the human AdministratorAccess SSO role) is not
  allow-listed - only `trippycreds-deploy` is.** Operator/CLI access per the
  "Account" section above is expected to go through SSO roles in general,
  but any direct DynamoDB access now has to go through the narrower deploy
  role specifically (already the CLI's default profile - see
  `trippycreds/config.py`), not raw admin. This also sidesteps hardcoding
  Identity Center's auto-generated permission-set role ARN suffix, which
  isn't stable to begin with.

Caveat this layer doesn't remove: unlike the RCP (enforced above IAM,
binding even against this account's own admin/root), a table's own resource
policy is something this account's admin can edit or delete at will. It
narrows the blast radius of an over-permissioned *ordinary* role; it is not
a hard backstop against a fully compromised admin session the way the RCP
is.

## Backlog

- **TODO: add an `aws:PrincipalOrgID` condition to the service-claim API's
  resource policy** (`rest_api_service.tf`'s `service_api_resource_policy`) -
  the Org-identity-perimeter equivalent of the DynamoDB RCP in "Defense in
  depth — protecting the DynamoDB tables directly" above, needed because
  `execute-api` isn't RCP-supported and so can't be enforced at the Org level
  the way DynamoDB now is.
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
