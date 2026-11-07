import argparse
import sys

from trippycreds import actor as actor_module
from trippycreds import iam_lifecycle
from trippycreds.clients import Clients
from trippycreds.config import Config


def _caller_actor(clients: Clients) -> dict:
    """The CLI runs with the operator's own AWS profile - no Cognito session,
    so attribution comes from sts:GetCallerIdentity instead.
    """
    arn = clients.sts.get_caller_identity()["Arn"]
    return actor_module.from_aws_principal(arn)


def cmd_batch_create(args, clients: Clients) -> None:
    if args.count < 1 or args.count > 100:
        print("error: --count must be between 1 and 100", file=sys.stderr)
        raise SystemExit(1)
    try:
        created = iam_lifecycle.batch_create(clients, _caller_actor(clients), args.count)
    except iam_lifecycle.IamUserLimitReachedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"created {len(created)} canary user(s):")
    for item in created:
        print(f"  {item['iam_username']}  {item['access_key_id']}  status=unclaimed")
    print("secret key material is never printed here - it's only returned by `claim`.")


def cmd_claim(args, clients: Clients) -> None:
    try:
        item = iam_lifecycle.claim(
            clients,
            _caller_actor(clients),
            placement_description=args.placement_description,
            placed_by=args.placed_by,
            environment=args.environment,
        )
    except iam_lifecycle.NoUnclaimedCanariesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print("claimed canary - this is the only time the secret key is shown:")
    print(f"  iam_username:          {item['iam_username']}")
    print(f"  access_key_id:         {item['access_key_id']}")
    print(f"  secret_access_key:     {item['secret_access_key']}")
    print(f"  batch_id:              {item['batch_id']}")
    print(f"  placement_description: {item['placement_description']}")
    print(f"  placed_by:             {item['placed_by']}")
    print(f"  environment:           {item['environment']}")
    print(f"  claimed_by (actor):    {item['claimed_by']}")


def cmd_purge_unclaimed(args, clients: Clients) -> None:
    # Unlike the console/API (which goes through API Gateway's 30s cap and
    # purges in bounded batches), the CLI talks to AWS directly with no such
    # limit, so there's no need to default to a small batch here.
    items = iam_lifecycle.purge_unclaimed(
        clients, _caller_actor(clients), dry_run=not args.execute, limit=args.limit
    )
    verb = "would delete" if not args.execute else "deleted"
    print(f"{verb} {len(items)} unclaimed canary user(s):")
    for item in items:
        print(f"  {item['iam_username']}  {item['access_key_id']}")
    if not args.execute and items:
        print("\nre-run with --execute to actually delete these.")
    elif args.execute:
        print("\nIAM users are gone; their rows remain in DynamoDB with status=deleted.")
        remaining = len(iam_lifecycle.list_pool(clients, "unclaimed"))
        if remaining:
            print(f"{remaining} unclaimed canary user(s) still remain - run again to continue.")


def cmd_list_pool(args, clients: Clients) -> None:
    items = iam_lifecycle.list_pool(clients, args.status)
    print(f"{len(items)} canary user(s) with status={args.status}:")
    for item in items:
        extra = ""
        if args.status == "claimed":
            extra = (
                f"  placed_by={item.get('placed_by')}  placement={item.get('placement_description')}"
                f"  claimed_by={item.get('claimed_by')}"
            )
        elif args.status == "deleted":
            extra = f"  deleted_at={item.get('deleted_at')}  deleted_by={item.get('deleted_by')}"
        print(f"  {item['iam_username']}  {item['access_key_id']}{extra}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trippycreds", description="Manage AWS canary credentials.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    batch_create = subparsers.add_parser("batch-create", help="pre-provision N unclaimed canaries")
    batch_create.add_argument("--count", type=int, required=True)
    batch_create.set_defaults(handler=cmd_batch_create)

    claim = subparsers.add_parser("claim", help="claim any one unclaimed canary")
    claim.add_argument("--placement-description", required=True)
    claim.add_argument("--placed-by", required=True)
    claim.add_argument("--environment", required=True)
    claim.set_defaults(handler=cmd_claim)

    purge = subparsers.add_parser("purge-unclaimed", help="delete unclaimed canaries (dry-run by default)")
    purge.add_argument("--execute", action="store_true", help="actually delete, instead of just listing")
    purge.add_argument("--limit", type=int, default=10_000, help="max canaries to delete in this run")
    purge.set_defaults(handler=cmd_purge_unclaimed)

    list_pool = subparsers.add_parser("list-pool", help="list canaries by status")
    list_pool.add_argument("--status", choices=list(iam_lifecycle.VALID_STATUSES), default="unclaimed")
    list_pool.set_defaults(handler=cmd_list_pool)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    clients = Clients(config=Config.load())
    args.handler(args, clients)


if __name__ == "__main__":
    main()
