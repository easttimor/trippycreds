import random
import uuid

# Deliberately mundane service-account-style names: a leaked canary key should
# look like routine automation, not an obvious trap, to whoever finds it.
PREFIXES = ("svc", "sys", "data", "app")
MIDDLES = (
    "billing", "export", "sync", "ingest", "report", "metrics", "audit",
    "pipeline", "backup", "analytics", "inventory", "usage", "events",
    "search", "notify",
)
SUFFIX_WORDS = (
    "worker", "sync", "job", "agent", "processor", "loader", "connector",
    "runner", "handler",
)


def generate_username() -> str:
    prefix = random.choice(PREFIXES)
    middle = random.choice(MIDDLES)
    suffix_word = random.choice(SUFFIX_WORDS)
    suffix_hex = uuid.uuid4().hex[:8]
    return f"{prefix}-{middle}-{suffix_word}-{suffix_hex}"
