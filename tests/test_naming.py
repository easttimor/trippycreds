import re

from trippycreds import naming

_USERNAME_RE = re.compile(
    r"^(" + "|".join(naming.PREFIXES) + r")-(" + "|".join(naming.MIDDLES) + r")-("
    + "|".join(naming.SUFFIX_WORDS) + r")-[0-9a-f]{8}$"
)


def test_generate_username_matches_expected_shape():
    for _ in range(50):
        username = naming.generate_username()
        assert _USERNAME_RE.match(username), username


def test_generate_username_varies():
    usernames = {naming.generate_username() for _ in range(50)}
    assert len(usernames) > 1
