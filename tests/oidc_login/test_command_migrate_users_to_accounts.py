"""Tests for the migrate_users_to_accounts management command."""

import base64
import json
from datetime import timedelta
from io import StringIO

import pytest
import responses
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.utils import timezone

from lasuite.oidc_login.management.commands.migrate_users_to_accounts import Command
from tests.factories import UserFactory

User = get_user_model()

ENDPOINT = "https://accounts.test/api/v1.0/o/users-import/"
LOGGER = "lasuite.oidc_login.management.commands.migrate_users_to_accounts"

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def accounts_settings(settings):
    """Configure the users import endpoint of accounts."""
    settings.OIDC_OP_USERS_IMPORT_ENDPOINT = ENDPOINT


def mock_users_import(known_subs):
    """
    Mock the users import endpoint of accounts.

    `known_subs` tells what accounts answers for each sub, e.g.
    `{"proconnect-sub": ("identity_provider", "accounts-known")}`: the user of
    `proconnect-sub` gets the status `identity_provider` and the accounts sub
    `accounts-known`. Any other sub is unknown to accounts, so it is created.

    The payloads sent by the command are kept in `callback.payloads`.
    """
    payloads = []

    def callback(request):
        payload = json.loads(request.body)
        payloads.append(payload)
        results = []
        for row in payload["users"]:
            if row["sub"] in known_subs:
                status, accounts_sub = known_subs[row["sub"]]
            elif payload["dry_run"]:
                # Would be created, but a dry run creates nothing.
                status, accounts_sub = "to_create", None
            else:
                status, accounts_sub = "created", f"accounts-{row['sub']}"
            results.append({"pk": row["pk"], "sub": row["sub"], "status": status, "accounts_sub": accounts_sub})
        return 200, {}, json.dumps({"counts": {}, "results": results})

    callback.payloads = payloads
    return callback


def run_command(*args, command="migrate_users_to_accounts"):
    """Run the command, return its standard output."""
    stdout = StringIO()
    call_command(command, *args, stdout=stdout)
    return stdout.getvalue()


def warnings(caplog):
    """Return the warnings logged by the command."""
    return [record.getMessage() for record in caplog.records if record.name == LOGGER and record.levelname == "WARNING"]


@responses.activate
def test_migrate_users_to_accounts(settings, caplog):
    """The users get the accounts sub of their identity provider's sub."""
    settings.OIDC_RP_CLIENT_ID = "product"
    settings.OIDC_RP_CLIENT_SECRET = "secret"  # noqa: S105

    # Create some users to migrate.
    already = UserFactory(sub="accounts-sub")
    known = UserFactory(sub="proconnect-sub")
    unknown = UserFactory(sub="unknown-sub")
    # Mock the answers of accounts: `accounts-sub` already is an accounts sub, `proconnect-sub` is the
    # ProConnect sub of the accounts user `accounts-known`, and `unknown-sub` is unknown
    # to accounts, so it is created as `accounts-unknown-sub`.
    callback = mock_users_import(
        {
            "accounts-sub": ("accounts", "accounts-sub"),
            "proconnect-sub": ("identity_provider", "accounts-known"),
        }
    )
    # The command posts to accounts: answer with the callback instead of the network.
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    stdout = run_command()

    assert (
        responses.calls[0].request.headers["Authorization"] == f"Basic {base64.b64encode(b'product:secret').decode()}"
    )
    assert callback.payloads == [
        {
            "users": [
                {"pk": str(already.pk), "sub": "accounts-sub", "email": already.email},
                {"pk": str(known.pk), "sub": "proconnect-sub", "email": known.email},
                {"pk": str(unknown.pk), "sub": "unknown-sub", "email": unknown.email},
            ],
            "dry_run": False,
        }
    ]
    assert responses.calls[0].response.json() == {
        "counts": {},
        "results": [
            {"pk": str(already.pk), "sub": "accounts-sub", "status": "accounts", "accounts_sub": "accounts-sub"},
            {
                "pk": str(known.pk),
                "sub": "proconnect-sub",
                "status": "identity_provider",
                "accounts_sub": "accounts-known",
            },
            {"pk": str(unknown.pk), "sub": "unknown-sub", "status": "created", "accounts_sub": "accounts-unknown-sub"},
        ],
    }
    assert dict(User.objects.values_list("pk", "sub")) == {
        already.pk: "accounts-sub",
        known.pk: "accounts-known",
        unknown.pk: "accounts-unknown-sub",
    }
    assert "{'accounts': 1, 'created': 1, 'identity_provider': 1, 'updated': 2}" in stdout
    assert warnings(caplog) == []


@responses.activate
def test_migrate_users_to_accounts_batches():
    """The users are sent by batches, ordered by creation date then by primary key."""
    UserFactory.create_batch(5)
    # UUID primary keys are random: the expected order is the one of the command.
    users = list(User.objects.order_by("created_at", "pk"))
    callback = mock_users_import({})
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    stdout = run_command("--batch-size", "2")

    assert [[row["pk"] for row in payload["users"]] for payload in callback.payloads] == [
        [str(users[0].pk), str(users[1].pk)],
        [str(users[2].pk), str(users[3].pk)],
        [str(users[4].pk)],
    ]
    assert "5 users processed" in stdout
    # Every batch is stored
    assert set(User.objects.values_list("sub", flat=True)) == {f"accounts-{user.sub}" for user in users}


@responses.activate
def test_migrate_users_to_accounts_batches_same_creation_date():
    """The users created at the same time are ordered by primary key, none is skipped nor sent twice."""
    newest, oldest, *same = UserFactory.create_batch(5)
    now = timezone.now()
    User.objects.filter(pk=newest.pk).update(created_at=now)
    User.objects.filter(pk=oldest.pk).update(created_at=now - timedelta(days=2))
    # Created at the same time, across the boundary of two batches.
    User.objects.filter(pk__in=[user.pk for user in same]).update(created_at=now - timedelta(days=1))
    # UUID primary keys are random: order the users of the same date by primary key.
    same_1, same_2, same_3 = sorted(same, key=lambda user: user.pk)
    callback = mock_users_import({})
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    run_command("--batch-size", "2")

    assert [[row["pk"] for row in payload["users"]] for payload in callback.payloads] == [
        [str(oldest.pk), str(same_1.pk)],
        [str(same_2.pk), str(same_3.pk)],
        [str(newest.pk)],
    ]


@responses.activate
def test_migrate_users_to_accounts_skips_users_without_sub():
    """The users without sub are not sent."""
    user_without_sub = UserFactory(sub=None)
    user_empty_sub = UserFactory(sub="")
    user_none_email = UserFactory(email=None)
    callback = mock_users_import({})
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    run_command()

    assert callback.payloads[0]["users"] == [
        {"pk": str(user_none_email.pk), "sub": user_none_email.sub, "email": ""},
    ]
    # Only users with sub are sent and updated, the others are not.
    user_none_email.refresh_from_db()
    assert user_none_email.sub
    assert user_none_email.email is None
    user_empty_sub.refresh_from_db()
    assert user_empty_sub.sub == ""
    user_without_sub.refresh_from_db()
    assert user_without_sub.sub is None


@responses.activate
def test_migrate_users_to_accounts_skips_staff_users():
    """Staff users are not sent."""
    regular_user = UserFactory()
    UserFactory(is_staff=True)

    callback = mock_users_import({})
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    run_command()

    assert callback.payloads[0]["users"] == [
        {"pk": str(regular_user.pk), "sub": regular_user.sub, "email": regular_user.email},
    ]


@responses.activate
def test_migrate_users_to_accounts_duplicates(caplog):
    """A user whose accounts sub belongs to another user is logged and left unchanged."""
    holder = UserFactory(sub="accounts-sub")
    duplicate = UserFactory(sub="proconnect-sub")
    first = UserFactory(sub="first-sub")
    second = UserFactory(sub="second-sub")
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "accounts-sub": ("accounts", "accounts-sub"),
                "proconnect-sub": ("identity_provider", "accounts-sub"),
                "first-sub": ("identity_provider", "accounts-shared"),
                "second-sub": ("identity_provider", "accounts-shared"),
            }
        ),
    )

    stdout = run_command()

    assert dict(User.objects.values_list("pk", "sub")) == {
        holder.pk: "accounts-sub",
        duplicate.pk: "proconnect-sub",
        first.pk: "accounts-shared",
        second.pk: "second-sub",
    }
    assert warnings(caplog) == [
        f"User {duplicate.pk}: duplicate of user {holder.pk}",
        f"User {second.pk}: duplicate of user {first.pk}",
    ]
    assert "'duplicate': 2" in stdout
    assert "'updated': 1" in stdout


@pytest.mark.parametrize("dry_run", [False, True])
@responses.activate
def test_migrate_users_to_accounts_duplicates_across_batches(dry_run, caplog):
    """The duplicates are logged whatever their batches, in a dry run too."""
    duplicate = UserFactory(sub="proconnect-sub")
    holder = UserFactory(sub="accounts-sub")
    first = UserFactory(sub="first-sub")
    second = UserFactory(sub="second-sub")
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "proconnect-sub": ("identity_provider", "accounts-sub"),
                "accounts-sub": ("accounts", "accounts-sub"),
                "first-sub": ("identity_provider", "accounts-shared"),
                "second-sub": ("identity_provider", "accounts-shared"),
            }
        ),
    )

    stdout = run_command("--batch-size", "1", *(["--dry-run"] if dry_run else []))

    assert len(responses.calls) == 4
    assert warnings(caplog) == [
        f"User {duplicate.pk}: duplicate of user {holder.pk}",
        f"User {second.pk}: duplicate of user {first.pk}",
    ]
    assert "'duplicate': 2" in stdout
    assert f"'{'to_update' if dry_run else 'updated'}': 1" in stdout
    assert User.objects.get(pk=first.pk).sub == ("first-sub" if dry_run else "accounts-shared")
    assert User.objects.get(pk=second.pk).sub == "second-sub"


@responses.activate
def test_migrate_users_to_accounts_logs_unmatched_users(caplog):
    """The users accounts could not match nor create are logged and left unchanged."""
    conflict = UserFactory(sub="conflict-sub")
    invalid = UserFactory(sub="invalid-sub")
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "conflict-sub": ("email_conflict", None),
                "invalid-sub": ("invalid", None),
            }
        ),
    )

    run_command()

    assert set(User.objects.values_list("sub", flat=True)) == {"conflict-sub", "invalid-sub"}
    assert warnings(caplog) == [f"User {conflict.pk}: email_conflict", f"User {invalid.pk}: invalid"]


@responses.activate
def test_migrate_users_to_accounts_dry_run():
    """A dry run asks accounts for a dry run and updates nothing."""
    UserFactory(sub="proconnect-sub")
    UserFactory(sub="unknown-sub")
    callback = mock_users_import({"proconnect-sub": ("identity_provider", "accounts-known")})
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    stdout = run_command("--dry-run")

    assert callback.payloads[0]["dry_run"] is True
    assert set(User.objects.values_list("sub", flat=True)) == {"proconnect-sub", "unknown-sub"}
    assert "Dry run: {'identity_provider': 1, 'to_create': 1, 'to_update': 1}" in stdout


@responses.activate
def test_migrate_users_to_accounts_retries_conflicts():
    """A conflict with a concurrent import is retried."""
    user = UserFactory(sub="unknown-sub")
    responses.add(responses.POST, ENDPOINT, status=409, json={"error": "conflict"})
    responses.add_callback(responses.POST, ENDPOINT, callback=mock_users_import({}))

    run_command()

    assert len(responses.calls) == 2
    user.refresh_from_db()
    assert user.sub == "accounts-unknown-sub"


@responses.activate
def test_migrate_users_to_accounts_stops_on_errors():
    """An error of accounts stops the command, the previous batches are kept."""
    first = UserFactory(sub="first-sub")
    second = UserFactory(sub="second-sub")
    responses.add_callback(responses.POST, ENDPOINT, callback=mock_users_import({}))
    responses.add(responses.POST, ENDPOINT, status=403, json={"error": "unauthorized_client"})

    with pytest.raises(CommandError, match="403"):
        run_command("--batch-size", "1")

    first.refresh_from_db()
    second.refresh_from_db()
    assert first.sub == "accounts-first-sub"
    assert second.sub == "second-sub"


@responses.activate
def test_migrate_users_to_accounts_no_users():
    """Without users, accounts is not called."""
    stdout = run_command()

    assert len(responses.calls) == 0
    assert "Done: {}" in stdout


@responses.activate
def test_migrate_users_to_accounts_custom_users_and_update():
    """A subclass may select the users to send and store more than their sub."""

    class CustomCommand(Command):
        def get_users_queryset(self):
            return super().get_users_queryset().exclude(name="skipped")

        def update_users(self, users):
            for user in users:
                user.name = "migrated"
            self.user_model.objects.bulk_update(users, ["sub", "name"])

    skipped = UserFactory(sub="skipped-sub", name="skipped")
    user = UserFactory(sub="proconnect-sub")
    # No known sub: accounts creates `proconnect-sub` as `accounts-proconnect-sub`.
    callback = mock_users_import({})
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    run_command(command=CustomCommand())

    assert [row["pk"] for row in callback.payloads[0]["users"]] == [str(user.pk)]
    assert User.objects.values_list("sub", "name").get(pk=user.pk) == ("accounts-proconnect-sub", "migrated")
    assert User.objects.values_list("sub", "name").get(pk=skipped.pk) == ("skipped-sub", "skipped")


@pytest.mark.parametrize("dry_run", [False, True])
@responses.activate
def test_migrate_users_to_accounts_custom_duplicate(dry_run, caplog):
    """A subclass may merge a duplicate, which then gets the accounts sub, never in a dry run."""
    handled = []

    class CustomCommand(Command):
        def handle_duplicate(self, user, holder):
            handled.append((user.pk, holder.pk, holder.sub))
            holder.delete()
            return True

    holder = UserFactory(sub="accounts-sub")
    duplicate = UserFactory(sub="proconnect-sub")
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "accounts-sub": ("accounts", "accounts-sub"),
                "proconnect-sub": ("identity_provider", "accounts-sub"),
            }
        ),
    )

    stdout = run_command(*(["--dry-run"] if dry_run else []), command=CustomCommand())

    assert warnings(caplog) == [f"User {duplicate.pk}: duplicate of user {holder.pk}"]
    if dry_run:
        assert handled == []
        assert dict(User.objects.values_list("pk", "sub")) == {
            holder.pk: "accounts-sub",
            duplicate.pk: "proconnect-sub",
        }
    else:
        assert handled == [(duplicate.pk, holder.pk, "accounts-sub")]
        assert dict(User.objects.values_list("pk", "sub")) == {duplicate.pk: "accounts-sub"}
        assert "'duplicate': 1" in stdout
        assert "'updated': 1" in stdout


@responses.activate
def test_migrate_users_to_accounts_custom_unmatched_users(caplog):
    """A subclass may handle the users accounts could not match nor create."""
    handled = []

    class CustomCommand(Command):
        def handle_email_conflict(self, user):
            handled.append(("email_conflict", user.pk))

        def handle_invalid(self, user):
            handled.append(("invalid", user.pk))

    conflict = UserFactory(sub="conflict-sub")
    invalid = UserFactory(sub="invalid-sub")
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "conflict-sub": ("email_conflict", None),
                "invalid-sub": ("invalid", None),
            }
        ),
    )

    run_command(command=CustomCommand())

    assert handled == [("email_conflict", conflict.pk), ("invalid", invalid.pk)]
    assert warnings(caplog) == []


ISSUER = "https://accounts.test/api/v1.0/o"


@pytest.fixture(name="issuer_settings")
def issuer_settings_fixture(settings):
    """Store the issuer of the users' sub."""
    settings.OIDC_USER_ISSUER_FIELD = "issuer"
    settings.OIDC_OP_URL = ISSUER


@pytest.mark.usefixtures("issuer_settings")
@responses.activate
def test_migrate_users_to_accounts_issuer():
    """The users of accounts are not sent, the others get the accounts sub and issuer."""
    migrated = UserFactory(sub="migrated-sub", issuer=ISSUER)
    already = UserFactory(sub="accounts-sub", issuer=None)
    known = UserFactory(sub="proconnect-sub", issuer="https://proconnect.test")
    callback = mock_users_import(
        {
            "accounts-sub": ("accounts", "accounts-sub"),
            "proconnect-sub": ("identity_provider", "accounts-known"),
        }
    )
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    stdout = run_command()

    assert [row["pk"] for row in callback.payloads[0]["users"]] == [str(already.pk), str(known.pk)]
    assert {user.pk: (user.sub, user.issuer) for user in User.objects.all()} == {
        migrated.pk: ("migrated-sub", ISSUER),
        already.pk: ("accounts-sub", ISSUER),
        known.pk: ("accounts-known", ISSUER),
    }
    assert "'updated': 2" in stdout


@pytest.mark.usefixtures("issuer_settings")
@responses.activate
def test_migrate_users_to_accounts_issuer_dry_run():
    """A dry run stores neither the sub nor the issuer."""
    UserFactory(sub="accounts-sub", issuer=None)
    UserFactory(sub="proconnect-sub", issuer=None)
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "accounts-sub": ("accounts", "accounts-sub"),
                "proconnect-sub": ("identity_provider", "accounts-known"),
            }
        ),
    )

    stdout = run_command("--dry-run")

    assert set(User.objects.values_list("sub", "issuer")) == {("accounts-sub", None), ("proconnect-sub", None)}
    assert "'to_update': 2" in stdout


def test_migrate_users_to_accounts_issuer_requires_the_op_url(settings):
    """The issuer of accounts is needed to store it."""
    settings.OIDC_USER_ISSUER_FIELD = "issuer"
    settings.OIDC_OP_URL = None

    with pytest.raises(CommandError, match="OIDC_OP_URL"):
        run_command()


@pytest.mark.usefixtures("issuer_settings")
@responses.activate
def test_migrate_users_to_accounts_max_batches():
    """Each run stops after the maximum number of batches, the next one goes on with the next users."""
    users = UserFactory.create_batch(5, issuer=None)
    callback = mock_users_import({})
    responses.add_callback(responses.POST, ENDPOINT, callback=callback)

    # The first run sends 2 batches of 2 users, then stops.
    first_stdout = run_command("--batch-size", "2", "--max-batches", "2")
    # The users it migrated now have the accounts issuer: the second run only sends the last one.
    second_stdout = run_command("--batch-size", "2", "--max-batches", "2")

    assert [[row["pk"] for row in payload["users"]] for payload in callback.payloads] == [
        [str(users[0].pk), str(users[1].pk)],
        [str(users[2].pk), str(users[3].pk)],
        [str(users[4].pk)],
    ]
    assert "'updated': 4" in first_stdout
    assert "'updated': 1" in second_stdout
    assert set(User.objects.values_list("issuer", flat=True)) == {ISSUER}


@pytest.mark.usefixtures("issuer_settings")
@responses.activate
def test_migrate_users_to_accounts_max_batches_stalled():
    """A run which migrates nobody fails when the reported users hold back the others."""
    UserFactory(sub="conflict-sub", issuer=None)
    UserFactory(sub="invalid-sub", issuer=None)
    # Behind the batch of the 2 reported users, a user waits to be migrated.
    waiting = UserFactory(sub="waiting-sub", issuer=None)
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "conflict-sub": ("email_conflict", None),
                "invalid-sub": ("invalid", None),
            }
        ),
    )

    with pytest.raises(CommandError, match="No user was migrated"):
        run_command("--batch-size", "2", "--max-batches", "1")

    waiting.refresh_from_db()
    assert waiting.sub == "waiting-sub"


@pytest.mark.usefixtures("issuer_settings")
@responses.activate
def test_migrate_users_to_accounts_max_batches_only_reported_users_left():
    """A run which migrates nobody succeeds when only the reported users are left."""
    UserFactory(sub="conflict-sub", issuer=None)
    UserFactory(sub="invalid-sub", issuer=None)
    responses.add_callback(
        responses.POST,
        ENDPOINT,
        callback=mock_users_import(
            {
                "conflict-sub": ("email_conflict", None),
                "invalid-sub": ("invalid", None),
            }
        ),
    )

    stdout = run_command("--batch-size", "2", "--max-batches", "1")

    assert "Done: {'email_conflict': 1, 'invalid': 1, 'updated': 0}" in stdout


def test_migrate_users_to_accounts_max_batches_requires_the_issuer_field():
    """Without the issuer, each run would send the same users."""
    with pytest.raises(CommandError, match="OIDC_USER_ISSUER_FIELD"):
        run_command("--max-batches", "1")


def test_migrate_users_to_accounts_invalid_max_batches():
    """The maximum number of batches must be positive."""
    with pytest.raises(CommandError, match="maximum number of batches"):
        run_command("--max-batches", "0")


def test_migrate_users_to_accounts_requires_the_endpoint(settings):
    """The endpoint setting is required."""
    settings.OIDC_OP_USERS_IMPORT_ENDPOINT = None

    with pytest.raises(CommandError, match="OIDC_OP_USERS_IMPORT_ENDPOINT"):
        run_command()


def test_migrate_users_to_accounts_invalid_batch_size():
    """The batch size must be positive."""
    with pytest.raises(CommandError, match="batch size"):
        run_command("--batch-size", "0")
