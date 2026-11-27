"""Management command to replace the identity provider's subs of the users by accounts subs."""

import logging
from collections import Counter

import requests
from django.contrib.auth import get_user_model
from django.core.exceptions import FieldDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q
from mozilla_django_oidc.utils import import_from_settings

logger = logging.getLogger(__name__)

CONFLICT_RETRIES = 3


class Command(BaseCommand):
    """
    Send the users by batches to the users import endpoint of accounts, then store their accounts sub.

    The endpoint matches each sub with an accounts user, and creates the unknown ones.
    Both sides can be replayed: run the command again after an interruption. With
    `--max-batches` and `OIDC_USER_ISSUER_FIELD`, it can run from a cron, a few users at a time.

    A user whose accounts sub already belongs to another user is a duplicate: it is logged
    as a warning and left unchanged, merging them is up to the product.

    Products are encouraged to subclass this command to customize it: by default, it only
    logs the duplicates and the unmatched users. See `get_users_queryset` to select the
    users, `update_users` to store more than their sub, and the `handle_*` methods to handle
    the duplicates and the unmatched users automatically.
    """

    help = "Replace the identity provider's subs of the users by accounts subs."

    # The users are sent by creation date, the oldest first, then by primary key for the
    # users created at the same time. Override it when the user model names it otherwise,
    # e.g. `date_joined`.
    created_at_field = "created_at"

    def add_arguments(self, parser):
        """Add the command arguments."""
        parser.add_argument("--batch-size", type=int, default=1000, help="Number of users per request.")
        parser.add_argument(
            "--max-batches",
            type=int,
            help="Stop after this number of batches, e.g. to run from a cron. Requires OIDC_USER_ISSUER_FIELD.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be created and updated, without writing anything.",
        )

    def handle(self, *args, batch_size, max_batches, dry_run, **options):
        """Handle the command."""
        self.endpoint = import_from_settings("OIDC_OP_USERS_IMPORT_ENDPOINT", None)
        if not self.endpoint:
            raise CommandError("The OIDC_OP_USERS_IMPORT_ENDPOINT setting is required.")
        if batch_size < 1:
            raise CommandError("The batch size must be positive.")
        if max_batches is not None and max_batches < 1:
            raise CommandError("The maximum number of batches must be positive.")
        self.user_model = get_user_model()
        self.sub_field = import_from_settings("OIDC_USER_SUB_FIELD", "sub")
        self.issuer_field = import_from_settings("OIDC_USER_ISSUER_FIELD", None)
        self.issuer = import_from_settings("OIDC_OP_URL", None)
        if self.issuer_field and not self.issuer:
            raise CommandError("The OIDC_OP_URL setting is required with OIDC_USER_ISSUER_FIELD.")
        # Only the issuer tells the migrated users apart: each run would send the same users.
        if max_batches and not self.issuer_field:
            raise CommandError("The OIDC_USER_ISSUER_FIELD setting is required with --max-batches.")
        self.dry_run = dry_run
        self.given_subs = {}

        counts = Counter()
        processed = 0
        stalled = False
        for number, batch in enumerate(self._iter_batches(batch_size), start=1):
            results = self._import_batch(batch)
            counts.update(result["status"] for result in results)
            counts.update(self._update_subs(results))
            processed += len(batch)
            self.stdout.write(f"{processed} users processed")
            if max_batches and number >= max_batches:
                # The users this run could not migrate (duplicates, email conflicts, invalid
                # users) do not get the accounts issuer, so the next run sends them first
                # again. When they fill the batches, the runs migrate nobody and never reach
                # the users behind them: fail, so that the cron job alerts. When only these
                # users are left, succeed, not to fail every run once the migration is done.
                stalled = (
                    not counts["updated"] + counts["to_update"]
                    and self._after(self.get_users_queryset(), batch[-1]).exists()
                )
                break

        self.stdout.write(self.style.SUCCESS(f"{'Dry run' if dry_run else 'Done'}: {dict(sorted(counts.items()))}"))
        if stalled:
            raise CommandError(
                "No user was migrated and other users are waiting: handle the users logged as warnings, "
                "or increase --batch-size or --max-batches."
            )

    def get_users_queryset(self):
        """
        Return the users to send to accounts, by default all non-staff users with a sub.

        With `OIDC_USER_ISSUER_FIELD`, the users whose sub was issued by accounts are left
        out: an unknown issuer is kept, as for the users of before this field.
        """
        queryset = self.user_model.objects.exclude(**{f"{self.sub_field}__isnull": True}).exclude(
            **{self.sub_field: ""}
        )
        if self.issuer_field:
            queryset = queryset.exclude(**{self.issuer_field: self.issuer})

        # Exclude staff members, if the field exists
        try:
            self.user_model._meta.get_field("is_staff")  # noqa: SLF001
        except FieldDoesNotExist:
            pass
        else:
            queryset = queryset.exclude(is_staff=True)
        return queryset

    def update_users(self, users):
        """
        Store the users, their accounts sub and its issuer already set.

        Called in the transaction of the batch, never in a dry run.
        """
        fields = [self.sub_field, self.issuer_field] if self.issuer_field else [self.sub_field]
        self.user_model.objects.bulk_update(users, fields)

    def handle_duplicate(self, user, holder):
        """
        Handle a user whose accounts sub is already held by another user, its holder.

        Called in the transaction of the batch, once the other users of the batch are stored,
        never in a dry run. Return whether the user gets the accounts sub:
        - True: the user gets it, e.g. the holder was merged into the user and deleted. The
          holder must no longer hold it.
        - False: the user is left unchanged, e.g. it was merged into the holder, which keeps
          the sub. By default, merging them is up to the product.
        """
        return False

    def handle_email_conflict(self, user):
        """
        Log a user whose sub is unknown to accounts, but whose email belongs to another accounts user.

        Called in a dry run too: check `self.dry_run` before writing anything.
        """
        logger.warning("User %s: email_conflict", user.pk)

    def handle_invalid(self, user):
        """
        Log a user whose sub or email is not valid for accounts.

        Called in a dry run too: check `self.dry_run` before writing anything.
        """
        logger.warning("User %s: invalid", user.pk)

    def _after(self, queryset, user):
        """Filter the users which come after this user, in the order of the batches."""
        created_at = getattr(user, self.created_at_field)
        # Created later, or at the same time with a greater primary key: the creation date
        # alone is not unique, the users sharing it would be skipped or sent twice.
        return queryset.filter(
            Q(**{f"{self.created_at_field}__gt": created_at})
            | Q(**{self.created_at_field: created_at, "pk__gt": user.pk})
        )

    def _iter_batches(self, batch_size):
        """
        Yield the users by batches, ordered by creation date, then by primary key.

        Each batch is a new query for the users after the last one of the previous batch:
        no query stays open while accounts answers, and the users already migrated, which
        leave the queryset, do not shift the next ones.
        """
        queryset = self.get_users_queryset().order_by(self.created_at_field, "pk")
        last_user = None
        while True:
            page = queryset if last_user is None else self._after(queryset, last_user)
            batch = list(page[:batch_size])
            if not batch:
                return
            yield batch
            last_user = batch[-1]

    def _post(self, payload):
        """Post a batch to accounts, retrying when a concurrent import conflicts."""
        for _ in range(CONFLICT_RETRIES):
            try:
                response = requests.post(
                    self.endpoint,
                    json=payload,
                    auth=(
                        import_from_settings("OIDC_RP_CLIENT_ID"),
                        import_from_settings("OIDC_RP_CLIENT_SECRET"),
                    ),
                    verify=import_from_settings("OIDC_VERIFY_SSL", True),
                    timeout=import_from_settings("OIDC_TIMEOUT", 30),
                    proxies=import_from_settings("OIDC_PROXY", None),
                )
            except requests.RequestException as error:
                raise CommandError(f"Could not reach accounts: {error}") from error
            if response.status_code != requests.codes.conflict:
                break
        if not response.ok:
            raise CommandError(f"Accounts refused the batch ({response.status_code}): {response.text}")
        return response.json()["results"]

    def _import_batch(self, batch):
        """Return the result of accounts for each user of the batch, with the user."""
        users = {str(user.pk): user for user in batch}
        results = self._post(
            {
                "users": [
                    {"pk": pk, "sub": getattr(user, self.sub_field), "email": user.email or ""}
                    for pk, user in users.items()
                ],
                "dry_run": self.dry_run,
            }
        )
        for result in results:
            result["user"] = users[result["pk"]]
            if result["status"] == "email_conflict":
                self.handle_email_conflict(result["user"])
            elif result["status"] == "invalid":
                self.handle_invalid(result["user"])
        return results

    def _set_accounts_sub(self, user, accounts_sub):
        """Set the accounts sub of a user, and its issuer when the product stores it."""
        setattr(user, self.sub_field, accounts_sub)
        if self.issuer_field:
            setattr(user, self.issuer_field, self.issuer)

    def _update_subs(self, results):
        """
        Store the accounts subs which do not belong to another user, return the counts.

        The sub is unique in the product: an accounts sub already held by another user, its
        holder, cannot be given to a second one. Such a user is a duplicate, e.g. the same
        person logged in through accounts and got a second account, or two former subs of
        the same person, which accounts both matches with one accounts user.
        """
        # 1. Sort the users: the ones to store, and the duplicates. Nothing is written yet.

        # The users whose sub changes: accounts returned an accounts sub (None for the email
        # conflicts and the invalid users) which is not their sub yet.
        changes = [
            (result["user"], result["accounts_sub"])
            for result in results
            if result["accounts_sub"] and result["accounts_sub"] != getattr(result["user"], self.sub_field)
        ]
        # The users whose sub already is the accounts sub, but without the accounts issuer,
        # e.g. created by the resource server: only their issuer is stored.
        confirmed = (
            [
                result["user"]
                for result in results
                if result["accounts_sub"]
                and result["accounts_sub"] == getattr(result["user"], self.sub_field)
                and getattr(result["user"], self.issuer_field) != self.issuer
            ]
            if self.issuer_field
            else []
        )
        for user in confirmed:
            self._set_accounts_sub(user, getattr(user, self.sub_field))
        # The holder of each accounts sub to give, by accounts sub: the users which already
        # hold it in the database, and the users of the previous batches it was given to by
        # this run. A dry run writes nothing: those are only known from `given_subs`, which
        # takes precedence as the latest state.
        holders = {
            getattr(holder, self.sub_field): holder
            for holder in self.user_model.objects.filter(
                **{f"{self.sub_field}__in": [accounts_sub for _user, accounts_sub in changes]}
            )
        } | self.given_subs
        counts = Counter()
        # The users to store, and the duplicates with the holder of their accounts sub.
        users, duplicates = list(confirmed), []
        for user, accounts_sub in changes:
            if accounts_sub in holders:
                # Another user holds this accounts sub: the user keeps its sub for now.
                counts["duplicate"] += 1
                logger.warning("User %s: duplicate of user %s", user.pk, holders[accounts_sub].pk)
                duplicates.append((user, holders[accounts_sub], accounts_sub))
                continue
            # The user becomes the holder of the accounts sub, so that a next user getting
            # the same one, in this batch or a next one, is a duplicate.
            holders[accounts_sub] = self.given_subs[accounts_sub] = user
            self._set_accounts_sub(user, accounts_sub)
            users.append(user)

        # 2. Store the users, then hand the duplicates to the product. Skipped in dry run.

        if self.dry_run:
            counts["to_update"] += len(users)
            return counts
        # One transaction per batch: a failing handle_duplicate rolls back the whole batch.
        with transaction.atomic():
            if users:
                self.update_users(users)
            resolved = []
            for user, holder, accounts_sub in duplicates:
                # True: the holder no longer holds the accounts sub, the user gets it.
                if self.handle_duplicate(user, holder):
                    self.given_subs[accounts_sub] = user
                    self._set_accounts_sub(user, accounts_sub)
                    resolved.append(user)
            # Stored after the merges, once the holders released their accounts sub.
            if resolved:
                self.update_users(resolved)
        counts["updated"] += len(users) + len(resolved)
        return counts
