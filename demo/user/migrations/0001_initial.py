"""Initial migration for the user app."""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Create the User model."""

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "sub",
                    models.CharField(
                        blank=True,
                        max_length=255,
                        null=True,
                        unique=True,
                        verbose_name="sub",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        blank=True,
                        max_length=255,
                        null=True,
                        verbose_name="name",
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        blank=True,
                        max_length=254,
                        null=True,
                        unique=True,
                        verbose_name="email address",
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(default=True, verbose_name="active"),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
