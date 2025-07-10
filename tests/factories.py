"""Factories for creating test data."""

import factory.django
from django.contrib.auth import get_user_model

from lasuite.malware_detection.models import MalwareDetection

User = get_user_model()


class UserFactory(factory.django.DjangoModelFactory):
    """A factory to create random users for testing purposes."""

    sub = factory.Sequence(lambda n: f"user{n!s}")
    email = factory.Faker("email")
    name = factory.Faker("name")

    class Meta:  # noqa: D106
        model = User


class MalwareDetectionFactory(factory.django.DjangoModelFactory):
    """A factory to create random malware detections for testing purposes."""

    path = factory.Faker("file_path")

    class Meta:  # noqa: D106
        model = MalwareDetection
