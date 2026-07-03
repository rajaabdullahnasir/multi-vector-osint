from django.contrib.auth import get_user_model
from django.test import TestCase

from username_osint.models import UsernameLookup

User = get_user_model()


class UsernameLookupModelTests(TestCase):
    def test_upsert_updates_same_username(self):
        user = User.objects.create_user(
            username="upsert@test.com",
            email="upsert@test.com",
            password="TestPass1!",
        )
        UsernameLookup.upsert_for_user(
            user,
            "johndoe",
            status=UsernameLookup.Status.COMPLETED,
            found_count=1,
            checked_count=20,
        )
        lookup, created = UsernameLookup.upsert_for_user(
            user,
            "johndoe",
            status=UsernameLookup.Status.COMPLETED,
            found_count=3,
            checked_count=20,
        )
        self.assertFalse(created)
        self.assertEqual(UsernameLookup.objects.filter(user=user, username="johndoe").count(), 1)
        self.assertEqual(lookup.found_count, 3)
