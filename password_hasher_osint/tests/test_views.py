from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from password_hasher_osint.models import HashJob

User = get_user_model()


class PasswordHasherViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="hs@test.com",
            email="hs@test.com",
            password="TestPass1!",
        )
        self.client = Client()
        self.client.login(username="hs@test.com", password="TestPass1!")

    def test_hash_creates_job(self):
        response = self.client.post(
            reverse("password_hasher_osint:hash"),
            {
                "hash-plaintext": "password",
                "hash-algorithms": ["sha256"],
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(HashJob.objects.filter(user=self.user).count(), 1)
        job = HashJob.objects.get(user=self.user)
        self.assertEqual(job.mode, HashJob.Mode.HASH)
        self.assertFalse("password" in str(job.report_json))

    def test_compare_creates_job(self):
        response = self.client.post(
            reverse("password_hasher_osint:compare"),
            {
                "compare-plaintext": "password",
                "compare-target_hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                "compare-algorithm": "sha1",
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 200)
        job = HashJob.objects.get(user=self.user)
        self.assertTrue(job.matched)
