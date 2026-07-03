import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from subdomain_osint.models import SubdomainScan

User = get_user_model()


class RunScanViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="sd@test.com",
            email="sd@test.com",
            password="TestPass1!",
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="sd@test.com", password="TestPass1!")
        self.url = reverse("subdomain_osint:scan")

    def test_invalid_domain_not_saved(self):
        before = SubdomainScan.objects.count()
        response = self.client.post(
            self.url,
            {"domain": "not valid!!!"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(SubdomainScan.objects.count(), before)
        self.assertEqual(response.status_code, 422)
        data = json.loads(response.content)
        self.assertFalse(data["ok"])
        self.assertTrue(data["validation_failed"])
