import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from whois_osint.models import DomainLookup

User = get_user_model()


class RunLookupViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="whois@test.com",
            email="whois@test.com",
            password="TestPass1!",
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="whois@test.com", password="TestPass1!")
        self.url = reverse("whois_osint:lookup")

    def test_invalid_domain_not_saved_html(self):
        before = DomainLookup.objects.count()
        response = self.client.post(self.url, {"domain": "not valid!!!"})
        self.assertEqual(DomainLookup.objects.count(), before)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "valid domain")

    def test_invalid_domain_not_saved_ajax(self):
        before = DomainLookup.objects.count()
        response = self.client.post(
            self.url,
            {"domain": "not valid!!!"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(DomainLookup.objects.count(), before)
        self.assertEqual(response.status_code, 422)
        data = json.loads(response.content)
        self.assertFalse(data["ok"])
        self.assertTrue(data["validation_failed"])

    def test_empty_domain_ajax(self):
        before = DomainLookup.objects.count()
        response = self.client.post(
            self.url,
            {"domain": "   "},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(DomainLookup.objects.count(), before)
        self.assertEqual(response.status_code, 422)
