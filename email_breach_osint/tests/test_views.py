import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from email_breach_osint.models import EmailBreachCheck

User = get_user_model()


class RunCheckViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="em@test.com",
            email="em@test.com",
            password="TestPass1!",
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="em@test.com", password="TestPass1!")
        self.url = reverse("email_breach_osint:check")

    def test_invalid_email_not_saved(self):
        before = EmailBreachCheck.objects.count()
        response = self.client.post(
            self.url,
            {"email": "not-an-email"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(EmailBreachCheck.objects.count(), before)
        self.assertEqual(response.status_code, 422)
        data = json.loads(response.content)
        self.assertFalse(data["ok"])
