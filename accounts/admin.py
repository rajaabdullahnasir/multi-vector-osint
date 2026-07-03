from django.contrib import admin

from .models import EmailVerificationToken, LoginAttemptTracker, UserProfile

admin.site.register(UserProfile)
admin.site.register(EmailVerificationToken)
admin.site.register(LoginAttemptTracker)
