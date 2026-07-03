from django.urls import path, re_path

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.SecureLoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("verify/", views.VerifyEmailView.as_view(), name="verify_email"),
    re_path(
        r"^verify/(?P<token>[A-Za-z0-9_-]+)/$",
        views.VerifyEmailView.as_view(),
        name="verify_email_legacy",
    ),
    path(
        "resend-verification/",
        views.ResendVerificationView.as_view(),
        name="resend_verification",
    ),
    path("profile/", views.profile_view, name="profile"),
]
