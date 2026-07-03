from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect, render
from django.views import View

from .forms import LoginForm, RegistrationForm, ResendVerificationForm
from .services import (
    check_login_lockout,
    get_or_create_profile,
    record_failed_login,
    record_successful_login,
    resend_verification_email,
    send_verification_email,
    verify_email_token,
)
from .verification import build_verification_url


class RegisterView(View):
    template_name = "accounts/register.html"
    pending_template = "accounts/pending_verification.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("core:dashboard")
        return render(request, self.template_name, {"form": RegistrationForm()})

    def post(self, request):
        form = RegistrationForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        user = form.save()
        profile = get_or_create_profile(user)
        profile.organization = form.cleaned_data.get("organization", "")
        profile.email_verified = False
        profile.save()

        token_obj = send_verification_email(request, user)
        verify_url = build_verification_url(request, token_obj.token)

        return render(
            request,
            self.pending_template,
            {
                "email": user.email,
                "verify_url": verify_url,
            },
        )


class SecureLoginView(LoginView):
    template_name = "accounts/login.html"
    authentication_form = LoginForm
    redirect_authenticated_user = True

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["resend_form"] = ResendVerificationForm()
        return context

    def form_valid(self, form):
        email = form.cleaned_data.get("username", "").lower()
        locked, message = check_login_lockout(email)
        if locked:
            messages.error(self.request, message)
            return self.form_invalid(form)

        user = form.get_user()
        profile = get_or_create_profile(user)
        if not profile.email_verified:
            messages.error(
                self.request,
                "Please verify your email before logging in. "
                "Use “Resend verification” below if your link did not work.",
            )
            return self.form_invalid(form)

        record_successful_login(email)
        messages.success(self.request, f"Welcome back, {user.first_name or user.username}.")
        return super().form_valid(form)

    def form_invalid(self, form):
        email = self.request.POST.get("username", "").lower()
        if email and "@" in email:
            tracker = record_failed_login(email)
            remaining = max(0, 5 - tracker.failed_count)
            if remaining and not tracker.is_locked:
                messages.warning(
                    self.request,
                    f"Invalid credentials. {remaining} attempt(s) remaining before lockout.",
                )
        return super().form_invalid(form)


class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.info(request, "You have been logged out.")
        return redirect("accounts:login")

    def get(self, request):
        return self.post(request)


class VerifyEmailView(View):
    template_name = "accounts/verify_email.html"

    def get(self, request, token=None):
        raw = token or request.GET.get("token", "")
        user, error = verify_email_token(raw)
        return render(
            request,
            self.template_name,
            {
                "success": user is not None,
                "error": error,
                "show_resend": user is None,
            },
        )


class ResendVerificationView(View):
    template_name = "accounts/resend_verification.html"
    pending_template = "accounts/pending_verification.html"

    def get(self, request):
        return render(request, self.template_name, {"form": ResendVerificationForm()})

    def post(self, request):
        form = ResendVerificationForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        ok, result = resend_verification_email(request, form.cleaned_data["email"])
        if not ok:
            messages.error(request, result)
            return render(request, self.template_name, {"form": form})

        return render(
            request,
            self.pending_template,
            {
                "email": form.cleaned_data["email"],
                "verify_url": result,
                "resent": True,
            },
        )


@login_required
def profile_view(request):
    profile = get_or_create_profile(request.user)
    return render(
        request,
        "accounts/profile.html",
        {"profile": profile},
    )
