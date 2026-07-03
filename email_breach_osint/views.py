import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import EmailBreachCheckForm
from .models import EmailBreachCheck
from .services import EmailBreachAnalyzer


def _home_context(request, form, checks):
    return {
        "form": form,
        "checks": checks,
        "active_module": "email-breach",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_check(user, email: str) -> dict:
    report = EmailBreachAnalyzer().analyze(email)

    if not report.success:
        if report.validation_failed:
            return {
                "ok": False,
                "validation_failed": True,
                "error": report.error,
            }

        check, _ = EmailBreachCheck.upsert_for_user(
            user,
            report.email or email,
            status=EmailBreachCheck.Status.FAILED,
            error_message=report.error or "Check failed.",
            breach_count=0,
            is_pwned=False,
            risk_flags=[],
            report_json=report.to_storage_dict(),
        )
        return {
            "ok": True,
            "saved": True,
            "check_id": str(check.pk),
            "email": check.email,
            "status": check.status,
            "redirect_url": reverse("email_breach_osint:detail", kwargs={"pk": check.pk}),
            "message": report.error,
        }

    check, _ = EmailBreachCheck.upsert_for_user(
        user,
        report.email,
        status=EmailBreachCheck.Status.COMPLETED,
        error_message="",
        breach_count=report.breach_count,
        is_pwned=report.is_pwned,
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )
    if report.is_pwned:
        msg = f"Found in {report.breach_count} known breach(es)."
    else:
        msg = "No known breaches found for this email."
    return {
        "ok": True,
        "saved": True,
        "check_id": str(check.pk),
        "email": check.email,
        "status": check.status,
        "redirect_url": reverse("email_breach_osint:detail", kwargs={"pk": check.pk}),
        "message": msg,
    }


@login_required
def module_home(request):
    checks = EmailBreachCheck.objects.filter(user=request.user)[:20]
    return render(
        request,
        "email_breach_osint/home.html",
        _home_context(request, EmailBreachCheckForm(), checks),
    )


@login_required
@require_http_methods(["POST"])
def run_check(request):
    checks = EmailBreachCheck.objects.filter(user=request.user)[:20]
    form = EmailBreachCheckForm(request.POST)
    wants_json = _wants_json(request)

    if not form.is_valid():
        if wants_json:
            return JsonResponse(
                {
                    "ok": False,
                    "validation_failed": True,
                    "errors": {
                        field: [str(err) for err in errors]
                        for field, errors in form.errors.items()
                    },
                },
                status=422,
            )
        messages.error(request, "Fix the email field and try again.")
        return render(
            request,
            "email_breach_osint/home.html",
            _home_context(request, form, checks),
        )

    result = _execute_check(request.user, form.cleaned_data["email"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = EmailBreachCheckForm(data={"email": request.POST.get("email", "")})
        form.add_error("email", result.get("error"))
        return render(
            request,
            "email_breach_osint/home.html",
            _home_context(request, form, checks),
        )

    if result.get("message"):
        level = messages.warning if "breach" in result["message"].lower() and "No" not in result["message"] else messages.success
        level(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def check_detail(request, pk):
    check = get_object_or_404(EmailBreachCheck, pk=pk, user=request.user)
    report = check.report_json or {}
    sections = report.get("sections") or {}
    ordered_sections = []
    for key in ("Target", "Summary", "Breaches"):
        if key in sections:
            ordered_sections.append((key, sections[key]))
    for key in sorted(sections.keys()):
        if key not in ("Target", "Summary"):
            ordered_sections.append((key, sections[key]))

    return render(
        request,
        "email_breach_osint/detail.html",
        {
            "check": check,
            "report": report,
            "metadata_sections": ordered_sections,
            "breaches": report.get("breaches") or [],
            "risk_flags": check.risk_flags or [],
            "active_module": "email-breach",
        },
    )


@login_required
def export_json(request, pk):
    check = get_object_or_404(EmailBreachCheck, pk=pk, user=request.user)
    payload = {
        "id": str(check.pk),
        "email": check.email,
        "created_at": check.created_at.isoformat(),
        "updated_at": check.updated_at.isoformat(),
        "status": check.status,
        "breach_count": check.breach_count,
        "is_pwned": check.is_pwned,
        "report": check.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="email-breach-{check.email}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_check(request, pk):
    check = get_object_or_404(EmailBreachCheck, pk=pk, user=request.user)
    check.delete()
    messages.info(request, "Email breach check deleted.")
    return redirect("email_breach_osint:home")
