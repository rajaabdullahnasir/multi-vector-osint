import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import PasswordBreachCheckForm
from .models import PasswordBreachCheck
from .services import PasswordBreachAnalyzer


def _home_context(request, form, checks):
    return {
        "form": form,
        "checks": checks,
        "active_module": "password-breach",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_check(user, password: str) -> dict:
    report = PasswordBreachAnalyzer().analyze(password)

    if not report.success:
        if report.validation_failed:
            return {
                "ok": False,
                "validation_failed": True,
                "error": report.error,
            }

        if not report.sha1_hash:
            return {
                "ok": False,
                "error": report.error or "Check failed.",
            }

        check, _ = PasswordBreachCheck.upsert_for_user(
            user,
            report.sha1_hash,
            status=PasswordBreachCheck.Status.FAILED,
            error_message=report.error or "Check failed.",
            hash_prefix=report.hash_prefix,
            exposure_count=0,
            is_pwned=False,
            risk_flags=[],
            report_json=report.to_storage_dict(),
        )
        return {
            "ok": True,
            "saved": True,
            "check_id": str(check.pk),
            "status": check.status,
            "redirect_url": reverse("password_breach_osint:detail", kwargs={"pk": check.pk}),
            "message": report.error,
        }

    check, _ = PasswordBreachCheck.upsert_for_user(
        user,
        report.sha1_hash,
        status=PasswordBreachCheck.Status.COMPLETED,
        error_message="",
        hash_prefix=report.hash_prefix,
        exposure_count=report.exposure_count,
        is_pwned=report.is_pwned,
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )

    if report.is_pwned:
        msg = f"Password pwned — seen {report.exposure_count:,} time(s) in breach data."
    else:
        msg = "Password not found in the Pwned Passwords corpus."

    return {
        "ok": True,
        "saved": True,
        "check_id": str(check.pk),
        "status": check.status,
        "redirect_url": reverse("password_breach_osint:detail", kwargs={"pk": check.pk}),
        "message": msg,
    }


@login_required
def module_home(request):
    checks = PasswordBreachCheck.objects.filter(user=request.user)[:20]
    return render(
        request,
        "password_breach_osint/home.html",
        _home_context(request, PasswordBreachCheckForm(), checks),
    )


@login_required
@require_http_methods(["POST"])
def run_check(request):
    checks = PasswordBreachCheck.objects.filter(user=request.user)[:20]
    form = PasswordBreachCheckForm(request.POST)
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
        messages.error(request, "Fix the password field and try again.")
        return render(
            request,
            "password_breach_osint/home.html",
            _home_context(request, form, checks),
        )

    result = _execute_check(request.user, form.cleaned_data["password"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = PasswordBreachCheckForm()
        messages.error(request, result.get("error", "Check failed."))
        return render(
            request,
            "password_breach_osint/home.html",
            _home_context(request, form, checks),
        )

    if result.get("message"):
        if "pwned" in result["message"].lower():
            messages.error(request, result["message"])
        else:
            messages.success(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def check_detail(request, pk):
    check = get_object_or_404(PasswordBreachCheck, pk=pk, user=request.user)
    report = check.report_json or {}
    sections = report.get("sections") or {}
    ordered_sections = []
    for key in ("Target", "Summary"):
        if key in sections:
            ordered_sections.append((key, sections[key]))
    for key in sorted(sections.keys()):
        if key not in ("Target", "Summary"):
            ordered_sections.append((key, sections[key]))

    return render(
        request,
        "password_breach_osint/detail.html",
        {
            "check": check,
            "report": report,
            "metadata_sections": ordered_sections,
            "risk_flags": check.risk_flags or [],
            "k_anonymity_note": report.get("k_anonymity_note", ""),
            "active_module": "password-breach",
        },
    )


@login_required
def export_json(request, pk):
    check = get_object_or_404(PasswordBreachCheck, pk=pk, user=request.user)
    payload = {
        "id": str(check.pk),
        "password_sha1_masked": check.masked_sha1,
        "created_at": check.created_at.isoformat(),
        "updated_at": check.updated_at.isoformat(),
        "status": check.status,
        "exposure_count": check.exposure_count,
        "is_pwned": check.is_pwned,
        "report": check.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = 'attachment; filename="password-breach-report.json"'
    return response


@login_required
@require_http_methods(["POST"])
def delete_check(request, pk):
    check = get_object_or_404(PasswordBreachCheck, pk=pk, user=request.user)
    check.delete()
    messages.info(request, "Password breach check deleted.")
    return redirect("password_breach_osint:home")
