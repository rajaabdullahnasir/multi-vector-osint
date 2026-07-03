import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import UrlRiskCheckForm
from .models import UrlRiskCheck
from .services import RISK_DANGEROUS, RISK_SUSPICIOUS, UrlRiskAnalyzer


def _home_context(request, form, checks):
    return {
        "form": form,
        "checks": checks,
        "active_module": "url-risk",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_check(user, url: str) -> dict:
    report = UrlRiskAnalyzer().analyze(url)

    if not report.success:
        if report.validation_failed:
            return {
                "ok": False,
                "validation_failed": True,
                "error": report.error,
            }

        check, _ = UrlRiskCheck.upsert_for_user(
            user,
            report.url or url,
            status=UrlRiskCheck.Status.FAILED,
            error_message=report.error or "Analysis failed.",
            risk_level=UrlRiskCheck.RiskLevel.SAFE,
            risk_score=0,
            risk_flags=[],
            report_json=report.to_storage_dict(),
        )
        return {
            "ok": True,
            "saved": True,
            "check_id": str(check.pk),
            "url": check.url,
            "status": check.status,
            "redirect_url": reverse("url_risk_osint:detail", kwargs={"pk": check.pk}),
            "message": report.error,
        }

    check, _ = UrlRiskCheck.upsert_for_user(
        user,
        report.url,
        status=UrlRiskCheck.Status.COMPLETED,
        error_message="",
        risk_level=report.risk_level,
        risk_score=report.risk_score,
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )

    if report.risk_level == RISK_DANGEROUS:
        msg = f"Dangerous — risk score {report.risk_score}/100."
    elif report.risk_level == RISK_SUSPICIOUS:
        msg = f"Suspicious — risk score {report.risk_score}/100."
    else:
        msg = f"Safe — risk score {report.risk_score}/100."

    return {
        "ok": True,
        "saved": True,
        "check_id": str(check.pk),
        "url": check.url,
        "status": check.status,
        "redirect_url": reverse("url_risk_osint:detail", kwargs={"pk": check.pk}),
        "message": msg,
    }


@login_required
def module_home(request):
    checks = UrlRiskCheck.objects.filter(user=request.user)[:20]
    return render(
        request,
        "url_risk_osint/home.html",
        _home_context(request, UrlRiskCheckForm(), checks),
    )


@login_required
@require_http_methods(["POST"])
def run_check(request):
    checks = UrlRiskCheck.objects.filter(user=request.user)[:20]
    form = UrlRiskCheckForm(request.POST)
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
        messages.error(request, "Fix the URL field and try again.")
        return render(
            request,
            "url_risk_osint/home.html",
            _home_context(request, form, checks),
        )

    result = _execute_check(request.user, form.cleaned_data["url"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = UrlRiskCheckForm(data={"url": request.POST.get("url", "")})
        form.add_error("url", result.get("error"))
        return render(
            request,
            "url_risk_osint/home.html",
            _home_context(request, form, checks),
        )

    if result.get("message"):
        if "Dangerous" in result["message"]:
            level = messages.error
        elif "Suspicious" in result["message"]:
            level = messages.warning
        else:
            level = messages.success
        level(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def check_detail(request, pk):
    check = get_object_or_404(UrlRiskCheck, pk=pk, user=request.user)
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
        "url_risk_osint/detail.html",
        {
            "check": check,
            "report": report,
            "metadata_sections": ordered_sections,
            "parsed": report.get("parsed") or {},
            "lexical_findings": report.get("lexical_findings") or [],
            "blacklist_hits": report.get("blacklist_hits") or [],
            "risk_flags": check.risk_flags or [],
            "active_module": "url-risk",
        },
    )


@login_required
def export_json(request, pk):
    check = get_object_or_404(UrlRiskCheck, pk=pk, user=request.user)
    payload = {
        "id": str(check.pk),
        "url": check.url,
        "created_at": check.created_at.isoformat(),
        "updated_at": check.updated_at.isoformat(),
        "status": check.status,
        "risk_level": check.risk_level,
        "risk_score": check.risk_score,
        "report": check.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = 'attachment; filename="url-risk-report.json"'
    return response


@login_required
@require_http_methods(["POST"])
def delete_check(request, pk):
    check = get_object_or_404(UrlRiskCheck, pk=pk, user=request.user)
    check.delete()
    messages.info(request, "URL risk check deleted.")
    return redirect("url_risk_osint:home")
