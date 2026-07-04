import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import OrgFootprintForm
from .models import OrgFootprint
from .services import OrgFootprintAnalyzer


def _home_context(request, form, records):
    return {
        "form": form,
        "records": records,
        "active_module": "org-footprint",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_scan(user, domain: str) -> dict:
    report = OrgFootprintAnalyzer().analyze(domain)

    if not report.success:
        if report.validation_failed:
            return {
                "ok": False,
                "validation_failed": True,
                "error": report.error,
            }

        record, _ = OrgFootprint.upsert_for_user(
            user,
            report.domain or domain,
            status=OrgFootprint.Status.FAILED,
            error_message=report.error or "Scan failed.",
            report_json=report.to_storage_dict(),
        )
        return {
            "ok": True,
            "saved": True,
            "record_id": str(record.pk),
            "domain": record.domain,
            "status": record.status,
            "redirect_url": reverse("org_footprint_osint:detail", kwargs={"pk": record.pk}),
            "message": report.error,
        }

    record, _ = OrgFootprint.upsert_for_user(
        user,
        report.domain,
        status=OrgFootprint.Status.COMPLETED,
        error_message="",
        org_name=report.org_name[:255],
        org_country=report.org_country[:8],
        whois_privacy=report.whois_privacy,
        spf_status=report.spf_status,
        dmarc_status=report.dmarc_status,
        dkim_selector_count=report.dkim_selector_count,
        security_header_score=report.security_header_score,
        social_platform_count=report.social_platform_count,
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )
    return {
        "ok": True,
        "saved": True,
        "record_id": str(record.pk),
        "domain": record.domain,
        "status": record.status,
        "redirect_url": reverse("org_footprint_osint:detail", kwargs={"pk": record.pk}),
        "message": f"Footprint scan completed for {record.domain}.",
    }


@login_required
def module_home(request):
    records = OrgFootprint.objects.filter(user=request.user)[:20]
    return render(
        request,
        "org_footprint_osint/home.html",
        _home_context(request, OrgFootprintForm(), records),
    )


@login_required
@require_http_methods(["POST"])
def run_scan(request):
    records = OrgFootprint.objects.filter(user=request.user)[:20]
    form = OrgFootprintForm(request.POST)
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
        messages.error(request, "Fix the domain field and try again.")
        return render(
            request,
            "org_footprint_osint/home.html",
            _home_context(request, form, records),
        )

    result = _execute_scan(request.user, form.cleaned_data["domain"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = OrgFootprintForm(data={"domain": request.POST.get("domain", "")})
        form.add_error("domain", result.get("error"))
        return render(
            request,
            "org_footprint_osint/home.html",
            _home_context(request, form, records),
        )

    if result.get("message"):
        level = messages.error if result.get("status") == "failed" else messages.success
        level(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def scan_detail(request, pk):
    record = get_object_or_404(OrgFootprint, pk=pk, user=request.user)
    report = record.report_json or {}
    sections = report.get("sections") or {}

    ordered_sections = []
    priority = (
        "Target",
        "Organization Identity",
        "Mail Security Posture",
        "HTTP Fingerprint",
        "Official Platform Presence",
    )
    for key in priority:
        if key in sections:
            ordered_sections.append((key, sections[key]))
    for key in sorted(sections.keys()):
        if key not in priority:
            ordered_sections.append((key, sections[key]))

    return render(
        request,
        "org_footprint_osint/detail.html",
        {
            "record": record,
            "report": report,
            "metadata_sections": ordered_sections,
            "risk_flags": record.risk_flags or [],
            "active_module": "org-footprint",
        },
    )


@login_required
def export_json(request, pk):
    record = get_object_or_404(OrgFootprint, pk=pk, user=request.user)
    payload = {
        "id": str(record.pk),
        "domain": record.domain,
        "created_at": record.created_at.isoformat(),
        "status": record.status,
        "report": record.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="org-footprint-{record.domain}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_scan(request, pk):
    record = get_object_or_404(OrgFootprint, pk=pk, user=request.user)
    record.delete()
    messages.info(request, "Footprint scan deleted.")
    return redirect("org_footprint_osint:home")
