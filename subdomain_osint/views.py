import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import SubdomainScanForm
from .models import SubdomainScan
from .services import SubdomainAnalyzer


def _home_context(request, form, scans):
    return {
        "form": form,
        "scans": scans,
        "active_module": "subdomain",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_scan(user, domain: str) -> dict:
    report = SubdomainAnalyzer().analyze(domain)

    if not report.success:
        if report.validation_failed:
            return {
                "ok": False,
                "validation_failed": True,
                "error": report.error,
            }

        scan, _ = SubdomainScan.upsert_for_user(
            user,
            report.domain or domain,
            status=SubdomainScan.Status.FAILED,
            error_message=report.error or "Scan failed.",
            subdomain_count=0,
            dns_verified_count=0,
            sources_used=[],
            risk_flags=[],
            report_json=report.to_storage_dict(),
        )
        return {
            "ok": True,
            "saved": True,
            "scan_id": str(scan.pk),
            "domain": scan.domain,
            "status": scan.status,
            "redirect_url": reverse("subdomain_osint:detail", kwargs={"pk": scan.pk}),
            "message": report.error,
        }

    scan, _ = SubdomainScan.upsert_for_user(
        user,
        report.domain,
        status=SubdomainScan.Status.COMPLETED,
        error_message="",
        subdomain_count=report.subdomain_count,
        dns_verified_count=report.dns_verified_count,
        live_host_count=report.live_host_count,
        sources_used=report.sources_used or [],
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )
    return {
        "ok": True,
        "saved": True,
        "scan_id": str(scan.pk),
        "domain": scan.domain,
        "status": scan.status,
        "redirect_url": reverse("subdomain_osint:detail", kwargs={"pk": scan.pk}),
        "message": (
            f"Subdomain scan completed for {scan.domain} "
            f"({scan.subdomain_count} hosts found)."
        ),
    }


@login_required
def module_home(request):
    scans = SubdomainScan.objects.filter(user=request.user)[:20]
    return render(
        request,
        "subdomain_osint/home.html",
        _home_context(request, SubdomainScanForm(), scans),
    )


@login_required
@require_http_methods(["POST"])
def run_scan(request):
    scans = SubdomainScan.objects.filter(user=request.user)[:20]
    form = SubdomainScanForm(request.POST)
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
            "subdomain_osint/home.html",
            _home_context(request, form, scans),
        )

    result = _execute_scan(request.user, form.cleaned_data["domain"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = SubdomainScanForm(data={"domain": request.POST.get("domain", "")})
        form.add_error("domain", result.get("error"))
        return render(
            request,
            "subdomain_osint/home.html",
            _home_context(request, form, scans),
        )

    if result.get("message"):
        level = messages.error if result.get("status") == "failed" else messages.success
        level(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def scan_detail(request, pk):
    scan = get_object_or_404(SubdomainScan, pk=pk, user=request.user)
    report = scan.report_json or {}
    sections = report.get("sections") or {}

    ordered_sections = []
    priority = ("Target", "Scan Summary")
    for key in priority:
        if key in sections:
            ordered_sections.append((key, sections[key]))
    for key in sorted(sections.keys()):
        if key not in priority:
            ordered_sections.append((key, sections[key]))

    return render(
        request,
        "subdomain_osint/detail.html",
        {
            "scan": scan,
            "report": report,
            "metadata_sections": ordered_sections,
            "subdomains": report.get("subdomains") or [],
            "warnings": report.get("warnings") or [],
            "risk_flags": scan.risk_flags or [],
            "active_module": "subdomain",
        },
    )


@login_required
def export_json(request, pk):
    scan = get_object_or_404(SubdomainScan, pk=pk, user=request.user)
    payload = {
        "id": str(scan.pk),
        "domain": scan.domain,
        "created_at": scan.created_at.isoformat(),
        "updated_at": scan.updated_at.isoformat(),
        "status": scan.status,
        "report": scan.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="subdomains-{scan.domain}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_scan(request, pk):
    scan = get_object_or_404(SubdomainScan, pk=pk, user=request.user)
    scan.delete()
    messages.info(request, "Subdomain scan deleted.")
    return redirect("subdomain_osint:home")
