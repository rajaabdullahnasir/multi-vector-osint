import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import IPIntelForm
from .models import IPIntelligence
from .services import IPIntelAnalyzer


def _home_context(request, form, records):
    return {
        "form": form,
        "records": records,
        "active_module": "ip-intel",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_scan(user, query_input: str) -> dict:
    report = IPIntelAnalyzer().analyze(query_input)

    if not report.success:
        if report.validation_failed:
            return {"ok": False, "validation_failed": True, "error": report.error}

        record, _ = IPIntelligence.upsert_for_user(
            user,
            query_input,
            status=IPIntelligence.Status.FAILED,
            error_message=report.error or "Lookup failed.",
            report_json=report.to_storage_dict(),
        )
        return {
            "ok": True,
            "record_id": str(record.pk),
            "redirect_url": reverse("ip_intel_osint:detail", kwargs={"pk": record.pk}),
            "message": report.error,
            "status": record.status,
        }

    record, _ = IPIntelligence.upsert_for_user(
        user,
        report.query_input,
        status=IPIntelligence.Status.COMPLETED,
        error_message="",
        ip_address=report.ip,
        ptr_hostname=report.ptr_hostname[:255],
        asn=report.asn[:32],
        isp=report.isp[:255],
        org_name=report.org_name[:255],
        country=report.country[:8],
        region=report.region[:128],
        city=report.city[:128],
        latitude=report.latitude,
        longitude=report.longitude,
        timezone=report.timezone[:64],
        is_proxy_or_vpn=report.is_proxy_or_vpn,
        is_hosting=report.is_hosting,
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )
    return {
        "ok": True,
        "record_id": str(record.pk),
        "redirect_url": reverse("ip_intel_osint:detail", kwargs={"pk": record.pk}),
        "message": f"IP intelligence lookup completed for {record.query_input}.",
        "status": record.status,
    }


@login_required
def module_home(request):
    records = IPIntelligence.objects.filter(user=request.user)[:20]
    return render(
        request,
        "ip_intel_osint/home.html",
        _home_context(request, IPIntelForm(), records),
    )


@login_required
@require_http_methods(["POST"])
def run_scan(request):
    records = IPIntelligence.objects.filter(user=request.user)[:20]
    form = IPIntelForm(request.POST)
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
        messages.error(request, "Fix the field and try again.")
        return render(request, "ip_intel_osint/home.html", _home_context(request, form, records))

    result = _execute_scan(request.user, form.cleaned_data["query"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = IPIntelForm(data={"query": request.POST.get("query", "")})
        form.add_error("query", result.get("error"))
        return render(request, "ip_intel_osint/home.html", _home_context(request, form, records))

    if result.get("message"):
        level = messages.error if result.get("status") == "failed" else messages.success
        level(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def scan_detail(request, pk):
    record = get_object_or_404(IPIntelligence, pk=pk, user=request.user)
    report = record.report_json or {}
    sections = report.get("sections") or {}

    priority = ("Target", "Geolocation", "Network", "RDAP Registration")
    ordered_sections = [(key, sections[key]) for key in priority if key in sections]
    for key in sorted(sections.keys()):
        if key not in priority:
            ordered_sections.append((key, sections[key]))

    return render(
        request,
        "ip_intel_osint/detail.html",
        {
            "record": record,
            "report": report,
            "metadata_sections": ordered_sections,
            "risk_flags": record.risk_flags or [],
            "active_module": "ip-intel",
        },
    )


@login_required
def export_json(request, pk):
    record = get_object_or_404(IPIntelligence, pk=pk, user=request.user)
    payload = {
        "id": str(record.pk),
        "query_input": record.query_input,
        "ip_address": record.ip_address,
        "created_at": record.created_at.isoformat(),
        "status": record.status,
        "report": record.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="ip-intel-{record.query_input}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_scan(request, pk):
    record = get_object_or_404(IPIntelligence, pk=pk, user=request.user)
    record.delete()
    messages.info(request, "Lookup deleted.")
    return redirect("ip_intel_osint:home")
