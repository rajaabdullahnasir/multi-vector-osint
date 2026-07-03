import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import DomainLookupForm
from .models import DomainLookup
from .services import DomainIntelAnalyzer


def _home_context(request, form, lookups):
    return {
        "form": form,
        "lookups": lookups,
        "active_module": "whois",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_lookup(user, domain: str) -> dict:
    """Run WHOIS + DNS; persist only valid domains. Returns payload for HTML or JSON."""
    report = DomainIntelAnalyzer().analyze(domain)

    if not report.success:
        if report.validation_failed:
            return {
                "ok": False,
                "validation_failed": True,
                "error": report.error,
            }

        lookup, _ = DomainLookup.upsert_for_user(
            user,
            report.domain or domain,
            status=DomainLookup.Status.FAILED,
            error_message=report.error or "Lookup failed.",
            report_json=report.to_storage_dict(),
            registrar="",
            creation_date="",
            expiry_date="",
            name_server_count=0,
            dns_record_count=0,
            risk_flags=[],
        )
        return {
            "ok": True,
            "saved": True,
            "lookup_id": str(lookup.pk),
            "domain": lookup.domain,
            "status": lookup.status,
            "redirect_url": reverse("whois_osint:detail", kwargs={"pk": lookup.pk}),
            "message": report.error,
        }

    sections = report.sections or {}
    registration = sections.get("WHOIS — Registration", {})

    lookup, _ = DomainLookup.upsert_for_user(
        user,
        report.domain,
        status=DomainLookup.Status.COMPLETED,
        error_message="",
        registrar=registration.get("Registrar", "")[:255],
        creation_date=registration.get("Creation Date", "")[:64],
        expiry_date=registration.get("Registry Expiry Date", "")[:64],
        name_server_count=len(report.name_servers or []),
        dns_record_count=report.dns_records_count,
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )
    return {
        "ok": True,
        "saved": True,
        "lookup_id": str(lookup.pk),
        "domain": lookup.domain,
        "status": lookup.status,
        "redirect_url": reverse("whois_osint:detail", kwargs={"pk": lookup.pk}),
        "message": f"WHOIS and DNS lookup completed for {lookup.domain}.",
    }


@login_required
def module_home(request):
    lookups = DomainLookup.objects.filter(user=request.user)[:20]
    return render(
        request,
        "whois_osint/home.html",
        _home_context(request, DomainLookupForm(), lookups),
    )


@login_required
@require_http_methods(["POST"])
def run_lookup(request):
    lookups = DomainLookup.objects.filter(user=request.user)[:20]
    form = DomainLookupForm(request.POST)
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
            "whois_osint/home.html",
            _home_context(request, form, lookups),
        )

    result = _execute_lookup(request.user, form.cleaned_data["domain"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = DomainLookupForm(data={"domain": request.POST.get("domain", "")})
        form.add_error("domain", result.get("error"))
        return render(
            request,
            "whois_osint/home.html",
            _home_context(request, form, lookups),
        )

    if result.get("message"):
        level = messages.error if result.get("status") == "failed" else messages.success
        level(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def lookup_detail(request, pk):
    lookup = get_object_or_404(DomainLookup, pk=pk, user=request.user)
    report = lookup.report_json or {}
    sections = report.get("sections") or {}

    ordered_sections = []
    priority = ("Target",)
    for key in priority:
        if key in sections:
            ordered_sections.append((key, sections[key]))
    for key in sorted(sections.keys()):
        if key not in priority:
            ordered_sections.append((key, sections[key]))

    return render(
        request,
        "whois_osint/detail.html",
        {
            "lookup": lookup,
            "report": report,
            "metadata_sections": ordered_sections,
            "whois_raw": report.get("whois_raw", ""),
            "risk_flags": lookup.risk_flags or [],
            "active_module": "whois",
        },
    )


@login_required
def export_json(request, pk):
    lookup = get_object_or_404(DomainLookup, pk=pk, user=request.user)
    payload = {
        "id": str(lookup.pk),
        "domain": lookup.domain,
        "created_at": lookup.created_at.isoformat(),
        "status": lookup.status,
        "report": lookup.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="whois-{lookup.domain}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_lookup(request, pk):
    lookup = get_object_or_404(DomainLookup, pk=pk, user=request.user)
    lookup.delete()
    messages.info(request, "Domain lookup deleted.")
    return redirect("whois_osint:home")
