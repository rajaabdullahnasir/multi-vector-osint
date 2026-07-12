import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import InvestigationForm
from .models import Investigation
from .services import InvestigationEngine


def _home_context(request, form, records):
    return {"form": form, "records": records, "active_module": "investigation"}


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    return "application/json" in request.headers.get("Accept", "")


@login_required
def module_home(request):
    records = Investigation.objects.filter(user=request.user)[:20]
    return render(
        request,
        "investigation_osint/home.html",
        _home_context(request, InvestigationForm(), records),
    )


@login_required
@require_http_methods(["POST"])
def run_investigation(request):
    records = Investigation.objects.filter(user=request.user)[:20]
    form = InvestigationForm(request.POST)
    wants_json = _wants_json(request)

    if not form.is_valid():
        if wants_json:
            return JsonResponse(
                {
                    "ok": False,
                    "validation_failed": True,
                    "errors": {
                        field: [str(e) for e in errs] for field, errs in form.errors.items()
                    },
                },
                status=422,
            )
        messages.error(request, "Fix the highlighted field(s) and try again.")
        return render(request, "investigation_osint/home.html", _home_context(request, form, records))

    domain = form.cleaned_data["domain"]
    email_hint = form.cleaned_data.get("email_hint", "")
    username_hint = form.cleaned_data.get("username_hint", "")

    report = InvestigationEngine(request.user).run(domain, email_hint, username_hint)

    if not report.success:
        if wants_json:
            return JsonResponse(
                {"ok": False, "validation_failed": True, "error": report.error}, status=422
            )
        form.add_error("domain", report.error)
        return render(request, "investigation_osint/home.html", _home_context(request, form, records))

    record, _ = Investigation.upsert_for_user(
        request.user,
        report.domain,
        email_hint=email_hint,
        username_hint=username_hint,
        status=Investigation.Status.COMPLETED,
        modules_run=report.modules_run,
        emails_checked=report.emails_checked,
        ips_checked=report.ips_checked,
        usernames_checked=report.usernames_checked,
        overall_risk_level=report.overall_risk_level,
        risk_flags=report.risk_flags,
        report_json=report.to_storage_dict(),
    )

    redirect_url = reverse("investigation_osint:detail", kwargs={"pk": record.pk})
    if wants_json:
        return JsonResponse({"ok": True, "redirect_url": redirect_url, "record_id": str(record.pk)})

    messages.success(
        request,
        f"Investigation complete for {record.target_domain} — "
        f"{len(report.modules_run)} module(s) run.",
    )
    return redirect(redirect_url)


@login_required
def investigation_detail(request, pk):
    record = get_object_or_404(Investigation, pk=pk, user=request.user)
    report = record.report_json or {}
    return render(
        request,
        "investigation_osint/detail.html",
        {
            "record": record,
            "outcomes": report.get("outcomes") or [],
            "nodes": report.get("nodes") or [],
            "edges": report.get("edges") or [],
            "risk_flags": record.risk_flags or [],
            "active_module": "investigation",
        },
    )


@login_required
def export_json(request, pk):
    record = get_object_or_404(Investigation, pk=pk, user=request.user)
    payload = {
        "id": str(record.pk),
        "target_domain": record.target_domain,
        "created_at": record.created_at.isoformat(),
        "overall_risk_level": record.overall_risk_level,
        "report": record.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str), content_type="application/json"
    )
    response["Content-Disposition"] = (
        f'attachment; filename="investigation-{record.target_domain}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_investigation(request, pk):
    record = get_object_or_404(Investigation, pk=pk, user=request.user)
    record.delete()
    messages.info(request, "Investigation deleted.")
    return redirect("investigation_osint:home")
