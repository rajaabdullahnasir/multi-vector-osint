import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import DirBusterForm
from .models import DirBusterScan
from .services import DirBusterAnalyzer


def _home_context(request, form, records):
    return {"form": form, "records": records, "active_module": "dirbuster"}


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    return "application/json" in request.headers.get("Accept", "")


@login_required
def module_home(request):
    records = DirBusterScan.objects.filter(user=request.user)[:20]
    initial = {}
    prefill_target = request.GET.get("target", "").strip()
    if prefill_target:
        initial["target"] = prefill_target
    form = DirBusterForm(initial=initial)
    return render(request, "dirbuster_osint/home.html", _home_context(request, form, records))


@login_required
@require_http_methods(["POST"])
def run_scan(request):
    records = DirBusterScan.objects.filter(user=request.user)[:20]
    form = DirBusterForm(request.POST)
    wants_json = _wants_json(request)

    if not form.is_valid():
        errors_by_field = {f: [str(e) for e in errs] for f, errs in form.errors.items()}
        flat_message = " ".join(msg for errs in errors_by_field.values() for msg in errs)
        if wants_json:
            return JsonResponse(
                {
                    "ok": False,
                    "validation_failed": True,
                    "errors": errors_by_field,
                    "error": flat_message or "Please fix the highlighted field(s).",
                },
                status=422,
            )
        messages.error(request, "Fix the highlighted field(s) and try again.")
        return render(request, "dirbuster_osint/home.html", _home_context(request, form, records))

    target = form.cleaned_data["target"]
    tier = form.cleaned_data["wordlist_tier"]

    report = DirBusterAnalyzer().analyze(target, tier)

    if not report.success:
        if wants_json:
            return JsonResponse(
                {"ok": False, "validation_failed": True, "error": report.error}, status=422
            )
        form.add_error("target", report.error)
        return render(request, "dirbuster_osint/home.html", _home_context(request, form, records))

    record, _ = DirBusterScan.upsert_for_user(
        request.user,
        target,
        status=DirBusterScan.Status.COMPLETED,
        error_message="",
        base_url=report.base_url,
        host=report.host,
        wordlist_tier=report.wordlist_tier,
        checked_count=report.checked_count,
        found_count=report.found_count,
        redirect_count=report.redirect_count,
        forbidden_count=report.forbidden_count,
        filtered_count=report.filtered_count,
        risk_flags=report.risk_flags,
        report_json=report.to_storage_dict(),
    )

    redirect_url = reverse("dirbuster_osint:detail", kwargs={"pk": record.pk})
    if wants_json:
        return JsonResponse({"ok": True, "redirect_url": redirect_url, "record_id": str(record.pk)})

    messages.success(
        request,
        f"Directory scan complete for {record.host} — {record.found_count} found, "
        f"{record.filtered_count} soft-404 filtered.",
    )
    return redirect(redirect_url)


@login_required
def scan_detail(request, pk):
    record = get_object_or_404(DirBusterScan, pk=pk, user=request.user)
    report = record.report_json or {}
    entries = report.get("entries") or []

    return render(
        request,
        "dirbuster_osint/detail.html",
        {
            "record": record,
            "sections": report.get("sections") or {},
            "found": [e for e in entries if e["category"] == "found"],
            "redirects": [e for e in entries if e["category"] == "redirect"],
            "forbidden": [e for e in entries if e["category"] == "forbidden"],
            "filtered": [e for e in entries if e["category"] == "soft_404_filtered"],
            "errored": [e for e in entries if e["category"] == "error"],
            "risk_flags": record.risk_flags or [],
            "active_module": "dirbuster",
        },
    )


@login_required
def export_json(request, pk):
    record = get_object_or_404(DirBusterScan, pk=pk, user=request.user)
    payload = {
        "id": str(record.pk),
        "target": record.target,
        "host": record.host,
        "created_at": record.created_at.isoformat(),
        "status": record.status,
        "report": record.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str), content_type="application/json"
    )
    response["Content-Disposition"] = f'attachment; filename="dirbuster-{record.host}.json"'
    return response


@login_required
@require_http_methods(["POST"])
def delete_scan(request, pk):
    record = get_object_or_404(DirBusterScan, pk=pk, user=request.user)
    record.delete()
    messages.info(request, "Scan deleted.")
    return redirect("dirbuster_osint:home")
