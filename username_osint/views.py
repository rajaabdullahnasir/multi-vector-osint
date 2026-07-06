import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import UsernameLookupForm
from .models import UsernameLookup
from .services import UsernameOsintAnalyzer


def _home_context(request, form, lookups):
    return {
        "form": form,
        "lookups": lookups,
        "active_module": "username",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _execute_lookup(user, username: str) -> dict:
    report = UsernameOsintAnalyzer().analyze(username)

    if not report.success:
        if report.validation_failed:
            return {
                "ok": False,
                "validation_failed": True,
                "error": report.error,
            }

        lookup, _ = UsernameLookup.upsert_for_user(
            user,
            report.username or username,
            status=UsernameLookup.Status.FAILED,
            error_message=report.error or "Lookup failed.",
            found_count=0,
            checked_count=0,
            risk_flags=[],
            report_json=report.to_storage_dict(),
        )
        return {
            "ok": True,
            "saved": True,
            "lookup_id": str(lookup.pk),
            "username": lookup.username,
            "status": lookup.status,
            "redirect_url": reverse("username_osint:detail", kwargs={"pk": lookup.pk}),
            "message": report.error,
        }

    lookup, _ = UsernameLookup.upsert_for_user(
        user,
        report.username,
        status=UsernameLookup.Status.COMPLETED,
        error_message="",
        found_count=report.found_count,
        checked_count=report.checked_count,
        risk_flags=report.risk_flags or [],
        report_json=report.to_storage_dict(),
    )
    if report.found_count:
        msg = f"Found on {report.found_count} of {report.checked_count} platforms."
    else:
        msg = f"No profiles found across {report.checked_count} platforms."
    return {
        "ok": True,
        "saved": True,
        "lookup_id": str(lookup.pk),
        "username": lookup.username,
        "status": lookup.status,
        "redirect_url": reverse("username_osint:detail", kwargs={"pk": lookup.pk}),
        "message": msg,
    }


@login_required
def module_home(request):
    lookups = UsernameLookup.objects.filter(user=request.user)[:20]
    return render(
        request,
        "username_osint/home.html",
        _home_context(request, UsernameLookupForm(), lookups),
    )


@login_required
@require_http_methods(["POST"])
def run_lookup(request):
    lookups = UsernameLookup.objects.filter(user=request.user)[:20]
    form = UsernameLookupForm(request.POST)
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
        messages.error(request, "Fix the username field and try again.")
        return render(
            request,
            "username_osint/home.html",
            _home_context(request, form, lookups),
        )

    result = _execute_lookup(request.user, form.cleaned_data["username"])

    if wants_json:
        status = 422 if result.get("validation_failed") else 200
        return JsonResponse(result, status=status)

    if not result["ok"]:
        form = UsernameLookupForm(data={"username": request.POST.get("username", "")})
        form.add_error("username", result.get("error"))
        return render(
            request,
            "username_osint/home.html",
            _home_context(request, form, lookups),
        )

    if result.get("message"):
        level = messages.success if result["message"].startswith("No") else messages.warning
        level(request, result["message"])

    return redirect(result["redirect_url"])


@login_required
def lookup_detail(request, pk):
    lookup = get_object_or_404(UsernameLookup, pk=pk, user=request.user)
    report = lookup.report_json or {}
    sections = report.get("sections") or {}
    ordered_sections = []
    for key in ("Target", "Summary"):
        if key in sections:
            ordered_sections.append((key, sections[key]))
    for key in sorted(sections.keys()):
        if key not in ("Target", "Summary"):
            ordered_sections.append((key, sections[key]))

    platforms = report.get("platforms") or []
    found_platforms = [p for p in platforms if p.get("found")]
    inconclusive_platforms = [p for p in platforms if p.get("inconclusive") and not p.get("found")]
    not_found_platforms = [
        p for p in platforms if not p.get("found") and not p.get("inconclusive")
    ]

    return render(
        request,
        "username_osint/detail.html",
        {
            "lookup": lookup,
            "report": report,
            "metadata_sections": ordered_sections,
            "found_platforms": found_platforms,
            "not_found_platforms": not_found_platforms,
            "inconclusive_platforms": inconclusive_platforms,
            "risk_flags": lookup.risk_flags or [],
            "active_module": "username",
        },
    )


@login_required
def export_json(request, pk):
    lookup = get_object_or_404(UsernameLookup, pk=pk, user=request.user)
    payload = {
        "id": str(lookup.pk),
        "username": lookup.username,
        "created_at": lookup.created_at.isoformat(),
        "updated_at": lookup.updated_at.isoformat(),
        "status": lookup.status,
        "found_count": lookup.found_count,
        "checked_count": lookup.checked_count,
        "report": lookup.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="username-osint-{lookup.username}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_lookup(request, pk):
    lookup = get_object_or_404(UsernameLookup, pk=pk, user=request.user)
    lookup.delete()
    messages.info(request, "Username lookup deleted.")
    return redirect("username_osint:home")
