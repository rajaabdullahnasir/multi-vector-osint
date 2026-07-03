import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import HashCompareForm, HashGenerateForm
from .models import HashJob
from .services import PasswordHasherAnalyzer


def _home_context(request, hash_form, compare_form, jobs):
    return {
        "hash_form": hash_form,
        "compare_form": compare_form,
        "jobs": jobs,
        "active_module": "hasher",
    }


def _wants_json(request) -> bool:
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _save_job(user, report) -> HashJob:
    digest_count = len(report.hashes) if report.hashes else 0
    return HashJob.objects.create(
        user=user,
        mode=report.mode,
        algorithms=report.algorithms or [],
        digest_count=digest_count,
        matched=report.matched,
        status=HashJob.Status.COMPLETED,
        error_message="",
        report_json=report.to_storage_dict(),
        risk_flags=report.risk_flags or [],
    )


def _json_result(job: HashJob, message: str) -> dict:
    return {
        "ok": True,
        "saved": True,
        "job_id": str(job.pk),
        "mode": job.mode,
        "redirect_url": reverse("password_hasher_osint:detail", kwargs={"pk": job.pk}),
        "message": message,
    }


@login_required
def module_home(request):
    jobs = HashJob.objects.filter(user=request.user)[:20]
    return render(
        request,
        "password_hasher_osint/home.html",
        _home_context(request, HashGenerateForm(prefix="hash"), HashCompareForm(prefix="compare"), jobs),
    )


@login_required
@require_http_methods(["POST"])
def run_hash(request):
    jobs = HashJob.objects.filter(user=request.user)[:20]
    form = HashGenerateForm(request.POST, prefix="hash")
    wants_json = _wants_json(request)

    if not form.is_valid():
        if wants_json:
            return JsonResponse(
                {
                    "ok": False,
                    "validation_failed": True,
                    "errors": {
                        f: [str(e) for e in errs] for f, errs in form.errors.items()
                    },
                },
                status=422,
            )
        messages.error(request, "Fix the hash form and try again.")
        return render(
            request,
            "password_hasher_osint/home.html",
            _home_context(request, form, HashCompareForm(prefix="compare"), jobs),
        )

    report = PasswordHasherAnalyzer().generate_hashes(
        form.cleaned_data["plaintext"],
        form.cleaned_data["algorithms"],
    )

    if not report.success:
        if wants_json:
            return JsonResponse(
                {"ok": False, "error": report.error},
                status=422 if report.validation_failed else 400,
            )
        form.add_error(None, report.error)
        return render(
            request,
            "password_hasher_osint/home.html",
            _home_context(request, form, HashCompareForm(prefix="compare"), jobs),
        )

    job = _save_job(request.user, report)
    msg = f"Generated {job.digest_count} digest(s)."

    if wants_json:
        return JsonResponse(_json_result(job, msg))

    messages.success(request, msg)
    return redirect("password_hasher_osint:detail", pk=job.pk)


@login_required
@require_http_methods(["POST"])
def run_compare(request):
    jobs = HashJob.objects.filter(user=request.user)[:20]
    form = HashCompareForm(request.POST, prefix="compare")
    wants_json = _wants_json(request)

    if not form.is_valid():
        if wants_json:
            return JsonResponse(
                {
                    "ok": False,
                    "validation_failed": True,
                    "errors": {
                        f: [str(e) for e in errs] for f, errs in form.errors.items()
                    },
                },
                status=422,
            )
        messages.error(request, "Fix the compare form and try again.")
        return render(
            request,
            "password_hasher_osint/home.html",
            _home_context(request, HashGenerateForm(prefix="hash"), form, jobs),
        )

    report = PasswordHasherAnalyzer().compare(
        form.cleaned_data["plaintext"],
        form.cleaned_data["target_hash"],
        form.cleaned_data["algorithm"],
    )

    if not report.success:
        if wants_json:
            return JsonResponse(
                {"ok": False, "error": report.error},
                status=422 if report.validation_failed else 400,
            )
        form.add_error(None, report.error)
        return render(
            request,
            "password_hasher_osint/home.html",
            _home_context(request, HashGenerateForm(prefix="hash"), form, jobs),
        )

    job = _save_job(request.user, report)
    msg = "Hash matches." if job.matched else "Hash does not match."

    if wants_json:
        return JsonResponse(_json_result(job, msg))

    level = messages.success if job.matched else messages.warning
    level(request, msg)
    return redirect("password_hasher_osint:detail", pk=job.pk)


@login_required
def job_detail(request, pk):
    job = get_object_or_404(HashJob, pk=pk, user=request.user)
    report = job.report_json or {}
    sections = report.get("sections") or {}

    return render(
        request,
        "password_hasher_osint/detail.html",
        {
            "job": job,
            "report": report,
            "metadata_sections": list(sections.items()),
            "hashes": report.get("hashes") or [],
            "compare": report.get("compare"),
            "risk_flags": job.risk_flags or [],
            "active_module": "hasher",
        },
    )


@login_required
def export_json(request, pk):
    job = get_object_or_404(HashJob, pk=pk, user=request.user)
    payload = {
        "id": str(job.pk),
        "mode": job.mode,
        "created_at": job.created_at.isoformat(),
        "algorithms": job.algorithms,
        "digest_count": job.digest_count,
        "matched": job.matched,
        "report": job.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = f'attachment; filename="hash-job-{job.pk}.json"'
    return response


@login_required
@require_http_methods(["POST"])
def delete_job(request, pk):
    job = get_object_or_404(HashJob, pk=pk, user=request.user)
    job.delete()
    messages.info(request, "Hash job deleted.")
    return redirect("password_hasher_osint:home")
