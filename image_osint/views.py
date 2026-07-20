import json
from io import BytesIO

from django.conf import settings
from django.contrib import messages
from django.core.files.base import ContentFile
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import ImageUploadForm
from .models import ImageAnalysis
from .services import ImageOsintAnalyzer


@login_required
def module_home(request):
    analyses = ImageAnalysis.objects.filter(user=request.user)[:20]
    form = ImageUploadForm()
    return render(
        request,
        "image_osint/home.html",
        {
            "form": form,
            "analyses": analyses,
            "active_module": "image",
            "upload_max_bytes": settings.IMAGE_OSINT_MAX_BYTES,
            "upload_max_mb": settings.IMAGE_OSINT_MAX_BYTES // (1024 * 1024),
        },
    )


@login_required
@require_http_methods(["POST"])
def analyze_image(request):
    form = ImageUploadForm(request.POST, request.FILES)
    if not form.is_valid():
        messages.error(request, "Please select a valid image file.")
        return redirect("image_osint:home")

    uploaded = form.cleaned_data["image"]
    file_bytes = uploaded.read()

    analyzer = ImageOsintAnalyzer()
    report = analyzer.analyze(
        BytesIO(file_bytes),
        declared_name=uploaded.name,
        public_image_url=None,
    )

    analysis = ImageAnalysis.objects.create(
        user=request.user,
        original_filename=uploaded.name,
        image=ContentFile(file_bytes, name=uploaded.name),
        status=ImageAnalysis.Status.PENDING,
    )
    if not report.success:
        analysis.status = ImageAnalysis.Status.FAILED
        analysis.error_message = report.error or "Analysis failed."
        analysis.report_json = report.to_storage_dict()
        analysis.save()
        messages.error(request, analysis.error_message)
        return redirect("image_osint:detail", pk=analysis.pk)

    exif = report.exif or {}
    fingerprint = report.fingerprint or {}
    validation = report.validation or {}

    analysis.status = ImageAnalysis.Status.COMPLETED
    analysis.file_size_bytes = validation.get("size_bytes", 0)
    analysis.mime_type = validation.get("mime_type", "")
    analysis.detected_format = validation.get("detected_format", "")
    analysis.width = exif.get("width", 0)
    analysis.height = exif.get("height", 0)
    analysis.has_exif = bool(exif.get("has_exif"))
    analysis.perceptual_hash = fingerprint.get("perceptual_hash_hex", "")
    analysis.sha256_file = fingerprint.get("sha256_file", "")
    analysis.risk_flags = report.risk_flags or []
    analysis.report_json = report.to_storage_dict()
    analysis.save()

    messages.success(request, "Image analysis completed.")
    return redirect("image_osint:detail", pk=analysis.pk)


@login_required
def analysis_detail(request, pk):
    analysis = get_object_or_404(ImageAnalysis, pk=pk, user=request.user)
    report = analysis.report_json or {}
    exif = report.get("exif") or {}
    gps = exif.get("gps") or {}
    metadata_sections = exif.get("sections") or {}
    section_order = (
        "File",
        "EXIF",
        "GPS",
        "ICC_Profile",
        "MakerNote",
        "Thumbnail",
        "Composite",
        "PNG",
    )
    ordered_sections = [
        (name, metadata_sections[name])
        for name in section_order
        if name in metadata_sections and metadata_sections[name]
    ]
    for name, fields in metadata_sections.items():
        if name not in section_order and fields:
            ordered_sections.append((name, fields))

    return render(
        request,
        "image_osint/detail.html",
        {
            "analysis": analysis,
            "report": report,
            "exif": exif,
            "gps": gps,
            "metadata_sections": ordered_sections,
            "fingerprint": report.get("fingerprint") or {},
            "reverse_search": report.get("reverse_search") or [],
            "reverse_notice": report.get("reverse_search_notice", ""),
            "geo_context": report.get("geo_context"),
            "risk_flags": analysis.risk_flags or [],
            "active_module": "image",
        },
    )


@login_required
def export_json(request, pk):
    analysis = get_object_or_404(ImageAnalysis, pk=pk, user=request.user)
    payload = {
        "id": str(analysis.pk),
        "filename": analysis.original_filename,
        "created_at": analysis.created_at.isoformat(),
        "status": analysis.status,
        "report": analysis.report_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="image-osint-{analysis.pk}.json"'
    )
    return response


@login_required
@require_http_methods(["POST"])
def delete_analysis(request, pk):
    analysis = get_object_or_404(ImageAnalysis, pk=pk, user=request.user)
    if analysis.image:
        analysis.image.delete(save=False)
    analysis.delete()
    messages.info(request, "Investigation record deleted.")
    return redirect("image_osint:home")
