from django.urls import path

from . import views

app_name = "investigation_osint"

urlpatterns = [
    path("", views.module_home, name="home"),
    path("run/", views.run_investigation, name="run"),
    path("<uuid:pk>/", views.investigation_detail, name="detail"),
    path("<uuid:pk>/generate-ai-report/", views.generate_ai_report, name="generate_ai_report"),
    path("<uuid:pk>/export.json", views.export_json, name="export_json"),
    path("<uuid:pk>/delete/", views.delete_investigation, name="delete"),
]
