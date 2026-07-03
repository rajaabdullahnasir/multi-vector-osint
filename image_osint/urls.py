from django.urls import path

from . import views

app_name = "image_osint"

urlpatterns = [
    path("", views.module_home, name="home"),
    path("analyze/", views.analyze_image, name="analyze"),
    path("<uuid:pk>/", views.analysis_detail, name="detail"),
    path("<uuid:pk>/export.json", views.export_json, name="export_json"),
    path("<uuid:pk>/delete/", views.delete_analysis, name="delete"),
]
