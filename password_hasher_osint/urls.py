from django.urls import path

from . import views

app_name = "password_hasher_osint"

urlpatterns = [
    path("", views.module_home, name="home"),
    path("hash/", views.run_hash, name="hash"),
    path("compare/", views.run_compare, name="compare"),
    path("<uuid:pk>/", views.job_detail, name="detail"),
    path("<uuid:pk>/export.json", views.export_json, name="export_json"),
    path("<uuid:pk>/delete/", views.delete_job, name="delete"),
]
