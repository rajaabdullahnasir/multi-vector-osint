from django.urls import path

from . import views

app_name = "password_breach_osint"

urlpatterns = [
    path("", views.module_home, name="home"),
    path("check/", views.run_check, name="check"),
    path("<uuid:pk>/", views.check_detail, name="detail"),
    path("<uuid:pk>/export.json", views.export_json, name="export_json"),
    path("<uuid:pk>/delete/", views.delete_check, name="delete"),
]
