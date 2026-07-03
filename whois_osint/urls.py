from django.urls import path

from . import views

app_name = "whois_osint"

urlpatterns = [
    path("", views.module_home, name="home"),
    path("lookup/", views.run_lookup, name="lookup"),
    path("<uuid:pk>/", views.lookup_detail, name="detail"),
    path("<uuid:pk>/export.json", views.export_json, name="export_json"),
    path("<uuid:pk>/delete/", views.delete_lookup, name="delete"),
]
