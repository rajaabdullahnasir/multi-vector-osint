from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("whois_osint", "0003_domainlookup_subdomain_count"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="domainlookup",
            name="subdomain_count",
        ),
    ]
