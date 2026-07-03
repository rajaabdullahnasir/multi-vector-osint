from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("whois_osint", "0002_domainlookup_user_domain_unique"),
    ]

    operations = [
        migrations.AddField(
            model_name="domainlookup",
            name="subdomain_count",
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]
