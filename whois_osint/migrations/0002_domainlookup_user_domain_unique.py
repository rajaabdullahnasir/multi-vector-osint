from django.conf import settings
from django.db import migrations, models


def dedupe_domain_lookups(apps, schema_editor):
    DomainLookup = apps.get_model("whois_osint", "DomainLookup")
    seen = {}
    duplicates = []

    for lookup in DomainLookup.objects.order_by("-updated_at", "-created_at"):
        key = (lookup.user_id, lookup.domain.lower())
        if key in seen:
            duplicates.append(lookup.pk)
        else:
            seen[key] = lookup.pk

    if duplicates:
        DomainLookup.objects.filter(pk__in=duplicates).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("whois_osint", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RunPython(dedupe_domain_lookups, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="domainlookup",
            constraint=models.UniqueConstraint(
                fields=("user", "domain"),
                name="whois_domainlookup_user_domain_uniq",
            ),
        ),
        migrations.AlterModelOptions(
            name="domainlookup",
            options={"ordering": ["-updated_at", "-created_at"]},
        ),
    ]
