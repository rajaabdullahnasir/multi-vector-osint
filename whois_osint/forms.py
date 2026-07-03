from django import forms

from .services.domain_validator import DOMAIN_HTML_PATTERN, DomainValidator


class DomainLookupForm(forms.Form):
    domain = forms.CharField(
        label="Domain name",
        max_length=253,
        help_text="e.g. example.com (no https:// prefix)",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "example.com",
                "autocomplete": "off",
                "spellcheck": "false",
                "inputmode": "url",
                "pattern": DOMAIN_HTML_PATTERN,
                "title": "Enter a valid domain such as example.com",
                "required": "required",
            }
        ),
    )

    def clean_domain(self):
        raw = self.cleaned_data.get("domain", "")
        result = DomainValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.domain
