from django import forms

from .services.ip_validator import IPInputResolver


class IPIntelForm(forms.Form):
    query = forms.CharField(
        label="IP address or domain",
        max_length=253,
        help_text="e.g. 8.8.8.8 or example.com",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "8.8.8.8 or example.com",
                "autocomplete": "off",
                "spellcheck": "false",
                "required": "required",
            }
        ),
    )

    def clean_query(self):
        raw = self.cleaned_data.get("query", "")
        result = IPInputResolver().resolve(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.query_input
