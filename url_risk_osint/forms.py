from django import forms

from .services.url_validator import UrlValidator


class UrlRiskCheckForm(forms.Form):
    url = forms.URLField(
        label="URL",
        max_length=2048,
        assume_scheme="https",
        help_text="Lexical heuristics + static blacklist → Safe / Suspicious / Dangerous.",
        widget=forms.URLInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "https://example.com/path",
                "spellcheck": "false",
                "required": "required",
            }
        ),
    )

    def clean_url(self):
        raw = self.cleaned_data.get("url", "")
        result = UrlValidator().validate(str(raw))
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.url
