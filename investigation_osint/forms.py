from django import forms

from email_breach_osint.services.email_validator import EmailValidator
from username_osint.services.username_validator import UsernameValidator
from whois_osint.services.domain_validator import DomainValidator


class InvestigationForm(forms.Form):
    domain = forms.CharField(
        label="Target domain",
        max_length=253,
        help_text="e.g. example.com — the investigation's starting point.",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "example.com",
                "autocomplete": "off",
                "spellcheck": "false",
                "required": "required",
            }
        ),
    )
    email_hint = forms.CharField(
        label="Known email (optional)",
        max_length=254,
        required=False,
        help_text="If you already know an associated email, it's checked directly instead of guessed.",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "person@example.com",
                "autocomplete": "off",
                "spellcheck": "false",
            }
        ),
    )
    username_hint = forms.CharField(
        label="Known username (optional)",
        max_length=64,
        required=False,
        help_text="If you already know an associated handle, it's checked directly instead of guessed.",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "johndoe",
                "autocomplete": "off",
                "spellcheck": "false",
            }
        ),
    )

    def clean_domain(self):
        raw = self.cleaned_data.get("domain", "")
        result = DomainValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.domain

    def clean_email_hint(self):
        raw = self.cleaned_data.get("email_hint", "").strip()
        if not raw:
            return ""
        result = EmailValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.email

    def clean_username_hint(self):
        raw = self.cleaned_data.get("username_hint", "").strip()
        if not raw:
            return ""
        result = UsernameValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.username
