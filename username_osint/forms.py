from django import forms

from .services.username_validator import UsernameValidator


class UsernameLookupForm(forms.Form):
    username = forms.CharField(
        label="Username",
        max_length=32,
        help_text="Passive scan across public profile URLs (Sherlock-style).",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "johndoe",
                "autocomplete": "off",
                "spellcheck": "false",
                "required": "required",
            }
        ),
    )

    def clean_username(self):
        raw = self.cleaned_data.get("username", "")
        result = UsernameValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.username
