from django import forms

from .services.password_validator import PasswordValidator


class PasswordBreachCheckForm(forms.Form):
    password = forms.CharField(
        label="Password",
        strip=False,
        help_text="Checked via k-anonymity — only SHA-1 hash prefix is sent to the API.",
        widget=forms.PasswordInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "Enter password to check",
                "autocomplete": "off",
                "required": "required",
            }
        ),
    )

    def clean_password(self):
        raw = self.cleaned_data.get("password", "")
        result = PasswordValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return raw
