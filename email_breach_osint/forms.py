from django import forms

from .services.email_validator import EmailValidator


class EmailBreachCheckForm(forms.Form):
    email = forms.EmailField(
        label="Email address",
        max_length=254,
        help_text="Checked via XposedOrNot free public API (open-source, no key).",
        widget=forms.EmailInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "user@example.com",
                "autocomplete": "email",
                "spellcheck": "false",
                "required": "required",
            }
        ),
    )

    def clean_email(self):
        raw = self.cleaned_data.get("email", "")
        result = EmailValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.email
