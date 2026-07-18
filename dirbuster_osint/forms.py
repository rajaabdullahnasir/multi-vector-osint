from django import forms

from .services.target_validator import TargetValidator
from .services.wordlists import WORDLIST_LABELS


class DirBusterForm(forms.Form):
    target = forms.CharField(
        label="Target URL or domain",
        max_length=512,
        help_text="e.g. https://example.com or example.com — must be a site you're authorized to test.",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "https://example.com",
                "autocomplete": "off",
                "spellcheck": "false",
                "required": "required",
            }
        ),
    )
    wordlist_tier = forms.ChoiceField(
        label="Wordlist",
        choices=[(key, label) for key, label in WORDLIST_LABELS.items()],
        initial="quick",
        widget=forms.Select(attrs={"class": "ov-input"}),
    )

    def clean_target(self):
        raw = self.cleaned_data.get("target", "")
        result = TargetValidator().validate(raw)
        if not result.ok:
            raise forms.ValidationError(result.error)
        return raw.strip()
