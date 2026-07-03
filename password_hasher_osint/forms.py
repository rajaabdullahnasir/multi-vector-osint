from django import forms

from .services.hash_engine import ALGORITHMS, algorithm_label
from .services.input_validator import PasswordInputValidator


class HashGenerateForm(forms.Form):
    plaintext = forms.CharField(
        label="Password / text",
        widget=forms.PasswordInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "Enter text to hash",
                "autocomplete": "off",
                "required": "required",
            }
        ),
    )
    algorithms = forms.MultipleChoiceField(
        label="Algorithms",
        choices=[(a, algorithm_label(a)) for a in ALGORITHMS],
        initial=["sha256"],
        widget=forms.CheckboxSelectMultiple(),
    )

    def clean_plaintext(self):
        result = PasswordInputValidator().validate_text(
            self.cleaned_data.get("plaintext", ""),
            field_name="Password / text",
        )
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.value

    def clean_algorithms(self):
        selected = self.cleaned_data.get("algorithms") or []
        result = PasswordInputValidator().validate_algorithms(list(selected))
        if not result.ok:
            raise forms.ValidationError(result.error)
        return [a for a in selected if a in ALGORITHMS]


class HashCompareForm(forms.Form):
    plaintext = forms.CharField(
        label="Password / text",
        widget=forms.PasswordInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "Enter text to test",
                "autocomplete": "off",
                "required": "required",
            }
        ),
    )
    target_hash = forms.CharField(
        label="Target hash (hex)",
        widget=forms.TextInput(
            attrs={
                "class": "ov-input ov-input--mono",
                "placeholder": "e.g. 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                "spellcheck": "false",
                "required": "required",
            }
        ),
    )
    algorithm = forms.ChoiceField(
        label="Algorithm",
        choices=[
            ("md5", "MD5"),
            ("sha1", "SHA-1"),
            ("sha256", "SHA-256"),
            ("sha512", "SHA-512"),
        ],
        initial="sha256",
        widget=forms.Select(attrs={"class": "ov-input"}),
    )

    def clean_plaintext(self):
        result = PasswordInputValidator().validate_text(
            self.cleaned_data.get("plaintext", ""),
            field_name="Password / text",
        )
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.value

    def clean_target_hash(self):
        result = PasswordInputValidator().validate_text(
            self.cleaned_data.get("target_hash", ""),
            field_name="Target hash",
        )
        if not result.ok:
            raise forms.ValidationError(result.error)
        return result.value.strip()
