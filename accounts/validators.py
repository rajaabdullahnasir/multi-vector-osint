import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class StrongPasswordValidator:
    """
  SRS-4: 8+ chars, 1 uppercase, 1 number, 1 special character.
    """

    def validate(self, password, user=None):
        errors = []
        if len(password) < 8:
            errors.append(_("Password must be at least 8 characters long."))
        if not re.search(r"[A-Z]", password):
            errors.append(_("Password must contain at least one uppercase letter."))
        if not re.search(r"\d", password):
            errors.append(_("Password must contain at least one number."))
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;/'`~]", password):
            errors.append(_("Password must contain at least one special character."))
        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return _(
            "Your password must be at least 8 characters and include uppercase, "
            "a number, and a special character."
        )
