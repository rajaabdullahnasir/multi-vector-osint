from django import template
from django.utils.safestring import mark_safe

register = template.Library()

_ICON_PATHS = {
    "brand": (
        '<circle cx="12" cy="12" r="10"/>'
        '<line x1="22" x2="18" y1="12" y2="12"/>'
        '<line x1="6" x2="2" y1="12" y2="12"/>'
        '<line x1="12" x2="12" y1="6" y2="2"/>'
        '<line x1="12" x2="12" y1="22" y2="18"/>'
    ),
    "dashboard": (
        '<rect width="7" height="9" x="3" y="3" rx="1"/>'
        '<rect width="7" height="5" x="14" y="3" rx="1"/>'
        '<rect width="7" height="9" x="14" y="12" rx="1"/>'
        '<rect width="7" height="5" x="3" y="16" rx="1"/>'
    ),
    "image": (
        '<rect width="18" height="18" x="3" y="3" rx="2" ry="2"/>'
        '<circle cx="9" cy="9" r="2"/>'
        '<path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>'
    ),
    "globe": (
        '<circle cx="12" cy="12" r="10"/>'
        '<path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>'
        '<path d="M2 12h20"/>'
    ),
    "layers": (
        '<path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/>'
        '<path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/>'
        '<path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/>'
    ),
    "mail": (
        '<rect width="20" height="16" x="2" y="4" rx="2"/>'
        '<path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>'
    ),
    "shield-alert": (
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>'
        '<path d="M12 8v4"/>'
        '<path d="M12 16h.01"/>'
    ),
    "users": (
        '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>'
        '<circle cx="9" cy="7" r="4"/>'
        '<path d="M22 21v-2a4 4 0 0 0-3-3.87"/>'
        '<path d="M16 3.13a4 4 0 0 1 0 7.75"/>'
    ),
    "link": (
        '<path d="M9 17H7A5 5 0 0 1 7 7h2"/>'
        '<path d="M15 7h2a5 5 0 0 1 0 10h-2"/>'
        '<line x1="8" x2="16" y1="12" y2="12"/>'
    ),
    "hash": (
        '<line x1="4" x2="20" y1="9" y2="9"/>'
        '<line x1="4" x2="20" y1="15" y2="15"/>'
        '<line x1="10" x2="8" y1="3" y2="21"/>'
        '<line x1="16" x2="14" y1="3" y2="21"/>'
    ),
    "log-in": (
        '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/>'
        '<polyline points="10 17 15 12 10 7"/>'
        '<line x1="15" x2="3" y1="12" y2="12"/>'
    ),
    "log-out": (
        '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>'
        '<polyline points="16 17 21 12 16 7"/>'
        '<line x1="21" x2="9" y1="12" y2="12"/>'
    ),
    "user-plus": (
        '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>'
        '<circle cx="9" cy="7" r="4"/>'
        '<line x1="19" x2="19" y1="8" y2="14"/>'
        '<line x1="22" x2="16" y1="11" y2="11"/>'
    ),
    "chevron-right": '<path d="m9 18 6-6-6-6"/>',
    "external-link": (
        '<path d="M15 3h6v6"/>'
        '<path d="M10 14 21 3"/>'
        '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>'
    ),
    "arrow-left": '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
    "download": (
        '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
        '<polyline points="7 10 12 15 17 10"/>'
        '<line x1="12" x2="12" y1="15" y2="3"/>'
    ),
    "trash": (
        '<path d="M3 6h18"/>'
        '<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>'
        '<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>'
    ),
    "eye": (
        '<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/>'
        '<circle cx="12" cy="12" r="3"/>'
    ),
    "search": (
        '<circle cx="11" cy="11" r="8"/>'
        '<path d="m21 21-4.3-4.3"/>'
    ),
    "upload": (
        '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
        '<polyline points="17 8 12 3 7 8"/>'
        '<line x1="12" x2="12" y1="3" y2="15"/>'
    ),
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "x": '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    "alert-triangle": (
        '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/>'
        '<path d="M12 9v4"/>'
        '<path d="M12 17h.01"/>'
    ),
    "clock": '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    "activity": '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
    "bar-chart": (
        '<line x1="12" x2="12" y1="20" y2="10"/>'
        '<line x1="18" x2="18" y1="20" y2="4"/>'
        '<line x1="6" x2="6" y1="20" y2="16"/>'
    ),
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>',
    "user": (
        '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/>'
        '<circle cx="12" cy="7" r="4"/>'
    ),
    "lock": (
        '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>'
        '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
    ),
    "mail-check": (
        '<path d="M22 13V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v12c0 1.1.9 2 2 2h8"/>'
        '<path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>'
        '<path d="m16 19 2 2 4-4"/>'
    ),
    "map-pin": (
        '<path d="M20 10c0 4.993-5.539 10.193-7.399 11.799a1 1 0 0 1-1.202 0C9.539 20.193 4 14.993 4 10a8 8 0 0 1 16 0"/>'
        '<circle cx="12" cy="10" r="3"/>'
    ),
    "info": (
        '<circle cx="12" cy="12" r="10"/>'
        '<path d="M12 16v-4"/>'
        '<path d="M12 8h.01"/>'
    ),
    "copy": (
        '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>'
        '<path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>'
    ),
    "file-image": (
        '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/>'
        '<path d="M14 2v4a2 2 0 0 0 2 2h4"/>'
        '<circle cx="10" cy="12" r="2"/>'
        '<path d="m20 17-1.296-1.296a2.41 2.41 0 0 0-3.408 0L9 22"/>'
    ),
    "building": (
        '<rect width="16" height="20" x="4" y="2" rx="2" ry="2"/>'
        '<path d="M9 22v-4h6v4"/>'
        '<path d="M8 6h.01"/><path d="M16 6h.01"/>'
        '<path d="M12 6h.01"/><path d="M12 10h.01"/>'
        '<path d="M12 14h.01"/><path d="M16 10h.01"/>'
        '<path d="M16 14h.01"/><path d="M8 10h.01"/>'
        '<path d="M8 14h.01"/>'
    ),
}

_SIZE_PX = {
    "xs": 14,
    "sm": 16,
    "md": 18,
    "lg": 20,
    "xl": 24,
}


def render_icon(name: str, size: str = "md", class_name: str = "", label: str = "") -> str:
    paths = _ICON_PATHS.get(name, _ICON_PATHS["info"])
    px = _SIZE_PX.get(size, 18)
    classes = " ".join(part for part in ("ov-icon", f"ov-icon--{size}", class_name) if part)
    aria = f' aria-label="{label}" role="img"' if label else ' aria-hidden="true"'
    return mark_safe(
        f'<span class="{classes}"{aria}>'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{px}" height="{px}" '
        f'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round">{paths}</svg>'
        f"</span>"
    )


@register.simple_tag
def ov_icon(name, size="md", class_name=""):
    return render_icon(name, size=size, class_name=class_name)


@register.simple_tag
def ov_icon_labeled(name, label, size="md", class_name=""):
    return render_icon(name, size=size, class_name=class_name, label=label)
