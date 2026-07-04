from django.urls import NoReverseMatch, reverse

MODULE_NAV = [
    {
        "slug": "image",
        "name": "Image OSINT",
        "description": "EXIF extraction, perceptual hash, reverse-search links",
        "url_name": "image_osint:home",
        "icon": "image",
        "abbr": "IM",
        "available": True,
    },
    {
        "slug": "whois",
        "name": "WHOIS & DNS",
        "description": "Registration data, name servers, public DNS records",
        "url_name": "whois_osint:home",
        "icon": "globe",
        "abbr": "WH",
        "available": True,
    },
    {
        "slug": "subdomain",
        "name": "Subdomain Finder",
        "description": "DNS wordlist probing and certificate transparency",
        "url_name": "subdomain_osint:home",
        "icon": "layers",
        "abbr": "SD",
        "available": True,
    },
    {
        "slug": "email-breach",
        "name": "Email Breach",
        "description": "XposedOrNot check-email breach name lookup",
        "url_name": "email_breach_osint:home",
        "icon": "mail",
        "abbr": "EM",
        "available": True,
    },
    {
        "slug": "password-breach",
        "name": "Password Breach",
        "description": "Pwned Passwords k-anonymity exposure check",
        "url_name": "password_breach_osint:home",
        "icon": "shield-alert",
        "abbr": "PW",
        "available": True,
    },
    {
        "slug": "username",
        "name": "Username OSINT",
        "description": "Public profile URL checks across platforms",
        "url_name": "username_osint:home",
        "icon": "users",
        "abbr": "UN",
        "available": True,
    },
    {
        "slug": "url-risk",
        "name": "URL Risk",
        "description": "Lexical heuristics and blacklist scoring",
        "url_name": "url_risk_osint:home",
        "icon": "link",
        "abbr": "UR",
        "available": True,
    },
    {
        "slug": "hasher",
        "name": "Password Hasher",
        "description": "Hash generation and digest comparison",
        "url_name": "password_hasher_osint:home",
        "icon": "hash",
        "abbr": "HS",
        "available": True,
    },
    {
        "slug": "org-footprint",
        "name": "Company Footprint",
        "description": "WHOIS org identity, mail security posture, HTTP headers, platform presence",
        "url_name": "org_footprint_osint:home",
        "icon": "building",
        "abbr": "CF",
        "available": True,
    },
    {
        "slug": "ip-intel",
        "name": "IP Intelligence",
        "description": "Geolocation, ASN/ISP, RDAP registration, and proxy/hosting detection",
        "url_name": "ip_intel_osint:home",
        "icon": "map-pin",
        "abbr": "IP",
        "available": True,
    },
]

NAMESPACE_TO_MODULE_SLUG = {
    "image_osint": "image",
    "whois_osint": "whois",
    "subdomain_osint": "subdomain",
    "email_breach_osint": "email-breach",
    "password_breach_osint": "password-breach",
    "username_osint": "username",
    "url_risk_osint": "url-risk",
    "password_hasher_osint": "hasher",
    "org_footprint_osint": "org-footprint",
    "ip_intel_osint": "ip-intel",
}

MODULE_ICON_BY_SLUG = {item["slug"]: item["icon"] for item in MODULE_NAV}


def _active_module_from_request(request):
    match = getattr(request, "resolver_match", None)
    if not match:
        return None
    if match.namespace == "core" and match.url_name == "dashboard":
        return "dashboard"
    return NAMESPACE_TO_MODULE_SLUG.get(match.namespace)


def resolve_module_nav():
    module_nav = []
    for mod in MODULE_NAV:
        item = dict(mod)
        href = None
        if item.get("available") and item.get("url_name"):
            try:
                href = reverse(item["url_name"])
            except NoReverseMatch:
                item["available"] = False
        item["href"] = href
        module_nav.append(item)
    return module_nav


def navigation(request):
    active_module = _active_module_from_request(request)
    if active_module == "dashboard":
        active_module_icon = "dashboard"
    else:
        active_module_icon = MODULE_ICON_BY_SLUG.get(active_module or "")
    return {
        "module_nav": resolve_module_nav(),
        "active_module": active_module,
        "active_module_icon": active_module_icon,
        "app_name": "OSINT Vector",
    }
