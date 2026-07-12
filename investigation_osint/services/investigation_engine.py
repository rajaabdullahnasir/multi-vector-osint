"""
Investigation engine — the actual "multi-vector" part of multi-vector-osint.

Takes one starting domain (plus optional email/username hints) and pivots
automatically across modules the way a human analyst would:

    domain --WHOIS--> nameservers, registrant emails (if published)
    domain --Subdomain Finder--> hosts + resolved IPs
    each IP --IP Intelligence--> geolocation, ASN, proxy/hosting
    domain --Company Footprint--> SPF/DMARC, DMARC report email, social handles
    discovered/hinted emails --Email Breach--> breach exposure
    discovered/hinted username --Username OSINT--> cross-platform presence
    domain --URL Risk--> lexical + blacklist + live DNSBL

Every underlying analyzer is the same one already used (and fixed/tested)
by that module's own standalone page — this engine does not reimplement
any detection logic, it only chains real results together and persists a
real record into each module's own table via that module's own
upsert_for_user, so cross-navigation into the full individual report
always works.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from email_breach_osint.models import EmailBreachCheck
from email_breach_osint.services.analyzer import EmailBreachAnalyzer
from ip_intel_osint.models import IPIntelligence
from ip_intel_osint.services.analyzer import IPIntelAnalyzer
from org_footprint_osint.models import OrgFootprint
from org_footprint_osint.services.analyzer import OrgFootprintAnalyzer
from subdomain_osint.models import SubdomainScan
from subdomain_osint.services.analyzer import SubdomainAnalyzer
from url_risk_osint.models import UrlRiskCheck
from url_risk_osint.services.analyzer import UrlRiskAnalyzer
from username_osint.models import UsernameLookup
from username_osint.services.analyzer import UsernameOsintAnalyzer
from whois_osint.models import DomainLookup
from whois_osint.services.analyzer import DomainIntelAnalyzer
from whois_osint.services.domain_validator import DomainValidator

_MAX_IPS_TO_PIVOT = 5
_MAX_EMAILS_TO_CHECK = 3
_MAX_USERNAMES_TO_CHECK = 2

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_IP_FROM_RECORD_RE = re.compile(r"^A\s+(\d{1,3}(?:\.\d{1,3}){3})$")


@dataclass
class GraphNode:
    id: str
    type: str  # domain | ip | email | username | subdomain
    label: str


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str


@dataclass
class ModuleOutcome:
    module: str
    label: str
    key: str
    record_id: str | None
    url_name: str
    summary: str
    risk_contribution: list[str] = field(default_factory=list)
    ok: bool = True


@dataclass
class InvestigationReport:
    success: bool
    domain: str = ""
    error: str | None = None
    validation_failed: bool = False
    modules_run: list[str] = field(default_factory=list)
    outcomes: list[ModuleOutcome] = field(default_factory=list)
    nodes: list[dict[str, str]] = field(default_factory=list)
    edges: list[dict[str, str]] = field(default_factory=list)
    emails_checked: int = 0
    ips_checked: int = 0
    usernames_checked: int = 0
    overall_risk_level: str = "low"
    risk_flags: list[str] = field(default_factory=list)

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "domain": self.domain,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "modules_run": self.modules_run,
            "outcomes": [o.__dict__ for o in self.outcomes],
            "nodes": self.nodes,
            "edges": self.edges,
            "risk_flags": self.risk_flags,
        }


class InvestigationEngine:
    def __init__(self, user):
        self.user = user
        self.validator = DomainValidator()
        self.whois_analyzer = DomainIntelAnalyzer()
        self.subdomain_analyzer = SubdomainAnalyzer()
        self.org_analyzer = OrgFootprintAnalyzer()
        self.url_analyzer = UrlRiskAnalyzer()
        self.email_analyzer = EmailBreachAnalyzer()
        self.ip_analyzer = IPIntelAnalyzer()
        self.username_analyzer = UsernameOsintAnalyzer()

    def run(
        self, domain_input: str, email_hint: str = "", username_hint: str = ""
    ) -> InvestigationReport:
        validation = self.validator.validate(domain_input)
        if not validation.ok:
            return InvestigationReport(success=False, error=validation.error, validation_failed=True)

        domain = validation.domain
        nodes: list[GraphNode] = [GraphNode(id=domain, type="domain", label=domain)]
        edges: list[GraphEdge] = []
        outcomes: list[ModuleOutcome] = []
        modules_run: list[str] = []
        all_risk_flags: list[str] = []

        discovered_ips: set[str] = set()
        discovered_emails: set[str] = set()
        if email_hint:
            discovered_emails.add(email_hint.lower())

        # 1. WHOIS
        whois_report = self.whois_analyzer.analyze(domain)
        modules_run.append("whois")
        if whois_report.success:
            record, _ = DomainLookup.upsert_for_user(
                self.user,
                domain,
                status=DomainLookup.Status.COMPLETED,
                name_server_count=len(whois_report.name_servers or []),
                dns_record_count=whois_report.dns_records_count,
                report_json=whois_report.to_storage_dict(),
                risk_flags=whois_report.risk_flags or [],
            )
            for email in _EMAIL_RE.findall(whois_report.whois_raw or ""):
                discovered_emails.add(email.lower())
            outcomes.append(
                ModuleOutcome(
                    module="whois",
                    label="WHOIS & DNS",
                    key=domain,
                    record_id=str(record.pk),
                    url_name="whois_osint:detail",
                    summary=f"{whois_report.dns_records_count} DNS record(s), "
                    f"{len(whois_report.name_servers or [])} nameserver(s).",
                    risk_contribution=whois_report.risk_flags or [],
                )
            )
            all_risk_flags.extend(f"[WHOIS] {f}" for f in (whois_report.risk_flags or []))
        else:
            outcomes.append(
                ModuleOutcome(
                    module="whois", label="WHOIS & DNS", key=domain, record_id=None,
                    url_name="whois_osint:detail", summary=whois_report.error or "Lookup failed.",
                    ok=False,
                )
            )

        # 2. Subdomain Finder -> pivot IPs
        subdomain_report = self.subdomain_analyzer.analyze(domain)
        modules_run.append("subdomain")
        if subdomain_report.success:
            record, _ = SubdomainScan.upsert_for_user(
                self.user,
                domain,
                status=SubdomainScan.Status.COMPLETED,
                subdomain_count=subdomain_report.subdomain_count,
                dns_verified_count=subdomain_report.dns_verified_count,
                sources_used=subdomain_report.sources_used or [],
                report_json=subdomain_report.to_storage_dict(),
                risk_flags=subdomain_report.risk_flags or [],
            )
            for entry in subdomain_report.subdomains or []:
                host = entry.get("host", "")
                if host and host != domain and not host.startswith("*"):
                    nodes.append(GraphNode(id=host, type="subdomain", label=host))
                    edges.append(GraphEdge(source=domain, target=host, relation="subdomain"))
                for rec in entry.get("records", []):
                    match = _IP_FROM_RECORD_RE.match(rec)
                    if match:
                        ip = match.group(1)
                        discovered_ips.add(ip)
                        edges.append(
                            GraphEdge(
                                source=host or domain, target=ip, relation="resolves_to"
                            )
                        )
            outcomes.append(
                ModuleOutcome(
                    module="subdomain",
                    label="Subdomain Finder",
                    key=domain,
                    record_id=str(record.pk),
                    url_name="subdomain_osint:detail",
                    summary=f"{subdomain_report.subdomain_count} host(s) discovered, "
                    f"{len(discovered_ips)} unique IP(s) for pivoting.",
                    risk_contribution=subdomain_report.risk_flags or [],
                )
            )
            all_risk_flags.extend(f"[Subdomain] {f}" for f in (subdomain_report.risk_flags or []))
        else:
            outcomes.append(
                ModuleOutcome(
                    module="subdomain", label="Subdomain Finder", key=domain, record_id=None,
                    url_name="subdomain_osint:detail", summary=subdomain_report.error or "Scan failed.",
                    ok=False,
                )
            )

        # 3. Company Footprint -> DMARC report email + social handles
        org_report = self.org_analyzer.analyze(domain)
        modules_run.append("org-footprint")
        social_handles: list[str] = []
        if org_report.success:
            record, _ = OrgFootprint.upsert_for_user(
                self.user,
                domain,
                status=OrgFootprint.Status.COMPLETED,
                org_name=org_report.org_name[:255],
                spf_status=org_report.spf_status,
                dmarc_status=org_report.dmarc_status,
                security_header_score=org_report.security_header_score,
                risk_flags=org_report.risk_flags or [],
                report_json=org_report.to_storage_dict(),
            )
            dmarc_text = (org_report.sections or {}).get("Mail Security Posture", {}).get("DMARC", "")
            for email in _EMAIL_RE.findall(dmarc_text or ""):
                discovered_emails.add(email.lower())
            platform_section = (org_report.sections or {}).get("Official Platform Presence", {})
            slug = platform_section.get("Guessed handle", "")
            if slug:
                social_handles.append(slug)
            outcomes.append(
                ModuleOutcome(
                    module="org-footprint",
                    label="Company Footprint",
                    key=domain,
                    record_id=str(record.pk),
                    url_name="org_footprint_osint:detail",
                    summary=f"SPF {org_report.spf_status}, DMARC {org_report.dmarc_status}, "
                    f"{org_report.security_header_score}/4 security headers.",
                    risk_contribution=org_report.risk_flags or [],
                )
            )
            all_risk_flags.extend(f"[Company Footprint] {f}" for f in (org_report.risk_flags or []))
        else:
            outcomes.append(
                ModuleOutcome(
                    module="org-footprint", label="Company Footprint", key=domain, record_id=None,
                    url_name="org_footprint_osint:detail", summary=org_report.error or "Scan failed.",
                    ok=False,
                )
            )

        # 4. URL Risk on the main site
        url_report = self.url_analyzer.analyze(f"https://{domain}")
        modules_run.append("url-risk")
        if url_report.success:
            record, _ = UrlRiskCheck.upsert_for_user(
                self.user,
                f"https://{domain}",
                status="completed",
                risk_level=url_report.risk_level,
                risk_score=url_report.risk_score,
                report_json=url_report.to_storage_dict(),
                risk_flags=url_report.risk_flags or [],
            )
            outcomes.append(
                ModuleOutcome(
                    module="url-risk",
                    label="URL Risk",
                    key=f"https://{domain}",
                    record_id=str(record.pk),
                    url_name="url_risk_osint:detail",
                    summary=f"Risk level: {url_report.risk_level.title()} "
                    f"({url_report.risk_score}/100).",
                    risk_contribution=url_report.risk_flags or [],
                )
            )
            all_risk_flags.extend(f"[URL Risk] {f}" for f in (url_report.risk_flags or []))
        else:
            outcomes.append(
                ModuleOutcome(
                    module="url-risk", label="URL Risk", key=f"https://{domain}", record_id=None,
                    url_name="url_risk_osint:detail", summary=url_report.error or "Check failed.",
                    ok=False,
                )
            )

        # 5. IP Intelligence — pivot on discovered IPs (capped)
        ips_checked = 0
        for ip in list(discovered_ips)[:_MAX_IPS_TO_PIVOT]:
            ip_report = self.ip_analyzer.analyze(ip)
            ips_checked += 1
            if ip_report.success:
                record, _ = IPIntelligence.upsert_for_user(
                    self.user,
                    ip,
                    status=IPIntelligence.Status.COMPLETED,
                    ip_address=ip_report.ip,
                    country=ip_report.country[:8],
                    city=ip_report.city[:128],
                    isp=ip_report.isp[:255],
                    is_proxy_or_vpn=ip_report.is_proxy_or_vpn,
                    is_hosting=ip_report.is_hosting,
                    risk_flags=ip_report.risk_flags or [],
                    report_json=ip_report.to_storage_dict(),
                )
                nodes.append(GraphNode(id=ip, type="ip", label=f"{ip} ({ip_report.city or ip_report.country or '—'})"))
                outcomes.append(
                    ModuleOutcome(
                        module="ip-intel",
                        label=f"IP Intelligence — {ip}",
                        key=ip,
                        record_id=str(record.pk),
                        url_name="ip_intel_osint:detail",
                        summary=f"{ip_report.city or '—'}, {ip_report.country or '—'} · "
                        f"{ip_report.isp or 'Unknown ISP'}"
                        + (" · proxy/VPN flagged" if ip_report.is_proxy_or_vpn else "")
                        + (" · hosting IP" if ip_report.is_hosting else ""),
                        risk_contribution=ip_report.risk_flags or [],
                    )
                )
                all_risk_flags.extend(f"[IP {ip}] {f}" for f in (ip_report.risk_flags or []))
        if "ip-intel" not in modules_run and ips_checked:
            modules_run.append("ip-intel")

        # 6. Email Breach — hint + discovered (capped)
        emails_checked = 0
        for email in list(discovered_emails)[:_MAX_EMAILS_TO_CHECK]:
            email_report = self.email_analyzer.analyze(email)
            emails_checked += 1
            if email_report.success:
                record, _ = EmailBreachCheck.upsert_for_user(
                    self.user,
                    email,
                    status="completed",
                    breach_count=email_report.breach_count,
                    is_pwned=email_report.is_pwned,
                    risk_flags=email_report.risk_flags or [],
                    report_json=email_report.to_storage_dict(),
                )
                nodes.append(GraphNode(id=email, type="email", label=email))
                edges.append(GraphEdge(source=domain, target=email, relation="associated_email"))
                outcomes.append(
                    ModuleOutcome(
                        module="email-breach",
                        label=f"Email Breach — {email}",
                        key=email,
                        record_id=str(record.pk),
                        url_name="email_breach_osint:detail",
                        summary=(
                            f"Found in {email_report.breach_count} breach(es)."
                            if email_report.is_pwned
                            else "No known breaches."
                        ),
                        risk_contribution=email_report.risk_flags or [],
                    )
                )
                all_risk_flags.extend(f"[Email {email}] {f}" for f in (email_report.risk_flags or []))
        if "email-breach" not in modules_run and emails_checked:
            modules_run.append("email-breach")

        # 7. Username OSINT — hint or guessed from domain slug
        usernames_checked = 0
        username_candidates = []
        if username_hint:
            username_candidates.append(username_hint)
        else:
            slug = domain.split(".")[0]
            if slug and slug not in username_candidates:
                username_candidates.append(slug)
            for handle in social_handles:
                if handle not in username_candidates:
                    username_candidates.append(handle)

        for username in username_candidates[:_MAX_USERNAMES_TO_CHECK]:
            username_report = self.username_analyzer.analyze(username)
            usernames_checked += 1
            if username_report.success:
                record, _ = UsernameLookup.upsert_for_user(
                    self.user,
                    username,
                    status="completed",
                    found_count=username_report.found_count,
                    checked_count=username_report.checked_count,
                    report_json=username_report.to_storage_dict(),
                    risk_flags=username_report.risk_flags or [],
                )
                nodes.append(GraphNode(id=username, type="username", label=f"@{username}"))
                edges.append(GraphEdge(source=domain, target=username, relation="guessed_handle"))
                outcomes.append(
                    ModuleOutcome(
                        module="username",
                        label=f"Username OSINT — {username}",
                        key=username,
                        record_id=str(record.pk),
                        url_name="username_osint:detail",
                        summary=f"Found on {username_report.found_count} platform(s) "
                        f"of {username_report.checked_count} checked.",
                        risk_contribution=username_report.risk_flags or [],
                    )
                )
                all_risk_flags.extend(f"[Username {username}] {f}" for f in (username_report.risk_flags or []))
        if "username" not in modules_run and usernames_checked:
            modules_run.append("username")

        overall_risk = self._compute_overall_risk(url_report, outcomes)

        return InvestigationReport(
            success=True,
            domain=domain,
            modules_run=modules_run,
            outcomes=outcomes,
            nodes=[n.__dict__ for n in nodes],
            edges=[e.__dict__ for e in edges],
            emails_checked=emails_checked,
            ips_checked=ips_checked,
            usernames_checked=usernames_checked,
            overall_risk_level=overall_risk,
            risk_flags=all_risk_flags,
        )

    def _compute_overall_risk(self, url_report, outcomes: list[ModuleOutcome]) -> str:
        if url_report.success and url_report.risk_level == "dangerous":
            return "critical"
        for outcome in outcomes:
            if outcome.module == "email-breach" and outcome.summary.startswith("Found in"):
                return "critical"
        elevated_signals = sum(len(outcome.risk_contribution) for outcome in outcomes)
        if elevated_signals >= 4:
            return "elevated"
        if elevated_signals >= 1:
            return "moderate"
        return "low"
