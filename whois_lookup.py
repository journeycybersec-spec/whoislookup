# path: whois_lookup.py
import datetime
import sys
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple, Iterable

import whois

# Optional DNS lib for DS verification (strong DNSSEC signal)
try:
    import dns.resolver  # dnspython
    _DNSPY_AVAILABLE = True
except Exception:
    _DNSPY_AVAILABLE = False


# -------------------- core utils --------------------

def _now() -> datetime.datetime:
    return datetime.datetime.now()

def _get(w: Any, key: str, default: Any = None) -> Any:
    if isinstance(w, dict):
        return w.get(key, default)
    return getattr(w, key, default)

def _first_or_same(val: Any) -> Any:
    if isinstance(val, (list, tuple, set)):
        return next(iter(val), None)
    return val

def _as_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(x) for x in val if x is not None]
    return [str(val)]

def _safe_lower(s: Optional[str]) -> str:
    return (s or "").lower()

def _normalize_text(text: Optional[str]) -> str:
    if not text:
        return ""
    s = unicodedata.normalize("NFKD", text)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.casefold()
    s = re.sub(r"\s+", " ", s).strip()
    return s


# -------------------- formatting --------------------

def _format_datetime(dt: Any) -> str:
    if isinstance(dt, datetime.datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(dt, list):
        try:
            latest = dt[-1]
            if isinstance(latest, str):
                try:
                    latest = datetime.datetime.strptime(latest, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return latest
            return latest.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Invalid date format"
    if isinstance(dt, str):
        try:
            parsed = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%SZ")
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return dt
    return "N/A"

def _format_status(status: Any) -> str:
    vals = _as_list(status)
    return ", ".join(vals) if vals else "N/A"


# -------------------- fetching & metrics --------------------

def get_whois_data(domain: str):
    try:
        return whois.whois(domain)
    except Exception as e:
        print(f"Error: Could not fetch WHOIS data for {domain}")
        print(e)
        sys.exit(1)

def get_domain_age_days(whois_data: Any) -> int:
    creation_date = _get(whois_data, "creation_date")
    creation_date = _first_or_same(creation_date)
    if isinstance(creation_date, str):
        try:
            creation_date = datetime.datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return 0
    if not isinstance(creation_date, datetime.datetime):
        return 0
    return (_now() - creation_date).days


# -------------------- DNSSEC (with DS verification) --------------------

def verify_dnssec_via_dns(domain: str, timeout: float = 2.0) -> Optional[bool]:
    """
    Returns True if DS records exist; False if definitely none; None if not verifiable.
    Why: WHOIS text can be stale/ambiguous; DS proves signed delegation.
    """
    if not _DNSPY_AVAILABLE:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answer = resolver.resolve(domain.strip("."), "DS")
        return bool(answer and len(answer) > 0)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return False
    except Exception:
        return None  # timeouts/network/etc.

def normalize_dnssec(value) -> str:
    """
    Normalize WHOIS/RDAP dnssec to: 'signed' | 'unsigned' | 'unknown'.
    Treat ambiguous positives ('active/yes/enabled') as unknown; DS decides.
    """
    if value is None or value == "":
        return "unknown"
    if isinstance(value, bool):
        return "signed" if value else "unsigned"
    if isinstance(value, (list, tuple, set)):
        return normalize_dnssec(" ".join(str(v) for v in value if v is not None))

    s = _normalize_text(str(value))

    if "signeddelegation" in s:
        return "signed"

    if any(m in s for m in ("unsigned", "no", "inactive", "disabled", "off", "not signed", "not secure")):
        return "unsigned"

    if any(m in s for m in ("active", "enabled", "on", "valid", "yes", "dnssec")):
        return "unknown"

    return "unknown"

def get_dnssec_status(whois_data: Any, domain: Optional[str] = None) -> str:
    """
    Final DNSSEC status: 'signed' | 'unsigned' | 'unknown'.
    Prefers DS verification; downgrades false positives when DS missing.
    """
    raw = _get(whois_data, "dnssec", None)
    prelim = normalize_dnssec(raw)

    ds = None
    if domain:
        ds = verify_dnssec_via_dns(domain)

    if ds is True:
        return "signed"
    if ds is False:
        return "unsigned"
    return prelim


# -------------------- registrant privacy detection --------------------

PRIVACY_KEYWORDS = {
    "anonymous", "anonymized", "privacy", "private", "proxy", "redacted", "withheld",
    "protected", "masked", "hidden", "not disclosed", "not available", "n/a", "gdpr",
    "data protected", "redacted for privacy", "whois privacy", "whoisprotected",
    "the rdap server redacted the value",
    "privacy service", "privacy protection", "privacyguardian",
    "domains by proxy", "contact privacy", "whoisguard",
    "privacy limited", "privacy ltd", "namecheap whoisguard",
    "gandi privacy", "tucows contact privacy", "register.com private",
    "godaddy privacy", "hostmaster privacy", "redacted for gdpr",
    "withheld for privacy",
}
PRIVACY_EMAIL_DOMAINS = {
    "withheldforprivacy.com",
    "domainsbyproxy.com",
    "contactprivacy.com",
    "whoisguard.com",
    "privacyprotect.org",
    "1and1.com",
    "gandi.net",
    "registrar-servers.com",
    "namecheap.com",
    "tucows.com",
}
_PRIVACY_PATTERN = re.compile(
    r"|".join(re.escape(k) for k in sorted(PRIVACY_KEYWORDS, key=len, reverse=True)),
    flags=re.IGNORECASE,
)
_EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

CANDIDATE_KEYS_ORDER = [
    "registrant_org",
    "registrant_organization",
    "organization",
    "org",
    "owner_organization",
    "owner_org",
    "registrantOrganization",
    "registrant_name",
    "name",
]

def _iter_kv(obj: Any, path: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            newp = f"{path}.{k}" if path else str(k)
            yield from _iter_kv(v, newp)
    elif isinstance(obj, (list, tuple, set)):
        for idx, v in enumerate(obj):
            newp = f"{path}[{idx}]"
            yield from _iter_kv(v, newp)
    else:
        yield path, obj

def _collect_registrant_strings(whois_data: Any) -> List[str]:
    texts: List[str] = []
    for k in ["org", "organization", "registrant_org", "registrant_organization",
              "registrant", "registrant_name", "name", "email", "emails",
              "owner_org", "owner_organization"]:
        v = _get(whois_data, k, None)
        if v:
            texts.extend(_as_list(v))
    contacts = _get(whois_data, "contacts", None)
    if isinstance(contacts, dict):
        for role in ["registrant", "owner", "holder"]:
            c = contacts.get(role)
            if isinstance(c, dict):
                for ck in ["organization", "org", "name", "email", "address", "street"]:
                    if ck in c and c[ck]:
                        texts.extend(_as_list(c[ck]))
    for path, val in _iter_kv(whois_data):
        if val and isinstance(val, (str, int, float)):
            if "registrant" in path.lower():
                texts.append(str(val))
    entities = _get(whois_data, "entities", None)
    if isinstance(entities, list):
        for ent in entities:
            roles = _get(ent, "roles", []) or []
            if any(_safe_lower(r) in {"registrant", "holder"} for r in roles):
                v = _get(ent, "vcardArray", None)
                if isinstance(v, (list, tuple)) and len(v) == 2 and isinstance(v[1], list):
                    for item in v[1]:
                        if isinstance(item, (list, tuple)) and len(item) >= 4:
                            value = item[3]
                            if isinstance(value, str):
                                texts.append(value)
    normed, seen = [], set()
    for t in texts:
        n = _normalize_text(str(t))
        if n and n not in seen:
            seen.add(n); normed.append(n)
    return normed

def get_candidate_org(whois_data: Any) -> Optional[str]:
    contacts = _get(whois_data, "contacts", None)
    if isinstance(contacts, dict):
        reg = contacts.get("registrant")
        if isinstance(reg, dict):
            for k in ["organization", "org", "name"]:
                v = reg.get(k)
                if isinstance(v, str) and v.strip():
                    return v
    registrant = _get(whois_data, "registrant", None)
    if isinstance(registrant, dict):
        for k in ["organization", "org", "name"] + CANDIDATE_KEYS_ORDER:
            v = registrant.get(k)
            if isinstance(v, str) and v.strip():
                return v
    for k in CANDIDATE_KEYS_ORDER:
        v = _get(whois_data, k, None)
        if isinstance(v, str) and v.strip():
            return v
    return None

def _email_domain_hit(text: str) -> Optional[str]:
    m = _EMAIL_DOMAIN_RE.search(text)
    if not m:
        return None
    dom = m.group(1).lower()
    for p in PRIVACY_EMAIL_DOMAINS:
        if dom.endswith(p):
            return dom
    return None

def is_anonymous_any(texts: List[str]) -> Tuple[bool, Optional[str]]:
    for t in texts:
        m = _PRIVACY_PATTERN.search(t)
        if m:
            return True, m.group(0)
        dm = _email_domain_hit(t)
        if dm:
            return True, f"email_domain:{dm}"
    return False, None

def analyze_registrant_privacy(
    whois_data: Any,
    results: Optional[Dict[str, str]] = None,
    red_flags: Optional[List[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    results = results or {}
    red_flags = red_flags or []
    org_raw = get_candidate_org(whois_data)
    collected = _collect_registrant_strings(whois_data)
    if org_raw:
        n = _normalize_text(org_raw)
        if n and n not in collected:
            collected.append(n)
    hit, matched = is_anonymous_any(collected)
    if hit:
        results["Anonymous registrant detected"] = "Not Safe ❌"
        red_flags.append(f"Anonymous registrant detected (matched: '{matched}')")
    else:
        results["Anonymous registrant detected"] = "Safe ✅"
    return results, red_flags


# -------------------- red flags & reporting --------------------

def check_red_flags(domain: str, whois_data: Any) -> Tuple[Dict[str, str], str, Optional[str]]:
    results: Dict[str, str] = {}
    red_flags: List[str] = []

    # 1) New domain
    domain_age = get_domain_age_days(whois_data)
    if domain_age < 180:
        results["New domain (under 6 months)"] = "Not Safe ❌"
        red_flags.append("New domain (under 6 months)")
    else:
        results["New domain (under 6 months)"] = "Safe ✅"

    # 2) Anonymous registrant
    results, red_flags = analyze_registrant_privacy(whois_data, results, red_flags)

    # 3) Frequent ownership changes (placeholder)
    ownership_history = ownership_change_check(whois_data)
    if "frequent" in _safe_lower(ownership_history):
        results["Frequent ownership changes detected"] = "Not Safe ❌"
        red_flags.append("Frequent ownership changes detected")
    else:
        results["Frequent ownership changes detected"] = "Safe ✅"

    # 4) DNSSEC (verified)
    dnssec = get_dnssec_status(whois_data, domain)  # 'signed' | 'unsigned' | 'unknown'
    if dnssec != "signed":
        results["No DNSSEC found"] = "Not Safe ❌"
        red_flags.append(f"DNSSEC status: {dnssec}")
    else:
        results["No DNSSEC found"] = "Safe ✅"

    # 5) Offshore registrar (naive)
    registrar = _safe_lower(_get(whois_data, "registrar", ""))
    if registrar and "offshore" in registrar:
        results["Offshore registrar detected"] = "Not Safe ❌"
        red_flags.append("Offshore registrar detected")
    else:
        results["Offshore registrar detected"] = "Safe ✅"

    # Final judgment with Warning rule
    anon_not_safe = results.get("Anonymous registrant detected") == "Not Safe ❌"
    other_not_safe = any(
        v == "Not Safe ❌" and k != "Anonymous registrant detected"
        for k, v in results.items()
    )
    if other_not_safe:
        final_judgment = "Not Safe ❌"
        reason = None
    elif anon_not_safe:
        final_judgment = "Warning ⚠️"
        reason = "anonymous registrant only"
    else:
        final_judgment = "Safe ✅"
        reason = None

    return results, final_judgment, reason


# -------------------- placeholders kept for API parity --------------------

def ownership_change_check(whois_data: Any) -> str:
    registrar = _get(whois_data, "registrar", "") or ""
    return str(registrar)


# -------------------- CLI output --------------------

def whois_lookup(domain: str) -> None:
    print(f"\nPerforming WHOIS lookup for {domain}...\n")
    w = get_whois_data(domain)

    print(f"Domain Information for: {domain}")
    print("=" * 40)

    print(f"Registered On    : {_format_datetime(_get(w, 'creation_date'))}")
    print(f"Expires On       : {_format_datetime(_get(w, 'expiration_date'))}")
    print(f"Updated On       : {_format_datetime(_get(w, 'updated_date'))}")
    print(f"Domain Status    : {_format_status(_get(w, 'status'))}")

    name_servers = _as_list(_get(w, "name_servers"))
    print(f"Name Servers     : {', '.join(sorted(name_servers)) if name_servers else 'N/A'}")

    print("-" * 40)
    candidate_org = get_candidate_org(w) or "N/A"
    print(f"Registrant Organization : {candidate_org}")
    print(f"Domain Age (Days)      : {get_domain_age_days(w)} days")
    print(f"DNSSEC Status          : {get_dnssec_status(w, domain)}")

    results, final_judgment, reason = check_red_flags(domain, w)

    print("\nRed Flags Checklist:")
    for flag, result in results.items():
        print(f" - {flag}: {result}")

    print("\nFinal Judgment:")
    print(final_judgment)
    if final_judgment == "Warning ⚠️" and reason:
        print(f"Reason: {reason}")
    print("=" * 40)


# -------------------- entry --------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python whois_lookup.py <domain>")
        sys.exit(1)
    whois_lookup(sys.argv[1])
