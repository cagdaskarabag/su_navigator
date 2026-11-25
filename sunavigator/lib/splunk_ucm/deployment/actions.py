"""Email and webhook alert actions for deployed searches (D-072).

A drafter may ask for an email, a webhook or both. The request is part of the revision, so the approver sees
exactly what will be sent and where, and must acknowledge it. Nothing else is configurable: results are never
mailed or posted (only a link to them), script and log actions are refused, and every destination must pass the
administrator's allowlists in ``[actions]`` of ``ucm.conf``. The lists are empty by default, so nothing can be
sent until an administrator names the permitted mail domains and webhook hosts.
"""

import dataclasses
import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple
from urllib.parse import urlsplit

from ..errors import ValidationError

EMAIL, WEBHOOK = "email", "webhook"
KINDS = (EMAIL, WEBHOOK)
MAX_RECIPIENTS_LIMIT = 50
MAX_SUBJECT = 200
MAX_MESSAGE = 1000
MAX_URL = 500
_ADDRESS = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HOST = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9\-.]{0,251}[a-z0-9])?$")


@dataclasses.dataclass
class ActionPolicy:
    enabled: bool = True
    email_domains: Tuple[str, ...] = ()
    webhook_hosts: Tuple[str, ...] = ()
    webhook_allow_http: bool = False
    max_recipients: int = 10
    require_suppression: bool = True

    def public(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "email_domains": list(self.email_domains),
                "webhook_hosts": list(self.webhook_hosts), "webhook_allow_http": self.webhook_allow_http,
                "max_recipients": self.max_recipients, "require_suppression": self.require_suppression}


def parse_list(text: str) -> Tuple[str, ...]:
    values = []
    for item in str(text or "").replace(";", ",").split(","):
        item = item.strip().lower()
        if not item:
            continue
        if _HOST.match(item):
            values.append(item)
    return tuple(dict.fromkeys(values))


def _host_allowed(host: str, allowed: Sequence[str]) -> bool:
    host = host.lower()
    for entry in allowed:
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and len(host) > len(entry) - 1:
                return True
        elif host == entry:
            return True
    return False


def _clean_text(value: Any, name: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        raise ValidationError("%s is too long (at most %d characters)" % (name, limit))
    if _CONTROL.search(text):
        raise ValidationError("%s must be a single line without control characters" % name)
    return text


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("1", "true", "yes", "on")


def _email(raw: Dict[str, Any], policy: ActionPolicy) -> Dict[str, Any]:
    if not policy.email_domains:
        raise ValidationError("email actions are not allowed: an administrator has not listed any permitted mail "
                              "domains ([actions] email_domains in ucm.conf)")
    recipients: List[str] = []
    raw_to = raw.get("to")
    items = raw_to if isinstance(raw_to, list) else str(raw_to or "").replace(";", ",").split(",")
    for item in items:
        address = str(item).strip()
        if address:
            recipients.append(address.lower())
    recipients = list(dict.fromkeys(recipients))
    if not recipients:
        raise ValidationError("email needs at least one recipient")
    limit = min(policy.max_recipients, MAX_RECIPIENTS_LIMIT)
    if len(recipients) > limit:
        raise ValidationError("at most %d recipients are allowed" % limit)
    for address in recipients:
        match = _ADDRESS.match(address)
        if not match:
            raise ValidationError("invalid email address", {"value": address[:80]})
        if not _host_allowed(match.group(1), policy.email_domains):
            raise ValidationError("email domain %s is not on the permitted list" % match.group(1),
                                  {"allowed": list(policy.email_domains)})
    return {"to": recipients, "subject": _clean_text(raw.get("subject"), "email subject", MAX_SUBJECT),
            "message": _clean_text(raw.get("message"), "email message", MAX_MESSAGE),
            "include_link": _truthy(raw.get("include_link", True))}


def _webhook(raw: Dict[str, Any], policy: ActionPolicy) -> Dict[str, Any]:
    if not policy.webhook_hosts:
        raise ValidationError("webhook actions are not allowed: an administrator has not listed any permitted hosts "
                              "([actions] webhook_hosts in ucm.conf)")
    url = _clean_text(raw.get("url"), "webhook URL", MAX_URL)
    if not url or " " in url:
        raise ValidationError("webhook needs a URL without spaces")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        raise ValidationError("webhook URL is not valid")
    allowed_schemes = ("https", "http") if policy.webhook_allow_http else ("https",)
    if parts.scheme not in allowed_schemes:
        raise ValidationError("webhook URL must use %s" % " or ".join(allowed_schemes))
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValidationError("webhook URL must not contain credentials or a fragment")
    if not host or not _host_allowed(host, policy.webhook_hosts):
        raise ValidationError("webhook host %s is not on the permitted list" % (host or "?"),
                              {"allowed": list(policy.webhook_hosts)})
    return {"url": url}


def normalize_actions(raw: Any, policy: ActionPolicy, alert_mode: str, suppress_period: str) -> Dict[str, Any]:
    """Validated actions, or ``{}`` when none are requested. Unknown kinds are refused, never ignored."""
    if raw in (None, "", {}, []):
        return {}
    if not isinstance(raw, dict):
        raise ValidationError("actions must be an object with email and/or webhook")
    unknown = sorted(set(raw) - set(KINDS))
    if unknown:
        raise ValidationError("unsupported action %s; only email and webhook are available" % ", ".join(unknown))
    wanted = {k: v for k, v in raw.items() if isinstance(v, dict) and v.get("enabled", True) not in (False, "false", "0", 0)}
    if not wanted:
        return {}
    if not policy.enabled:
        raise ValidationError("alert actions are turned off ([actions] enabled in ucm.conf)")
    if alert_mode != "track":
        raise ValidationError("alert actions need the Alert type; a scheduled report would send on every run")
    if policy.require_suppression and not suppress_period:
        raise ValidationError("alert actions need 'Suppress repeats for' (for example 1h) so one condition does not "
                              "send a message on every run")
    out: Dict[str, Any] = {}
    if EMAIL in wanted:
        out[EMAIL] = _email(wanted[EMAIL], policy)
    if WEBHOOK in wanted:
        out[WEBHOOK] = _webhook(wanted[WEBHOOK], policy)
    return out


def validate_current(actions: Dict[str, Any], policy: ActionPolicy, alert_mode: str, suppress_period: str) -> None:
    """Re-check a frozen revision against today's policy (deploy, enable and rollback)."""
    if actions:
        normalize_actions(actions, policy, alert_mode, suppress_period)


def digest(actions: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(actions or {}, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def kinds(actions: Dict[str, Any]) -> List[str]:
    return [k for k in KINDS if (actions or {}).get(k)]


def settings(actions: Dict[str, Any]) -> Dict[str, str]:
    """Saved-search keys. Always writes every key so removing an action in a new revision switches it off."""
    actions = actions or {}
    out = {"actions": ",".join(kinds(actions)), "action.email": "0", "action.webhook": "0"}
    email = actions.get(EMAIL)
    if email:
        out.update({
            "action.email": "1", "action.email.to": ",".join(email["to"]),
            "action.email.include.results_link": "1" if email.get("include_link") else "0",
            "action.email.sendresults": "0", "action.email.sendcsv": "0", "action.email.sendpdf": "0",
            "action.email.inline": "0",
            "action.email.subject": email.get("subject") or "",
            "action.email.message.alert": email.get("message") or "",
        })
    webhook = actions.get(WEBHOOK)
    if webhook:
        out.update({"action.webhook": "1", "action.webhook.param.url": webhook["url"]})
    return out


def summary(actions: Dict[str, Any]) -> Dict[str, Any]:
    """What the audit trail records: counts and destinations without the webhook path (it may carry a token)."""
    out: Dict[str, Any] = {}
    email = (actions or {}).get(EMAIL)
    if email:
        out[EMAIL] = {"recipients": len(email["to"]),
                      "domains": sorted({a.split("@", 1)[1] for a in email["to"]})}
    webhook = (actions or {}).get(WEBHOOK)
    if webhook:
        out[WEBHOOK] = {"host": (urlsplit(webhook["url"]).hostname or "").lower()}
    return out


def _flag(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _list(value: Any) -> List[str]:
    return sorted(v.strip().lower() for v in str(value or "").split(",") if v.strip())


def drift(actions: Dict[str, Any], live: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Differences between the frozen revision's actions and the saved search."""
    out: List[Dict[str, Any]] = []
    actions = actions or {}
    expected_kinds = sorted(kinds(actions))
    observed_kinds = sorted(a.strip() for a in str(live.get("actions") or "").split(",") if a.strip())
    if expected_kinds != observed_kinds:
        out.append({"field": "actions", "expected": ",".join(expected_kinds), "observed": ",".join(observed_kinds)})
        return out
    email = actions.get(EMAIL)
    if email:
        if _list(live.get("action.email.to")) != sorted(email["to"]):
            out.append({"field": "action.email.to", "expected": ",".join(email["to"]),
                        "observed": live.get("action.email.to")})
        if str(live.get("action.email.subject") or "") != (email.get("subject") or ""):
            out.append({"field": "action.email.subject", "expected": email.get("subject") or "",
                        "observed": live.get("action.email.subject")})
        for key in ("action.email.sendresults", "action.email.sendcsv", "action.email.sendpdf", "action.email.inline"):
            if key in live and _flag(live.get(key)):
                out.append({"field": key, "expected": False, "observed": True})
    webhook = actions.get(WEBHOOK)
    if webhook and str(live.get("action.webhook.param.url") or "") != webhook["url"]:
        out.append({"field": "action.webhook.param.url", "detail": "webhook URL differs from the revision"})
    return out
