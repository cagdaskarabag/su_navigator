"""Minimal robots.txt support (RFC 9309 matching, plus Crawl-delay and Request-rate).

``urllib.robotparser`` ignores ``*`` and ``$`` in rules, which Lantern uses
(``Disallow: /Special:*``), so matching is implemented here.
"""

import re
from typing import List, Optional, Tuple

USER_AGENT_TOKEN = "sunavigator"


def _rule_regex(pattern: str):
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    regex = "".join(".*" if ch == "*" else re.escape(ch) for ch in body)
    return re.compile("^" + regex + ("$" if anchored else ""))


class RobotsPolicy:
    def __init__(self, rules: List[Tuple[bool, str]], crawl_delay: Optional[float] = None,
                 allow_all: bool = False, disallow_all: bool = False):
        self.rules = [(allow, pattern, _rule_regex(pattern)) for allow, pattern in rules if pattern]
        self.crawl_delay = crawl_delay
        self.allow_all = allow_all
        self.disallow_all = disallow_all

    @classmethod
    def allow_everything(cls) -> "RobotsPolicy":
        return cls([], allow_all=True)

    @classmethod
    def deny_everything(cls) -> "RobotsPolicy":
        return cls([], disallow_all=True)

    @classmethod
    def parse(cls, text: str, token: str = USER_AGENT_TOKEN) -> "RobotsPolicy":
        groups: List[Tuple[List[str], List[Tuple[bool, str]], Optional[float]]] = []
        agents: List[str] = []
        rules: List[Tuple[bool, str]] = []
        delay: Optional[float] = None
        in_rules = False
        for raw in (text or "").splitlines()[:5000]:
            line = raw.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            field, value = line.split(":", 1)
            field, value = field.strip().lower(), value.strip()
            if field == "user-agent":
                if in_rules:
                    groups.append((agents, rules, delay))
                    agents, rules, delay, in_rules = [], [], None, False
                agents.append(value.lower())
            elif field in ("allow", "disallow"):
                in_rules = True
                rules.append((field == "allow", value))
            elif field == "crawl-delay":
                in_rules = True
                try:
                    delay = max(delay or 0.0, float(value))
                except ValueError:
                    pass
            elif field == "request-rate":
                in_rules = True
                match = re.match(r"^(\d+)\s*/\s*(\d+)\s*([smhd]?)", value.lower())
                if match and int(match.group(1)) > 0:
                    unit = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(3)]
                    delay = max(delay or 0.0, int(match.group(2)) * unit / float(match.group(1)))
        if agents:
            groups.append((agents, rules, delay))
        token = token.lower()
        chosen = [g for g in groups if any(a != "*" and a in token for a in g[0])]
        if not chosen:
            chosen = [g for g in groups if "*" in g[0]]
        merged_rules: List[Tuple[bool, str]] = []
        merged_delay: Optional[float] = None
        for _agents, group_rules, group_delay in chosen:
            merged_rules.extend(group_rules)
            if group_delay is not None:
                merged_delay = max(merged_delay or 0.0, group_delay)
        return cls(merged_rules, merged_delay)

    def allowed(self, path_and_query: str) -> bool:
        if self.disallow_all:
            return False
        if self.allow_all:
            return True
        target = path_and_query or "/"
        best: Optional[Tuple[int, bool]] = None
        for allow, pattern, regex in self.rules:
            if regex.match(target):
                length = len(pattern)
                if best is None or length > best[0] or (length == best[0] and allow):
                    best = (length, allow)
        return True if best is None else best[1]
