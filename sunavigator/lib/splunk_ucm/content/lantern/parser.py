"""Classify Splunk Lantern pages and extract collections and articles.

The extractor only reports what the page contains: every field is copied or
derived from page text, nothing is generated. Fields the page does not provide
stay empty and lower the extraction confidence.
"""

import dataclasses
import html as htmllib
import re
from typing import Any, Dict, List, Optional, Tuple

from ...util import sha256_json
from .html import Node, parse_html
from .urls import (BASE_URL, HOST, path_segments, record_id_for, resolve_link, segment_label,
                   try_canonical)

EXTRACTION_VERSION = "lantern-extract-1.0.0"
RAW_SCHEMA = "sun.lantern.article/1"

KIND_ARTICLE = "article"
KIND_COLLECTION = "collection"
KIND_UNSUPPORTED = "unsupported"

MAX_BLOCKS = 1500
MAX_BLOCK_CHARS = 20000
MAX_CODE_CHARS = 65536
MAX_TABLE_ROWS = 200
MAX_TABLE_COLS = 20
MAX_TEXT_CHARS = 400000

# Regions that are navigation, chrome or embedded widgets rather than page content.
_NOISE_CLASSES = {"mt-content-footer", "mt-author-container", "mt-toc-content", "mt-tags", "mt-classification",
                  "mt-related-listings-container", "elm-related-articles-container", "mt-video-widget",
                  "mt-social-share", "use-cases-buttons-group", "use-case-button", "mt-self-link",
                  "mt-breadcrumbs", "elm-nav", "mt-feedback", "mt-page-rating"}
_NOISE_IDS = {"surveyContainer", "mt-toc-container", "feedbackButton"}
_NOISE_TAGS = {"nav", "footer", "aside", "form", "header"}

_SECTION_KEYWORDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("prerequisites", ("prerequisite", "before you begin", "requirements", "what you need")),
    ("data", ("data required", "required data", "data sources", "data source")),
    ("software", ("software", "apps and add-ons", "required apps", "products required")),
    ("value", ("possible outcomes", "expected outcomes", "outcomes", "business value", "benefits",
               "why this matters", "understanding why this matters", "solving the business problem")),
    ("related", ("next steps", "additional resources", "related resources", "related articles", "learn more",
                 "resources")),
    ("implementation", ("how to use", "how splunk", "procedure", "implementation", "implement", "steps",
                        "recommended solutions", "solution", "deploy", "configur", "set up", "setting up",
                        "instructions", "workflow", "search", "architecture", "connecting", "installing")),
]
_SPL_START = re.compile(r"^\s*(\||index\s*=|sourcetype\s*=|search\s|tstats\s|from\s|`[a-z0-9_]+`|\(index=|"
                        r"datamodel\s*=|eventtype\s*=|source\s*=)", re.IGNORECASE)
_SPL_COMMANDS = re.compile(r"\|\s*(stats|tstats|eval|where|table|timechart|chart|rex|lookup|inputlookup|search|"
                           r"fields|dedup|sort|rename|transaction|iplocation|bin|top|rare|join|append|"
                           r"spath|mstats|makeresults|fillnull|streamstats|eventstats)\b", re.IGNORECASE)
_MITRE = re.compile(r"\b(T[0-9]{4}(?:\.[0-9]{3})?)\b")
_SPLUNKBASE = re.compile(r"^https://splunkbase\.splunk\.com/app/([0-9]{1,7})", re.IGNORECASE)
_GENERIC_HEADINGS = re.compile(r"^(explore .*guidance.*|explore more .*|related .*|featured.*)$", re.IGNORECASE)
_WS = re.compile(r"\s+")
_BLOCKISH = {"p", "div", "ul", "ol", "table", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "dl", "dt", "dd",
             "section", "blockquote", "li", "article", "figure"}


@dataclasses.dataclass
class PageMeta:
    url: str
    canonical_url: str
    title: str
    description: str
    page_type: str
    body_classes: List[str]
    breadcrumbs: List[Dict[str, str]]
    published: str
    modified: str
    classifications: Dict[str, List[str]]
    tags: List[str]
    authors: str
    generator: str


@dataclasses.dataclass
class ParsedPage:
    meta: PageMeta
    root: Node
    content: Optional[Node]
    content_fallback: bool


@dataclasses.dataclass
class Classification:
    kind: str
    reason: str
    signals: List[str]


def clean(text: str) -> str:
    return _WS.sub(" ", htmllib.unescape(text or "").replace("\xa0", " ").replace("\u200b", "")).strip()


def _is_noise(node: Node) -> bool:
    if node.tag in _NOISE_TAGS:
        return True
    if node.get("id") in _NOISE_IDS:
        return True
    return any(c in _NOISE_CLASSES for c in node.classes)


def _meta(root: Node, *names: str) -> str:
    for name in names:
        node = root.find(lambda n: n.tag == "meta" and (n.get("property") == name or n.get("name") == name))
        if node is not None and node.get("content"):
            return clean(node.get("content"))
    return ""


def _page_type(classes: List[str]) -> str:
    for name, label in (("columbia-page-home", "home"), ("columbia-article-topic-category", "category"),
                        ("columbia-article-topic-guide", "guide"), ("columbia-article-howto", "howto"),
                        ("columbia-article-reference", "reference"), ("columbia-article-topic", "topic")):
        if name in classes:
            return label
    return "unknown"


def parse_page(text: str, url: str) -> ParsedPage:
    root = parse_html(text)
    body = root.find(lambda n: n.tag == "body")
    classes = body.classes if body is not None else []
    h1 = root.find(lambda n: n.tag == "h1" and n.get("id") == "title") or root.find(lambda n: n.tag == "h1")
    title = clean(h1.text()) if h1 is not None else ""
    if not title:
        title = _meta(root, "og:title")
    canonical = ""
    link = root.find(lambda n: n.tag == "link" and n.get("rel").lower() == "canonical")
    if link is not None:
        canonical = try_canonical(link.get("href"))[0] or ""
    breadcrumbs: List[Dict[str, str]] = []
    trail = root.find(lambda n: n.tag == "ol" and n.has_class("mt-breadcrumbs"))
    if trail is not None:
        for anchor in trail.find_all(lambda n: n.tag == "a"):
            crumb_url = try_canonical(anchor.get("href"))[0]
            label = clean(anchor.text())
            if crumb_url and label and crumb_url != BASE_URL + "/":
                breadcrumbs.append({"title": label, "url": crumb_url})
    classifications: Dict[str, List[str]] = {}
    for label_node in root.find_all(lambda n: n.tag == "dt" and n.has_class("mt-classification-label")):
        label = clean(label_node.text())
        siblings = label_node.parent.children if label_node.parent else []
        idx = siblings.index(label_node)
        for sib in siblings[idx + 1:]:
            if isinstance(sib, Node) and sib.tag == "dt":
                break
            if isinstance(sib, Node) and sib.tag == "dd":
                value = clean(sib.text())
                if label and value:
                    classifications.setdefault(label, [])
                    for part in [v.strip() for v in value.split(",")] if label != "Author Name" else [value]:
                        if part and part not in classifications[label]:
                            classifications[label].append(part)
    tags: List[str] = []
    tag_block = root.find(lambda n: n.tag == "dl" and n.has_class("mt-tags"))
    if tag_block is not None:
        for anchor in tag_block.find_all(lambda n: n.tag == "a"):
            value = clean(anchor.text())
            if value and value not in tags:
                tags.append(value)
    authors = ", ".join(classifications.get("Author Name", []))
    if not authors:
        author = root.find(lambda n: n.has_class("mt-author-information"))
        if author is not None:
            authors = re.sub(r"^Written by\s*", "", clean(author.text()))
    modified = _meta(root, "article:modified_time")
    stamp = root.find(lambda n: n.has_class("mt-last-updated") and bool(n.get("data-timestamp")))
    if stamp is not None:
        modified = clean(stamp.get("data-timestamp")) or modified
    content = root.find(lambda n: n.tag == "section" and n.has_class("mt-content-container"))
    fallback = False
    if content is None:
        fallback = True
        content = (root.find(lambda n: n.tag == "article") or root.find(lambda n: n.tag == "main")
                   or body or root)
    meta = PageMeta(url=url, canonical_url=canonical or url, title=title,
                    description=_meta(root, "og:description", "description"), page_type=_page_type(classes),
                    body_classes=classes, breadcrumbs=breadcrumbs,
                    published=_meta(root, "article:published_time"), modified=modified,
                    classifications=classifications, tags=tags, authors=authors,
                    generator=_meta(root, "generator"))
    return ParsedPage(meta=meta, root=root, content=content, content_fallback=fallback)


# -- classification -----------------------------------------------------------------------------

def _listing_links(page: ParsedPage) -> List[Node]:
    if page.content is None:
        return []
    links = []
    for anchor in page.content.find_all(lambda n: n.tag == "a" and bool(n.get("href"))):
        if any(_is_noise(a) for a in [anchor] + list(anchor.ancestors())):
            continue
        if anchor.has_class("featured-article-learn-more") or any(a.tag == "li" for a in anchor.ancestors()):
            links.append(anchor)
    return links


def classify(page: ParsedPage) -> Classification:
    meta = page.meta
    signals = ["page_type=%s" % meta.page_type]
    if meta.generator and "mindtouch" not in meta.generator.lower():
        signals.append("generator=%s" % meta.generator[:40])
    if meta.page_type == "home":
        return Classification(KIND_UNSUPPORTED, "The Lantern home page is not a use-case collection. Paste a "
                              "collection page (for example a use-case category) or an article.", signals)
    if not meta.title:
        return Classification(KIND_UNSUPPORTED, "The page has no title; it does not look like a Lantern "
                              "content page.", signals)
    if meta.page_type in ("category", "guide"):
        return Classification(KIND_COLLECTION, "", signals)
    if meta.page_type in ("topic", "howto", "reference"):
        return Classification(KIND_ARTICLE, "", signals)
    # Unknown template: decide on structure and flag it.
    signals.append("structural_fallback")
    listing = len(_listing_links(page))
    prose = sum(len(clean(p.text())) for p in page.content.find_all(lambda n: n.tag == "p")) if page.content else 0
    headings = len(page.content.find_all(lambda n: n.tag in ("h2", "h3"))) if page.content else 0
    if listing >= 5 and prose < listing * 120:
        return Classification(KIND_COLLECTION, "", signals)
    if prose >= 400 and headings >= 1:
        return Classification(KIND_ARTICLE, "", signals)
    return Classification(KIND_UNSUPPORTED, "The page layout was not recognised as a Lantern article or "
                          "collection.", signals)


# -- collections --------------------------------------------------------------------------------

@dataclasses.dataclass
class CollectionResult:
    title: str
    url: str
    description: str
    items: List[Dict[str, Any]]
    categories: List[Dict[str, Any]]
    truncated: bool
    skipped: Dict[str, int]


def _heading_level(node: Node) -> int:
    if node.tag in ("h2", "h3", "h4", "h5", "h6"):
        return int(node.tag[1])
    return 0


def parse_collection(page: ParsedPage, max_items: int = 300) -> CollectionResult:
    meta = page.meta
    self_url = meta.canonical_url
    items: List[Dict[str, Any]] = []
    index: Dict[str, Dict[str, Any]] = {}
    skipped: Dict[str, int] = {}
    truncated = False
    category = ""
    subcategory = ""
    section_text: Dict[str, str] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    def add(url: str, title: str, role: str, kind: str, description: str = "") -> None:
        nonlocal truncated
        cat = category or meta.title
        if url in index:
            entry = index[url]
            place = {"category": cat, "subcategory": subcategory}
            if place != {"category": entry["category"], "subcategory": entry["subcategory"]} \
                    and place not in entry["also_in"]:
                entry["also_in"].append(place)
            skip("duplicate")
            return
        if len(items) >= max_items:
            truncated = True
            return
        entry = {"url": url, "record_id": record_id_for(url), "title": title[:300], "category": cat[:200],
                 "subcategory": subcategory[:200], "kind_guess": kind, "role": role,
                 "description": description[:1000], "also_in": [], "position": len(items)}
        items.append(entry)
        index[url] = entry

    def walk(node: Node) -> None:
        nonlocal category, subcategory
        for child in node.children:
            if not isinstance(child, Node) or _is_noise(child):
                if isinstance(child, Node):
                    skip("navigation")
                continue
            if child.has_class("mt-tip-container") or child.has_class("mt-contentreuse-widget"):
                skip("navigation")
                continue
            if child.has_class("featured-article-wrapper"):
                title_node = child.find(lambda n: n.has_class("featured-article-title"))
                summary = child.find(lambda n: n.has_class("featured-article-summary"))
                link = child.find(lambda n: n.tag == "a" and n.has_class("featured-article-learn-more")) \
                    or child.find(lambda n: n.tag == "a" and bool(n.get("href")))
                if link is not None:
                    url, reason = resolve_link(self_url, link.get("href"))
                    if url and url != self_url:
                        add(url, clean(title_node.text()) if title_node else clean(link.text()), "featured",
                            KIND_COLLECTION, clean(summary.text()) if summary else "")
                    else:
                        skip(reason or "self_link")
                continue
            level = _heading_level(child)
            if level:
                text = clean(child.text())
                if not text:
                    continue
                if level == 2:
                    category = meta.title if _GENERIC_HEADINGS.match(text) else text
                    subcategory = ""
                else:
                    subcategory = text
                continue
            if child.tag == "p" and category and not any(a.tag == "li" for a in child.ancestors()):
                section_text.setdefault(category, clean(child.text())[:500])
            if child.tag == "a" and child.get("href"):
                in_list = any(a.tag == "li" for a in child.ancestors())
                url, reason = resolve_link(self_url, child.get("href"))
                if not url:
                    skip("external" if reason == "host_not_allowed" else (reason or "invalid"))
                elif url == self_url:
                    skip("self_link")
                elif not in_list:
                    skip("inline_link")
                else:
                    kind = KIND_ARTICLE
                    segments = path_segments(url)
                    if segments and segments[0] in ("Data_Sources", "Data_Types"):
                        kind = "reference"
                    elif child.find(lambda n: n.has_class("mt-icon-article-topic")) is None and len(segments) <= 1:
                        kind = KIND_COLLECTION
                    add(url, clean(child.text()) or clean(child.get("title")) or segment_label(segments[-1]),
                        "listed", kind)
                continue
            walk(child)

    if page.content is not None:
        walk(page.content)
    categories: List[Dict[str, Any]] = []
    for item in items:
        bucket = next((c for c in categories if c["name"] == item["category"]), None)
        if bucket is None:
            bucket = {"name": item["category"], "description": section_text.get(item["category"], ""),
                      "subcategories": [], "count": 0}
            categories.append(bucket)
        bucket["count"] += 1
        if item["subcategory"] and item["subcategory"] not in bucket["subcategories"]:
            bucket["subcategories"].append(item["subcategory"])
    return CollectionResult(title=meta.title, url=self_url, description=meta.description, items=items,
                            categories=categories, truncated=truncated, skipped=skipped)


# -- articles -----------------------------------------------------------------------------------

def looks_like_spl(text: str) -> bool:
    sample = text.strip()
    if not sample:
        return False
    return bool(_SPL_START.match(sample)) or len(_SPL_COMMANDS.findall(sample)) >= 1


def _product_key(name: str) -> str:
    return re.sub(r"^splunk\s+", "", clean(name).lower())


def _section_role(heading: str) -> str:
    lowered = heading.lower().strip()
    if lowered in ("data", "data required"):
        return "data"
    for role, words in _SECTION_KEYWORDS:
        if any(lowered.startswith(w) or (" " in w and w in lowered) for w in words):
            return role
    return ""


class _ArticleWalker:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.blocks: List[Dict[str, Any]] = []
        self.headings: List[Tuple[int, str]] = []
        self.links: List[Dict[str, str]] = []
        self.truncated = False
        self.chars = 0

    def path(self) -> List[str]:
        return [h for _, h in self.headings]

    def roles(self) -> List[str]:
        return [r for r in (_section_role(h) for _, h in self.headings) if r]

    def emit(self, block: Dict[str, Any]) -> None:
        if len(self.blocks) >= MAX_BLOCKS or self.chars >= MAX_TEXT_CHARS:
            self.truncated = True
            return
        block["section"] = self.path()
        block["roles"] = self.roles()
        self.chars += len(block.get("text", "")) + sum(len(i) for i in block.get("items", []))
        self.blocks.append(block)

    def collect_links(self, node: Node) -> None:
        for anchor in node.find_all(lambda n: n.tag == "a" and bool(n.get("href"))):
            self.links.append({"href": anchor.get("href"), "text": clean(anchor.text()) or clean(anchor.get("title")),
                               "section": " > ".join(self.path()), "roles": ",".join(self.roles())})

    def walk(self, node: Node) -> None:
        for child in node.children:
            if isinstance(child, str):
                text = clean(child)
                if text and node.tag not in ("ul", "ol", "table", "tr", "tbody", "thead", "dl"):
                    self.emit({"type": "paragraph", "text": text[:MAX_BLOCK_CHARS]})
                continue
            if _is_noise(child) or child.get("id") == "surveyContainer":
                continue
            tag = child.tag
            level = _heading_level(child)
            if level:
                text = clean(child.text())
                if text:
                    while self.headings and self.headings[-1][0] >= level:
                        self.headings.pop()
                    self.headings.append((level, text))
                    self.emit({"type": "heading", "level": level, "text": text[:500]})
                continue
            if tag == "p":
                text = clean(child.text())
                if text:
                    self.emit({"type": "paragraph", "text": text[:MAX_BLOCK_CHARS]})
                    self.collect_links(child)
                continue
            if tag in ("ul", "ol"):
                items = self._list_items(child, 0)
                if items:
                    self.emit({"type": "list", "ordered": tag == "ol", "items": items})
                self.collect_links(child)
                continue
            if tag == "table":
                self._table(child)
                self.collect_links(child)
                continue
            if tag == "pre":
                self._code(child)
                continue
            if tag == "dt":
                text = clean(child.text()).lstrip("►▼▶ ").strip()
                if text:
                    self.emit({"type": "paragraph", "text": text[:MAX_BLOCK_CHARS], "label": True})
                continue
            if tag == "img":
                continue
            if tag in ("blockquote",) or child.has_class("mt-note") or child.has_class("mt-tip-container"):
                before = len(self.blocks)
                self.walk(child)
                for block in self.blocks[before:]:
                    block["note"] = True
                continue
            if (tag == "a" and child.get("href")) or child.find(lambda n: n.tag in _BLOCKISH) is None:
                text = clean(child.text())
                if text:
                    self.emit({"type": "paragraph", "text": text[:MAX_BLOCK_CHARS]})
                self.collect_links(child)
                continue
            self.walk(child)

    def _list_items(self, node: Node, depth: int) -> List[str]:
        items: List[str] = []
        for li in [c for c in node.children if isinstance(c, Node) and c.tag == "li"]:
            nested = [c for c in li.children if isinstance(c, Node) and c.tag in ("ul", "ol")]
            parts = []
            for c in li.children:
                if isinstance(c, Node) and c in nested:
                    continue
                parts.append(c if isinstance(c, str) else c.raw_text())
            text = clean(" ".join(parts))
            if text:
                items.append(("  " * depth + ("- " if depth else "") + text)[:MAX_BLOCK_CHARS])
            for sub in nested:
                items.extend(self._list_items(sub, depth + 1))
        return items[:500]

    def _table(self, node: Node) -> None:
        rows = node.find_all(lambda n: n.tag == "tr")
        header: List[str] = []
        body: List[List[str]] = []
        for row in rows:
            cells = [c for c in row.children if isinstance(c, Node) and c.tag in ("td", "th")]
            values = [clean(c.text())[:2000] for c in cells][:MAX_TABLE_COLS]
            if not any(values):
                continue
            if not header and cells and all(c.tag == "th" for c in cells):
                header = values
            elif len(body) < MAX_TABLE_ROWS:
                body.append(values)
            else:
                self.truncated = True
        if header or body:
            self.emit({"type": "table", "header": header, "rows": body})

    def _code(self, node: Node) -> None:
        raw = node.raw_text().replace("\r\n", "\n").replace("\xa0", " ")
        lines = [line.rstrip() for line in raw.split("\n")]
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        text = "\n".join(lines)
        if not text:
            return
        if len(text) > MAX_CODE_CHARS:
            text = text[:MAX_CODE_CHARS]
            self.truncated = True
        classes = " ".join(node.classes).lower()
        is_spl = "spl" in classes or "splunk" in classes or looks_like_spl(text)
        language = "spl" if is_spl else (re.sub(r"^language-", "", node.classes[0]) if node.classes else "text")
        self.emit({"type": "code", "language": language[:30], "text": text, "is_spl": is_spl})


def _texts(blocks: List[Dict[str, Any]], role: str) -> List[str]:
    out: List[str] = []
    for block in blocks:
        if role not in block.get("roles", []) or block["type"] == "heading":
            continue
        if block["type"] == "paragraph":
            out.append(block["text"])
        elif block["type"] == "list":
            out.extend(i.strip() for i in block["items"])
        elif block["type"] == "table":
            out.extend(" | ".join(r) for r in block["rows"])
    return [t for t in out if t]


def render_text(blocks: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for block in blocks:
        kind = block["type"]
        if kind == "heading":
            lines.append("")
            lines.append("#" * min(block["level"], 6) + " " + block["text"])
        elif kind == "paragraph":
            lines.append(block["text"])
        elif kind == "list":
            number = 0
            for item in block["items"]:
                if item.startswith(" "):
                    lines.append(item)
                    continue
                number += 1
                lines.append(("%d. " % number if block.get("ordered") else "- ") + item)
        elif kind == "table":
            if block.get("header"):
                lines.append(" | ".join(block["header"]))
            for row in block["rows"]:
                lines.append(" | ".join(row))
        elif kind == "code":
            lines.append("```" + block.get("language", ""))
            lines.append(block["text"])
            lines.append("```")
    return "\n".join(lines).strip()


def _blocks_for_role(blocks: List[Dict[str, Any]], role: str) -> List[Dict[str, Any]]:
    return [b for b in blocks if role in b.get("roles", [])]


def content_hash(raw: Dict[str, Any]) -> str:
    """Hash of the extracted page content; retrieval and import bookkeeping are excluded."""
    excluded = {"retrieved_at", "content_hash", "import", "extraction", "id"}
    return sha256_json({k: v for k, v in raw.items() if k not in excluded})


def extract_article(page: ParsedPage, retrieved_at: str) -> Dict[str, Any]:
    meta = page.meta
    url = meta.canonical_url
    walker = _ArticleWalker(url)
    if page.content is not None:
        walker.walk(page.content)
    blocks = walker.blocks
    warnings: List[str] = []

    intro: List[str] = []
    for block in blocks:
        if block["type"] == "heading":
            break
        if block["type"] == "paragraph" and not block.get("note"):
            intro.append(block["text"])
    description = "\n\n".join(intro).strip() or meta.description

    spl_blocks = [{"spl": b["text"], "section": " > ".join(b["section"]), "language": b["language"]}
                  for b in blocks if b["type"] == "code" and b.get("is_spl")]
    code_count = sum(1 for b in blocks if b["type"] == "code")

    related: List[Dict[str, str]] = []
    resources: List[Dict[str, str]] = []
    internal: List[Dict[str, str]] = []
    dashboards: List[Dict[str, str]] = []
    addons: List[Dict[str, Any]] = []
    seen = set()
    for link in walker.links:
        target, reason = resolve_link(url, link["href"])
        text = link["text"][:300]
        if target:
            if target == url or target in seen:
                continue
            seen.add(target)
            entry = {"title": text or segment_label(path_segments(target)[-1]), "url": target}
            (related if "related" in link["roles"] else internal).append(entry)
            continue
        href = link["href"].strip()
        if reason != "host_not_allowed" or not href.lower().startswith("https://") or href in seen:
            continue
        seen.add(href)
        entry = {"title": text or href[:120], "url": href[:1000]}
        match = _SPLUNKBASE.match(href)
        if match:
            addons.append({"name": text or "Splunkbase app %s" % match.group(1), "splunkbase_id": match.group(1),
                           "url": href[:1000], "role": "recommended", "source": "splunkbase_link"})
        resources.append(entry)
    named = set()
    for block in blocks:
        candidates = [block["text"]] if block["type"] == "heading" else (
            block["items"] if block["type"] == "list" else [])
        for text in candidates:
            lowered = text.lower().strip()
            if "dashboard" in lowered and len(text) <= 150 and lowered not in named \
                    and lowered not in ("dashboard", "dashboards"):
                named.add(text.lower())
                dashboards.append({"title": text.strip(), "url": ""})
    for entry in internal + related + resources:
        if "dashboard" in entry["title"].lower() and entry["title"].lower() not in named:
            named.add(entry["title"].lower())
            dashboards.append(dict(entry))

    classifications = meta.classifications
    for name in classifications.get("Technical Add-On", []):
        addons.insert(0, {"name": name, "splunkbase_id": "", "url": "", "role": "primary", "source": "classification"})
    for name in classifications.get("Technical App", []):
        addons.append({"name": name, "splunkbase_id": "", "url": "", "role": "app", "source": "classification"})
    products: List[str] = []
    for text in list(classifications.get("Applies To", [])) + _texts(blocks, "software"):
        if len(text) <= 120 and _product_key(text) not in {_product_key(p) for p in products}:
            products.append(text)

    data_sources = [t for t in _texts(blocks, "data") if len(t) <= 300]
    prerequisites = _texts(blocks, "prerequisites")
    business_value = "\n".join(_texts(blocks, "value"))
    impl_blocks = _blocks_for_role(blocks, "implementation")
    implementation = render_text(impl_blocks)
    mitre = sorted(set(_MITRE.findall(" ".join(b.get("text", "") for b in blocks if b["type"] != "code"))))

    segments = path_segments(url)
    section_path = [c["title"] for c in meta.breadcrumbs] or [segment_label(s) for s in segments[:-1]]

    score = 1.0
    if page.content_fallback:
        score -= 0.35
        warnings.append("The standard Lantern content region was not found; the whole page body was used.")
    if meta.page_type == "unknown":
        score -= 0.15
        warnings.append("The Lantern page template was not recognised.")
    text_size = sum(len(b.get("text", "")) + sum(len(i) for i in b.get("items", [])) for b in blocks)
    if text_size < 300:
        score -= 0.35 if text_size >= 120 else 0.5
        warnings.append("Very little text was extracted.")
    if not any(b["type"] == "heading" for b in blocks):
        score -= 0.15
        warnings.append("No section headings were found.")
    if walker.truncated:
        score -= 0.1
        warnings.append("The article exceeded extraction limits and was truncated.")
    if not description:
        score -= 0.1
        warnings.append("No description or introduction was found.")
    if code_count and not spl_blocks:
        warnings.append("Code blocks were found but none were recognised as SPL.")
    if not spl_blocks:
        warnings.append("The article contains no SPL search; nothing can be deployed from it directly.")
    if not data_sources and not prerequisites:
        warnings.append("No data or prerequisite section was found.")
    score = max(0.0, min(1.0, score))
    confidence = "high" if score >= 0.75 else ("medium" if score >= 0.5 else "low")
    needs_review = confidence != "high" or page.content_fallback

    raw: Dict[str, Any] = {
        "id": record_id_for(url),
        "schema": RAW_SCHEMA,
        "extraction_version": EXTRACTION_VERSION,
        "title": meta.title[:300],
        "source_url": url,
        "source_host": HOST,
        "page_type": meta.page_type,
        "article_type": ", ".join(classifications.get("Article Type", [])),
        "description": description[:8000],
        "business_value": business_value[:8000],
        "breadcrumbs": meta.breadcrumbs,
        "section_path": section_path,
        "published": meta.published,
        "modified": meta.modified,
        "authors": meta.authors[:300],
        "tags": meta.tags[:50],
        "classifications": classifications,
        "products": products[:50],
        "addons": addons[:50],
        "data_sources": data_sources[:100],
        "prerequisites": prerequisites[:100],
        "implementation": implementation[:60000],
        "spl_blocks": spl_blocks[:50],
        "code_block_count": code_count,
        "dashboards": dashboards[:50],
        "related_articles": related[:100],
        "internal_links": internal[:200],
        "resources": resources[:200],
        "mitre": mitre[:100],
        "blocks": blocks,
        "retrieved_at": retrieved_at,
    }
    raw["extraction"] = {"confidence": confidence, "score": round(score, 2), "warnings": warnings,
                         "needs_review": needs_review, "content_fallback": page.content_fallback,
                         "truncated": walker.truncated}
    raw["content_hash"] = content_hash(raw)
    return raw


def article_summary(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Compact view of an extraction used in session previews."""
    extraction = raw.get("extraction", {})
    return {"title": raw.get("title", ""), "description": (raw.get("description") or "")[:600],
            "page_type": raw.get("page_type", ""), "article_type": raw.get("article_type", ""),
            "section_path": raw.get("section_path", []), "modified": raw.get("modified", ""),
            "products": raw.get("products", [])[:10], "addons": [a.get("name") for a in raw.get("addons", [])][:10],
            "data_sources": raw.get("data_sources", [])[:10], "spl_count": len(raw.get("spl_blocks", [])),
            "block_count": len(raw.get("blocks", [])), "related_count": len(raw.get("related_articles", [])),
            "confidence": extraction.get("confidence", "low"), "needs_review": bool(extraction.get("needs_review")),
            "warnings": extraction.get("warnings", [])[:10], "content_hash": raw.get("content_hash", "")}


_DIFF_FIELDS = ("title", "description", "business_value", "products", "addons", "data_sources", "prerequisites",
                "implementation", "spl_blocks", "dashboards", "related_articles", "resources", "mitre", "tags",
                "classifications", "section_path", "modified", "blocks")


def diff_articles(old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Field-level summary of what changed between two extractions."""
    if not old:
        return []
    changes: List[Dict[str, Any]] = []
    for field in _DIFF_FIELDS:
        before, after = old.get(field), new.get(field)
        if before == after:
            continue
        change: Dict[str, Any] = {"field": field}
        if isinstance(after, list) or isinstance(before, list):
            change["before_count"] = len(before or [])
            change["after_count"] = len(after or [])
        elif isinstance(after, str) or isinstance(before, str):
            change["before"] = (before or "")[:160]
            change["after"] = (after or "")[:160]
        changes.append(change)
    if old.get("extraction_version") != new.get("extraction_version"):
        changes.append({"field": "extraction_version", "before": old.get("extraction_version", ""),
                        "after": new.get("extraction_version", "")})
    return changes


def parse(text: str, url: str) -> Tuple[ParsedPage, Classification]:
    page = parse_page(text, url)
    return page, classify(page)
