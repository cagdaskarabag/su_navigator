"""A small, bounded DOM built with :mod:`html.parser` (no third-party parser).

Retrieved HTML is untrusted: scripts, styles and embedded objects are dropped
while parsing, and node count and depth are capped.
"""

import re
from html.parser import HTMLParser
from typing import Callable, Dict, Iterator, List, Optional, Union

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
        "track", "wbr"}
DROP = {"script", "style", "noscript", "template", "svg", "math", "iframe", "object", "canvas", "select",
        "textarea", "button"}
_BLOCK = {"address", "article", "aside", "blockquote", "dd", "div", "dl", "dt", "fieldset", "figure", "footer",
          "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre",
          "section", "table", "ul"}
_IMPLIED_CLOSE = {"li": {"li"}, "dt": {"dt", "dd"}, "dd": {"dt", "dd"}, "tr": {"tr", "td", "th"},
                  "td": {"td", "th"}, "th": {"td", "th"}, "option": {"option"}}
MAX_NODES = 150000
MAX_DEPTH = 300
_TEXT_BREAK_TAGS = {"p", "div", "li", "tr", "td", "th", "dt", "dd", "h1", "h2", "h3", "h4", "h5", "h6",
                    "section", "article", "blockquote", "pre", "ul", "ol", "table"}
_WS = re.compile(r"\s+")

Child = Union["Node", str]


class Node:
    __slots__ = ("tag", "attrs", "children", "parent")

    def __init__(self, tag: str, attrs: Optional[Dict[str, str]] = None, parent: Optional["Node"] = None):
        self.tag = tag
        self.attrs = attrs or {}
        self.children: List[Child] = []
        self.parent = parent

    @property
    def classes(self) -> List[str]:
        return self.attrs.get("class", "").split()

    def has_class(self, name: str) -> bool:
        return name in self.classes

    def get(self, name: str, default: str = "") -> str:
        return self.attrs.get(name, default)

    def iter(self) -> Iterator["Node"]:
        stack: List[Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed([c for c in node.children if isinstance(c, Node)]))

    def find_all(self, pred: Callable[["Node"], bool]) -> List["Node"]:
        return [n for n in self.iter() if pred(n)]

    def find(self, pred: Callable[["Node"], bool]) -> Optional["Node"]:
        for node in self.iter():
            if pred(node):
                return node
        return None

    def raw_text(self, block_breaks: bool = False) -> str:
        parts: List[str] = []
        stack: List[Child] = [self]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                parts.append(item)
            else:
                if item.tag == "br":
                    parts.append("\n")
                children = list(item.children)
                if block_breaks and item.tag in _TEXT_BREAK_TAGS:
                    parts.append(" ")
                    children.append(" ")
                stack.extend(reversed(children))
        return "".join(parts)

    def text(self) -> str:
        return _WS.sub(" ", self.raw_text(block_breaks=True)).strip()

    def ancestors(self) -> Iterator["Node"]:
        node = self.parent
        while node is not None:
            yield node
            node = node.parent


def by_tag(*tags: str) -> Callable[[Node], bool]:
    wanted = set(tags)
    return lambda n: n.tag in wanted


def by_class(name: str, tag: str = "") -> Callable[[Node], bool]:
    return lambda n: (not tag or n.tag == tag) and name in n.classes


class _Builder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("#document")
        self.stack: List[Node] = [self.root]
        self.count = 0
        self.drop_depth = 0
        self.truncated = False

    def _open_names(self) -> List[str]:
        return [n.tag for n in self.stack]

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if self.drop_depth:
            if tag in DROP:
                self.drop_depth += 1
            return
        if tag in DROP:
            self.drop_depth = 1
            return
        if self.count >= MAX_NODES:
            self.truncated = True
            return
        closers = _IMPLIED_CLOSE.get(tag)
        if closers:
            for idx in range(len(self.stack) - 1, 0, -1):
                name = self.stack[idx].tag
                if name in closers:
                    del self.stack[idx:]
                    break
                if name in ("ul", "ol", "dl", "table", "tbody", "thead", "tr" if tag in ("td", "th") else "_"):
                    break
        if tag in _BLOCK and self.stack[-1].tag == "p":
            self.stack.pop()
        parent = self.stack[-1]
        node = Node(tag, {k.lower(): (v or "") for k, v in attrs}, parent)
        parent.children.append(node)
        self.count += 1
        if tag not in VOID and len(self.stack) < MAX_DEPTH:
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs) -> None:
        if tag.lower() in DROP:
            return
        self.handle_starttag(tag, attrs)
        if tag.lower() not in VOID and self.stack[-1].tag == tag.lower():
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self.drop_depth:
            if tag in DROP:
                self.drop_depth -= 1
            return
        for idx in range(len(self.stack) - 1, 0, -1):
            if self.stack[idx].tag == tag:
                del self.stack[idx:]
                return

    def handle_data(self, data: str) -> None:
        if self.drop_depth or not data:
            return
        self.stack[-1].children.append(data)


def parse_html(text: str) -> Node:
    builder = _Builder()
    builder.feed(text or "")
    builder.close()
    builder.root.attrs["data-truncated"] = "1" if builder.truncated else ""
    return builder.root
