#!/usr/bin/env python3
"""Normalize KeePassXC XML exports and compare them."""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

TIME_TAG_RE = re.compile(r"(Time|Changed)$")
IGNORED_META_KEYS = {"KPXC_RANDOM_SLUG", "_LAST_MODIFIED"}


def sort_entry_children(element: ET.Element) -> None:
    for child in element:
        sort_entry_children(child)

    children = list(element)
    if not any(child.tag == "Entry" for child in children):
        return

    def sort_key(item: tuple[int, ET.Element]) -> tuple[int, str | int]:
        index, child = item
        if child.tag == "Entry":
            return (1, child.findtext("UUID", default=""))
        return (0, index)

    element[:] = [child for _, child in sorted(enumerate(children), key=sort_key)]


def normalize(path: Path) -> bytes:
    tree = ET.parse(path)
    root = tree.getroot()

    for element in root.iter():
        if TIME_TAG_RE.search(element.tag):
            element.text = "<normalized>"

    for custom_data in root.findall(".//CustomData"):
        for item in list(custom_data.findall("Item")):
            key = item.findtext("Key")
            if key in IGNORED_META_KEYS:
                custom_data.remove(item)

    sort_entry_children(root)

    ET.indent(tree, space="  ")
    return ET.tostring(root, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: kpxc-diff.py <expected.xml> <actual.xml>", file=sys.stderr)
        return 2

    left = normalize(Path(sys.argv[1]))
    right = normalize(Path(sys.argv[2]))
    if left == right:
        return 0

    print("--- normalized expected ---")
    print(left.decode())
    print("--- normalized actual ---")
    print(right.decode())
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
