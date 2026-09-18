#!/usr/bin/env python3
"""Check that a WebAssembly component exposes exactly its declared WIT surface.

Both sides are read through `wasm-tools component wit`: the canonical WIT file
on one side, the compiled component on the other. The printed text is then
matched on declaration syntax (statements and their braces), never on bare
substrings, and two things are compared:

* the export set: every free function, resource method and constructor of each
  exported interface, named `interface.function` or `interface.resource.method`,
  compared as a set for exact equality;
* the declaration text of every interface the component carries: record and
  variant bodies, flags, and function signatures, so a changed parameter list or
  a dropped variant case is a mismatch even when every name is still present.

Doc comments are ignored. The theory that comments could cause a false pass was
tested and disproved: doc comments are not embedded in compiled components, so
the decoded side never contains any. Ignoring them is defence in depth.

Exit status: 0 the surfaces match, 1 they differ, 2 the check itself could not
run (missing wasm-tools, unreadable input, unsupported WIT). A caller that must
distinguish a rejection from a failure to check should look at that difference.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

IDENT = r"%?[A-Za-z][A-Za-z0-9-]*"
FUNCTION_RE = re.compile(rf"^({IDENT})\s*:\s*(?:static\s+)?(?:async\s+)?func\s*\(")
CONSTRUCTOR_RE = re.compile(r"^constructor\s*\(")
RESOURCE_RE = re.compile(rf"^resource\s+({IDENT})$")
INTERFACE_RE = re.compile(rf"^interface\s+({IDENT})$")
WORLD_RE = re.compile(rf"^world\s+({IDENT})$")


class WitSyntaxError(ValueError):
    """Raised when this deliberately small declaration parser cannot proceed."""


@dataclass(frozen=True)
class Statement:
    """One top-level statement: its header text, optional brace body, and span."""

    header: str
    body: str | None
    start: int
    end: int
    body_span: tuple[int, int] | None


def blank_comments(source: str) -> str:
    """Replace WIT comments with spaces, keeping every offset and newline.

    Handles `//` and `///` line comments and nested `/* */` block comments, and
    scans left to right so a `/*` inside a line comment is not a block start.
    """
    out = list(source)
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end == -1 else end
            for i in range(index, end):
                out[i] = " "
            index = end
        elif source.startswith("/*", index):
            depth = 0
            end = index
            while end < len(source):
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                    if depth == 0:
                        break
                else:
                    end += 1
            else:
                raise WitSyntaxError("unterminated block comment")
            for i in range(index, end):
                if out[i] != "\n":
                    out[i] = " "
            index = end
        else:
            index += 1
    return "".join(out)


def matching_brace(text: str, open_brace: int) -> int:
    """Return the index of the `}` that closes the `{` at `open_brace`."""
    depth = 0
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise WitSyntaxError("unterminated WIT declaration block")


def statements(text: str, lo: int = 0, hi: int | None = None) -> list[Statement]:
    """Split text[lo:hi] into top-level statements, respecting balanced braces.

    A statement ends at a `;`, or at the `}` closing its body when no `;`
    follows it. `use a.{b, c};` therefore stays one statement with no body, and
    a trailing run with no terminator (a comma list) is one final statement.
    """
    hi = len(text) if hi is None else hi
    result: list[Statement] = []
    index = lo
    start = lo
    while index < hi:
        char = text[index]
        if char == "{":
            close = matching_brace(text, index)
            if close >= hi:
                raise WitSyntaxError("declaration block crosses its parent")
            after = close + 1
            while after < hi and text[after].isspace():
                after += 1
            if after < hi and text[after] == ";":
                index = after
                continue
            result.append(
                Statement(
                    header=" ".join(text[start:index].split()),
                    body=text[index + 1 : close],
                    start=start + (len(text[start:index]) - len(text[start:index].lstrip())),
                    end=close + 1,
                    body_span=(index + 1, close),
                )
            )
            start = index = close + 1
        elif char == ";":
            header = " ".join(text[start:index].split())
            if header:
                result.append(
                    Statement(
                        header=header,
                        body=None,
                        start=start + (len(text[start:index]) - len(text[start:index].lstrip())),
                        end=index + 1,
                        body_span=None,
                    )
                )
            start = index = index + 1
        else:
            index += 1
    tail = " ".join(text[start:hi].split())
    if tail:
        result.append(Statement(tail, None, start, hi, None))
    return result


def collect(text: str, parsed: list[Statement], interfaces, worlds) -> None:
    """Gather interface and world statements, descending into `package x { }`."""
    for statement in parsed:
        if statement.body_span is None:
            continue
        lo, hi = statement.body_span
        if statement.header.startswith("package "):
            collect(text, statements(text, lo, hi), interfaces, worlds)
            continue
        interface = INTERFACE_RE.match(statement.header)
        world = WORLD_RE.match(statement.header)
        if interface:
            name = interface.group(1)
            if name in interfaces:
                raise WitSyntaxError(f"interface {name!r} is declared more than once")
            interfaces[name] = statement
        elif world:
            name = world.group(1)
            if name in worlds:
                raise WitSyntaxError(f"world {name!r} is declared more than once")
            worlds[name] = statement


def parse_document(source: str):
    """Return (blanked text, {interface: Statement}, {world: Statement})."""
    text = blank_comments(source)
    interfaces: dict[str, Statement] = {}
    worlds: dict[str, Statement] = {}
    collect(text, statements(text), interfaces, worlds)
    return text, interfaces, worlds


def exported_interface_names(text: str, worlds, world: str | None) -> list[str]:
    """Names of the interfaces the chosen world exports, in declaration order."""
    if world is None:
        if len(worlds) != 1:
            raise WitSyntaxError(
                f"{len(worlds)} worlds found; pass --world to say which one is checked"
            )
        world = next(iter(worlds))
    if world not in worlds:
        raise WitSyntaxError(f"world {world!r} not found")
    lo, hi = worlds[world].body_span
    names: list[str] = []
    for statement in statements(text, lo, hi):
        header = statement.header
        if header.startswith("include "):
            raise WitSyntaxError(f"unsupported world include: {header!r}")
        if not header.startswith("export "):
            continue
        reference = header[len("export ") :].strip()
        if (
            statement.body is not None
            or re.match(rf"^{IDENT}\s*:\s", reference)
            or "=" in reference
        ):
            raise WitSyntaxError(f"unsupported inline or aliased world export: {reference!r}")
        name = reference.rsplit("/", 1)[-1].split("@", 1)[0].strip()
        if not re.fullmatch(IDENT, name):
            raise WitSyntaxError(f"unsupported world export: {reference!r}")
        names.append(name.lstrip("%"))
    if not names:
        raise WitSyntaxError("no named interface exports found in a WIT world")
    return names


def interface_exports(text: str, name: str, interface: Statement) -> set[str]:
    """Free functions, resource methods and constructors of one interface."""
    exports: set[str] = set()
    lo, hi = interface.body_span
    for statement in statements(text, lo, hi):
        function = FUNCTION_RE.match(statement.header)
        resource = RESOURCE_RE.match(statement.header)
        if function and statement.body is None:
            exports.add(f"{name}.{function.group(1).lstrip('%')}")
        elif resource and statement.body_span:
            resource_name = resource.group(1).lstrip("%")
            for member in statements(text, *statement.body_span):
                method = FUNCTION_RE.match(member.header)
                if method:
                    exports.add(f"{name}.{resource_name}.{method.group(1).lstrip('%')}")
                elif CONSTRUCTOR_RE.match(member.header):
                    exports.add(f"{name}.{resource_name}.constructor")
    return exports


def extract_exports(wit_source: str, world: str | None = None) -> set[str]:
    """Extract canonical export names from WIT text (a file or wasm-tools output)."""
    text, interfaces, worlds = parse_document(wit_source)
    exports: set[str] = set()
    for name in exported_interface_names(text, worlds, world):
        if name not in interfaces:
            raise WitSyntaxError(f"exported interface declaration not found: {name}")
        exports |= interface_exports(text, name, interfaces[name])
    return exports


def declaration_lines(text: str, body_span: tuple[int, int], prefix: str = "") -> list[str]:
    """Normalised declaration text of a body, resources expanded member by member.

    Record, variant and flags bodies are kept whole and in order, because case
    and field order is part of the wire shape.
    """
    lines: list[str] = []
    for statement in statements(text, *body_span):
        if statement.body_span is None:
            lines.append(prefix + statement.header)
        elif RESOURCE_RE.match(statement.header):
            lines.append(f"{prefix}{statement.header} {{}}")
            lines += declaration_lines(text, statement.body_span, f"{prefix}{statement.header} :: ")
        else:
            body = " ".join(statement.body.split())
            lines.append(f"{prefix}{statement.header} {{ {body} }}")
    return lines


def describe_interfaces(wit_source: str) -> dict[str, list[str]]:
    """Map interface name to its sorted, normalised declaration lines."""
    text, interfaces, _ = parse_document(wit_source)
    return {
        name: sorted(declaration_lines(text, statement.body_span))
        for name, statement in interfaces.items()
    }


def wasm_tools_wit(path: Path) -> str:
    """Print a WIT file or component through component-aware wasm-tools."""
    try:
        return subprocess.run(
            ["wasm-tools", "component", "wit", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except FileNotFoundError as error:
        raise RuntimeError("wasm-tools is required to inspect component exports") from error
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.stderr.strip() or "wasm-tools component wit failed") from error


def format_exports(exports: set[str]) -> str:
    return "\n".join(sorted(exports))


def check_exports(expected: set[str], actual: set[str]) -> tuple[set[str], set[str]]:
    """Return (missing, unexpected), allowing callers and tests to use set equality."""
    return expected - actual, actual - expected


def check_declarations(
    expected: dict[str, list[str]], actual: dict[str, list[str]]
) -> dict[str, dict[str, list[str]]]:
    """Interfaces the component carries whose declarations differ from the WIT's."""
    changed: dict[str, dict[str, list[str]]] = {}
    for name, lines in actual.items():
        want = expected.get(name)
        if want is None:
            changed[name] = {"expected": [], "actual": lines}
        elif want != lines:
            changed[name] = {
                "expected": [line for line in want if line not in lines],
                "actual": [line for line in lines if line not in want],
            }
    return changed


def compare(wit_text: str, component_text: str, world: str | None = None) -> dict:
    """Compare the WIT's surface with the component's; the result is JSON-ready."""
    expected = extract_exports(wit_text, world)
    actual = extract_exports(component_text)
    missing, unexpected = check_exports(expected, actual)
    changed = check_declarations(
        describe_interfaces(wit_text), describe_interfaces(component_text)
    )
    return {
        "ok": not (missing or unexpected or changed),
        "exports": len(expected),
        "missing": sorted(missing),
        "unexpected": sorted(unexpected),
        "changed": changed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare WIT-derived exports with a component's decoded WIT."
    )
    parser.add_argument("wit_file", type=Path, help="canonical expected WIT file")
    parser.add_argument("component_file", type=Path, help="compiled component file")
    parser.add_argument("--world", help="world to check, required if the WIT has several")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)

    try:
        result = compare(
            wasm_tools_wit(args.wit_file), wasm_tools_wit(args.component_file), args.world
        )
    except (OSError, RuntimeError, WitSyntaxError) as error:
        print(f"component export check error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 1

    if not result["ok"]:
        print("Component surface does not match the WIT.")
        if result["missing"]:
            print("\nMissing exports:")
            print("\n".join(result["missing"]))
        if result["unexpected"]:
            print("\nUnexpected exports:")
            print("\n".join(result["unexpected"]))
        for name, difference in sorted(result["changed"].items()):
            print(f"\nDeclarations differ in interface {name}:")
            for line in difference["expected"]:
                print(f"  WIT only:       {line}")
            for line in difference["actual"]:
                print(f"  component only: {line}")
        return 1

    print(f"WIT-derived export set ({result['exports']} exports) matches the component exactly.")
    print("Interface declarations match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
