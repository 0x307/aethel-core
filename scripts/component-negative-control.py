#!/usr/bin/env python3
"""Negative control for check-component-exports.py.

A checker that has only ever been shown passing proves nothing. This control
builds a component that is missing one export the WIT declares, and requires the
checker to reject it for exactly that reason.

  mutate SCRATCH TARGET   remove TARGET (`interface.resource.method`) from the WIT
                          and from src/component.rs under SCRATCH, so a build of
                          SCRATCH yields a component lacking only that export.
  verify WIT COMPONENT TARGET
                          run the checker on COMPONENT against the unchanged WIT
                          and require: exit status 1, and the only difference is
                          TARGET missing.

The declaration and its Rust method are found by parsing, not by matching text
that includes the signature, so a change to the signature does not break the
control. Renaming or removing the target does, on purpose and with a message.

Exit status: 0 the control worked, 1 the control failed, 2 it could not be set up.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("checker", HERE / "check-component-exports.py")
assert _spec and _spec.loader
checker = importlib.util.module_from_spec(_spec)
sys.modules["checker"] = checker
_spec.loader.exec_module(checker)

GUARDS = (
    "This control guards resource-method coverage: a component that lacks a "
    "method of a resource must be rejected, and for that reason only."
)


class SetupError(Exception):
    pass


def wit_declaration_span(source: str, target: str) -> tuple[int, int]:
    parts = target.split(".")
    if len(parts) != 3:
        raise SetupError(f"target must be interface.resource.method, got {target!r}")
    interface_name, resource_name, method = parts
    text, interfaces, _ = checker.parse_document(source)
    if interface_name not in interfaces:
        raise SetupError(f"interface {interface_name!r} not found in the WIT")
    matches = []
    for statement in checker.statements(text, *interfaces[interface_name].body_span):
        resource = checker.RESOURCE_RE.match(statement.header)
        if resource and resource.group(1) == resource_name and statement.body_span:
            for member in checker.statements(text, *statement.body_span):
                function = checker.FUNCTION_RE.match(member.header)
                if function and function.group(1) == method:
                    matches.append((member.start, member.end))
    if len(matches) != 1:
        raise SetupError(
            f"expected exactly one declaration of {target} in the WIT, found {len(matches)}; "
            "if it was renamed or removed on purpose, choose a different control target"
        )
    start, end = matches[0]
    while start > 0 and source[start - 1] in " \t":
        start -= 1
    if end < len(source) and source[end] == "\n":
        end += 1
    return start, end


def rust_method_span(source: str, method: str) -> tuple[int, int]:
    name = method.replace("-", "_")
    matches = list(re.finditer(rf"^[ \t]*(?:pub\s+)?fn {re.escape(name)}\s*[(<]", source, re.M))
    if len(matches) != 1:
        raise SetupError(
            f"expected exactly one `fn {name}` in src/component.rs, found {len(matches)}"
        )
    start = matches[0].start()
    index = source.index("{", matches[0].end())
    depth = 0
    while index < len(source):
        char = source[index]
        if source.startswith("//", index):
            index = source.find("\n", index)
            continue
        if char == '"':
            index += 1
            while source[index] != '"':
                index += 2 if source[index] == "\\" else 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                if source[end : end + 1] == "\n":
                    end += 1
                return start, end
        index += 1
    raise SetupError(f"`fn {name}` is unterminated")


def mutate(scratch: Path, target: str) -> None:
    wit_path = scratch / "wit" / "aethel-core.wit"
    wit = wit_path.read_text(encoding="utf-8")
    start, end = wit_declaration_span(wit, target)
    wit_path.write_text(wit[:start] + wit[end:], encoding="utf-8")
    rust_path = scratch / "src" / "component.rs"
    rust = rust_path.read_text(encoding="utf-8")
    start, end = rust_method_span(rust, target.split(".")[-1])
    rust_path.write_text(rust[:start] + rust[end:], encoding="utf-8")
    print(f"removed {target} from {wit_path} and {rust_path}")


def verify(wit: Path, component: Path, target: str) -> int:
    print(f"Negative control: {target} is intentionally missing from the component.")
    print(GUARDS)
    run = subprocess.run(
        [sys.executable, str(HERE / "check-component-exports.py"), "--json", str(wit), str(component)],
        capture_output=True,
        text=True,
    )
    if run.returncode != 1:
        print(
            f"CONTROL FAILED: the checker exited {run.returncode}, expected 1 (a rejection).\n"
            "Exit 0 means it accepted a component that lacks the export; exit 2 means it "
            "could not run, which proves nothing about coverage.\n" + run.stdout + run.stderr
        )
        return 1
    result = json.loads(run.stdout)
    if result["missing"] != [target] or result["unexpected"]:
        print(f"CONTROL FAILED: expected exactly {target} missing, got:\n{run.stdout}")
        return 1
    print(f"Control worked: the checker rejected the component because {target} is missing.")
    return 0


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "mutate":
            mutate(Path(argv[2]), argv[3])
            return 0
        if len(argv) == 5 and argv[1] == "verify":
            return verify(Path(argv[2]), Path(argv[3]), argv[4])
    except (SetupError, checker.WitSyntaxError, OSError) as error:
        print(f"negative control setup error: {error}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
