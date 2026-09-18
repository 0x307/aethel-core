#!/usr/bin/env python3
"""Self-tests for check-component-exports.py and component-negative-control.py.

No wasm-tools is needed: the decoded-component side is supplied as WIT text.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


checker = load("checker", "check-component-exports.py")
control = load("control", "component-negative-control.py")

WIT = """\
package aethel:core@0.1.0;

interface types {
  variant identity-error { bad-input, refused }
}

interface identity {
  use types.{identity-error};
  /// Comments can say ghost: func() and must not count.
  plp-project-at-context: func() -> bool;
  resource master-identity {
    constructor(seed: list<u8>);
    sign: func() -> bool;
  }
  resource issuer-public-parameters {
    deserialize: static func() -> bool;
  }
  resource credential {
    present: func(tau: list<u8>) -> result<bool, identity-error>;
  }
}

interface secret-sharing {
  htss-reconstruct: func() -> bool;
}

world aethel-core {
  import types;
  export identity;
  export secret-sharing;
}
"""

ALL = {
    "identity.plp-project-at-context",
    "identity.master-identity.constructor",
    "identity.master-identity.sign",
    "identity.issuer-public-parameters.deserialize",
    "identity.credential.present",
    "secret-sharing.htss-reconstruct",
}

PRESENT = "    present: func(tau: list<u8>) -> result<bool, identity-error>;\n"


def run_main(wit: str, component: str, *extra: str) -> tuple[int, str]:
    def fake(path: Path) -> str:
        return wit if path.name == "expected.wit" else component

    output = io.StringIO()
    with patch.object(checker, "wasm_tools_wit", fake), contextlib.redirect_stdout(output):
        code = checker.main(["expected.wit", "component.wasm", *extra])
    return code, output.getvalue()


class ExtractionTests(unittest.TestCase):
    def test_functions_methods_and_constructors_are_extracted(self) -> None:
        self.assertEqual(checker.extract_exports(WIT), ALL)

    def test_doc_comments_are_not_declarations(self) -> None:
        self.assertNotIn("identity.ghost", checker.extract_exports(WIT))

    def test_async_functions_are_extracted(self) -> None:
        source = (
            "interface i { f: async func(); resource r { m: static async func(); } }\n"
            "world w { export i; }"
        )
        self.assertEqual(checker.extract_exports(source), {"i.f", "i.r.m"})

    def test_same_function_name_in_two_interfaces_is_two_exports(self) -> None:
        source = (
            "interface a { f: func(); }\ninterface b { f: func(); }\n"
            "world w { export a; export b; }"
        )
        self.assertEqual(checker.extract_exports(source), {"a.f", "b.f"})

    def test_glob_in_line_comment_does_not_swallow_code(self) -> None:
        source = (
            "interface i {\n // see src/*.rs\n f: func();\n /* x */\n g: func();\n}\n"
            "world w { export i; }"
        )
        self.assertEqual(checker.extract_exports(source), {"i.f", "i.g"})

    def test_nested_block_comments(self) -> None:
        source = "interface i { /* a /* b */ c: func(); */ f: func(); }\nworld w { export i; }"
        self.assertEqual(checker.extract_exports(source), {"i.f"})

    def test_versioned_and_packaged_export_names(self) -> None:
        source = "package a:b@1.0.0 { interface i { f: func(); } world w { export a:b/i@1.0.0; } }"
        self.assertEqual(checker.extract_exports(source), {"i.f"})

    def test_unsupported_shapes_fail_closed(self) -> None:
        for source in (
            "interface i { f: func(); }\nworld w { export i; export x: func(); }",
            "interface i { f: func(); }\nworld b { export i; }\nworld w { include b; }",
            "interface i { f: func(); }\nworld a { export i; }\nworld b { export i; }",
            "interface i { f: func(); }\nworld w { import i; }",
            "world w { export missing; }",
            "interface i { f: func(); ",
        ):
            with self.subTest(source=source), self.assertRaises(checker.WitSyntaxError):
                checker.extract_exports(source)

    def test_world_can_be_chosen(self) -> None:
        source = (
            "interface i { f: func(); }\ninterface j { g: func(); }\n"
            "world a { export i; }\nworld b { export j; }"
        )
        self.assertEqual(checker.extract_exports(source, "b"), {"j.g"})


class ComparisonTests(unittest.TestCase):
    def test_identical_surfaces_match(self) -> None:
        self.assertTrue(checker.compare(WIT, WIT)["ok"])

    def test_missing_resource_method_is_rejected(self) -> None:
        result = checker.compare(WIT, WIT.replace(PRESENT, ""))
        self.assertEqual(result["missing"], ["identity.credential.present"])
        self.assertFalse(result["ok"])

    def test_unexpected_export_is_rejected(self) -> None:
        extra = WIT.replace("  resource credential {", "  resource credential {\n    extra: func();")
        self.assertEqual(checker.compare(WIT, extra)["unexpected"], ["identity.credential.extra"])

    def test_dropped_constructor_is_rejected(self) -> None:
        broken = WIT.replace("    constructor(seed: list<u8>);\n", "")
        self.assertEqual(
            checker.compare(WIT, broken)["missing"], ["identity.master-identity.constructor"]
        )

    def test_changed_signature_is_rejected_with_all_names_present(self) -> None:
        changed = WIT.replace("present: func(tau: list<u8>)", "present: func(tau: list<u8>, extra: u32)")
        result = checker.compare(WIT, changed)
        self.assertFalse(result["ok"])
        self.assertFalse(result["missing"] or result["unexpected"])
        self.assertIn("identity", result["changed"])

    def test_dropped_variant_case_is_rejected(self) -> None:
        result = checker.compare(WIT, WIT.replace("bad-input, refused", "bad-input"))
        self.assertIn("types", result["changed"])

    def test_reordered_variant_cases_are_rejected(self) -> None:
        result = checker.compare(WIT, WIT.replace("bad-input, refused", "refused, bad-input"))
        self.assertIn("types", result["changed"])

    def test_declaration_order_and_whitespace_are_irrelevant(self) -> None:
        moved = WIT.replace(
            "  plp-project-at-context: func() -> bool;\n  resource master-identity {",
            "  resource master-identity {",
        ).replace(
            "  resource issuer-public-parameters {",
            "  plp-project-at-context:   func()  ->  bool;\n  resource issuer-public-parameters {",
        )
        self.assertNotEqual(moved, WIT)
        self.assertTrue(checker.compare(WIT, moved)["ok"])


class ExitStatusTests(unittest.TestCase):
    def test_match_is_zero(self) -> None:
        self.assertEqual(run_main(WIT, WIT)[0], 0)

    def test_rejection_is_one(self) -> None:
        code, out = run_main(WIT, WIT.replace("    sign: func() -> bool;\n", ""))
        self.assertEqual(code, 1)
        self.assertIn("Missing exports:\nidentity.master-identity.sign", out)

    def test_json_reports_the_rejection(self) -> None:
        code, out = run_main(WIT, WIT.replace("    sign: func() -> bool;\n", ""), "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["missing"], ["identity.master-identity.sign"])

    def test_inability_to_check_is_two_not_one(self) -> None:
        def boom(path: Path) -> str:
            raise RuntimeError("wasm-tools component wit failed")

        with patch.object(checker, "wasm_tools_wit", boom), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(checker.main(["a.wit", "b.wasm"]), 2)

    def test_empty_export_set_is_two(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run_main("world w {}", WIT)[0], 2)


class NegativeControlTests(unittest.TestCase):
    TARGET = "identity.credential.present"
    RUST = (
        "impl GuestCredential for Component {\n"
        "    fn issue() -> u8 { 1 }\n\n"
        "    fn present(\n        &self,\n        tau: Vec<u8>,\n    ) -> Result<u8, E> {\n"
        '        let s = "}{";\n        if tau.is_empty() { return Err(E); }\n        Ok(1)\n    }\n'
        "}\n"
    )

    def make_tree(self, root: Path, wit: str = WIT) -> None:
        (root / "wit").mkdir()
        (root / "src").mkdir()
        (root / "wit" / "aethel-core.wit").write_text(wit, encoding="utf-8")
        (root / "src" / "component.rs").write_text(self.RUST, encoding="utf-8")

    def mutated(self, wit: str = WIT) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_tree(root, wit)
            with contextlib.redirect_stdout(io.StringIO()):
                control.mutate(root, self.TARGET)
            return (
                (root / "wit" / "aethel-core.wit").read_text(encoding="utf-8"),
                (root / "src" / "component.rs").read_text(encoding="utf-8"),
            )

    def test_mutate_removes_only_the_target_from_both_files(self) -> None:
        wit, rust = self.mutated()
        self.assertEqual(checker.compare(WIT, wit)["missing"], [self.TARGET])
        self.assertNotIn("fn present", rust)
        self.assertIn("fn issue", rust)
        self.assertTrue(rust.rstrip().endswith("}"))

    def test_control_survives_a_changed_signature(self) -> None:
        changed = WIT.replace("present: func(tau: list<u8>)", "present: func(tau: list<u8>, extra: u32)")
        wit, _ = self.mutated(changed)
        self.assertNotIn("present", wit)

    def test_control_refuses_a_missing_or_ambiguous_target(self) -> None:
        with self.assertRaises(control.SetupError):
            control.wit_declaration_span(WIT, "identity.credential.nope")
        with self.assertRaises(control.SetupError):
            control.rust_method_span(self.RUST + self.RUST, "present")

    def verify(self, returncode: int, payload: dict | str) -> tuple[int, str]:
        stdout = payload if isinstance(payload, str) else json.dumps(payload)
        done = subprocess.CompletedProcess([], returncode, stdout, "")
        output = io.StringIO()
        with patch.object(control.subprocess, "run", return_value=done), contextlib.redirect_stdout(output):
            code = control.verify(Path("w.wit"), Path("c.wasm"), self.TARGET)
        return code, output.getvalue()

    def test_verify_accepts_only_the_right_rejection(self) -> None:
        good = {"ok": False, "missing": [self.TARGET], "unexpected": [], "changed": {}}
        self.assertEqual(self.verify(1, good)[0], 0)

    def test_verify_fails_when_the_checker_accepts(self) -> None:
        self.assertEqual(self.verify(0, {"ok": True, "missing": [], "unexpected": []})[0], 1)

    def test_verify_fails_when_the_checker_could_not_run(self) -> None:
        code, out = self.verify(2, "")
        self.assertEqual(code, 1)
        self.assertIn("could not run", out)

    def test_verify_fails_for_the_wrong_reason(self) -> None:
        other = {"ok": False, "missing": ["identity.credential.issue"], "unexpected": []}
        self.assertEqual(self.verify(1, other)[0], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
