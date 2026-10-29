"""Read-only, offline heuristic static checks; never executes scanned code."""
import argparse
import ast
import json
from pathlib import Path

SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
MAX_SIZE = 1_000_000

def name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = name(node.value)
        return base + "." + node.attr if base else node.attr
    return ""

def inspect_file(path, root):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (UnicodeError, OSError):
        return []
    except SyntaxError as err:
        return [{"file": path.relative_to(root).as_posix(), "line": err.lineno or 1,
                 "rule": "PY001", "severity": "medium", "message": "Python syntax error"}]
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = name(node.func)
        rule = None
        if fn in ("eval", "exec", "builtins.eval", "builtins.exec"):
            rule = ("PY002", "medium", "Dynamic code execution: review untrusted input")
        if fn in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                  "subprocess.check_output", "subprocess.check_call"):
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                rule = ("PY003", "high", "shell=True: review command construction")
        if fn in ("app.run", "application.run"):
            if any(k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                rule = ("PY004", "high", "Web debug=True: avoid in production")
        if fn in ("pickle.load", "pickle.loads"):
            rule = ("PY005", "medium", "Pickle deserialization: only use trusted data")
        if rule:
            findings.append({"file": path.relative_to(root).as_posix(), "line": node.lineno,
                             "rule": rule[0], "severity": rule[1], "message": rule[2]})
    return findings

def scan(directory):
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError("Directory not found")
    findings = []
    analyzed = 0
    skipped = 0
    for path in root.rglob("*.py"):
        if any(part in SKIP for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or path.stat().st_size > MAX_SIZE:
            skipped += 1
            continue
        analyzed += 1
        findings.extend(inspect_file(path, root))
    return {"version": "0.1.0", "files_analyzed": analyzed, "files_skipped": skipped,
            "findings": sorted(findings, key=lambda f: (f["file"], f["line"], f["rule"])),
            "limitations": ["Only heuristic checks of local Python files",
                            "False positives and missed issues are possible",
                            "No code is executed and results do not certify security"]}

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline local Python code security checks")
    parser.add_argument("directory", nargs="?", default=".")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on-high", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = scan(args.directory)
    except ValueError as error:
        parser.error(str(error))
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Scanned {result['files_analyzed']} Python files; {len(result['findings'])} findings")
        for f in result["findings"]:
            print(f"{f['file']}:{f['line']} {f['severity']} {f['rule']} {f['message']}")
    return int(args.fail_on_high and any(f["severity"] == "high" for f in result["findings"]))
