#!/usr/bin/env python3
"""Mutation check for the threat-model validator: introduce known mistakes into a copy of data/threats.yaml and confirm
`scripts/build.py --check` rejects each one. Exit 0 only if the clean model passes and every mutant is killed."""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def drop_note(block_id):
    def fn(s):
        i = s.index(f"id: {block_id}")
        j = s.find("  - id:", i)
        j = len(s) if j == -1 else j
        return s[:i] + re.sub(r"    detection_note:.*\n", "", s[i:j]) + s[j:]
    return fn


def unknown_rule(s):
    return s.replace("detections: [110150, 110153]", "detections: [110150, 119999]", 1)


MUTANTS = [
    ("reference a detection rule that does not exist", unknown_rule),
    ("remove the explanation from a critical threat with no detection (TM-20)", drop_note("TM-20")),
    ("use an unknown STRIDE letter", lambda s: s.replace("stride: S\n", "stride: Q\n", 1)),
    ("map a malformed ATT&CK id", lambda s: s.replace("attack: [T1110]", "attack: [T110]", 1)),
    ("score likelihood out of range", lambda s: s.replace("likelihood: 4", "likelihood: 9", 1)),
    ("reference an element that does not exist", lambda s: s.replace("element: P2", "element: P9", 1)),
]


def check(tree: Path) -> int:
    return subprocess.run([sys.executable, "scripts/build.py", "--check"], cwd=tree, capture_output=True).returncode


def main() -> int:
    if check(ROOT) != 0:
        print("clean model does not pass --check; run scripts/build.py first")
        return 1
    survived = []
    for name, fn in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "m"
            shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(".git", "diagrams", "__pycache__"))
            f = tree / "data/threats.yaml"
            original = f.read_text()
            f.write_text(fn(original))
            if f.read_text() == original:
                print(f"  [SKIP]     {name} (pattern not found; update the mutant)")
                survived.append(name)
                continue
            killed = check(tree) != 0
            print(f"  [{'KILLED' if killed else 'SURVIVED'}] {name}")
            if not killed:
                survived.append(name)
    print(f"\n{len(MUTANTS) - len(survived)}/{len(MUTANTS)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
