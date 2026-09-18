#!/usr/bin/env python3
"""
Generate Release Notes from Git Commits following Conventional Commits.
Categorizes commits into Features, Bug Fixes, Documentation, Refactoring, Maintenance.
"""

import re
import subprocess
import sys


def get_commit_range():
    try:
        prev_tag = subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0", "HEAD^"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return f"{prev_tag}..HEAD"
    except Exception:
        return "HEAD"


def generate_notes(output_file="RELEASE_NOTES.md"):
    commit_range = get_commit_range()
    try:
        raw_logs = subprocess.check_output(
            ["git", "log", "--reverse", "--no-merges", commit_range, "--pretty=format:%h%x09%s"],
            text=True,
        ).strip()
    except Exception as e:
        print(f"Warning: Failed to fetch git logs: {e}", file=sys.stderr)
        raw_logs = ""

    if not raw_logs:
        print("No commits found in range.")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("")
        return

    categories = {
        "Features": [],
        "Bug Fixes": [],
        "Documentation": [],
        "Refactoring & Performance": [],
        "Maintenance & CI": [],
        "Other Changes": [],
    }

    patterns = [
        (r"^(feat|feature)(\(.*\))?!?:\s*(.*)", "Features"),
        (r"^(fix|bug)(\(.*\))?!?:\s*(.*)", "Bug Fixes"),
        (r"^(docs|documentation)(\(.*\))?!?:\s*(.*)", "Documentation"),
        (r"^(refactor|perf)(\(.*\))?!?:\s*(.*)", "Refactoring & Performance"),
        (r"^(chore|ci|test|build)(\(.*\))?!?:\s*(.*)", "Maintenance & CI"),
    ]

    for line in raw_logs.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) == 2:
            sha, msg = parts
        else:
            sha, msg = "", parts[0]

        matched = False
        for pat, cat in patterns:
            m = re.match(pat, msg, re.IGNORECASE)
            if m:
                scope = m.group(2) or ""
                clean_msg = m.group(3).strip()
                desc = f"{scope.strip()}: {clean_msg}" if scope else clean_msg
                if desc:
                    desc = desc[0].upper() + desc[1:]
                categories[cat].append(f"* {desc} ({sha})" if sha else f"* {desc}")
                matched = True
                break

        if not matched:
            categories["Other Changes"].append(f"* {msg.strip()} ({sha})" if sha else f"* {msg.strip()}")

    output_lines = []
    for cat, items in categories.items():
        if items:
            output_lines.append(f"### {cat}\n")
            output_lines.extend(items)
            output_lines.append("")

    content = "\n".join(output_lines).strip() + "\n"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Generated release notes in {output_file}:\n")
    print(content)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "RELEASE_NOTES.md"
    generate_notes(out)
