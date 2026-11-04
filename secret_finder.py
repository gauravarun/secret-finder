#!/usr/bin/env python3
"""secret-finder: scan a git change for committed secrets.

Only *added* lines in a unified diff are scanned, so a secret that is being
removed is not reported.

Usage:
    python secret_finder.py                  # working dir changes vs HEAD (+ untracked files)
    python secret_finder.py --commit abc123  # changes introduced by one commit
    python secret_finder.py --diff my.patch  # a diff file
    git diff | python secret_finder.py --diff -   # diff from stdin
"""
from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    reason: str
    snippet: str


# --- Rules --------------------------------------------------------------------
# (rule id, compiled regex, reason). Specific token formats first.
PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
     "Private key block"),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "AWS access key ID"),
    ("aws-secret-key", re.compile(
        r"(?i)aws.{0,20}secret.{0,20}[=:]\s*['\"]?[A-Za-z0-9/+]{40}\b"),
     "AWS secret access key"),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}"),
     "GitHub token"),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
     "Slack token"),
    ("stripe-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
     "Stripe live secret key"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google API key"),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}"),
     "OpenAI-style API key"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JSON Web Token"),
    ("url-credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@/'\"]{3,})@[^\s'\"]+", re.I),
     "Credentials embedded in a URL"),
]

# key = "value" style assignments where the key name looks sensitive.
ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential)[\w.-]*)
    ['"]?\s*(?::=|=>|=|:)\s*
    (?P<q>['"`])(?P<value>[^'"`]+)(?P=q)
    """
)

PLACEHOLDER = re.compile(
    r"(?ix)^(?: \$\{.*\} | \$[A-Z_]+ | <.*> | \{\{.*\}\} | \{[\w.]+\} | %\(.*\)s"
    r" | x+ | \*+ | \.+ | changeme | change_me | pass | password | secret | example | dummy"
    r" | test | todo | none | null | your[_-].* | .*placeholder.* | redacted )$"
)

IGNORE_MARKER = "secret-finder:ignore"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def mask(text: str, secret: str) -> str:
    """Hide most of the secret in the output so the report itself doesn't leak it."""
    if len(secret) <= 6:
        shown = "*" * len(secret)
    else:
        shown = secret[:4] + "*" * (len(secret) - 4)
    out = text.replace(secret, shown).strip()
    return out if len(out) <= 120 else out[:117] + "..."


def scan_line(path: str, lineno: int, text: str) -> list[Finding]:
    if IGNORE_MARKER in text:
        return []
    findings: list[Finding] = []
    seen_spans: list[tuple[int, int]] = []

    for rule, rx, reason in PATTERNS:
        for m in rx.finditer(text):
            secret = m.group(1) if m.groups() else m.group(0)
            if rule == "url-credentials" and PLACEHOLDER.match(secret):
                continue
            seen_spans.append(m.span())
            findings.append(Finding(path, lineno, rule, reason, mask(text, secret)))

    for m in ASSIGNMENT.finditer(text):
        value = m.group("value").strip()
        if any(s <= m.start("value") < e for s, e in seen_spans):
            continue  # already reported by a specific rule
        if len(value) < 8 or PLACEHOLDER.match(value) or " " in value:
            continue
        ent = shannon_entropy(value)
        if ent < 3.0:
            continue
        findings.append(Finding(
            path, lineno, "hardcoded-secret",
            f"Value assigned to '{m.group('key')}' looks like a hard-coded secret (entropy {ent:.1f})",
            mask(text, value)))
    return findings


# --- Diff parsing -------------------------------------------------------------
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def iter_added_lines(diff: str):
    """Yield (path, new_line_number, text) for every added line in a unified diff."""
    path = None
    new_line = 0
    in_hunk = False
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            path, in_hunk = None, False
            continue
        if raw.startswith("+++ "):
            target = raw[4:].strip().split("\t")[0]
            if target == "/dev/null":
                path = None  # file deleted
            else:
                path = target[2:] if target.startswith(("b/", "w/", "i/")) else target
            in_hunk = False
            continue
        m = HUNK.match(raw)
        if m:
            new_line = int(m.group(1))
            in_hunk = True
            continue
        if not in_hunk or path is None:
            continue
        if raw.startswith("+"):
            yield path, new_line, raw[1:]
            new_line += 1
        elif raw.startswith(" ") or raw == "":
            new_line += 1
        # '-' lines and '\ No newline at end of file' don't advance the new-file counter


def scan_diff(diff: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, lineno, text in iter_added_lines(diff):
        findings.extend(scan_line(path, lineno, text))
    return findings


# --- Input sources ------------------------------------------------------------
def git(*args: str, cwd: str | None = None) -> str:
    res = subprocess.run(["git", *args], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", cwd=cwd)
    if res.returncode != 0:
        raise SystemExit(f"error: git {' '.join(args)} failed:\n{res.stderr.strip()}")
    return res.stdout


def diff_for_commit(commit: str, cwd: str | None = None) -> str:
    # --root makes the very first commit of a repo work too.
    return git("show", "--format=", "--no-color", "--no-ext-diff", "-U0", "--root", commit, cwd=cwd)


def diff_for_worktree(cwd: str | None = None) -> str:
    has_head = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"],
                              capture_output=True, cwd=cwd).returncode == 0
    # Before the first commit, compare against git's well-known empty tree.
    base = "HEAD" if has_head else "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    diff = git("diff", "--no-color", "--no-ext-diff", "-U0", base, cwd=cwd)
    # Untracked (but not ignored) files are new changes too: treat every line as added.
    untracked = git("ls-files", "--others", "--exclude-standard", "-z", cwd=cwd).split("\0")
    root = Path(cwd or ".")
    for rel in filter(None, untracked):
        try:
            content = (root / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable
        lines = content.splitlines()
        diff += f"\n+++ b/{rel}\n@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{l}\n" for l in lines)
    return diff


# --- CLI ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Find secrets (keys, passwords, tokens) added in a git change.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--diff", metavar="FILE", help="unified diff file to scan ('-' for stdin)")
    src.add_argument("--commit", metavar="HASH", help="scan the changes introduced by this commit")
    p.add_argument("--repo", metavar="DIR", help="git repository path (default: current directory)")
    p.add_argument("--json", action="store_true", help="output findings as JSON")
    args = p.parse_args(argv)

    if args.diff == "-":
        diff = sys.stdin.read()
    elif args.diff:
        diff = Path(args.diff).read_text(encoding="utf-8", errors="replace")
    elif args.commit:
        diff = diff_for_commit(args.commit, cwd=args.repo)
    else:
        diff = diff_for_worktree(cwd=args.repo)

    findings = scan_diff(diff)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif not findings:
        print("No secrets found.")
    else:
        for f in findings:
            print(f"{f.file}:{f.line}: [{f.rule}] {f.reason}\n    {f.snippet}")
        print(f"\n{len(findings)} potential secret(s) found.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
