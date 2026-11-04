# secret-finder

A small CLI that finds passwords, keys and tokens **added** in a git change.
One Python file, standard library only (Python 3.9+, `git` on PATH for the git modes).

## Run

```bash
# Current changes in the working directory (staged + unstaged + untracked files)
python secret_finder.py

# Changes introduced by a commit
python secret_finder.py --commit <hash>

# A diff file, or a diff from stdin
python secret_finder.py --diff changes.patch
git diff main...feature | python secret_finder.py --diff -

# Options
--repo DIR   run the git modes against another repository
--json       machine-readable output
```

Example output:

```
config.py:11: [aws-access-key-id] AWS access key ID
    AWS_ACCESS_KEY_ID = 'AKIA****************'
config.py:13: [hardcoded-secret] Value assigned to 'db_password' looks like a hard-coded secret (entropy 3.9)
    db_password = "Tr0u************"

2 potential secret(s) found.
```

Exit code: `0` = nothing found, `1` = findings (so it can gate a pre-commit hook or CI step).
Secrets are masked in the output so the report itself does not leak them.
Add `secret-finder:ignore` anywhere on a line to skip it.

## Tests

```bash
python -m unittest -v
```

1. Diff parsing: correct file and new-file line numbers across two files; removed lines are not reported; unquoted `.env` values are found; output is masked.
2. False positives: placeholders (`changeme`, `${VAR}`, `<your-key>`), env lookups, ignore markers, plain config words, and unquoted variables in source code are not reported.
3. End to end: creates a temp git repo, commits a token, and checks `--commit HEAD` finds it and `HEAD~1` is clean.

## How it works

1. Get a unified diff (from the file/stdin, `git show <hash>`, or `git diff HEAD` plus untracked files).
2. Walk the hunks and keep only `+` lines, tracking the line number in the new file.
3. Check each line against:
   - **Known token formats**: private key headers, AWS key IDs/secrets, GitHub, Slack, Stripe, Google, OpenAI-style keys, JWTs, `scheme://user:pass@host` URLs.
   - **Suspicious assignments**: a key name like `password`, `secret`, `token`, `api_key` assigned a quoted value that is at least 8 chars, not a known placeholder, and has Shannon entropy ≥ 3.0.
   - **Unquoted config values**: the same check for `KEY=value` / `key: value` without quotes, but only in config-style files (`.env`, `.yml`, `.ini`, `.properties`, `.toml`, `.cfg`, `.conf`). In source code an unquoted right-hand side is usually a variable, so it is skipped there.

## Where it fails

- **Regex + heuristics, not proof.** Unknown token formats are only caught if they are assigned to a suspicious-looking name.
- **False negatives:** unquoted values outside the listed config file types (e.g. `ENV PASSWORD=...` in a `Dockerfile`), short or low-entropy passwords (`password = "summer2024"` passes the entropy bar only sometimes), secrets split across lines or built by string concatenation, base64/encoded secrets, and secrets in variables with innocent names (`x = "..."`).
- **False positives:** long random-looking test fixtures, hashes or IDs assigned to names containing `token`/`auth`. Use `secret-finder:ignore`.
- **Only added lines in the change are scanned.** Secrets already in history, or in unchanged context lines, are not reported. Use `--commit` on each commit (or a full-history tool like gitleaks/trufflehog) for that.
- **Binary files** and non-UTF-8 untracked files are skipped.
- **No verification:** it does not check whether a key is live.
- Unusual diff formats (combined diffs from merge commits, `--word-diff`, renamed files with odd quoting of paths containing spaces) may give wrong paths or be skipped.

## AI usage

Built with Claude Code. Prompts and a log are in [AI_USAGE.md](AI_USAGE.md).
