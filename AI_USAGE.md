# AI use log

Tool: Claude (Anthropic).

## Prompt 1 (task)
"Secret Finder: build a CLI tool that finds committed passwords or keys in a change. Input: a git diff (file or stdin),
a commit hash, or the current working directory changes. Output: findings with file and line and a short reason.
Rules: start from scratch, CLI only, any language, README (how to run, where it fails), 2-3 tests, include prompts."

## Decisions made while building
- Python with the standard library only, so it runs anywhere without installs.
- Scan added lines only; report new-file line numbers from the `@@` hunk headers.
- Strong regex patterns for known formats, plus an entropy + placeholder filter for name-based guesses to limit false positives.
- Never print the full secret; mask it in the output.
- Exit code 1 on findings for use in hooks/CI.
- Working-directory mode also scans untracked files, not just `git diff HEAD`.
- Fake secrets in the tests are built from pieces so GitHub push protection doesn't block the repo.
- Tested end to end on a real temporary git repo (`--commit`); working-directory and stdin modes were also run by hand.
- Ran the tool on its own repo; it flagged 2 false positives (`user:pass@host` in the README, an f-string `{name}` in the tests), so both were added to the placeholder filter.

## Reviewed by me
I read and ran the code and tests myself and can explain each part: diff parsing, the detection rules, and the known limits listed in the README.
