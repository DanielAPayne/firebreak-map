# Threat model

Firebreak map reads a GitHub account and an AWS account and writes a local map of what each credential can reach. This is what it protects and where it stops.

| # | Threat | What the code does | What remains |
| --- | --- | --- | --- |
| T1 | The GitHub token is sent somewhere else | Requests outside `https://api.github.com` are refused, and redirects are not followed (`firebreak/github.py`) | None known |
| T2 | The tool changes something | The GitHub client can only send reads, and a test checks it has no write method; the AWS collector calls only list and get operations | Your credentials can write if you give it write credentials; give it read-only ones (`IAMReadOnlyAccess` is enough) |
| T3 | The map is stolen | `graph*.json` and key files are git-ignored | The map is not encrypted; store it like a secret |
| T4 | Reach is understated, so a real path is missed | Unreadable data is listed as "Not collected" rather than treated as empty; an OIDC subject is matched case-insensitively, so reach is over-reported rather than hidden | AWS reach reads identity-policy Allow statements and applies unconditional Deny statements on all resources (not conditional Denies, boundaries, SCPs, session or resource policies) and does not follow role chaining |
| T5 | A malicious dependency | The GitHub side uses the Python standard library only; AWS uses boto3 only; CI actions are pinned to commit hashes | `pip install '.[aws]'` accepts any boto3 at or above 1.34 |
| T6 | Secret types are misjudged | Providers are guessed from secret names and the guess is labelled as such | A secret with an unhelpful name is reported as `unknown` |
