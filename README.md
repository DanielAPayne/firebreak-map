# Firebreak map

If one CI job, token or laptop in your delivery pipeline were compromised today, what could it reach? Firebreak map answers that for a GitHub account or organization and, optionally, an AWS account, and prints the ordered plan to cut it off. It only reads; it changes nothing.

## Why

When a key leaks, the usual fix is to rotate it. In a test on real AWS, an access key was deactivated and refused within 10 seconds, but a session already issued with that key kept working for as long as it was watched. Containment means finding every place a credential reaches, including the sessions it opened, before you can cut it. This tool does the finding and the planning.

## See it in a minute

Python 3.10 or newer, nothing else to install for GitHub:

```text
git clone https://github.com/DanielAPayne/firebreak-map && cd firebreak-map
python3 -m firebreak map --owner <your-account-or-org> --out graph.json
python3 -m firebreak plan --graph graph.json --point <owner>/<repository>
```

The token comes from `FIREBREAK_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN` or `gh auth token`.

`map` lists every repository and workflow that can read a stored credential, what it reaches, what could be reduced, and anything it could not read. `plan` prints the steps to cut one exposure point: sever, reissue and propagate, verify.

## Add AWS

```text
pip install boto3
python3 -m firebreak map --owner <account-or-org> --aws --aws-profile <read-only profile> --out graph.json
```

A profile with only `IAMReadOnlyAccess` is enough. The map then shows which AWS users and roles each repository and workflow can act as: through access keys held in its secrets, through roles those users can assume, and through roles it can assume with GitHub OIDC. GitHub never reveals secret values, so tell it which secret holds which key with `--aws-links links.json` (`{"owner/repo:SECRET_NAME": "<access key id>"}`).

## What it flags

- AWS roles any GitHub repository can assume (OIDC trust without a subject condition), and OIDC subjects that span repositories
- Admin users with long-lived keys; keys never used, unused for 90 days, or older than 90 days; two active keys on one user
- Roles that trust another AWS account, or any principal
- Static AWS keys where OIDC could replace them, secrets nothing references, the same secret name in several repositories
- Deploy keys with write access, unpinned third-party actions in workflows that handle secrets, triggers outsiders can influence, `write-all` permissions
- Workflows that reference secrets that do not exist

## Limits

- AWS reach reads identity-policy Allow statements only: Deny statements, permission boundaries, SCPs, session policies and resource policies are not evaluated, so reach is an upper bound. Role chaining is not followed.
- Provider types are guessed from secret names. Workflow files are scanned as text, per file, not per job.
- It plans; it does not cut.

## Cutting

Firebreak's cut carries out a plan: it severs keys and the sessions issued with them, proves from the outside that the old access is refused, delivers the replacement to where it is used, and keeps a tamper-evident record. It is not part of this repository; it is offered as a fixed-fee engagement. To ask about it, see the maintainer's GitHub profile.

## More

- What it reads and sends: [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md)
- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Reporting a security problem: [SECURITY.md](SECURITY.md)
- Tests: `python3 -m unittest discover -s tests` (the AWS tests run when `boto3` and `moto` are installed: `pip install -r requirements-test.txt`)

Licensed under Apache-2.0.
