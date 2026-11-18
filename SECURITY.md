# Security policy

Please report a security problem privately, not in a public issue: use **Report a vulnerability** on this repository's Security tab (GitHub private vulnerability reporting).

In scope: anything that could leak a credential or token, send one anywhere other than the GitHub or AWS APIs, change something in a GitHub or AWS account (this tool is meant to be read-only), or report reach that hides a real path.

What the tool reads and where it sends it: [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md). Its threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
