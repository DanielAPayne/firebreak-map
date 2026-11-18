# What leaves your machine

Firebreak map runs where you run it. It has no server, no account and no telemetry. It only reads: network traffic goes to the GitHub and AWS APIs, with your own credentials, and nothing is changed in either.

## GitHub (api.github.com only)

`map` reads the repository list, Actions settings, secret names and dates, environment and Dependabot secret names, deploy key metadata and workflow file contents. GitHub never returns secret values, so they are never seen. The client refuses any host other than `api.github.com`, refuses redirects, and has no method that can send anything but a read.

`plan` reads only the local map file.

## AWS (IAM and STS)

`map --aws` reads users, groups, roles, access key metadata and last use, attached and inline policies and trust policies. It calls only list and get operations; IAM never returns secret access keys.

## Files on your machine

| File | Contains | Advice |
| --- | --- | --- |
| Map (`--out graph.json`) | Names, ids and permissions of every credential found, and what each can reach | Treat it as sensitive: it is a map an attacker would want. It is git-ignored by default |
| Links (`--aws-links`) | Which GitHub secret holds which AWS access key id | Key ids are not secrets, but keep the file with the map |
