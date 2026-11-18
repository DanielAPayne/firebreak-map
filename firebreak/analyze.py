"""Blast radius, reduction findings and the dry-run cut plan. Nothing here changes anything."""
from __future__ import annotations

from datetime import datetime, timezone

from . import aws
from .aws import CUT_INSTALLED
from .graph import Graph

STALE_DAYS = 180
CLOUD = ("aws", "gcp", "azure", "oci")
# Sever order: what an attacker can do the most damage with goes first.
PRIORITY = ["aws", "gcp", "azure", "oci", "kubernetes", "signing", "npm", "pypi", "container-registry",
            "github", "ssh", "unknown", "chat-webhook"]
SEVER = {
    "aws": "Deactivate the IAM access key (aws iam update-access-key --status Inactive), then revoke the role's active sessions.",
    "gcp": "Disable the service-account key in IAM.",
    "azure": "Remove the client secret from the app registration.",
    "oci": "Delete the API signing key from the user in Oracle Cloud (Identity, Users, API Keys).",
    "kubernetes": "Delete the service-account token or rotate the cluster credential it came from.",
    "signing": "Revoke the signing key and publish the revocation where verifiers look.",
    "npm": "Revoke the token on npmjs.com (Access Tokens).",
    "pypi": "Delete the API token on pypi.org (Account settings).",
    "container-registry": "Revoke the registry access token.",
    "github": "Revoke the token or key in GitHub (Settings, Developer settings, or the repository's deploy keys).",
    "ssh": "Remove the public key from every host and service that trusts it.",
    "chat-webhook": "Regenerate the webhook URL in the chat service.",
    "unknown": "Revoke it at the issuing system. The type could not be recognized from the name.",
}


def resolve_point(graph: Graph, text: str) -> dict:
    for candidate in (text, f"repo:{text}", f"workflow:{text}"):
        if candidate in graph.nodes and graph.nodes[candidate]["kind"] in ("repo", "workflow"):
            return graph.nodes[candidate]
    matches = [n for n in graph.nodes.values() if n["kind"] == "workflow"
               and (f"{n['repo']}:{n['path']}".endswith(text) or n["path"].endswith("/" + text))]
    if len(matches) == 1:
        return matches[0]
    raise SystemExit(f"Exposure point not found or ambiguous: {text} ({len(matches)} matches). "
                     "Use owner/repo or owner/repo:.github/workflows/file.yml")


def radius(graph: Graph, point: dict) -> dict:
    """What one exposure point can read. `direct` is referenced by the workflow file;
    `latent` is readable by anyone who can change a workflow in that repository."""
    repo_id = f"repo:{point['repo']}" if point["kind"] == "workflow" else point["id"]
    held = [n for n in graph.out(repo_id, "holds") if n["scope"] != "dependabot"]
    if point["kind"] == "workflow":
        referenced = graph.out(point["id"], "references")
        direct = held if point.get("all_secrets") else [n for n in referenced if n["scope"] != "unresolved"]
        missing = [n for n in referenced if n["scope"] == "unresolved"]
        direct_ids = {n["id"] for n in direct}
        latent = [n for n in held if n["id"] not in direct_ids]
        keys = []
    else:
        direct, latent, missing = held, [], []
        keys = graph.into(repo_id, "grants")
    return {"point": point, "repo": graph.nodes[repo_id], "direct": direct, "latent": latent, "missing": missing,
            "deploy_keys": keys, "aws": aws.reach(graph, point, direct, latent),
            "gaps": [g for g in graph.gaps if g["scope"] == graph.nodes[repo_id]["name"]]}


def same_name_elsewhere(graph: Graph, secret: dict) -> list[str]:
    return sorted({n["repo"] for n in graph.of_kind("secret")
                   if n["name"] == secret["name"] and n["repo"] != secret["repo"] and n["scope"] != "unresolved"})


def _age_days(stamp: str | None, now: datetime) -> int | None:
    if not stamp:
        return None
    return (now - datetime.fromisoformat(stamp.replace("Z", "+00:00"))).days


def findings(graph: Graph, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    out = []

    def add(kind, where, detail):
        out.append({"kind": kind, "where": where, "detail": detail})

    for repo in graph.of_kind("repo"):
        workflows = graph.out(repo["id"], "contains")
        held = graph.out(repo["id"], "holds")
        if repo.get("default_token") == "write":
            add("token-default-write", repo["name"], "The default workflow token has write permission.")
        referenced = {s["id"] for w in workflows for s in graph.out(w["id"], "references")}
        reads_all = any(w.get("all_secrets") for w in workflows)
        uses_oidc = any(w.get("oidc") for w in workflows)
        for secret in held:
            where = f"{repo['name']} secret {secret['name']} ({secret['scope']})"
            if secret["provider"] in CLOUD and not uses_oidc:
                add("oidc-candidate", where, "Static cloud credential, and no workflow here uses OIDC federation.")
            if secret["scope"] == "repo" and secret["id"] not in referenced and not reads_all:
                add("unused-candidate", where,
                    "No workflow file in this repository references it. Check reusable workflows before deleting.")
            age = _age_days(secret.get("updated_at"), now)
            if age is not None and age > STALE_DAYS:
                add("stale", where, f"Last set {age} days ago.")
        for key in graph.into(repo["id"], "grants"):
            if key.get("write"):
                add("deploy-key-write", f"{repo['name']} deploy key {key['title'] or key['key_id']}",
                    "Deploy key with write access.")
        for wf in workflows:
            uses_secrets = bool(graph.out(wf["id"], "references")) or wf.get("all_secrets")
            where = f"{repo['name']}:{wf['path']}"
            if uses_secrets and wf.get("unpinned_actions"):
                add("unpinned-action-with-secrets", where,
                    "Uses secrets and third-party actions not pinned to a commit: " + ", ".join(wf["unpinned_actions"]))
            if uses_secrets and wf.get("risky_triggers"):
                add("risky-trigger-with-secrets", where,
                    "Uses secrets and mentions a trigger outsiders can influence: " + ", ".join(wf["risky_triggers"]))
            for secret in graph.out(wf["id"], "references"):
                if secret["scope"] == "unresolved":
                    add("missing-secret", where, f"References {secret['name']}, which is not among the secrets this token can list. "
                        "The job gets an empty value unless a calling workflow or an organization secret supplies it.")
            if wf.get("write_all"):
                add("write-all", where, "Declares permissions: write-all.")
    names: dict[str, set] = {}
    for secret in graph.of_kind("secret"):
        if secret["scope"] not in ("unresolved", "org"):
            names.setdefault(secret["name"], set()).add(secret["repo"])
    for name, repos in sorted(names.items()):
        if len(repos) > 1:
            add("shared-name", f"secret {name}", "Same name in " + ", ".join(sorted(repos))
                + ". If it is one credential, a cut must cover all of them.")
    return out + aws.findings(graph, now)


def cut_plan(graph: Graph, point: dict) -> dict:
    """Ordered dry-run plan. Every step is an instruction for a person; none is executed."""
    r = radius(graph, point)
    creds = [(c, "direct") for c in r["direct"]] + [(c, "latent") for c in r["latent"]]
    creds.sort(key=lambda pair: (PRIORITY.index(pair[0]["provider"]), pair[1] != "direct", pair[0]["name"]))
    repo = r["repo"]["name"]
    sever, reissue, verify = [], [], []
    if point["kind"] == "workflow":
        sever.append({"action": f"Disable the workflow: gh workflow disable {point['path'].split('/')[-1]} --repo {repo}",
                      "human": False})
    # AWS roles the point can assume come first: they are usually the widest reach.
    roles_seen, keys_done = set(), set()
    for entry in r["aws"]:
        if entry["via"] == "GitHub OIDC" and entry["principal"]["id"] not in roles_seen:
            roles_seen.add(entry["principal"]["id"])
            s, i, v = aws.role_steps(entry["principal"], repo)
            sever += s; reissue += i; verify += v
    for key in r["deploy_keys"]:
        sever.append({"action": f"Delete deploy key '{key['title'] or key['key_id']}': "
                                f"gh api -X DELETE repos/{repo}/keys/{key['key_id']}", "human": False})
    for cred, exposure in creds:
        label = f"{cred['name']} ({cred['provider']}, {cred['scope']}, {exposure})"
        linked = graph.out(cred["id"], "is")
        if linked:
            for key in linked:
                if key["id"] in keys_done:
                    continue  # the other half of a key already planned
                keys_done.add(key["id"])
                names = sorted({c["name"] for c, _ in creds if key in graph.out(c["id"], "is")})
                s, i, v = aws.key_steps(graph, key, names, repo)
                sever += s; reissue += i; verify += v
            continue
        sever.append({"action": f"{label}: {SEVER[cred['provider']]}", "human": True})
        targets = [repo] + same_name_elsewhere(graph, cred)
        flag = {"repo": "", "org": " --org " + repo.split("/")[0]}.get(
            cred["scope"], f" --env {cred['scope'][4:]}")
        where = "; ".join(f"gh secret set {cred['name']} --repo {t}{flag if t == repo else ''}" for t in targets)
        note = "" if len(targets) == 1 else " (other repositories hold the same name: confirm it is the same credential)"
        reissue.append({"action": f"{label}: issue a replacement, then store it: {where}{note}", "human": True})
        verify.append({"action": f"{label}: use the OLD credential against a harmless resource and record the result; "
                                 "confirm a legitimate job still works with the NEW one." + aws.VERIFY_HINT.replace(" with environment observed", ""),
                       "human": True})
    for cred in r["missing"]:
        sever.append({"action": f"{cred['name']} ({cred['provider']}): referenced by the workflow but not found among stored secrets. "
                                "Confirm whether it exists anywhere (organization secret, calling workflow). If it does, sever it at the issuer.",
                      "human": True})
    if point["kind"] == "workflow":
        verify.append({"action": f"Re-enable the workflow only after every route above is denied: "
                                 f"gh workflow enable {point['path'].split('/')[-1]} --repo {repo}", "human": False})
    return {"point": point["id"], "dry_run": True,
            "stages": [{"name": "1. Sever", "steps": sever}, {"name": "2. Reissue and propagate", "steps": reissue},
                       {"name": "3. Verify", "steps": verify}],
            "commands": [] if not CUT_INSTALLED else ([f"firebreak cut --graph <graph> --point {repo} --keys <keys.json> --evidence <new file>"]
                         if r["deploy_keys"] and point["kind"] == "repo" else [])
                        + ([f"firebreak cut-aws --graph <graph> --point {point['id'].split(':', 1)[1]} "
                            "--keys <aws-keys.json> --evidence <new file>"] if r["aws"] else []),
            "credentials": len(creds), "unconfirmed": len(r["missing"]),
            "aws_principals": len({e["principal"]["id"] for e in r["aws"]}), "gaps": r["gaps"],
            "limits": (["Reach beyond GitHub is not collected yet: what each credential can do in its own system is unknown."]
                       if not graph.of_kind("aws_account") else
                       ["Reach is collected for AWS only; other providers are unknown."] + aws.LIMITS)
                      + ["Provider and type are guessed from secret names.",
                         "Secrets already copied by an attacker stay valid until severed at the issuer."]}
