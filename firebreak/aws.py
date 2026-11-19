"""Read-only AWS collector and AWS reach analysis.

Collects IAM users, their access keys, roles, what their policies allow, who can assume
each role, and which GitHub repositories can assume a role through OIDC. Only list and get
calls are made. IAM never returns secret access keys, so none are read.

Policy evaluation is simplified: Allow statements of identity policies are read, Deny
statements are counted but not applied, and permission boundaries, SCPs, session policies
and resource policies are not evaluated. Reach is therefore an upper bound on what the
identity policies grant, not a proof of what a request would be allowed to do."""
from __future__ import annotations

import fnmatch
import importlib.util
import json
import os
import re
import urllib.parse
from datetime import datetime, timezone

from .graph import Graph

GITHUB_OIDC = "token.actions.githubusercontent.com"
# The cut is not part of the open-source build; plans name its commands only where it is installed.
CUT_INSTALLED = importlib.util.find_spec(f"{__package__}.cut") is not None
VERIFY_HINT = " Feed the observations to `firebreak verify` with environment observed." if CUT_INSTALLED else ""
OLD_DAYS = 90
LIMITS = ["AWS reach applies unconditional Deny statements on all resources; other Deny statements, permission boundaries, "
          "SCPs, session policies and resource policies are not evaluated, so reach is an upper bound.",
          "Role chaining (a role assuming another role) is not followed."]


# ---------- collection (needs boto3) ----------

def _require_boto3():
    try:
        import boto3
        import botocore
    except ImportError:
        raise SystemExit("AWS support needs boto3: pip install 'firebreak[aws]'") from None
    return boto3, botocore


def make_session(profile: str | None = None, region: str | None = None):
    boto3, _ = _require_boto3()
    return boto3.Session(profile_name=profile, region_name=region or "us-east-1")


def environment_for(endpoint: str | None) -> tuple[str, str | None]:
    """A custom endpoint (LocalStack, Moto server) means the results are simulated."""
    endpoint = endpoint or os.environ.get("AWS_ENDPOINT_URL_IAM") or os.environ.get("AWS_ENDPOINT_URL")
    return ("simulated", endpoint) if endpoint else ("observed", None)


def _doc(value):
    return json.loads(urllib.parse.unquote(value)) if isinstance(value, str) else value


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _iso(value) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else value


# Action names that only read. Anything else, including a bare wildcard, counts as able to change things.
READ_VERBS = ("get", "list", "describe", "generate", "simulate", "view", "search", "lookup",
              "batchget", "query", "scan", "select", "head")


def _is_read(action: str) -> bool:
    verb = action.split(":", 1)[1] if ":" in action else action
    return verb != "*" and verb.startswith(READ_VERBS)


def summarize(documents: list[tuple[str, dict]]) -> dict:
    """Allow statements of a principal's policies, and a one-line reach."""
    allow, denies, denied = [], 0, []
    for name, doc in documents:
        for st in _as_list(doc.get("Statement")):
            if st.get("Effect") != "Allow":
                denies += 1
                # An unconditional Deny of named actions on every resource can be applied exactly.
                if (st.get("Effect") == "Deny" and not st.get("Condition") and "Action" in st
                        and "*" in _as_list(st.get("Resource"))):
                    denied += [a.lower() for a in _as_list(st["Action"])]
                continue
            not_action, not_resource = "NotAction" in st, "NotResource" in st
            allow.append({"policy": name,
                          "actions": [a.lower() for a in _as_list(st.get("NotAction" if not_action else "Action"))],
                          "resources": _as_list(st.get("NotResource" if not_resource else "Resource")),
                          "not_action": not_action, "not_resource": not_resource,
                          "conditional": bool(st.get("Condition"))})
    full_allow = any(not s["conditional"] and not s["not_action"] and not s["not_resource"]
                     and "*" in s["resources"] and any(a in ("*", "*:*") for a in s["actions"]) for s in allow)
    everything_denied = any(a in ("*", "*:*") for a in denied)
    denied_services = {a.split(":")[0] for a in denied if a.endswith(":*")}
    admin = full_allow and not denied
    services, writes = set(), set()
    for s in allow:
        if s["not_action"]:
            services.add("all except " + ", ".join(s["actions"]))
            continue
        for a in s["actions"]:
            service = "all" if a in ("*", "*:*") else a.split(":")[0]
            services.add(service)
            if not _is_read(a):
                writes.add(service)
    services -= denied_services
    labels = sorted(f"{s} (read)" if s not in writes and not s.startswith("all") else s for s in services)
    if everything_denied:
        reach = "none: every action is denied"
    elif admin:
        reach = "admin: every action on every resource"
    elif full_allow:
        reach = "all actions except " + ", ".join(sorted(set(denied)))
    elif not allow or not labels:
        reach = "none"
    else:
        reach = ", ".join(labels) + ("; some conditional" if any(s["conditional"] for s in allow) else "")
    return {"allow": allow, "deny_statements": denies, "denied_actions": sorted(set(denied)), "admin": admin,
            "reach": reach}


def allows(statements: list[dict], action: str, resource: str) -> dict | None:
    """First Allow statement covering this action on this resource, ignoring Denies."""
    action = action.lower()
    for st in statements:
        hit = any(fnmatch.fnmatchcase(action, a) for a in st["actions"])
        if st["not_action"]:
            hit = not hit
        if not hit:
            continue
        on = any(fnmatch.fnmatchcase(resource, r) for r in st["resources"])
        if on != st["not_resource"]:
            return st
    return None


def parse_trust(doc: dict) -> dict:
    out = {"aws": [], "services": [], "github_subjects": [], "github": False, "github_unrestricted": False,
           "other_federated": [], "anyone": False}
    for st in _as_list(doc.get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal", {})
        if principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))):
            out["anyone"] = True
        if not isinstance(principal, dict):
            continue
        out["aws"] += [p for p in _as_list(principal.get("AWS")) if p != "*"]
        out["services"] += _as_list(principal.get("Service"))
        for fed in _as_list(principal.get("Federated")):
            if GITHUB_OIDC not in fed:
                out["other_federated"].append(fed)
                continue
            out["github"] = True
            subjects, other_claims = [], []
            for conditions in (st.get("Condition") or {}).values():
                for key, value in conditions.items():
                    claim = key.lower()
                    if claim == f"{GITHUB_OIDC}:sub":
                        subjects += _as_list(value)
                    elif claim.startswith(GITHUB_OIDC) and not claim.endswith(":aud"):
                        other_claims.append(key)
            out["github_subjects"] += subjects
            # No subject condition (and no other claim restricting it), or one matching
            # everything: any repository on GitHub can assume the role.
            if (not subjects and not other_claims) or any(s.strip() in ("*", "repo:*", "repo:*/*") for s in subjects):
                out["github_unrestricted"] = True
    return out


def collect(session, graph: Graph | None = None, environment: str = "observed",
            endpoint: str | None = None) -> Graph:
    _, botocore = _require_boto3()
    graph = graph if graph is not None else Graph()
    client_error = botocore.exceptions.ClientError
    options = {"endpoint_url": endpoint} if endpoint else {}
    iam, sts = session.client("iam", **options), session.client("sts", **options)
    try:
        ident = sts.get_caller_identity()
    except (botocore.exceptions.NoCredentialsError, botocore.exceptions.PartialCredentialsError):
        raise SystemExit("No AWS credentials found: set AWS_PROFILE or pass --aws-profile.") from None
    account = ident["Account"]
    # The key Firebreak itself is using: AWS updates last-use data with a delay, so on a first
    # run it would be reported as never used.
    credentials = session.get_credentials() if hasattr(session, "get_credentials") else None
    own_key = credentials.access_key if credentials else None
    scope = f"aws:{account}"
    graph.add_source("aws", environment, account=account, caller=ident["Arn"], endpoint=endpoint)
    account_id = graph.add_node(f"aws-account:{account}", "aws_account", account=account, environment=environment)

    def attempt(what, call, default):
        try:
            return call()
        except client_error as err:
            graph.add_gap(scope, what, err.response.get("Error", {}).get("Code", "ClientError"))
            return default

    def pages(operation, key, **kwargs):
        return [item for page in iam.get_paginator(operation).paginate(**kwargs) for item in page[key]]

    managed_cache: dict[str, dict | None] = {}

    def managed(arn):
        if arn not in managed_cache:
            def fetch():
                policy = iam.get_policy(PolicyArn=arn)["Policy"]
                version = iam.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])
                return _doc(version["PolicyVersion"]["Document"])
            managed_cache[arn] = attempt(f"managed policy {arn}", fetch, None)
        return managed_cache[arn]

    def documents(kind, name):
        """(policy documents, complete) for a user, group or role."""
        field, start = f"{kind.capitalize()}Name", len(graph.gaps)
        docs = []
        for policy in attempt(f"attached policies of {kind} {name}",
                              lambda: pages(f"list_attached_{kind}_policies", "AttachedPolicies", **{field: name}), []):
            doc = managed(policy["PolicyArn"])
            if doc is not None:
                docs.append((policy["PolicyName"], doc))
        for policy_name in attempt(f"inline policies of {kind} {name}",
                                   lambda: pages(f"list_{kind}_policies", "PolicyNames", **{field: name}), []):
            doc = attempt(f"inline policy {policy_name} of {kind} {name}",
                          lambda: _doc(getattr(iam, f"get_{kind}_policy")(**{field: name, "PolicyName": policy_name})["PolicyDocument"]),
                          None)
            if doc is not None:
                docs.append((policy_name, doc))
        return docs, len(graph.gaps) == start

    users = []
    for user in attempt("IAM users", lambda: pages("list_users", "Users"), []):
        name, arn = user["UserName"], user["Arn"]
        docs, complete = documents("user", name)
        for group in attempt(f"groups of user {name}", lambda: pages("list_groups_for_user", "Groups", UserName=name), []):
            group_docs, group_complete = documents("group", group["GroupName"])
            docs += [(f"{group['GroupName']}/{n}", d) for n, d in group_docs]
            complete = complete and group_complete
        node = graph.add_node(f"aws-user:{arn}", "aws_user", arn=arn, name=name, account=account,
                              complete=complete, **summarize(docs))
        graph.add_edge(account_id, "contains", node)
        users.append(graph.nodes[node])
        for key in attempt(f"access keys of user {name}",
                           lambda: pages("list_access_keys", "AccessKeyMetadata", UserName=name), []):
            key_id = key["AccessKeyId"]
            used = attempt(f"last use of access key {key_id}",
                           lambda: iam.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"], {})
            kid = graph.add_node(f"aws-key:{key_id}", "aws_access_key", key_id=key_id, user=name, user_arn=arn,
                                 account=account, status=key.get("Status"), created=_iso(key.get("CreateDate")),
                                 last_used=_iso(used.get("LastUsedDate")), last_service=used.get("ServiceName"),
                                 used_by_firebreak=key_id == own_key)
            graph.add_edge(kid, "authenticates_as", node)

    for role in attempt("IAM roles", lambda: pages("list_roles", "Roles"), []):
        if role.get("Path", "/").startswith("/aws-service-role/"):
            continue  # owned and assumed by AWS services only
        name, arn = role["RoleName"], role["Arn"]
        docs, complete = documents("role", name)
        trust = parse_trust(_doc(role.get("AssumeRolePolicyDocument") or {}))
        rid = graph.add_node(f"aws-role:{arn}", "aws_role", arn=arn, name=name, account=account, complete=complete,
                             max_session_seconds=role.get("MaxSessionDuration"), **trust,
                             trusts_own_account=False, external_accounts=[], trusted_principals=[], **summarize(docs))
        graph.add_edge(account_id, "contains", rid)
        node = graph.nodes[rid]
        for principal in trust["aws"]:
            owner = principal if re.fullmatch(r"\d{12}", principal) else (principal.split(":")[4] if principal.count(":") >= 5 else "")
            if owner and owner != account:
                node["external_accounts"].append(owner)
            elif principal in (account, f"arn:aws:iam::{account}:root"):
                node["trusts_own_account"] = True
            elif f"aws-user:{principal}" in graph.nodes:
                graph.add_edge(f"aws-user:{principal}", "can_assume", rid)
            else:
                node["trusted_principals"].append(principal)
        if node["trusts_own_account"]:
            # Any identity in the account whose own policy allows sts:AssumeRole on this role.
            for user in users:
                if allows(user["allow"], "sts:AssumeRole", arn):
                    graph.add_edge(user["id"], "can_assume", rid)
    return graph


# ---------- linking and analysis (no boto3 needed) ----------

def _repo_part(subject: str) -> str:
    match = re.match(r"repo:([^:]+)", subject)
    return match.group(1) if match else subject


def link_github(graph: Graph) -> None:
    """Edges from GitHub repositories to the roles they can assume through OIDC. Subjects are
    matched case-insensitively, which can over-report reach but never hides it."""
    repos = graph.of_kind("repo")
    for role in graph.of_kind("aws_role"):
        if not role.get("github"):
            continue
        if role.get("github_unrestricted"):
            for repo in repos:
                graph.add_edge(repo["id"], "can_assume", role["id"])
            continue
        for subject in role.get("github_subjects", []):
            match = re.match(r"repo:([^:]+)", subject)
            if not match:
                continue
            pattern = match.group(1).lower()
            for repo in repos:
                if fnmatch.fnmatchcase(repo["name"].lower(), pattern):
                    graph.add_edge(repo["id"], "can_assume", role["id"])


def link_secrets(graph: Graph, links: dict) -> None:
    """Tie GitHub secrets to the AWS access keys they hold. GitHub never returns secret values,
    so this mapping comes from the person running the tool: {"owner/repo:SECRET": "AKIA..."}."""
    for target, key_id in links.items():
        repo, _, name = target.rpartition(":")
        secrets = [n for n in graph.of_kind("secret")
                   if n["repo"] == repo and n["name"] == name and n["scope"] != "unresolved"]
        if not secrets:
            graph.add_gap("links", target, "no such secret in the map")
        elif f"aws-key:{key_id}" not in graph.nodes:
            graph.add_gap("links", f"{target} -> {key_id}", "access key not found in the collected AWS account")
        else:
            for secret in secrets:
                graph.add_edge(secret["id"], "is", f"aws-key:{key_id}")


def reach(graph: Graph, point: dict, direct: list, latent: list) -> list[dict]:
    """AWS principals an exposure point can act as."""
    entries = []
    repo_id = f"repo:{point['repo']}" if point["kind"] == "workflow" else point["id"]
    oidc_exposure = "direct" if point["kind"] == "repo" or point.get("oidc") else "latent"
    for role in graph.out(repo_id, "can_assume"):
        entries.append({"via": "GitHub OIDC", "exposure": oidc_exposure, "principal": role, "reach": role["reach"]})
    # One key is usually held in two secrets (key id and secret key): one entry per key, naming both.
    held: dict[str, dict] = {}
    for exposure, secrets in (("direct", direct), ("latent", latent)):
        for secret in secrets:
            for key in graph.out(secret["id"], "is"):
                slot = held.setdefault(key["id"], {"key": key, "names": [], "exposure": exposure})
                if secret["name"] not in slot["names"]:
                    slot["names"].append(secret["name"])
    for slot in held.values():
        key, label = slot["key"], "secret" + ("s " if len(slot["names"]) > 1 else " ") + ", ".join(slot["names"])
        for user in graph.out(key["id"], "authenticates_as"):
            entries.append({"via": label, "exposure": slot["exposure"], "principal": key, "user": user,
                            "reach": user["reach"], "secrets": slot["names"]})
            for role in graph.out(user["id"], "can_assume"):
                entries.append({"via": f"{label}, then sts:AssumeRole", "exposure": slot["exposure"],
                                "principal": role, "reach": role["reach"]})
    return entries


def _days(stamp: str | None, now: datetime) -> int | None:
    if not stamp:
        return None
    moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (now - moment).days


def findings(graph: Graph, now: datetime) -> list[dict]:
    out = []

    def add(kind, where, detail):
        out.append({"kind": kind, "where": where, "detail": detail})

    if not graph.of_kind("aws_account"):
        return out
    active_per_user: dict[str, int] = {}
    for key in graph.of_kind("aws_access_key"):
        if key.get("status") != "Active":
            continue
        where = f"AWS key {key['key_id']} (user {key['user']})"
        active_per_user[key["user"]] = active_per_user.get(key["user"], 0) + 1
        age, idle = _days(key.get("created"), now), _days(key.get("last_used"), now)
        if age is not None and age > OLD_DAYS:
            add("aws-key-old", where, f"Active for {age} days.")
        if key.get("used_by_firebreak"):
            pass  # in use right now; last-use data lags
        elif idle is None:
            add("aws-key-never-used", where, "Active and never used. Delete it.")
        elif idle > OLD_DAYS:
            add("aws-key-unused", where, f"Not used for {idle} days.")
        user = graph.nodes.get(f"aws-user:{key['user_arn']}")
        if user and user.get("admin"):
            add("aws-admin-standing-key", where, "Long-lived key for a user with full admin rights.")
    for user, count in sorted(active_per_user.items()):
        if count > 1:
            add("aws-two-active-keys", f"AWS user {user}", "Two active access keys.")
    for role in graph.of_kind("aws_role"):
        where = f"AWS role {role['name']}"
        if role.get("github_unrestricted"):
            add("aws-oidc-any-repo", where, "Trusts GitHub OIDC without restricting the token subject: any GitHub "
                                            "repository, including ones you do not own, can assume it.")
        else:
            # repo:owner/name:* (any branch of one repository) is the usual pattern; a wildcard in
            # the owner/name part opens the role to other repositories.
            broad = [s for s in role.get("github_subjects", [])
                     if "*" in _repo_part(s) or "?" in _repo_part(s)]
            if broad:
                add("aws-oidc-wildcard", where, "GitHub OIDC trust matches more than one repository: " + ", ".join(broad))
        for account in sorted(set(role.get("external_accounts", []))):
            add("aws-trust-external-account", where, f"Trusts account {account}.")
        if role.get("anyone"):
            add("aws-trust-anyone", where, "Trust policy allows any AWS principal (check its conditions).")
    for secret in graph.of_kind("secret"):
        if secret["provider"] == "aws" and secret["scope"] != "unresolved" and not graph.out(secret["id"], "is"):
            add("aws-secret-unlinked", f"{secret['repo']} secret {secret['name']} ({secret['scope']})",
                "Holds an AWS credential, but which key is unknown, so its reach is unknown. Add it to --aws-links.")
    return out


REVOKE_DOC = ('{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",'
              '"Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CUT_TIME_UTC>"}}}]}')


def role_steps(role: dict, repo: str) -> tuple[list, list, list]:
    stop = ("the trust policy does not restrict the token subject, so ANY GitHub repository can assume it: add a "
            "subject condition naming only the repositories that need it" if role.get("github_unrestricted") else
            f"remove {repo} from the subjects in its trust policy, or narrow them")
    sever = [
        {"action": f"AWS role {role['name']} ({role['reach']}): stop new sessions: {stop} "
                   "(aws iam update-assume-role-policy).", "human": True},
        {"action": f"AWS role {role['name']}: revoke sessions already issued. Write the policy with the time of the cut, "
                   f"then: aws iam put-role-policy --role-name {role['name']} --policy-name AWSRevokeOlderSessions "
                   f"--policy-document '{REVOKE_DOC}'. This also ends legitimate sessions of the role.", "human": False},
    ]
    verify = [{"action": f"AWS role {role['name']}: call aws sts get-caller-identity with a session issued before the "
                         "cut and record AccessDenied or success; confirm a new session from an allowed workflow works.",
               "human": True}]
    return sever, [], verify


def key_steps(graph: Graph, key: dict, secret_names: list[str], repo: str) -> tuple[list, list, list]:
    user = key["user"]
    sever = [
        {"action": f"AWS key {key['key_id']} (user {user}): aws iam update-access-key --user-name {user} "
                   f"--access-key-id {key['key_id']} --status Inactive", "human": False},
        {"action": f"AWS user {user}: sessions already issued with this key stay valid after it is disabled. "
                   f"aws iam put-user-policy --user-name {user} --policy-name AWSRevokeOlderSessions "
                   f"--policy-document '{REVOKE_DOC}'", "human": False},
    ]
    for role in graph.out(f"aws-user:{key['user_arn']}", "can_assume"):
        sever.append({"action": f"AWS role {role['name']}: {user} can assume it, so revoke its older sessions too: "
                                f"aws iam put-role-policy --role-name {role['name']} --policy-name AWSRevokeOlderSessions "
                                f"--policy-document '{REVOKE_DOC}'. This also ends legitimate sessions of the role.",
                      "human": False})
    active = [k for k in graph.of_kind("aws_access_key") if k["user"] == user and k.get("status") == "Active"]
    room = "" if len(active) < 2 else " The user already has two active keys: delete one first (IAM allows two)."
    store = "; ".join(f"gh secret set {name} --repo {repo}" for name in secret_names)
    reissue = [{"action": f"AWS user {user}: aws iam create-access-key --user-name {user}, then store the new pair: "
                          f"{store}{'' if len(secret_names) > 1 else ' (and its companion secret)'}.{room}",
                "human": True},
               {"action": f"AWS key {key['key_id']}: after the replacement works, delete the old key: "
                          f"aws iam delete-access-key --user-name {user} --access-key-id {key['key_id']}", "human": False}]
    verify = [{"action": f"AWS key {key['key_id']}: call aws sts get-caller-identity with the OLD key and record the "
                         "result; confirm a legitimate job works with the NEW one." + VERIFY_HINT, "human": True}]
    return sever, reissue, verify
