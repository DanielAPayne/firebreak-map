"""Read-only GitHub collector. It reads secret names and metadata, never secret values
(the GitHub API does not return them). The client here can only read."""
from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request

from .graph import Graph


class NotFound(Exception):
    """Something the user named does not exist or is not visible to the token."""

API = "https://api.github.com"

# (provider, name pattern). First match wins. A guess from the secret's name only.
PROVIDERS = [
    ("aws", r"AWS|AMAZON"),
    ("gcp", r"GCP|GOOGLE|GCLOUD"),
    ("azure", r"AZURE|ARM_CLIENT"),
    ("oci", r"^OCI_|ORACLE"),
    ("kubernetes", r"KUBE|K8S"),
    ("npm", r"NPM"),
    ("pypi", r"PYPI|TWINE"),
    ("container-registry", r"DOCKER|GHCR|REGISTRY|QUAY"),
    ("github", r"GH_|GITHUB|_PAT$|^PAT_|DEPLOY_KEY"),
    ("ssh", r"SSH"),
    ("signing", r"SIGN|GPG|COSIGN|ED25519"),
    ("chat-webhook", r"SLACK|DISCORD|TEAMS|WEBHOOK"),
]


def classify(name: str) -> str:
    for provider, pattern in PROVIDERS:
        if re.search(pattern, name.upper()):
            return provider
    return "unknown"


class ApiError(Exception):
    def __init__(self, status: int, path: str):
        super().__init__(f"HTTP {status} for {path}")
        self.status, self.path = status, path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Never follow a redirect: the token must not be sent to another host.
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, token: str, base: str = API):
        self.token, self.base = token, base
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _check(self, url: str) -> None:
        if not url.startswith(self.base + "/"):
            raise ValueError("Refusing to send the token outside the GitHub API")

    def _headers(self, accept: str) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Accept": accept,
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "firebreak-cli"}

    def _open(self, request, path: str):
        try:
            with self._opener.open(request, timeout=30) as response:
                return response.read(), response.headers.get("Link", "")
        except urllib.error.HTTPError as err:
            raise ApiError(err.code, path) from None

    def _fetch(self, url: str, accept: str):
        """GET only: this client cannot change anything."""
        self._check(url)
        return self._open(urllib.request.Request(url, headers=self._headers(accept)), url[len(self.base):])

    def get(self, path: str):
        body, _ = self._fetch(self.base + path, "application/vnd.github+json")
        return json.loads(body)

    def get_raw(self, path: str) -> str:
        body, _ = self._fetch(self.base + path, "application/vnd.github.raw+json")
        return body.decode("utf-8", "replace")

    def get_all(self, path: str, key: str | None = None) -> list:
        """Follow pagination. `key` names the list inside a wrapped response."""
        items, url = [], self.base + path + ("&" if "?" in path else "?") + "per_page=100"
        while url:
            body, link = self._fetch(url, "application/vnd.github+json")
            page = json.loads(body)
            items.extend(page[key] if key else page)
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = match.group(1) if match else None
        return items


def token_from_environment() -> str:
    for name in ("FIREBREAK_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True,
                              check=True, timeout=15).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise SystemExit("No GitHub token: set FIREBREAK_GITHUB_TOKEN or sign in with `gh auth login`.")


RISKY_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")
FIRST_PARTY = ("actions", "github")


def scan_workflow(text: str) -> dict:
    """Heuristic text scan of one workflow file. Not a YAML parse: it reports what the
    file mentions, at file granularity."""
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    # Only inside ${{ }} expressions, so a file name such as secrets.py is not a reference.
    expressions = " ".join(re.findall(r"\$\{\{(.*?)\}\}", body, re.S))
    names = set(re.findall(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)", expressions))
    names |= set(re.findall(r"\bsecrets\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]", expressions))
    names.discard("GITHUB_TOKEN")
    unpinned = []
    for ref in re.findall(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", body, re.M):
        if ref.startswith(("./", "docker://")) or "@" not in ref:
            continue
        action, version = ref.rsplit("@", 1)
        if action.split("/")[0] not in FIRST_PARTY and not re.fullmatch(r"[0-9a-f]{40}", version):
            unpinned.append(ref)
    return {
        "secrets": sorted(names),
        "all_secrets": bool(re.search(r"toJSON\(\s*secrets\s*\)|secrets:\s*inherit", body, re.I)),
        "risky_triggers": [t for t in RISKY_TRIGGERS if re.search(rf"\b{t}\b", body)],
        "oidc": bool(re.search(r"id-token:\s*write", body)),
        "permissions_declared": bool(re.search(r"^\s*permissions:", body, re.M)),
        "write_all": bool(re.search(r"permissions:\s*write-all", body)),
        "unpinned_actions": sorted(set(unpinned)),
        "self_hosted": bool(re.search(r"runs-on:.*self-hosted", body)),
    }


def collect(client, owner: str, only_repo: str | None = None) -> Graph:
    graph = Graph()

    def attempt(scope, what, call, default):
        try:
            return call()
        except ApiError as err:
            graph.add_gap(scope, what, f"HTTP {err.status}")
            return default

    graph.add_source("github", "observed", owner=owner)
    account = client.get(f"/users/{owner}")
    is_org = account.get("type") == "Organization"
    me = attempt(owner, "authenticated user", lambda: client.get("/user"), {}).get("login", "")
    if is_org:
        repos = client.get_all(f"/orgs/{owner}/repos?type=all")
    elif me.lower() == owner.lower():
        repos = client.get_all("/user/repos?affiliation=owner")
    else:
        repos = client.get_all(f"/users/{owner}/repos?type=owner")
        graph.add_gap(owner, "private repositories", "token belongs to another user")

    if only_repo:
        match = [r for r in repos if r["name"].lower() == only_repo.lower()]
        if not match:
            raise NotFound(f"Repository {owner}/{only_repo} was not found, or this token cannot see it.")
        if match[0].get("archived") or match[0].get("disabled"):
            raise NotFound(f"Repository {owner}/{match[0]['name']} is archived or disabled, so its workflows cannot run; "
                           "nothing to map.")
        repos = match
    for repo in repos:
        name = repo["name"]
        if repo.get("archived") or repo.get("disabled"):
            continue
        full = f"{owner}/{name}"
        rid = graph.add_node(f"repo:{full}", "repo", name=full, private=repo.get("private", False))
        base = f"/repos/{full}"

        perms = attempt(full, "default workflow token permissions",
                        lambda: client.get(f"{base}/actions/permissions/workflow"), None)
        graph.nodes[rid]["default_token"] = perms.get("default_workflow_permissions") if perms else "unknown"

        def add_secret(scope, item, node_id):
            graph.add_node(node_id, "secret", name=item["name"], repo=full, scope=scope,
                           provider=classify(item["name"]), updated_at=item.get("updated_at"),
                           reach="not collected: no collector attached for this provider")
            graph.add_edge(rid, "holds", node_id)

        for item in attempt(full, "repository secrets",
                            lambda: client.get_all(f"{base}/actions/secrets", "secrets"), []):
            add_secret("repo", item, f"secret:{full}:{item['name']}")
        if is_org:
            for item in attempt(full, "organization secrets shared with the repository",
                                lambda: client.get_all(f"{base}/actions/organization-secrets", "secrets"), []):
                add_secret("org", item, f"secret:org/{owner}:{item['name']}")
        for item in attempt(full, "Dependabot secrets",
                            lambda: client.get_all(f"{base}/dependabot/secrets", "secrets"), []):
            add_secret("dependabot", item, f"secret:{full}:dependabot:{item['name']}")
        for env in attempt(full, "environments",
                           lambda: client.get_all(f"{base}/environments", "environments"), []):
            ename = env["name"]
            for item in attempt(full, f"secrets of environment {ename}",
                                lambda: client.get_all(f"{base}/environments/{ename}/secrets", "secrets"), []):
                add_secret(f"env:{ename}", item, f"secret:{full}:env/{ename}:{item['name']}")

        for key in attempt(full, "deploy keys", lambda: client.get_all(f"{base}/keys"), []):
            kid = graph.add_node(f"deploykey:{full}:{key['id']}", "deploy_key", repo=full,
                                 key_id=key["id"], title=key.get("title", ""),
                                 write=not key.get("read_only", True), created_at=key.get("created_at"))
            graph.add_edge(kid, "grants", rid)

        held = {n["name"]: n["id"] for n in graph.out(rid, "holds") if n["scope"] != "dependabot"}
        for wf in attempt(full, "workflows",
                          lambda: client.get_all(f"{base}/actions/workflows", "workflows"), []):
            path = wf["path"]
            if not path.startswith(".github/workflows/"):
                continue  # dynamic workflows (Dependabot, Pages) have no file to read
            text = attempt(full, f"workflow file {path}",
                           lambda: client.get_raw(f"{base}/contents/{path}"), None)
            if text is None:
                continue
            scan = scan_workflow(text)
            wid = graph.add_node(f"workflow:{full}:{path}", "workflow", repo=full, path=path,
                                 state=wf.get("state", ""), **{k: v for k, v in scan.items() if k != "secrets"})
            graph.add_edge(rid, "contains", wid)
            for secret in scan["secrets"]:
                sid = held.get(secret)
                if sid is None:
                    sid = graph.add_node(f"secret:{full}:?{secret}", "secret", name=secret, repo=full,
                                         scope="unresolved", provider=classify(secret), updated_at=None,
                                         reach="not collected: referenced but not found among the secrets this token can list")
                graph.add_edge(wid, "references", sid)
    return graph
