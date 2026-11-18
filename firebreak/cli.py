"""firebreak map | plan, and the paid commands where they are installed"""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
from pathlib import Path

from . import analyze, aws, github
from .graph import Graph

# The open-source build has map and plan only. Import errors inside the paid module still surface.
cut_commands = (importlib.import_module(f"{__package__}.cut_commands")
                if importlib.util.find_spec(f"{__package__}.cut_commands") else None)


def _load(path: str) -> Graph:
    return Graph.from_json(Path(path).read_text())


def render_map(graph: Graph) -> str:
    lines = []
    for source in graph.sources:
        detail = source.get("owner") or source.get("account", "")
        endpoint = f", endpoint {source['endpoint']}" if source.get("endpoint") else ""
        lines.append(f"Source: {source['provider']} {detail} ({source['environment']}{endpoint})")
    repos = graph.of_kind("repo")
    secrets = [s for s in graph.of_kind("secret") if s["scope"] != "unresolved"]
    if graph.gaps:
        lines.append("Collection incomplete. Counts below cover only the data Firebreak could read.")
    lines.append(f"Repositories: {len(repos)}   Workflows: {len(graph.of_kind('workflow'))}   "
                 f"Secrets: {len(secrets)}   Deploy keys: {len(graph.of_kind('deploy_key'))}")
    points = []
    for node in graph.of_kind("workflow") + repos:
        r = analyze.radius(graph, node)
        roles = len({e["principal"]["id"] for e in r["aws"]})
        points.append((len(r["direct"]), len(r["latent"]), len(r["deploy_keys"]), roles, node, r["aws"]))
    points.sort(key=lambda p: (-p[3], -p[0], -p[1], -p[2], p[4]["id"]))
    lines.append("\nExposure points, widest first (direct / also readable if the workflow is changed / deploy keys"
                 " / AWS principals):")
    shown = [p for p in points if any(p[:4])]
    for direct, latent, keys, roles, node, reach in shown[:25]:
        label = node["name"] if node["kind"] == "repo" else f"{node['repo']}:{node['path']}"
        lines.append(f"  {direct:>3} / {latent:>3} / {keys:>2} / {roles:>2}  {node['kind']:<8} {label}")
        for entry in reach:
            name = entry["principal"].get("name") or entry["principal"].get("key_id")
            lines.append(f"        AWS {name} via {entry['via']} ({entry['exposure']}): {entry['reach']}")
    if not shown:
        if graph.gaps:
            gap = graph.gaps[0]
            lines.append(f"  Credential exposure is unknown. Could not read {gap['what']} for "
                         f"{gap['scope']} ({gap['reason']}).")
        else:
            lines.append("  No credential exposure found in the collected data.")
    accounts = graph.of_kind("aws_account")
    for account in accounts:
        keys = [k for k in graph.of_kind("aws_access_key") if k["account"] == account["account"]]
        roles = [r for r in graph.of_kind("aws_role") if r["account"] == account["account"]]
        lines.append(f"\nAWS account {account['account']} ({account['environment']}): "
                     f"users {len([u for u in graph.of_kind('aws_user') if u['account'] == account['account']])}, "
                     f"active access keys {len([k for k in keys if k.get('status') == 'Active'])}, roles {len(roles)}, "
                     f"roles trusting GitHub OIDC {len([r for r in roles if r.get('github')])}")
        for user in graph.of_kind("aws_user"):
            if user["account"] == account["account"]:
                mark = "" if user.get("complete", True) else " (incomplete: some policies unreadable)"
                own = any(k.get("used_by_firebreak") for k in graph.of_kind("aws_access_key")
                          if k["user_arn"] == user["arn"])
                mark += " (Firebreak's own credentials)" if own else ""
                lines.append(f"  user {user['name']}: {user['reach']}{mark}")
        for role in roles:
            trusted = [f"GitHub {s}" for s in role.get("github_subjects", [])]
            if role.get("github_unrestricted"):
                trusted.append("ANY GitHub repository")
            if role.get("trusts_own_account"):
                trusted.append("this account")
            trusted += [f"account {a}" for a in role.get("external_accounts", [])]
            trusted += role.get("services", [])
            lines.append(f"  role {role['name']}: {role['reach']}; assumable by {', '.join(trusted) or 'nobody listed'}")
    found = analyze.findings(graph)
    lines.append(f"\nReduction candidates: {len(found)}")
    for item in found:
        lines.append(f"  [{item['kind']}] {item['where']}: {item['detail']}")
    lines.append(f"\nNot collected: {len(graph.gaps)}")
    for gap in graph.gaps:
        lines.append(f"  {gap['scope']}: {gap['what']} ({gap['reason']})")
    if accounts:
        lines.append("\nLimits: providers are guessed from secret names; workflow files are scanned as text, per file.")
        lines += [f"  - {limit}" for limit in aws.LIMITS]
    else:
        lines.append("\nLimits: reach beyond GitHub is not collected; providers are guessed from secret names; "
                     "workflow files are scanned as text, per file.")
    return "\n".join(lines)


def render_plan(plan: dict) -> str:
    lines = [f"DRY RUN cut plan for {plan['point']}"]
    empty_stage = "  nothing to do"
    if plan["gaps"]:
        lines.append("This plan is incomplete because some data could not be read.")
        empty_stage = "  No steps identified from the collected data."
    lines.append(f"Credentials in scope: {plan['credentials']}   Referenced but not found: {plan['unconfirmed']}   "
                 f"AWS principals reachable: {plan.get('aws_principals', 0)}")
    number = 0
    for stage in plan["stages"]:
        lines.append(f"\n{stage['name']}")
        for step in stage["steps"]:
            number += 1
            lines.append(f"  {number:>2}. {'[person]' if step['human'] else '[command]'} {step['action']}")
        if not stage["steps"]:
            lines.append(empty_stage)
    for gap in plan["gaps"]:
        lines.append(f"\nNot collected for this repository: {gap['what']} ({gap['reason']})")
    if plan.get("commands"):
        lines.append("\nTo carry out the steps marked for a tool:")
        lines += [f"  {command}" for command in plan["commands"]]
    lines.append("\nLimits:")
    lines += [f"  - {limit}" for limit in plan["limits"]]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="firebreak", description="Credential containment for the delivery pipeline. "
                                     + ("Read-only unless `cut --execute` is given." if cut_commands else "Read-only."))
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("map", help="collect GitHub and/or AWS and show blast radius")
    m.add_argument("--owner", help="GitHub account or organization")
    m.add_argument("--repo", help="limit to one repository")
    m.add_argument("--out", help="write the graph as JSON")
    m.add_argument("--aws", action="store_true", help="also collect the AWS account of the current credentials (read-only)")
    m.add_argument("--aws-profile", help="AWS profile to use")
    m.add_argument("--aws-endpoint", help="custom endpoint such as LocalStack; results are labelled simulated")
    m.add_argument("--aws-links", help='JSON file: {"owner/repo:SECRET_NAME": "<access key id>"}')
    m.add_argument("--graph", help="render a saved graph instead of collecting")
    p = sub.add_parser("plan", help="print a dry-run cut plan for one exposure point")
    p.add_argument("--graph", required=True)
    p.add_argument("--point", required=True, help="owner/repo or owner/repo:.github/workflows/file.yml")
    p.add_argument("--json", action="store_true")
    if cut_commands:
        cut_commands.register(sub)
    args = parser.parse_args(argv)

    if args.command == "map":
        if args.graph:
            graph = _load(args.graph)
        elif not (args.owner or args.aws):
            parser.error("map needs --owner, --aws, or --graph")
        else:
            graph = (github.collect(github.Client(github.token_from_environment()), args.owner, args.repo)
                     if args.owner else Graph())
        if args.aws:
            environment, endpoint = aws.environment_for(args.aws_endpoint)
            aws.collect(aws.make_session(args.aws_profile), graph, environment, endpoint)
        aws.link_github(graph)
        if args.aws_links:
            aws.link_secrets(graph, json.loads(Path(args.aws_links).read_text()))
        if args.out:
            Path(args.out).write_text(graph.to_json())
        print(render_map(graph))
    elif args.command == "plan":
        graph = _load(args.graph)
        plan = analyze.cut_plan(graph, analyze.resolve_point(graph, args.point))
        print(json.dumps(plan, indent=2) if args.json else render_plan(plan))
    else:
        return cut_commands.run(args, parser, _load)
    return 0
