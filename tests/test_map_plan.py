"""Collector, blast radius, findings and cut plan against a canned GitHub."""
from datetime import datetime, timezone
from pathlib import Path
import unittest

from firebreak import analyze, cli, github
from firebreak.graph import Graph

DEPLOY = """
name: deploy
on:
  pull_request_target:
permissions: write-all
jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: someone/uploader@v2
      # - run: echo ${{ secrets.COMMENTED_OUT }}
      - run: python tools/secrets.py && ./ship.sh
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          TOKEN: ${{ secrets['NPM_TOKEN'] }}
          GH: ${{ secrets.GITHUB_TOKEN }}
          GONE: ${{ secrets.MISSING_ONE }}
"""
CI = """
on: push
permissions:
  contents: read
  id-token: write
jobs:
  t:
    runs-on: [self-hosted, linux]
    steps:
      - uses: someone/tool@0123456789abcdef0123456789abcdef01234567
"""


class FakeClient:
    def __init__(self, deny=()):
        self.deny = deny
        self.data = {
            "/users/acme": {"type": "User"},
            "/user": {"login": "acme"},
            "/user/repos?affiliation=owner": [{"name": "app"}, {"name": "lib"}, {"name": "old", "archived": True}],
            "/repos/acme/app/actions/permissions/workflow": {"default_workflow_permissions": "write"},
            "/repos/acme/app/actions/secrets": [
                {"name": "AWS_ACCESS_KEY_ID", "updated_at": "2025-01-01T00:00:00Z"},
                {"name": "NPM_TOKEN", "updated_at": "2026-11-01T00:00:00Z"},
                {"name": "LEFTOVER", "updated_at": "2026-11-01T00:00:00Z"}],
            "/repos/acme/app/dependabot/secrets": [],
            "/repos/acme/app/environments": [{"name": "prod"}],
            "/repos/acme/app/environments/prod/secrets": [{"name": "SIGNING_KEY", "updated_at": "2026-11-01T00:00:00Z"}],
            "/repos/acme/app/keys": [{"id": 7, "title": "ci", "read_only": False}],
            "/repos/acme/app/actions/workflows": [
                {"path": ".github/workflows/deploy.yml", "state": "active"},
                {"path": ".github/workflows/ci.yml", "state": "active"},
                {"path": "dynamic/dependabot/dependabot-updates", "state": "active"}],
            "/repos/acme/app/contents/.github/workflows/deploy.yml": DEPLOY,
            "/repos/acme/app/contents/.github/workflows/ci.yml": CI,
            "/repos/acme/lib/actions/permissions/workflow": {"default_workflow_permissions": "read"},
            "/repos/acme/lib/actions/secrets": [{"name": "NPM_TOKEN", "updated_at": "2026-11-01T00:00:00Z"}],
            "/repos/acme/lib/dependabot/secrets": [],
            "/repos/acme/lib/environments": [],
            "/repos/acme/lib/keys": [],
            "/repos/acme/lib/actions/workflows": [],
        }

    def get(self, path):
        if path in self.deny or path not in self.data:
            raise github.ApiError(403 if path in self.deny else 404, path)
        return self.data[path]

    get_raw = get

    def get_all(self, path, key=None):
        return self.get(path)


NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)


class MapPlanTests(unittest.TestCase):
    def setUp(self):
        self.graph = github.collect(FakeClient(), "acme")

    def test_scan_ignores_comments_and_github_token(self):
        scan = github.scan_workflow(DEPLOY)
        self.assertEqual(scan["secrets"], ["AWS_ACCESS_KEY_ID", "MISSING_ONE", "NPM_TOKEN"])
        self.assertEqual(scan["unpinned_actions"], ["someone/uploader@v2"])
        self.assertEqual(scan["risky_triggers"], ["pull_request_target"])
        self.assertTrue(scan["write_all"])

    def test_scan_pinned_oidc_self_hosted(self):
        scan = github.scan_workflow(CI)
        self.assertEqual(scan["unpinned_actions"], [])
        self.assertTrue(scan["oidc"] and scan["self_hosted"])

    def test_archived_repo_skipped(self):
        self.assertEqual(sorted(n["name"] for n in self.graph.of_kind("repo")), ["acme/app", "acme/lib"])

    def test_workflow_radius_direct_and_latent(self):
        point = analyze.resolve_point(self.graph, "acme/app:.github/workflows/deploy.yml")
        r = analyze.radius(self.graph, point)
        self.assertEqual(sorted(n["name"] for n in r["direct"]), ["AWS_ACCESS_KEY_ID", "NPM_TOKEN"])
        self.assertEqual([n["name"] for n in r["missing"]], ["MISSING_ONE"])
        self.assertEqual(sorted(n["name"] for n in r["latent"]), ["LEFTOVER", "SIGNING_KEY"])

    def test_unresolved_reference_is_kept_not_dropped(self):
        node = self.graph.nodes["secret:acme/app:?MISSING_ONE"]
        self.assertEqual(node["scope"], "unresolved")

    def test_repo_radius_includes_deploy_keys(self):
        r = analyze.radius(self.graph, analyze.resolve_point(self.graph, "acme/app"))
        self.assertEqual(len(r["direct"]), 4)
        self.assertEqual([k["key_id"] for k in r["deploy_keys"]], [7])

    def test_findings(self):
        kinds = {}
        for item in analyze.findings(self.graph, NOW):
            kinds.setdefault(item["kind"], []).append(item["where"])
        self.assertEqual(kinds["token-default-write"], ["acme/app"])
        self.assertEqual(kinds["unused-candidate"], ["acme/app secret LEFTOVER (repo)", "acme/lib secret NPM_TOKEN (repo)"])
        self.assertEqual(kinds["stale"], ["acme/app secret AWS_ACCESS_KEY_ID (repo)"])
        self.assertEqual(kinds["shared-name"], ["secret NPM_TOKEN"])
        self.assertIn("deploy-key-write", kinds)
        self.assertEqual(kinds["missing-secret"], ["acme/app:.github/workflows/deploy.yml"])
        self.assertEqual(github.classify("OCI_CLI_KEY_CONTENT"), "oci")
        self.assertIn("unpinned-action-with-secrets", kinds)
        self.assertIn("risky-trigger-with-secrets", kinds)
        # ci.yml uses OIDC, so the static AWS key is not reported as an OIDC candidate here.
        self.assertNotIn("oidc-candidate", kinds)

    def test_plan_orders_cloud_first_and_covers_shared_names(self):
        plan = analyze.cut_plan(self.graph, analyze.resolve_point(self.graph, "deploy.yml"))
        sever = [s["action"] for s in plan["stages"][0]["steps"]]
        self.assertIn("gh workflow disable deploy.yml --repo acme/app", sever[0])
        self.assertTrue(sever[1].startswith("AWS_ACCESS_KEY_ID"))
        self.assertEqual(plan["credentials"], 4)
        self.assertEqual(plan["unconfirmed"], 1)
        self.assertIn("MISSING_ONE (unknown): referenced by the workflow but not found", sever[-1])
        reissue = " ".join(s["action"] for s in plan["stages"][1]["steps"])
        self.assertIn("gh secret set NPM_TOKEN --repo acme/lib", reissue)
        self.assertIn("gh secret set SIGNING_KEY --repo acme/app --env prod", reissue)
        self.assertTrue(plan["dry_run"])

    def test_denied_endpoint_becomes_a_gap(self):
        graph = github.collect(FakeClient(deny=("/repos/acme/app/actions/secrets",)), "acme")
        self.assertIn({"scope": "acme/app", "what": "repository secrets", "reason": "HTTP 403"}, graph.gaps)
        report = cli.render_map(graph)
        self.assertIn("repository secrets (HTTP 403)", report)
        self.assertLess(report.index("Collection incomplete"), report.index("Repositories:"))
        self.assertRegex(report, r"repo\s+acme/lib")
        self.assertNotIn("Credential exposure is unknown", report)

    def test_denied_secret_list_reports_unknown_exposure(self):
        graph = github.collect(FakeClient(deny=("/repos/acme/lib/actions/secrets",)), "acme", only_repo="lib")
        report = cli.render_map(graph)
        self.assertIn("Credential exposure is unknown", report)
        self.assertIn("Could not read repository secrets for acme/lib (HTTP 403)", report)
        self.assertNotIn("no exposure point can read", report)

    def test_readable_empty_secret_list_reports_no_observed_exposure(self):
        client = FakeClient()
        client.data["/repos/acme/lib/actions/secrets"] = []
        graph = github.collect(client, "acme", only_repo="lib")
        report = cli.render_map(graph)
        self.assertIn("No credential exposure found in the collected data", report)
        self.assertNotIn("Collection incomplete", report)
        self.assertNotIn("Credential exposure is unknown", report)

    def test_plan_with_a_denied_secret_list_marks_empty_stages_incomplete(self):
        graph = github.collect(FakeClient(deny=("/repos/acme/lib/actions/secrets",)), "acme", only_repo="lib")
        plan = analyze.cut_plan(graph, analyze.resolve_point(graph, "acme/lib"))
        report = cli.render_plan(plan)
        self.assertLess(report.index("This plan is incomplete"), report.index("Credentials in scope:"))
        self.assertIn("No steps identified from the collected data", report)
        self.assertIn("repository secrets (HTTP 403)", report)
        self.assertNotIn("nothing to do", report)

    def test_graph_round_trip_and_render(self):
        again = Graph.from_json(self.graph.to_json())
        self.assertEqual(cli.render_map(again), cli.render_map(self.graph))
        plan = analyze.cut_plan(again, analyze.resolve_point(again, "acme/app"))
        self.assertIn("DRY RUN", cli.render_plan(plan))

    def test_plans_name_no_command_that_is_not_installed(self):
        from firebreak.aws import CUT_INSTALLED
        text = cli.render_plan(analyze.cut_plan(self.graph, analyze.resolve_point(self.graph, "acme/app")))
        if not CUT_INSTALLED:
            self.assertNotRegex(text, r"firebreak (cut|verify|evidence)")

    def test_mistyped_or_archived_repo_is_an_error(self):
        with self.assertRaisesRegex(github.NotFound, "acme/nope-nope was not found"):
            github.collect(FakeClient(), "acme", "nope-nope")
        with self.assertRaisesRegex(github.NotFound, "archived"):
            github.collect(FakeClient(), "acme", "old")
        graph = github.collect(FakeClient(), "acme", "APP")  # GitHub names are case-insensitive
        self.assertEqual([n["name"] for n in graph.of_kind("repo")], ["acme/app"])

    def _cli_error(self, argv, collect_error=None):
        import contextlib, io
        from unittest import mock
        patch = mock.patch.object(github, "collect", side_effect=collect_error) if collect_error else contextlib.nullcontext()
        with patch, mock.patch.object(github, "token_from_environment", return_value="t"), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli.main(argv)
        return str(caught.exception.code)

    def test_user_errors_are_one_line_messages(self):
        import tempfile
        self.assertIn("rejected the token (HTTP 401)",
                      self._cli_error(["map", "--owner", "x"], github.ApiError(401, "/users/x")))
        self.assertIn("'ghost' was not found",
                      self._cli_error(["map", "--owner", "ghost"], github.ApiError(404, "/users/ghost")))
        self.assertIn("map file not found", self._cli_error(["plan", "--graph", "/no/such.json", "--point", "a/b"]))
        with tempfile.TemporaryDirectory() as d:
            bad, other, links = (Path(d) / n for n in ("bad.json", "other.json", "links.json"))
            bad.write_text("{bad"); other.write_text("[1, 2]"); links.write_text('["not", "a", "map"]')
            self.assertIn("is not valid JSON", self._cli_error(["map", "--graph", str(bad)]))
            self.assertIn("is not a Firebreak map", self._cli_error(["map", "--graph", str(other)]))
            good = Path(d) / "graph.json"
            good.write_text(self.graph.to_json())
            self.assertIn("must be a JSON object", self._cli_error(["map", "--graph", str(good), "--aws-links", str(links)]))

    def test_github_client_cannot_write(self):
        # map and plan only read: the client has no method that sends anything but a GET.
        client = github.Client("t")
        self.assertFalse(any(hasattr(client, name) for name in ("send", "post", "put", "patch", "delete")))

    def test_client_refuses_other_hosts(self):
        with self.assertRaises(ValueError):
            github.Client("t")._fetch("https://example.com/x", "a")


if __name__ == "__main__":
    unittest.main()
