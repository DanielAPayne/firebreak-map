"""AWS collector against Moto (simulated IAM), plus the pure analysis functions.

Moto does not enforce IAM authorization, so these tests check what is collected and how it
is analysed, never whether AWS would actually refuse a request."""
import json
import os
import unittest
from datetime import datetime, timezone
from unittest import mock

from firebreak import analyze, aws, cli, github
from firebreak.graph import Graph

try:
    import boto3
    from botocore.exceptions import ClientError
    from moto import mock_aws
except ImportError:  # the GitHub side must keep working without the AWS extra
    boto3 = None

from test_map_plan import FakeClient

ACCOUNT = "123456789012"
OIDC = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def github_trust(condition):
    return doc({"Effect": "Allow", "Principal": {"Federated": OIDC}, "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": condition})


class PureTests(unittest.TestCase):
    def test_summarize_admin_and_services(self):
        admin = aws.summarize([("a", {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})])
        self.assertTrue(admin["admin"])
        narrow = aws.summarize([("p", {"Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "sts:AssumeRole"], "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]})])
        self.assertFalse(narrow["admin"])
        self.assertEqual((narrow["reach"], narrow["deny_statements"]), ("s3 (read), sts", 1))
        iam_read = aws.summarize([("r", {"Statement": [{"Effect": "Allow", "Resource": "*",
                                                         "Action": ["iam:Get*", "iam:List*", "iam:Generate*"]}]})])
        self.assertEqual(iam_read["reach"], "iam (read)")
        iam_any = aws.summarize([("w", {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]})])
        self.assertEqual(iam_any["reach"], "iam")

    def test_conditional_wildcard_is_not_admin(self):
        s = aws.summarize([("c", {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                                                  "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]})])
        self.assertFalse(s["admin"])
        self.assertIn("conditional", s["reach"])

    def test_allows(self):
        s = aws.summarize([("p", {"Statement": [{"Effect": "Allow", "Action": "sts:Assume*",
                                                  "Resource": "arn:aws:iam::1:role/deploy-*"}]})])["allow"]
        self.assertTrue(aws.allows(s, "sts:AssumeRole", "arn:aws:iam::1:role/deploy-prod"))
        self.assertFalse(aws.allows(s, "sts:AssumeRole", "arn:aws:iam::1:role/admin"))
        not_action = aws.summarize([("n", {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]})])
        self.assertTrue(aws.allows(not_action["allow"], "sts:AssumeRole", "x"))
        self.assertFalse(aws.allows(not_action["allow"], "iam:CreateUser", "x"))

    def test_wildcard_owner_is_flagged(self):
        graph = Graph()
        graph.add_node("aws-account:1", "aws_account", account="1", environment="synthetic")
        graph.add_node("aws-role:r", "aws_role", name="r", account="1", github=True, github_unrestricted=False,
                       github_subjects=["repo:acme/*:ref:refs/heads/main"], external_accounts=[], anyone=False)
        kinds = [f["kind"] for f in aws.findings(graph, datetime(2027, 1, 1, tzinfo=timezone.utc))]
        self.assertEqual(kinds, ["aws-oidc-wildcard"])

    def test_trust_parsing(self):
        exact = aws.parse_trust(json.loads(github_trust({"StringLike": {
            "token.actions.githubusercontent.com:sub": "repo:acme/app:*",
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}})))
        self.assertEqual((exact["github_subjects"], exact["github_unrestricted"]), (["repo:acme/app:*"], False))
        open_role = aws.parse_trust(json.loads(github_trust({"StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}})))
        self.assertTrue(open_role["github_unrestricted"])
        owner_claim = aws.parse_trust(json.loads(github_trust({"StringEquals": {
            "token.actions.githubusercontent.com:repository_owner": "acme"}})))
        self.assertFalse(owner_claim["github_unrestricted"])  # restricted by another claim
        star = aws.parse_trust(json.loads(github_trust({"StringLike": {"token.actions.githubusercontent.com:sub": "*"}})))
        self.assertTrue(star["github_unrestricted"])


@unittest.skipIf(boto3 is None, "boto3 and moto not installed")
class MotoTests(unittest.TestCase):
    def setUp(self):
        env = {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
               "AWS_DEFAULT_REGION": "us-east-1",
               "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}  # so AdministratorAccess exists, as in a real account
        patcher = mock.patch.dict(os.environ, env)
        patcher.start(); self.addCleanup(patcher.stop)
        for name in ("AWS_PROFILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_IAM"):
            os.environ.pop(name, None)
        self.moto = mock_aws(); self.moto.start(); self.addCleanup(self.moto.stop)
        self.session = boto3.Session(region_name="us-east-1")
        iam = self.iam = self.session.client("iam")
        iam.create_open_id_connect_provider(Url="https://token.actions.githubusercontent.com",
                                            ClientIDList=["sts.amazonaws.com"], ThumbprintList=["a" * 40])
        iam.create_user(UserName="deployer")
        iam.put_user_policy(UserName="deployer", PolicyName="deploy", PolicyDocument=doc(
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::assets/*"},
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{ACCOUNT}:role/admin-role"}))
        iam.create_group(GroupName="devs")
        iam.put_group_policy(GroupName="devs", PolicyName="describe", PolicyDocument=doc(
            {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}))
        iam.add_user_to_group(GroupName="devs", UserName="deployer")
        self.deployer_key = iam.create_access_key(UserName="deployer")["AccessKey"]["AccessKeyId"]
        iam.create_user(UserName="root-ish")
        iam.attach_user_policy(UserName="root-ish", PolicyArn=ADMIN)
        self.admin_key = iam.create_access_key(UserName="root-ish")["AccessKey"]["AccessKeyId"]
        iam.create_role(RoleName="gha-deploy", AssumeRolePolicyDocument=github_trust({"StringLike": {
            "token.actions.githubusercontent.com:sub": "repo:acme/app:*"}}))
        iam.put_role_policy(RoleName="gha-deploy", PolicyName="put", PolicyDocument=doc(
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::assets/*"}))
        iam.create_role(RoleName="gha-open", AssumeRolePolicyDocument=github_trust({"StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}))
        iam.create_role(RoleName="admin-role", AssumeRolePolicyDocument=doc(
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}))
        iam.attach_role_policy(RoleName="admin-role", PolicyArn=ADMIN)
        iam.create_role(RoleName="partner", AssumeRolePolicyDocument=doc(
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}))

    def build(self, links=None, session=None):
        graph = github.collect(FakeClient(), "acme")
        aws.collect(session or self.session, graph, environment="simulated")
        aws.link_github(graph)
        if links:
            aws.link_secrets(graph, links)
        return graph

    def test_collects_users_keys_roles(self):
        graph = self.build()
        users = {u["name"]: u for u in graph.of_kind("aws_user")}
        self.assertTrue(users["root-ish"]["admin"])
        self.assertEqual(users["deployer"]["reach"], "ec2 (read), s3 (read), sts")  # group policy included
        self.assertEqual({k["key_id"] for k in graph.of_kind("aws_access_key")}, {self.deployer_key, self.admin_key})
        self.assertEqual({r["name"] for r in graph.of_kind("aws_role")}, {"gha-deploy", "gha-open", "admin-role", "partner"})
        self.assertEqual(graph.sources[-1]["environment"], "simulated")
        self.assertEqual(graph.gaps, [])

    def test_who_can_assume_what(self):
        graph = self.build()
        def assumers(role):
            return sorted(n["id"] for n in graph.into(f"aws-role:arn:aws:iam::{ACCOUNT}:role/{role}", "can_assume"))
        self.assertEqual(assumers("gha-deploy"), ["repo:acme/app"])
        self.assertEqual(assumers("gha-open"), ["repo:acme/app", "repo:acme/lib"])  # any repository
        self.assertEqual(assumers("admin-role"), [f"aws-user:arn:aws:iam::{ACCOUNT}:user/deployer",
                                                  f"aws-user:arn:aws:iam::{ACCOUNT}:user/root-ish"])
        partner = graph.nodes[f"aws-role:arn:aws:iam::{ACCOUNT}:role/partner"]
        self.assertEqual(partner["external_accounts"], ["999999999999"])

    def test_reach_through_a_linked_secret_reaches_admin(self):
        graph = self.build({"acme/app:AWS_ACCESS_KEY_ID": self.deployer_key})
        r = analyze.radius(graph, analyze.resolve_point(graph, "deploy.yml"))
        vias = {(e["via"], e["principal"].get("name") or e["principal"].get("key_id"), e["exposure"]) for e in r["aws"]}
        self.assertIn(("secret AWS_ACCESS_KEY_ID", self.deployer_key, "direct"), vias)
        self.assertIn(("secret AWS_ACCESS_KEY_ID, then sts:AssumeRole", "admin-role", "direct"), vias)
        # deploy.yml does not request id-token, so OIDC roles are reachable only by changing the workflow.
        self.assertIn(("GitHub OIDC", "gha-deploy", "latent"), vias)
        ci = analyze.radius(graph, analyze.resolve_point(graph, "ci.yml"))
        self.assertIn("direct", {e["exposure"] for e in ci["aws"] if e["via"] == "GitHub OIDC"})

    def test_findings(self):
        now = datetime(2027, 6, 1, tzinfo=timezone.utc)
        kinds = {}
        for item in analyze.findings(self.build(), now):
            kinds.setdefault(item["kind"], []).append(item["where"])
        self.assertEqual(kinds["aws-oidc-any-repo"], ["AWS role gha-open"])
        self.assertNotIn("aws-oidc-wildcard", kinds)  # repo:acme/app:* is one repository
        self.assertEqual(kinds["aws-trust-external-account"], ["AWS role partner"])
        self.assertEqual(kinds["aws-admin-standing-key"], [f"AWS key {self.admin_key} (user root-ish)"])
        self.assertEqual(len(kinds["aws-key-old"]), 2)
        # Moto's session key is not one of these two, so neither is Firebreak's own.
        self.assertEqual(len(kinds["aws-key-never-used"]), 2)
        self.assertEqual(kinds["aws-secret-unlinked"], ["acme/app secret AWS_ACCESS_KEY_ID (repo)"])
        self.assertNotIn("aws-secret-unlinked",
                         {f["kind"] for f in analyze.findings(self.build({"acme/app:AWS_ACCESS_KEY_ID": self.deployer_key}), now)})

    def test_plan_has_aws_steps_first(self):
        graph = self.build({"acme/app:AWS_ACCESS_KEY_ID": self.deployer_key})
        plan = analyze.cut_plan(graph, analyze.resolve_point(graph, "acme/app"))
        sever = [s["action"] for s in plan["stages"][0]["steps"]]
        self.assertTrue(sever[0].startswith("AWS role"))
        text = "\n".join(sever)
        self.assertIn(f"--access-key-id {self.deployer_key} --status Inactive", text)
        self.assertIn("put-role-policy --role-name admin-role --policy-name AWSRevokeOlderSessions", text)
        self.assertIn("put-role-policy --role-name gha-open", text)
        self.assertIn("aws:TokenIssueTime", text)
        self.assertIn("ANY GitHub repository can assume it", text)
        self.assertGreaterEqual(plan["aws_principals"], 4)
        self.assertTrue(any("not evaluated" in limit for limit in plan["limits"]))

    def test_own_key_is_not_reported_as_never_used(self):
        key = self.iam.create_access_key(UserName="deployer")["AccessKey"]
        own = boto3.Session(aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"],
                            region_name="us-east-1")
        graph = self.build(session=own)
        self.assertTrue(graph.nodes[f"aws-key:{key['AccessKeyId']}"]["used_by_firebreak"])
        never = [f["where"] for f in analyze.findings(graph, datetime(2027, 1, 1, tzinfo=timezone.utc))
                 if f["kind"] == "aws-key-never-used"]
        self.assertNotIn(f"AWS key {key['AccessKeyId']} (user deployer)", never)
        self.assertIn("(Firebreak's own credentials)", cli.render_map(graph))

    def test_bad_links_become_gaps(self):
        graph = self.build({"acme/app:NOPE": self.deployer_key, "acme/app:AWS_ACCESS_KEY_ID": "AKIANOTREAL"})
        self.assertEqual({g["reason"] for g in graph.gaps if g["scope"] == "links"},
                         {"no such secret in the map", "access key not found in the collected AWS account"})

    def test_denied_listing_becomes_a_gap(self):
        session = self.session

        class Denying:
            def client(self, name, **kw):
                real = session.client(name, **kw)
                if name != "iam":
                    return real

                class Wrapped:
                    def __getattr__(self, attr):
                        return getattr(real, attr)

                    def get_paginator(self, operation):
                        if operation == "list_roles":
                            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListRoles")
                        return real.get_paginator(operation)
                return Wrapped()

        graph = self.build(session=Denying())
        self.assertIn({"scope": f"aws:{ACCOUNT}", "what": "IAM roles", "reason": "AccessDenied"}, graph.gaps)
        self.assertEqual(graph.of_kind("aws_role"), [])

    def test_render_and_round_trip(self):
        graph = self.build({"acme/app:AWS_ACCESS_KEY_ID": self.deployer_key})
        again = Graph.from_json(graph.to_json())
        text = cli.render_map(again)
        self.assertEqual(text, cli.render_map(graph))
        self.assertIn(f"Source: aws {ACCOUNT} (simulated)", text)
        self.assertIn("ANY GitHub repository", text)
        self.assertIn("AWS admin-role via secret AWS_ACCESS_KEY_ID, then sts:AssumeRole (direct)", text)

    def test_environment_for(self):
        self.assertEqual(aws.environment_for(None), ("observed", None))
        self.assertEqual(aws.environment_for("http://localhost:4566"), ("simulated", "http://localhost:4566"))


if __name__ == "__main__":
    unittest.main()
