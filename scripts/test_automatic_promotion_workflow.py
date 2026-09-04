from __future__ import annotations

import re
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/automatic-promotion.yml"


class PromotionBranchBehaviorTests(unittest.TestCase):
    """Run the production Git stanza against a disposable, local bare remote."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="promotion-branch-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.remote = self.root / "remote.git"
        self.branch = "automation/roebel-staging-latest"
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("GIT_")
        } | {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "AUTOMATION_BRANCH": self.branch,
            "SOURCE_REVISION": "a" * 40,
        }
        self.git(self.root, "init", "--bare", str(self.remote))
        seed = self.root / "seed"
        self.git(self.root, "init", "--initial-branch=main", str(seed))
        target = seed / "reviewed-render/roebel-staging/head.json"
        target.parent.mkdir(parents=True)
        target.write_text("baseline\n")
        self.git(seed, "add", ".")
        self.git(seed, "commit", "-m", "baseline")
        self.base = self.git(seed, "rev-parse", "HEAD")
        self.git(seed, "remote", "add", "origin", str(self.remote))
        self.git(seed, "push", "origin", "main")
        workflow = WORKFLOW.read_text()
        stanza = workflow.split('          base_sha="$(git rev-parse HEAD)"\n', 1)[1]
        stanza = stanza.split('          title=', 1)[0]
        self.stanza = 'set -euo pipefail\nbase_sha="$(git rev-parse HEAD)"\n' + textwrap.dedent(stanza).replace("${{ steps.schema.outputs.version }}", "v1")
        self.attempt = 0

    def git(self, cwd: Path, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", *arguments], cwd=cwd, env=self.env,
            text=True, stderr=subprocess.PIPE,
        ).strip()

    def candidate(self, content: str) -> Path:
        self.attempt += 1
        workspace = self.root / f"attempt-{self.attempt}"
        self.git(self.root, "clone", "--branch", "main", str(self.remote), str(workspace))
        (workspace / "reviewed-render/roebel-staging/head.json").write_text(content)
        return workspace

    def publish(self, workspace: Path) -> subprocess.CompletedProcess[str]:
        # Different timestamps reproduce the CI-invalidating commit churn.
        timestamp = f"2001-01-{self.attempt:02d}T00:00:00Z"
        return subprocess.run(
            ["bash", "-c", self.stanza], cwd=workspace,
            env=self.env | {"GIT_AUTHOR_DATE": timestamp, "GIT_COMMITTER_DATE": timestamp},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20,
        )

    def remote_head(self) -> str:
        return self.git(self.root, "--git-dir", str(self.remote), "rev-parse", f"refs/heads/{self.branch}")

    def test_identical_candidate_preserves_commit_and_review_binding(self) -> None:
        first = self.publish(self.candidate("release one\n"))
        self.assertEqual(first.returncode, 0, first.stderr)
        head = self.remote_head()
        second = self.publish(self.candidate("release one\n"))
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.remote_head(), head)

    def test_new_render_replaces_candidate_with_one_current_base_parent(self) -> None:
        first = self.publish(self.candidate("release one\n"))
        self.assertEqual(first.returncode, 0, first.stderr)
        old = self.remote_head()
        workspace = self.candidate("release two\n")
        second = self.publish(workspace)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(self.remote_head(), old)
        self.assertEqual(self.git(workspace, "show", "-s", "--format=%P", "HEAD"), self.base)

    def test_same_tree_with_a_different_parent_is_not_reused(self) -> None:
        workspace = self.candidate("release one\n")
        self.git(workspace, "add", ".")
        tree = self.git(workspace, "write-tree")
        parentless = self.git(workspace, "commit-tree", tree, "-m", "wrong ancestry")
        self.git(workspace, "push", "origin", f"{parentless}:refs/heads/{self.branch}")
        result = self.publish(workspace)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.remote_head(), parentless)
        self.assertEqual(self.git(workspace, "show", "-s", "--format=%P", "HEAD"), self.base)

    def test_moved_protected_base_aborts_before_publishing(self) -> None:
        stale = self.candidate("release one\n")
        seed = self.root / "seed"
        (seed / "reviewed-render/roebel-staging/head.json").write_text("new baseline\n")
        self.git(seed, "commit", "-am", "advance protected base")
        self.git(seed, "push", "origin", "main")
        result = self.publish(stale)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git(self.root, "ls-remote", "--heads", str(self.remote), f"refs/heads/{self.branch}"), "")


class AutomaticPromotionWorkflowTests(unittest.TestCase):
    def test_workflow_is_remote_pull_based_and_human_reviewed(self) -> None:
        source = WORKFLOW.read_text()
        for marker in (
            'cron: "*/5 * * * *"',
            "workflow_dispatch:",
            "release-set-$SOURCE_REVISION",
            "gh attestation verify",
            "render-release-set-promotion.py",
            "verify-reviewed-render.py --root . --base-root",
            "gh pr create",
            'gh pr merge "$number" --auto --squash',
            "Human CODEOWNER review remains the deployment authority",
        ):
            self.assertIn(marker, source)

    def test_workflow_has_no_cluster_or_runtime_secret_surface(self) -> None:
        source = WORKFLOW.read_text().lower()
        for forbidden in (
            "kubectl",
            "talosctl",
            "kubeconfig",
            "wireguard",
            "wireproxy",
            "service_role",
            "inference_api_key",
            "kind: secret",
            "civiccase",
            "governance",
            "treasury",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotRegex(source, r"secrets\.[a-z0-9_]+")

    def test_permissions_and_actions_are_exactly_bounded(self) -> None:
        source = WORKFLOW.read_text()
        permissions = source.split("permissions:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(
            permissions,
            "  actions: read\n  contents: write\n  pull-requests: write\n  packages: read\n  attestations: read",
        )
        uses = re.findall(r"uses: ([^\s]+)", source)
        self.assertEqual(
            uses,
            [
                "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
                "oras-project/setup-oras@22ce207df3b08e061f537244349aac6ae1d214f6",
                "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
            ],
        )

    def test_single_branch_replaces_superseded_unreviewed_candidate(self) -> None:
        source = WORKFLOW.read_text()
        self.assertIn("AUTOMATION_BRANCH: automation/roebel-staging-latest", source)
        self.assertIn("--force-with-lease=", source)
        self.assertNotIn("git push --force ", source)
        self.assertIn("cancel-in-progress: false", source)

    def test_auto_merge_waits_for_the_existing_review_and_check_gate(self) -> None:
        source = WORKFLOW.read_text()
        self.assertIn('test -n "$number"', source)
        self.assertIn('gh pr merge "$number" --auto --squash', source)
        self.assertNotIn("--admin", source)

    def test_component_reuse_is_exact_and_fetched_handoff_is_removed(self) -> None:
        source = WORKFLOW.read_text()
        # Keep the component identifier data-bound.  A single-quoted jq
        # program cannot interpolate the shell variable, so this must remain
        # an explicit --arg binding.
        self.assertIn('jq -er --arg component "$component"', source)
        self.assertNotIn('select(.component=="$component")', source)
        self.assertIn('previous_manifest=', source)
        self.assertIn('previous_source=', source)
        self.assertIn('test "$manifest" = "$previous_manifest"', source)
        self.assertIn('test "$source" = "$previous_source"', source)
        self.assertIn('rm -rf -- incoming', source)
        self.assertLess(
            source.index('python3 scripts/render-release-set-promotion.py'),
            source.index('rm -rf -- incoming'),
        )

    def test_protected_unit_suites_run_before_render_and_candidate_verification_after(self) -> None:
        source = WORKFLOW.read_text()
        protected_base_unit_suites = (
            '(\n'
            '            cd "$RUNNER_TEMP/protected-base"\n'
            "            python3 -m unittest -v scripts/test_verify_reviewed_render.py "
            "scripts/test_render_release_set_promotion.py "
            "scripts/test_assemble_synthetic_citizen_pass_handoff.py "
            "scripts/test_automatic_promotion_workflow.py\n"
            '          )'
        )
        self.assertIn(protected_base_unit_suites, source)
        unit_suites = source.index(protected_base_unit_suites)
        render = source.index("python3 scripts/render-release-set-promotion.py")
        candidate_verifier = source.index(
            'python3 scripts/verify-reviewed-render.py --root . --base-root "$RUNNER_TEMP/protected-base"',
        )

        self.assertLess(unit_suites, render)
        self.assertLess(render, candidate_verifier)

    def test_v2_handoff_is_one_exact_pinned_exception(self) -> None:
        source = WORKFLOW.read_text()
        for marker in (
            "SYNTHETIC_SOURCE_REVISION: 1b004dc0a1b156baf639fcdd54ab5a1b5501a575",
            'SYNTHETIC_GATEWAY_RUN_ID: "33659908416"',
            "SYNTHETIC_GATEWAY_MANIFEST: sha256:c2920003a6e514d56c662731877e665d518b1a22bc921cd3d58c60c77651d7e2",
            "SYNTHETIC_SOURCE_TREE_SHA256: sha256:827fea9741a90f9d2eede3bea2074687cd464ad496de33dac441dce7c2f84f15",
            "SYNTHETIC_GATEWAY_WORKFLOW_SHA256: sha256:6c4c09517f53e18a301630cecb341f9996ba74eaa1dc1126ef735eb1c6460ac3",
            'test "$SOURCE_REVISION" = "$SYNTHETIC_SOURCE_REVISION"',
            '.head_sha == $source and .head_branch == "main" and .event == "push"',
            "staging-participant-gateway-publication-$SOURCE_REVISION",
            "assemble-synthetic-citizen-pass-handoff.py",
        ):
            self.assertIn(marker, source)

    def test_v2_recomputes_source_and_workflow_and_verifies_gateway_attestations(self) -> None:
        source = WORKFLOW.read_text()
        for marker in (
            'git -C synthetic-source ls-tree -r -z --full-tree "$SOURCE_REVISION"',
            'git -C synthetic-source show "$SOURCE_REVISION:.github/workflows/staging-participant-gateway-publish.yml"',
            'test "$source_tree_sha256" = "$SYNTHETIC_SOURCE_TREE_SHA256"',
            'test "$workflow_sha256" = "$SYNTHETIC_GATEWAY_WORKFLOW_SHA256"',
            '--cert-identity "$GATEWAY_SIGNER_IDENTITY"',
            "--predicate-type https://slsa.dev/provenance/v1 --deny-self-hosted-runners",
            "--predicate-type https://spdx.dev/Document/v2.3 --deny-self-hosted-runners",
            '--source-digest "$SOURCE_REVISION" --source-ref refs/heads/main',
        ):
            self.assertIn(marker, source)

    def test_v2_handoff_and_render_file_sets_are_explicit_and_closed(self) -> None:
        source = WORKFLOW.read_text()
        gateway_files = source.split(
            'cat > "$RUNNER_TEMP/gateway-files.expected" <<\'EOF\'\n',
            1,
        )[1].split("\n          EOF", 1)[0]
        self.assertEqual(
            gateway_files,
            "          publication-input/staging-participant-gateway.release-pins.json\n"
            "          publication-input/staging-participant-gateway.source-receipt.json\n"
            "          publication-output/staging-participant-gateway.publication-receipt.json\n"
            "          publication-output/staging-participant-gateway.spdx.json",
        )
        v2_changed = source.split(
            'if test \'${{ steps.schema.outputs.version }}\' = v2; then\n'
            '            cat > "$RUNNER_TEMP/changed.expected" <<\'EOF\'\n',
            1,
        )[1].split("\n          EOF", 1)[0]
        self.assertEqual(len(v2_changed.splitlines()), 16)
        for boundary in (
            "network-boundary-migration.json",
            "staging-participant-gateway/ingress.json",
            "staging-participant-gateway/runtime-pin.json",
            "tracer-data-plane/bootstrap/76-staging-synthetic-citizen-adoption.sql",
            "policy/repository-contract.json",
        ):
            self.assertIn(boundary, v2_changed)
        self.assertIn("git add policy/repository-contract.json", source)
        self.assertIn(
            "if test '${{ steps.schema.outputs.version }}' = v2; then\n"
            "            git add --intent-to-add -- \\\n"
            "              reviewed-render/roebel-staging/synthetic-citizen-pass-transition.json \\\n"
            "              reviewed-render/roebel-staging/tracer-data-plane/bootstrap/76-staging-synthetic-citizen-adoption.sql\n"
            "          fi\n"
            "          git diff --check\n"
            "          git diff --name-only",
            source,
        )

    def test_v1_path_remains_the_post_transition_default(self) -> None:
        source = WORKFLOW.read_text()
        self.assertIn(
            "transition=reviewed-render/roebel-staging/synthetic-citizen-pass-transition.json",
            source,
        )
        self.assertIn("echo 'version=v1' >> \"$GITHUB_OUTPUT\"", source)
        self.assertIn("echo 'version=v2' >> \"$GITHUB_OUTPUT\"", source)
        self.assertIn("steps.schema.outputs.version == 'v2'", source)


if __name__ == "__main__":
    unittest.main()
