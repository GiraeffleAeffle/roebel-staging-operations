from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/automatic-promotion.yml"


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
            "  contents: write\n  pull-requests: write\n  packages: read\n  attestations: read",
        )
        uses = re.findall(r"uses: ([^\s]+)", source)
        self.assertEqual(
            uses,
            [
                "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
                "oras-project/setup-oras@22ce207df3b08e061f537244349aac6ae1d214f6",
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
            "scripts/test_render_release_set_promotion.py\n"
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


if __name__ == "__main__":
    unittest.main()
