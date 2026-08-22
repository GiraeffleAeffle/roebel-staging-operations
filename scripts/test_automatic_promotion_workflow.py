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
            'cron: "7,22,37,52 * * * *"',
            "workflow_dispatch:",
            "release-set-$SOURCE_REVISION",
            "gh attestation verify",
            "render-release-set-promotion.py",
            "verify-reviewed-render.py --root . --base-root",
            "gh pr create",
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


if __name__ == "__main__":
    unittest.main()
