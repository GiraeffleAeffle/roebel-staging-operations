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
