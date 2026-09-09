#!/usr/bin/env python3
"""Explicit staging target-storage entrypoint, separate from bootstrap."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


def main():
    if not sys.flags.isolated or not sys.flags.safe_path:
        raise RuntimeError('isolated Python required')
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('plan', 'advance', 'consumer-plan', 'consumer-advance'), required=True)
    parser.add_argument('--expected-operations-revision', required=True)
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--kubeconfig')
    parser.add_argument('--receipt')
    parser.add_argument('--storage-receipt')
    parser.add_argument('--expected-storage-receipt-sha256')
    parser.add_argument('--prior-receipt')
    parser.add_argument('--expected-prior-sha256')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    def git(*arguments):
        return subprocess.check_output(['git', '-C', str(root), *arguments], text=True).strip()
    if git('rev-parse', 'HEAD') != args.expected_operations_revision or git('status', '--porcelain', '--untracked-files=all'):
        raise RuntimeError('approved clean checkout required')
    if git('remote', 'get-url', 'origin') != 'https://github.com/GiraeffleAeffle/roebel-staging-operations.git':
        raise RuntimeError('Operations repository mismatch')
    sys.path.insert(0, str(root))
    from scripts import case_review_storage as storage
    from scripts.case_runtime_bootstrap import _verifier
    from scripts.staging_participant_flux_bootstrap import ReceiptSink, load_receipt
    plan = storage.build_plan(root, args.operation_id)
    consumer = args.mode.startswith('consumer-')
    storage_plan = plan
    if consumer:
        plan = storage.build_consumer_plan(storage_plan)
    if args.mode in ('plan', 'consumer-plan'):
        if any((args.expected_plan_sha256, args.kubeconfig, args.receipt, args.prior_receipt, args.expected_prior_sha256, args.storage_receipt, args.expected_storage_receipt_sha256)):
            raise RuntimeError('plan mode accepts no live inputs')
        print(json.dumps(plan, indent=2)); return
    if args.expected_plan_sha256 != plan['planSha256'] or not args.kubeconfig or not args.receipt or bool(args.prior_receipt) != bool(args.expected_prior_sha256):
        raise RuntimeError('explicit pinned operation, kubeconfig and private receipt required')
    if consumer != bool(args.storage_receipt) or consumer != bool(args.expected_storage_receipt_sha256):
        raise RuntimeError('consumer requires independently pinned existing storage receipt')
    owned = load_receipt(Path(args.storage_receipt)) if consumer else None
    policy = _verifier().verify_tree(root)['stagingParticipantGatewayPolicy']
    prior = load_receipt(Path(args.prior_receipt)) if args.prior_receipt else None
    sink = ReceiptSink.reserve(Path(args.receipt))
    spec = importlib.util.spec_from_file_location('protected_review_storage_support', root / 'scripts/activate-staging-participant-gateway.py')
    support = importlib.util.module_from_spec(spec); sys.modules[spec.name] = support; spec.loader.exec_module(support)
    runner = support.Runner()
    snapshot = support.snapshot_kubeconfig_v4(args.kubeconfig, runner)
    try:
        support.cluster_binding_v4(runner, snapshot, policy)
        if consumer:
            transport = storage.KubectlConsumerTransport(runner, snapshot, plan, storage_plan, args.expected_plan_sha256)
            result = storage.advance_consumer(plan, storage_plan, expected_plan_sha256=args.expected_plan_sha256,
                storage_receipt=owned, expected_storage_receipt_sha256=args.expected_storage_receipt_sha256,
                transport=transport, sink=sink, prior=prior, expected_prior_sha256=args.expected_prior_sha256)
        else:
            transport = storage.KubectlStorageTransport(runner, snapshot, plan, args.expected_plan_sha256)
            result = storage.advance_storage(plan, expected_plan_sha256=args.expected_plan_sha256, transport=transport, sink=sink,
                                             prior=prior, expected_prior_sha256=args.expected_prior_sha256)
        print(json.dumps({'status': result['status'], 'receiptSha256': result['canonicalSha256']}))
    finally:
        snapshot.close()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Review storage stopped; preserve the target and private receipts.', file=sys.stderr)
        sys.exit(1)
