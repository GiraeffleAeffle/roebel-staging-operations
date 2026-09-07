"""Explicit Case plan/provision/bootstrap/recovery/handover invocation.

Run with python -I from an exact approved clean Operations checkout. Existing
protected transport supplies the explicit kubeconfig and pinned kubectl FD.
No ambient cluster context or unpinned executable is accepted.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def validate_scope(args):
    if args.mode=='provision':
        if args.configuration_fd is None or args.prior_receipt or args.bootstrap_receipt:raise RuntimeError('provision requires only the private descriptor')
    elif args.configuration_fd is not None:raise RuntimeError('private descriptor allowed only for provisioning')
    if (args.mode in ('recover','recover-handover')) != bool(args.prior_receipt):raise RuntimeError('recovery receipt scope mismatch')
    if (args.mode in ('handover','recover-handover','admit-saved-test')) != bool(args.bootstrap_receipt):raise RuntimeError('bootstrap receipt scope mismatch')
    if (args.mode=='admit-saved-test') != (args.bundle_fd is not None):raise RuntimeError('saved bundle descriptor scope mismatch')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode',required=True,choices=('plan','provision','bootstrap','recover','handover','recover-handover','admit-saved-test'))
    parser.add_argument('--expected-operations-revision',required=True)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--kubeconfig')
    parser.add_argument('--receipt')
    parser.add_argument('--prior-receipt')
    parser.add_argument('--bootstrap-receipt')
    parser.add_argument('--configuration-fd',type=int)
    parser.add_argument('--bundle-fd',type=int)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    if not sys.flags.isolated or not re.fullmatch('[0-9a-f]{40}',args.expected_operations_revision):
        raise RuntimeError('isolated interpreter and exact approved revision required')
    def git(*command):
        return subprocess.check_output(['git','-C',str(root),*command],text=True).strip()
    if git('rev-parse','HEAD')!=args.expected_operations_revision or git('status','--porcelain','--untracked-files=all'):
        raise RuntimeError('approved clean Operations checkout required')
    if git('remote','get-url','origin') not in ('https://github.com/GiraeffleAeffle/roebel-staging-operations.git','https://github.com/GiraeffleAeffle/roebel-staging-operations'):
        raise RuntimeError('Operations repository identity mismatch')
    sys.path.insert(0,str(root))
    from scripts import case_runtime_bootstrap as bootstrap
    from scripts import case_runtime_kubernetes as kubernetes
    from scripts import case_runtime_handover as handover
    from scripts import case_runtime_configuration as configuration
    from scripts import case_runtime_saved_adoption as saved
    from scripts.staging_participant_flux_bootstrap import ReceiptSink,load_receipt
    plan=bootstrap.build_plan(root)
    if args.mode=='plan':
        if any((args.kubeconfig,args.receipt,args.prior_receipt,args.bootstrap_receipt,args.configuration_fd is not None,args.bundle_fd is not None)):
            raise RuntimeError('plan mode accepts no live inputs')
        print(json.dumps(plan,indent=2));return
    if args.expected_plan_sha256!=plan['planSha256'] or not args.kubeconfig or not args.receipt:
        raise RuntimeError('exact reviewed plan, explicit kubeconfig and receipt required')
    validate_scope(args)
    prior=load_receipt(Path(args.prior_receipt)) if args.prior_receipt else None
    boot_receipt=load_receipt(Path(args.bootstrap_receipt)) if args.bootstrap_receipt else None
    sink=ReceiptSink.reserve(Path(args.receipt))
    path=root/'scripts/activate-staging-participant-gateway.py'
    spec=importlib.util.spec_from_file_location('protected_case_transport_support',path)
    support=importlib.util.module_from_spec(spec);sys.modules[spec.name]=support;spec.loader.exec_module(support)
    runner=support.Runner()
    snapshot=support.snapshot_kubeconfig_v4(args.kubeconfig,runner)
    try:
        support.cluster_binding_v4(runner,snapshot,bootstrap._verifier().verify_tree(root)["stagingParticipantGatewayPolicy"])
        transport=kubernetes.KubectlTransport(runner,snapshot,plan)
        adapter=kubernetes.KubernetesAdapter(root,args.expected_operations_revision,transport)
        if args.mode=='provision':result=configuration.provision_configuration(plan,args.configuration_fd,adapter=adapter,sink=sink)
        elif args.mode=='admit-saved-test':
            bundle=os.pread(args.bundle_fd,262145,0)
            result=saved.run_saved_adoption(plan,boot_receipt,bundle,adapter=adapter,sink=sink)
        elif args.mode in ('bootstrap','recover'):result=bootstrap.run_bootstrap(root,adapter=adapter,sink=sink,prior_receipt=prior)
        else:result=handover.run_handover(plan,boot_receipt,adapter=adapter,sink=sink,prior_receipt=prior)
        print(json.dumps({'status':result['status'],'receipt':str(sink.path),'planSha256':plan['planSha256']}))
    finally:snapshot.close()


if __name__=='__main__':
    try:main()
    except Exception:
        print('Case runtime operation stopped; inspect the durable receipt. No automatic cleanup or retry.',file=sys.stderr)
        sys.exit(1)
