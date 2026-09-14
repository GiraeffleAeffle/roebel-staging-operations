"""Compile the offline worker from the protected review predecessor.

No cluster access. The host must bind creation/deletion to observed UIDs and
persist intent before suspending a reconciler or stopping its writer.
"""
import copy
import json
from pathlib import Path
from . import case_runtime_bootstrap as core
from .staging_participant_flux_bootstrap import canonical_sha256

NAME = 'roebel-case-runtime-upgrade-v1'
PROGRAMS = ('case_runtime_upgrade.mjs', 'case_upgrade_runtime.mjs',
            'run-case-runtime-upgrade.mjs', 'case_review_backup.mjs')


def compile_worker(root):
    root = Path(root).resolve()
    verifier = core._verifier()
    verifier.verify_tree(root)
    interface = verifier.citizen_status_interface()
    verifier.require(verifier.TOWN_WORKSPACE.stage(interface, root) == 'review',
                     'upgrade worker requires the review predecessor')
    policy = json.loads((root/'proposals/synthetic-case-runtime-upgrade/transition.json').read_text())
    source, target = policy['sourceBinding'], policy['targetBinding']
    items = json.loads((root/'reviewed-render/roebel-staging/case-runtime/resources.json').read_text())['items']
    config = next(o for o in items if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'roebel-case-steward-review-reviewed-v1')
    verifier.require(json.loads(config['data']['reviewed-binding.json']) == source, 'upgrade source binding changed')
    spec = next(o for o in items if o['kind'] == 'Deployment' and o['metadata']['name'] == source['workloadName'])['spec']['template']['spec']
    env = spec['initContainers'][0]['env']
    reference = next(e['valueFrom']['secretKeyRef'] for e in env if e['name'] == 'ROEBEL_CASE_PRIVATE_CONFIG')
    actual = 'sha256:' + next(e['value'] for e in env if e['name'] == 'ROEBEL_CASE_PRIVATE_CONFIG_SHA256')
    verifier.require(actual == policy['configurationSha256'] and source['storage']['pvcUid'] == target['storage']['pvcUid'],
                     'upgrade configuration or retained volume changed')
    labels = {'app.kubernetes.io/name': NAME, 'stadtstack.io/authority': 'none'}
    metadata = {'name': NAME, 'namespace': source['storage']['pvcNamespace'], 'labels': labels}
    # Values cross a read-only Secret mount into a private memory-backed file.
    # They never appear in arguments, environment values, ConfigMap or stdout.
    entry = """import fs from 'node:fs';
import {createHash} from 'node:crypto';
try {
 process.umask(0o077); fs.mkdirSync('/work/private',{mode:0o700});
 fs.chmodSync('/work/private',0o700);
 const bytes=fs.readFileSync('/configuration/application.json');
 if(!bytes.length || bytes.length>1048576 || 'sha256:'+createHash('sha256').update(bytes).digest('hex')!==CONFIGURATION_PIN) throw Error();
 const fd=fs.openSync('/work/private/configuration.json','wx',0o600);
 try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 const directory=fs.openSync('/work/private','r');try{fs.fsyncSync(directory)}finally{fs.closeSync(directory)}
 console.log('case-upgrade-worker-ready');
 process.on('SIGTERM',()=>process.exit(0)); setInterval(()=>{},1000);
} catch {console.error('case_upgrade_worker_stopped');process.exitCode=78;}
""".replace('CONFIGURATION_PIN', json.dumps(policy['configurationSha256']))
    programs = {name: (root/'scripts'/name).read_text() for name in PROGRAMS}
    programs.update({'upgrade-policy.json': json.dumps(policy, sort_keys=True, separators=(',', ':')) + '\n', 'entry.mjs': entry})
    config_map = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': copy.deepcopy(metadata), 'immutable': True, 'data': programs}
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': copy.deepcopy(metadata), 'spec': {
        'automountServiceAccountToken': False, 'enableServiceLinks': False, 'restartPolicy': 'Never',
        'activeDeadlineSeconds': 3600, 'terminationGracePeriodSeconds': 30,
        'securityContext': copy.deepcopy(spec['securityContext']),
        'containers': [{'name': 'upgrade', 'image': 'ghcr.io/giraeffleaeffle/stadtstack-case-steward-control@' + target['releaseDigest'],
            'imagePullPolicy': 'IfNotPresent', 'command': ['node', '/reviewed/entry.mjs'],
            'env': [{'name': 'TMPDIR', 'value': '/work/private'},
                    {'name': 'ROEBEL_UPGRADE_WORKER_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}],
            'securityContext': copy.deepcopy(spec['containers'][0]['securityContext']),
            'resources': {'requests': {'cpu': '100m', 'memory': '256Mi'}, 'limits': {'cpu': '1', 'memory': '1Gi'}},
            'volumeMounts': [{'name': 'case-state', 'mountPath': '/var/lib/stadtstack-review'},
                {'name': 'reviewed', 'mountPath': '/reviewed', 'readOnly': True},
                {'name': 'configuration', 'mountPath': '/configuration', 'readOnly': True},
                {'name': 'work', 'mountPath': '/work'}]}],
        'volumes': [{'name': 'case-state', 'persistentVolumeClaim': {'claimName': source['storage']['pvcName']}},
            {'name': 'reviewed', 'configMap': {'name': NAME, 'defaultMode': 0o444}},
            {'name': 'configuration', 'secret': {'secretName': reference['name'], 'defaultMode': 0o440,
                'items': [{'key': reference['key'], 'path': 'application.json'}]}},
            {'name': 'work', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '512Mi'}}]}}
    network = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': copy.deepcopy(metadata),
               'spec': {'podSelector': {'matchLabels': labels}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
    body = {'schemaVersion': 'roebel_case_upgrade_worker_bundle_v1', 'status': 'prepared_not_created',
            'networkPolicy': network, 'configMap': config_map, 'pod': pod}
    return body | {'bundleChecksum': canonical_sha256(body)}
