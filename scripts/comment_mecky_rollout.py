"""Exact comment-only gateway successor; preparing this proposal has no effects.

The source SQL and OCI publication are independently bound. This module owns
the additive route, SQL verification and desired-state transformation together;
historical citizen/status policies and the retained bootstrap stay unchanged.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCHEMA = 'roebel_staging_participant_gateway_runtime_pin_v7'
ROOT = Path('policy/comment-mecky')
POLICY_PATH = ROOT / 'activation.json'
RECORD_PATH = Path('reviewed-render/roebel-staging/comment-mecky.json')
ROUTE = '/api/staging-participant/v1/nostr-comment'
RELEASE = {
    'sourceRevision': '063b2221c1eaafdf58edeff191d46fdb062ea257',
    'sourceTreeSha256': 'sha256:0c32062269a8787d7e07f601cf955e69c8c8dcdea1dbf00123d729e8ea0b045d',
    'workflowSha256': 'sha256:57f845cd106120c365a60fcf9e80e00e5304c410f2aafd462ee8f89073dd1a61',
    'manifestDigest': 'sha256:34e0f20ce51429e29962b774febaf53e18ae90f370c139a6f36870e6bbac0e35',
}
SQL_FILE = '20260915_staging_comment_mecky_mirror.sql'
SQL_SHA256 = 'sha256:c800768dc1877b9819a788edd01732ea47b698adc2609b24192b708aa5082f8c'
LICENSE_SHA256 = 'sha256:0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0'
PUBLICATION_SHA256 = 'sha256:b99bd6b4cf8389e340e1a1da5122c8084a86582920005b4d90a926316b758960'
FUNCTIONS = ('staging_participant_gateway_reserve_comment_mirror', 'staging_participant_gateway_complete_comment_mirror')
SIGNATURE = '(text,uuid,uuid,uuid,text,bigint,text)'
TABLE = 'staging_participant_private.staging_participant_comment_mirrors'
POLICY_FILES = {
    'scripts/comment_mecky_rollout.py', 'scripts/test_comment_mecky_rollout.py',
    str(POLICY_PATH), str(ROOT / SQL_FILE), str(ROOT / 'LICENSE.AGPL-3.0'),
}
TRANSITION_FILES = {
    str(RECORD_PATH), 'policy/repository-contract.json',
    'reviewed-render/roebel-staging/integrity.json',
    'reviewed-render/roebel-staging/network-boundary-migration.json',
    *(f'reviewed-render/roebel-staging/staging-participant-gateway/{name}.json'
      for name in ('runtime-pin', 'deployment', 'ingress')),
}


def descriptor():
    return {
        'schemaVersion': 'roebel_comment_mecky_activation_policy_v1',
        'source': {'repository': 'https://github.com/GiraeffleAeffle/Roebel-App.git',
                   'protectedRef': 'refs/heads/main', **RELEASE},
        'publication': {'runId': '34958089634', 'receiptSha256': PUBLICATION_SHA256,
                        'supplementalSqlAttestedByPublication': False},
        'sql': {'sourcePath': 'supabase/migrations/' + SQL_FILE,
                'operationsPath': str(ROOT / SQL_FILE), 'sha256': SQL_SHA256,
                'license': {'path': str(ROOT / 'LICENSE.AGPL-3.0'), 'sha256': LICENSE_SHA256}},
        'database': {'namespace': 'stadtstack-roebel-staging-lab', 'deployment': 'roebel-tracer-postgres',
                     'claim': 'roebel-tracer-postgres-data-v1', 'table': TABLE, 'functions': list(FUNCTIONS),
                     'mode': 'one-transaction-before-gateway-promotion', 'bootstrapReplay': False,
                     'isolatedCurrentBackupRehearsalRequired': True, 'automaticMigration': False,
                     'readiness': 'exact-catalog-and-function-body-check-before-and-after-migration'},
        'http': {'path': ROUTE, 'methods': ['POST', 'OPTIONS'], 'explicitMentionRequired': True,
                 'existingSignedSessionAndGatewayWriteRequired': True, 'sharedRateLimitUnchanged': True},
        'runtime': {'schemaVersion': SCHEMA, 'reuseExistingSecrets': True,
                    'newReadinessInStatusEndpoint': False, 'unavailableCommentRpcStatus': 503},
        'authority': {'binding': 'none', 'rolesAssigned': False, 'civicCommandsEnabled': False},
        'deactivation': 'revoke-only-comment-functions-and-retain-mirror-receipts',
        'rollback': 'exact-predecessor-gateway-requires-separate-admission',
    }


def enabled(root):
    return (root / RECORD_PATH).is_file()


def verify_policy(v, root):
    v.require((root / POLICY_PATH).is_file() and not (root / POLICY_PATH).is_symlink(), 'comment policy must be a regular file')
    v.require(v.load_json(root / POLICY_PATH) == descriptor(), 'comment policy drift')
    for filename, expected in ((SQL_FILE, SQL_SHA256), ('LICENSE.AGPL-3.0', LICENSE_SHA256)):
        path = root / ROOT / filename
        v.require(path.is_file() and not path.is_symlink(), 'comment artifact must be a regular file')
        v.require(v.bytes_digest(path.read_bytes()) == expected, 'comment source artifact drift: ' + filename)


def runtime_pin(v, participant_policy=None):
    value = v.CITIZEN_STATUS.runtime_pin(v, participant_policy)
    value.update(RELEASE)
    value.update(schemaVersion=SCHEMA, commentMeckyMigrationSha256=SQL_SHA256)
    return value


def resources(v, participant_policy, civic_projection_route):
    value = v.CITIZEN_STATUS.resources(v, participant_policy, civic_projection_route)
    container = value['deployment']['spec']['template']['spec']['containers'][0]
    container['image'] = runtime_pin(v, participant_policy)['imageRepository'] + '@' + RELEASE['manifestDigest']
    environment = {item['name']: item for item in container['env']}
    for suffix, field in (('SOURCE_REVISION', 'sourceRevision'), ('MANIFEST_DIGEST', 'manifestDigest')):
        environment['ROEBEL_STAGING_PARTICIPANT_GATEWAY_' + suffix]['value'] = RELEASE[field]
    key = 'haproxy-ingress.github.io/config-backend-early'
    rules = value['ingress']['metadata']['annotations'][key].splitlines()
    v.require(len(rules) == 9 and rules[0].startswith('http-request deny deny_status 404 if '), 'comment ingress predecessor drift')
    # Append to an existing exact-path ACL rather than another four-token ACL:
    # HAProxy has a fixed argument limit. No prefix or method is widened.
    for index in (0, 1, 2):
        left, right = rules[index].split(' }', 1)
        if index:  # The first ACL is the method; extend the following path ACL.
            prefix, rest = right.split('!{ path ', 1)
            path, suffix = rest.split(' }', 1)
            rules[index] = left + ' }' + prefix + '!{ path ' + path + ' ' + ROUTE + ' }' + suffix
        else:
            rules[index] = left + ' ' + ROUTE + ' }' + right
    v.require(all(len(line.split()) < 64 for line in rules), 'comment ingress exceeds HAProxy argument limit')
    value['ingress']['metadata']['annotations'][key] = '\n'.join(rules)
    return value


def extend_http(value):
    result = copy.deepcopy(value)
    result['schemaVersion'] = SCHEMA
    result['exactGatewayPaths'].append(ROUTE)
    for method in ('POST', 'OPTIONS'):
        result['methodPathMatrix'][method].append(ROUTE)
    return result


def network_receipt(v, value, gateway):
    result = copy.deepcopy(value)
    ingress = result['boundary']['ingress']
    ingress['exactGatewayPaths'].append(ROUTE)
    ingress['exactPostPaths'].append(ROUTE)
    for method in ('POST', 'OPTIONS'):
        ingress['gatewayMethodPathMatrix'][method].append(ROUTE)
    for item in result['objects']:
        if item['name'] == v.PARTICIPANT_GATEWAY_NAME and item['kind'] in ('Deployment', 'Ingress'):
            item['sha256'] = v.digest(gateway[item['kind'].lower()])
    return result


def record(v):
    return {'schemaVersion': 'roebel_comment_mecky_desired_state_v1', 'policy': str(POLICY_PATH),
            'policyCanonicalSha256': v.digest(descriptor()), 'runtimePinCanonicalSha256': v.digest(runtime_pin(v)),
            'databasePreflightRequired': True, 'liveEvidenceCommitted': False, 'authorityBinding': 'none'}


def catalog_assertion_sql(v, root):
    """Check exact stored function bodies, signatures, ACLs and private table."""
    verify_policy(v, root)
    sql = (root / ROOT / SQL_FILE).read_text()
    bodies = re.findall(r'create function public\.(\w+)\(.*?\nas \$\$(.*?)\$\$;', sql, re.S)
    v.require(tuple(name for name, _ in bodies) == FUNCTIONS, 'comment function envelope drift')
    checks = []
    for name, body in bodies:
        sha = hashlib.sha256(body.encode()).hexdigest()
        checks.append(f"""if not exists (select 1 from pg_proc p where p.oid=to_regprocedure('public.{name}{SIGNATURE}')
          and p.prosecdef and p.prorettype='jsonb'::regtype and p.prolang=(select oid from pg_language where lanname='plpgsql')
          and pg_get_userbyid(p.proowner)=current_user and p.provolatile='v'
          and p.proconfig=array['search_path=pg_catalog, public, staging_participant_private']
          and encode(extensions.digest(p.prosrc,'sha256'),'hex')='{sha}'
          and has_function_privilege('anon',p.oid,'EXECUTE')
          and not has_function_privilege('authenticated',p.oid,'EXECUTE')
          and not exists(select 1 from aclexplode(p.proacl) a where a.grantee<>p.proowner
            and (a.grantee<>(select oid from pg_roles where rolname='anon') or a.privilege_type<>'EXECUTE' or a.is_grantable)))
          then raise exception 'COMMENT_FUNCTION_CATALOG_MISMATCH: {name}'; end if;""")
    return """do $comment_catalog$
begin
  if current_database()<>'postgres' or current_user<>'supabase_admin' or not exists(
    select 1 from staging_participant_private.staging_participant_environment where singleton and environment='staging')
    then raise exception 'COMMENT_STAGING_OWNER_REQUIRED'; end if;
  if not exists(select 1 from pg_class where oid=to_regclass('""" + TABLE + """') and relrowsecurity and relkind='r' and relowner=(select oid from pg_roles where rolname=current_user))
    then raise exception 'COMMENT_PRIVATE_TABLE_REQUIRED'; end if;
  if exists(select 1 from pg_policy where polrelid='""" + TABLE + """'::regclass)
     or has_table_privilege('anon','""" + TABLE + """','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     or has_table_privilege('authenticated','""" + TABLE + """','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    then raise exception 'COMMENT_TABLE_ACCESS_EXPANDED'; end if;
  if (select count(*) from pg_proc where pronamespace='public'::regnamespace and proname in
    ('""" + "','".join(FUNCTIONS) + """'))<>2 then raise exception 'COMMENT_FUNCTION_OVERLOAD'; end if;
  if (select array_agg(attname::text||':'||format_type(atttypid,atttypmod)||':'||attnotnull::text order by attnum)
      from pg_attribute where attrelid='""" + TABLE + """'::regclass and attnum>0 and not attisdropped)
      is distinct from array['source_comment_id:uuid:true','source_post_id:uuid:true','wallet_address:text:true',
      'request_id:uuid:true','event_id:text:true','event_created_at:bigint:true','content_sha256:text:true','state:text:true']
    then raise exception 'COMMENT_TABLE_COLUMNS_DRIFT'; end if;
  if (select count(*) from pg_constraint where conrelid='""" + TABLE + """'::regclass)<>10
    or exists(select 1 from pg_constraint where conrelid='""" + TABLE + """'::regclass and (not convalidated or condeferrable))
    or not exists(select 1 from pg_constraint where conrelid='""" + TABLE + """'::regclass and contype='p' and conkey=array[1]::smallint[])
    or (select array_agg(conkey::text order by conkey::text) from pg_constraint where conrelid='""" + TABLE + """'::regclass and contype='u') is distinct from array['{4}','{5}']
    or not exists(select 1 from pg_constraint where conrelid='""" + TABLE + """'::regclass and contype='f' and conkey=array[1]::smallint[] and confrelid='public.post_comments'::regclass and confdeltype='a' and confupdtype='a')
    or not exists(select 1 from pg_constraint where conrelid='""" + TABLE + """'::regclass and contype='f' and conkey=array[2]::smallint[] and confrelid='public.posts'::regclass and confdeltype='a' and confupdtype='a')
    or (select array_agg(pg_get_constraintdef(oid) order by pg_get_constraintdef(oid)) from pg_constraint where conrelid='""" + TABLE + """'::regclass and contype='c')
      is distinct from array[$check$CHECK ((content_sha256 ~ '^[0-9a-f]{64}$'::text))$check$,
        $check$CHECK ((event_created_at >= 0))$check$,
        $check$CHECK ((event_id ~ '^[0-9a-f]{64}$'::text))$check$,
        $check$CHECK ((state = ANY (ARRAY['reserved'::text, 'published'::text])))$check$,
        $check$CHECK ((wallet_address ~ '^0x[0-9a-f]{40}$'::text))$check$]
    or exists(select 1 from pg_trigger where tgrelid='""" + TABLE + """'::regclass and (not tgisinternal or tgenabled<>'O'))
    then raise exception 'COMMENT_TABLE_CONSTRAINTS_DRIFT'; end if;
  if (select array_agg(a.attname::text||':'||pg_get_expr(d.adbin,d.adrelid)) from pg_attrdef d
    join pg_attribute a on a.attrelid=d.adrelid and a.attnum=d.adnum where d.adrelid='""" + TABLE + """'::regclass)
    is distinct from array[$default$state:'reserved'::text$default$]
    then raise exception 'COMMENT_TABLE_DEFAULT_DRIFT'; end if;
  """ + '\n  '.join(checks) + "\nend $comment_catalog$;\n"


def migration_sql(v, root):
    verify_policy(v, root)
    sql = (root / ROOT / SQL_FILE).read_text()
    v.require(sql.count('\nbegin;\n') == 1 and sql.endswith('\ncommit;\n'), 'comment migration envelope drift')
    body = sql.replace('\nbegin;\n', '\n', 1).removesuffix('\ncommit;\n')
    return "\\set ON_ERROR_STOP on\nbegin;\nset local lock_timeout = '5s';\nset local statement_timeout = '30s';\n" + body + '\n' + catalog_assertion_sql(v, root) + "notify pgrst, 'reload schema';\ncommit;\n"


def deactivation_sql():
    return "\\set ON_ERROR_STOP on\nbegin;\nset local lock_timeout = '5s';\n" + ''.join(
        f'revoke all on function public.{name}{SIGNATURE} from public, anon, authenticated;\n' for name in FUNCTIONS
    ) + "notify pgrst, 'reload schema';\ncommit;\n"


def activation_files(v, base_root, current):
    v.require(not enabled(base_root), 'comment route already enabled')
    v.require(current['tracerDataPlane']['persistentVolumeClaim'], 'comment route requires retained database')
    v.require(current['stagingParticipantGateway']['runtimePin'] == v.CITIZEN_STATUS.runtime_pin(v), 'comment gateway predecessor drift')
    pin = runtime_pin(v, current['stagingParticipantGatewayPolicy'])
    gateway = resources(v, current['stagingParticipantGatewayPolicy'], current['stagingParticipantGateway']['civicProjectionRoute'])
    files = {}
    def write(path, value):
        files[str(path)] = json.dumps(value, indent=2, sort_keys=True) + '\n'
    for name, value in (('runtime-pin', pin), ('deployment', gateway['deployment']), ('ingress', gateway['ingress'])):
        write(Path(v.PARTICIPANT_GATEWAY_ROOT) / (name + '.json'), value)
    contract = v.load_json(base_root / 'policy/repository-contract.json')
    http = extend_http(contract['stagingParticipantGatewayBoundary'])
    http['commentMecky'] = descriptor()
    contract['stagingParticipantGatewayBoundary'] = http
    write('policy/repository-contract.json', contract)
    network = network_receipt(v, current['migration'], gateway)
    write(Path(v.RENDER_ROOT) / 'network-boundary-migration.json', network)
    gateway_payload = {key: value for key, value in current['stagingParticipantGateway'].items() if key != 'civicProjectionRoute'}
    gateway_payload.update(gateway)
    gateway_payload['runtimePin'] = pin
    payload = {'nextEnvironmentHead': current['head'], 'objects': current['objects'], 'stagingParticipantGateway': gateway_payload}
    for key in ('reviewedPublicKnowledge', 'signedNostr'):
        if current[key] is not None:
            payload[key] = current[key]
    integrity = copy.deepcopy(current['integrity'])
    integrity.update(desiredRenderSha256=v.digest(payload), networkBoundaryMigrationSha256=v.digest(network))
    write(Path(v.RENDER_ROOT) / 'integrity.json', integrity)
    write(RECORD_PATH, record(v))
    v.require(set(files) == TRANSITION_FILES, 'comment transition file set drift')
    return files


def verify_state(v, root, gateway, tracer):
    active = enabled(root)
    v.require(active == bool(gateway and gateway['runtimePin']['schemaVersion'] == SCHEMA), 'comment record/runtime mismatch')
    if active:
        v.require(tracer['persistentVolumeClaim'], 'comment route requires retained database')
        v.require(v.load_json(root / RECORD_PATH) == record(v), 'comment desired-state record drift')
    return active


def status_predecessor(v, gateway):
    """Let the unchanged historical validator check its exact retained record."""
    if not gateway or gateway['runtimePin']['schemaVersion'] != SCHEMA:
        return gateway
    v.require(gateway['runtimePin'] == runtime_pin(v), 'comment runtime pin drift')
    predecessor = dict(gateway)
    predecessor['runtimePin'] = v.CITIZEN_STATUS.runtime_pin(v)
    return predecessor


def verify_transition(v, candidate, base):
    v.require(not base.get('commentMecky') and candidate.get('commentMecky'), 'comment rollback requires separate exact admission')
    v.require(v.changed_repository_files(candidate['root'], base['root']) == TRANSITION_FILES, 'comment transition file set drift')
    for path, content in activation_files(v, base['root'], base).items():
        v.require((candidate['root'] / path).read_bytes() == content.encode(), 'comment transition bytes drift: ' + path)


def prepare(v, root, base_root, product_root, publication_path):
    """Bind source, publication and predecessor; return files without writing."""
    verify_policy(v, root)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(product_root), *args])
    rev = RELEASE['sourceRevision']
    v.require(v.bytes_digest(git('ls-tree', '-r', '-z', '--full-tree', rev)) == RELEASE['sourceTreeSha256'], 'comment source tree drift')
    v.require(v.bytes_digest(git('show', rev + ':.github/workflows/staging-participant-gateway-publish.yml')) == RELEASE['workflowSha256'], 'comment publication workflow drift')
    v.require(v.bytes_digest(git('show', rev + ':supabase/migrations/' + SQL_FILE)) == SQL_SHA256, 'comment upstream SQL drift')
    v.require(not publication_path.is_symlink() and v.bytes_digest(publication_path.read_bytes()) == PUBLICATION_SHA256, 'comment publication receipt drift')
    current = v.verify_tree(base_root)
    files = activation_files(v, base_root, current)
    return {'schemaVersion': 'roebel_comment_mecky_review_proposal_v1', 'status': 'proposal-only',
            'policy': descriptor(), 'proposedFiles': files,
            'proposedFileSha256': {path: v.bytes_digest(raw.encode()) for path, raw in files.items()},
            'migrationSql': migration_sql(v, root), 'catalogAssertionSql': catalog_assertion_sql(v, root),
            'deactivationSql': deactivation_sql(), 'deploymentEffect': False, 'admissionPassed': False}


if __name__ == '__main__':
    import argparse
    import importlib.util
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'base-root', 'product-root', 'publication-receipt'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('protected_comment_verifier', Path(__file__).with_name('verify-reviewed-render.py'))
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    print(json.dumps(prepare(verifier, args.root, args.base_root, args.product_root, args.publication_receipt), indent=2))
