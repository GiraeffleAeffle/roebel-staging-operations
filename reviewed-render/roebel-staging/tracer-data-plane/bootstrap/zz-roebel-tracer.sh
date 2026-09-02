#!/usr/bin/env bash
set -euo pipefail
test "${ROEBEL_TRACER_ENVIRONMENT_ARM:-}" = 'staging-only'
test "${#ROEBEL_TRACER_RPC_SECRET}" -ge 32
test "${#ROEBEL_TRACER_AUTHENTICATOR_PASSWORD}" -ge 24
{
printf '%s  %s\n' 'f8f9745c1783043334ef24b3cde801d19a609867d12d0c23612bda7c5206ca5a' '/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql'
printf '%s  %s\n' 'ad050047a71bf2cc82361c16169627dc0a0a66a7982db804b1612624f0f97eab' '/roebel-tracer-bootstrap/73-staging-participant-gateway.sql'
printf '%s  %s\n' '739cbcb189e3b12913ebf28dae74c931eab3cfae514e476bea4071092aef242e' '/roebel-tracer-bootstrap/74-staging-participant-topic-tracer.sql'
printf '%s  %s\n' '35e12ecc7e54e76f8e12b17e828970bc2d3bd4393f14f58fe9604dd00d398a2d' '/roebel-tracer-bootstrap/75-staging-citizen-adoption.sql'
} | sha256sum --check --strict -
psql_args=(--set=ON_ERROR_STOP=1 --no-password --no-psqlrc --username=supabase_admin --dbname=postgres)
psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql
bash /roebel-tracer-bootstrap/72-provision-roebel-vault.sh
PGOPTIONS='-c search_path=pg_catalog,public,staging_participant_private' psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/73-staging-participant-gateway.sql
PGOPTIONS='-c search_path=pg_catalog,public,staging_participant_private' psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/74-staging-participant-topic-tracer.sql
PGOPTIONS='-c search_path=pg_catalog,public,staging_participant_private' psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/75-staging-citizen-adoption.sql
