#!/usr/bin/env bash
set -euo pipefail
test "${ROEBEL_TRACER_ENVIRONMENT_ARM:-}" = 'staging-only'
test "${#ROEBEL_TRACER_RPC_SECRET}" -ge 32
test "${#ROEBEL_TRACER_AUTHENTICATOR_PASSWORD}" -ge 24
{
printf '%s  %s\n' '8fe7fffca7a5b62720254eb4fade61ab7e2767e327af2b117c3c4635f45a9e32' '/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql'
printf '%s  %s\n' 'ad050047a71bf2cc82361c16169627dc0a0a66a7982db804b1612624f0f97eab' '/roebel-tracer-bootstrap/73-staging-participant-gateway.sql'
printf '%s  %s\n' '739cbcb189e3b12913ebf28dae74c931eab3cfae514e476bea4071092aef242e' '/roebel-tracer-bootstrap/74-staging-participant-topic-tracer.sql'
} | sha256sum --check --strict -
psql_args=(--set=ON_ERROR_STOP=1 --no-password --no-psqlrc --username=supabase_admin --dbname=postgres)
psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql
bash /roebel-tracer-bootstrap/72-provision-roebel-vault.sh
psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/73-staging-participant-gateway.sql
psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/74-staging-participant-topic-tracer.sql
