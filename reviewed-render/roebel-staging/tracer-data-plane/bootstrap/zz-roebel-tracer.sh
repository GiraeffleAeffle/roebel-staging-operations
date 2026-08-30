#!/usr/bin/env bash
set -euo pipefail
test "${ROEBEL_TRACER_ENVIRONMENT_ARM:-}" = 'staging-only'
test "${#ROEBEL_TRACER_RPC_SECRET}" -ge 32
test "${#ROEBEL_TRACER_AUTHENTICATOR_PASSWORD}" -ge 24
{
printf '%s  %s\n' 'c9d94bc0baa66fa1e0c7b4fa9da1677afac7a59178b82c8b37b0bc781db299d5' '/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql'
printf '%s  %s\n' 'ad050047a71bf2cc82361c16169627dc0a0a66a7982db804b1612624f0f97eab' '/roebel-tracer-bootstrap/73-staging-participant-gateway.sql'
printf '%s  %s\n' '739cbcb189e3b12913ebf28dae74c931eab3cfae514e476bea4071092aef242e' '/roebel-tracer-bootstrap/74-staging-participant-topic-tracer.sql'
} | sha256sum --check --strict -
psql_args=(--set=ON_ERROR_STOP=1 --no-password --no-psqlrc --username=supabase_admin --dbname=postgres)
psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql
bash /roebel-tracer-bootstrap/72-provision-roebel-vault.sh
psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/73-staging-participant-gateway.sql
psql "${psql_args[@]}" --file=/roebel-tracer-bootstrap/74-staging-participant-topic-tracer.sql
