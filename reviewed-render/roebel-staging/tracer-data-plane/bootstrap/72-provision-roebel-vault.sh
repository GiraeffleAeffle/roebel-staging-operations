#!/usr/bin/env bash
set -euo pipefail
psql --set=ON_ERROR_STOP=1 --no-password --no-psqlrc --username=supabase_admin --dbname=postgres <<'SQL'
\getenv roebel_environment_arm ROEBEL_TRACER_ENVIRONMENT_ARM
\getenv roebel_rpc_secret ROEBEL_TRACER_RPC_SECRET
\getenv roebel_authenticator_password ROEBEL_TRACER_AUTHENTICATOR_PASSWORD

select vault.create_secret(
  :'roebel_environment_arm',
  'roebel_staging_participant_environment_arm',
  'Röbel staging-only participant environment arm'
);
select vault.create_secret(
  :'roebel_rpc_secret',
  'roebel_staging_participant_rpc_secret',
  'Röbel staging-only participant RPC capability'
);
alter role authenticator login password :'roebel_authenticator_password';

do $$
begin
  if not exists (
    select 1 from vault.decrypted_secrets
    where name = 'roebel_staging_participant_environment_arm'
      and decrypted_secret = 'staging-only'
  ) then
    raise exception 'roebel tracer environment arm missing';
  end if;
  if not exists (
    select 1 from vault.decrypted_secrets
    where name = 'roebel_staging_participant_rpc_secret'
      and length(decrypted_secret) >= 32
  ) then
    raise exception 'roebel tracer RPC secret missing';
  end if;
end;
$$;
SQL
