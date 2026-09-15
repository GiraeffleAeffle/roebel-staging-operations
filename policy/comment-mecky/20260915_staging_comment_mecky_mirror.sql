-- Add a comment-only conversation capability. Existing post/promotion receipts
-- and civic tables are not changed. Roll out the gateway only after this migration.
begin;

do $$ begin
  if not exists (select 1 from staging_participant_private.staging_participant_environment
    where singleton and environment = 'staging') then
    raise exception 'STAGING_PARTICIPANT_ENVIRONMENT_REQUIRED';
  end if;
end $$;

create table staging_participant_private.staging_participant_comment_mirrors (
  source_comment_id uuid primary key references public.post_comments(id),
  source_post_id uuid not null references public.posts(id),
  wallet_address text not null check (wallet_address ~ '^0x[0-9a-f]{40}$'),
  request_id uuid not null unique,
  event_id text not null unique check (event_id ~ '^[0-9a-f]{64}$'),
  event_created_at bigint not null check (event_created_at >= 0),
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  state text not null default 'reserved' check (state in ('reserved', 'published'))
);
alter table staging_participant_private.staging_participant_comment_mirrors enable row level security;
revoke all on staging_participant_private.staging_participant_comment_mirrors from public, anon, authenticated;

create function public.staging_participant_gateway_reserve_comment_mirror(
  p_wallet_address text, p_source_post_id uuid, p_source_comment_id uuid,
  p_request_id uuid, p_event_id text, p_event_created_at bigint, p_content_sha256 text
) returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  receipt staging_participant_private.staging_participant_comment_mirrors%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null or p_wallet_address !~ '^0x[0-9a-f]{40}$'
    or p_source_post_id is null or p_source_comment_id is null or p_request_id is null
    or p_event_id is null or p_event_id !~ '^[0-9a-f]{64}$'
    or p_event_created_at is null or p_event_created_at < 0
    or p_content_sha256 is null or p_content_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'COMMENT_MIRROR_CONFLICT';
  end if;
  perform staging_participant_private.ensure_active_staging_participant(p_wallet_address);
  perform pg_advisory_xact_lock(hashtextextended(p_source_comment_id::text, 20260915));
  -- Recheck the persisted author, original gateway write, parent and content on
  -- every attempt, including a retry of an already-published receipt.
  if not exists (
    select 1 from public.post_comments c
    join public.posts p on p.id = c.post_id
    join staging_participant_private.staging_participant_write_audit a
      on a.result_id = c.id and a.action = 'comment'
      and a.wallet_address = p_wallet_address and a.source_post_id = p.id
    where c.id = p_source_comment_id and c.post_id = p_source_post_id
      and lower(c.wallet_address) = p_wallet_address and c.account_id is null
      and c.status = 'published' and p.status = 'published' and p.feed_type = 'main'
      and coalesce(cardinality(c.media_urls), 0) = 0 and c.video_url is null
      and encode(extensions.digest(c.content, 'sha256'), 'hex') = p_content_sha256
      and encode(a.content_sha256, 'hex') = p_content_sha256
  ) then raise exception 'COMMENT_MIRROR_CONFLICT'; end if;
  select * into receipt from staging_participant_private.staging_participant_comment_mirrors
    where source_comment_id = p_source_comment_id;
  if found then
    if receipt.wallet_address <> p_wallet_address or receipt.source_post_id <> p_source_post_id
      or receipt.request_id <> p_request_id or receipt.event_id <> p_event_id
      or receipt.event_created_at <> p_event_created_at or receipt.content_sha256 <> p_content_sha256 then
      raise exception 'COMMENT_MIRROR_CONFLICT';
    end if;
    return to_jsonb(receipt);
  end if;
  if abs(p_event_created_at - extract(epoch from clock_timestamp())::bigint) > 300 then
    raise exception 'COMMENT_MIRROR_STALE';
  end if;
  insert into staging_participant_private.staging_participant_comment_mirrors
    (source_comment_id, source_post_id, wallet_address, request_id, event_id, event_created_at, content_sha256)
    values (p_source_comment_id, p_source_post_id, p_wallet_address, p_request_id, p_event_id, p_event_created_at, p_content_sha256)
    returning * into receipt;
  return to_jsonb(receipt);
exception when unique_violation then raise exception 'COMMENT_MIRROR_CONFLICT';
end $$;

create function public.staging_participant_gateway_complete_comment_mirror(
  p_wallet_address text, p_source_post_id uuid, p_source_comment_id uuid,
  p_request_id uuid, p_event_id text, p_event_created_at bigint, p_content_sha256 text
) returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  receipt staging_participant_private.staging_participant_comment_mirrors%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  perform pg_advisory_xact_lock(hashtextextended(p_source_comment_id::text, 20260915));
  -- Completion never creates a reservation. Re-run the closed source/receipt
  -- checks before acknowledging the exact event published by the gateway.
  if not exists (select 1 from staging_participant_private.staging_participant_comment_mirrors
    where source_comment_id = p_source_comment_id) then raise exception 'COMMENT_MIRROR_CONFLICT'; end if;
  perform public.staging_participant_gateway_reserve_comment_mirror(p_wallet_address,
    p_source_post_id, p_source_comment_id, p_request_id, p_event_id, p_event_created_at, p_content_sha256);
  update staging_participant_private.staging_participant_comment_mirrors set state = 'published'
    where source_comment_id = p_source_comment_id returning * into receipt;
  return to_jsonb(receipt);
end $$;

revoke all on function public.staging_participant_gateway_reserve_comment_mirror(text,uuid,uuid,uuid,text,bigint,text) from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_complete_comment_mirror(text,uuid,uuid,uuid,text,bigint,text) from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_reserve_comment_mirror(text,uuid,uuid,uuid,text,bigint,text) to anon;
grant execute on function public.staging_participant_gateway_complete_comment_mirror(text,uuid,uuid,uuid,text,bigint,text) to anon;
commit;
