-- Run once in the Supabase SQL editor. No diary records or secrets belong here.
create table if not exists public.planner_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  revision bigint not null default 0,
  data jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.planner_state enable row level security;
revoke all on public.planner_state from anon, authenticated;
grant select on public.planner_state to authenticated;
create policy "Read own planner only" on public.planner_state
  for select to authenticated using ((select auth.uid()) = user_id);

-- Compare-and-swap prevents an older device silently replacing newer changes.
create or replace function public.save_planner(expected_revision bigint, new_data jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare owner_id uuid := auth.uid(); current_row public.planner_state;
begin
  if owner_id is null then raise exception 'Authentication required' using errcode='42501'; end if;
  if jsonb_typeof(new_data) <> 'object' or (new_data->>'version') is distinct from '1'
     or octet_length(new_data::text) > 5242880 then
    raise exception 'Invalid planner data' using errcode='22023';
  end if;
  insert into public.planner_state(user_id,revision,data) values(owner_id,0,'{}'::jsonb)
    on conflict(user_id) do nothing;
  select * into current_row from public.planner_state where user_id=owner_id for update;
  if coalesce((new_data->>'schemaVersion')::integer,1) <
     coalesce((current_row.data->>'schemaVersion')::integer,1) then
    raise exception 'Please reload the planner to use the latest version' using errcode='22023';
  end if;
  if current_row.revision <> expected_revision then
    return jsonb_build_object('conflict',true,'revision',current_row.revision,'data',current_row.data);
  end if;
  update public.planner_state set data=new_data, revision=revision+1, updated_at=now()
    where user_id=owner_id returning * into current_row;
  return jsonb_build_object('conflict',false,'revision',current_row.revision);
end $$;
revoke all on function public.save_planner(bigint,jsonb) from public,anon;
grant execute on function public.save_planner(bigint,jsonb) to authenticated;
