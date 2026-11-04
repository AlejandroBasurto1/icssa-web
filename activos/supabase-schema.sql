-- ICSSA | Esquema multiusuario Supabase
-- Ejecutar completo en Supabase > SQL Editor > New query.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  role text not null default 'viewer' check (role in ('admin','editor','viewer')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.assets (
  id text primary key,
  source_data jsonb not null default '{}'::jsonb,
  is_new boolean not null default false,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.asset_updates (
  asset_id text primary key references public.assets(id) on delete cascade,
  found boolean not null default false,
  area_found text not null default '',
  notes text not null default '',
  gps_lat double precision,
  gps_lng double precision,
  gps_accuracy double precision,
  gps_captured_at timestamptz,
  updated_by uuid references auth.users(id),
  updated_at timestamptz not null default now(),
  version bigint not null default 1
);

create table if not exists public.asset_audit (
  id bigint generated always as identity primary key,
  asset_id text not null,
  operation text not null,
  old_data jsonb,
  new_data jsonb,
  changed_by uuid references auth.users(id),
  changed_at timestamptz not null default now()
);

create or replace function public.icssa_is_active()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles p where p.id = auth.uid() and p.active = true); $$;

create or replace function public.icssa_role()
returns text language sql stable security definer set search_path = public
as $$ select coalesce((select p.role from public.profiles p where p.id = auth.uid() and p.active = true),''); $$;

create or replace function public.icssa_touch_asset_update()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  new.updated_at = now();
  new.updated_by = auth.uid();
  new.version = coalesce(old.version,0) + 1;
  return new;
end; $$;

drop trigger if exists asset_updates_touch on public.asset_updates;
create trigger asset_updates_touch before update on public.asset_updates
for each row execute function public.icssa_touch_asset_update();

create or replace function public.icssa_audit_asset_update()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
 insert into public.asset_audit(asset_id,operation,old_data,new_data,changed_by)
 values (coalesce(new.asset_id,old.asset_id), tg_op,
         case when tg_op='INSERT' then null else to_jsonb(old) end,
         case when tg_op='DELETE' then null else to_jsonb(new) end,
         auth.uid());
 return coalesce(new,old);
end; $$;

drop trigger if exists asset_updates_audit on public.asset_updates;
create trigger asset_updates_audit after insert or update or delete on public.asset_updates
for each row execute function public.icssa_audit_asset_update();

alter table public.profiles enable row level security;
alter table public.assets enable row level security;
alter table public.asset_updates enable row level security;
alter table public.asset_audit enable row level security;

drop policy if exists "profile read own or admin" on public.profiles;
create policy "profile read own or admin" on public.profiles for select to authenticated
using (id = auth.uid() or public.icssa_role() = 'admin');
drop policy if exists "admin manage profiles" on public.profiles;
create policy "admin manage profiles" on public.profiles for all to authenticated
using (public.icssa_role() = 'admin') with check (public.icssa_role() = 'admin');

drop policy if exists "active users read assets" on public.assets;
create policy "active users read assets" on public.assets for select to authenticated
using (public.icssa_is_active());
drop policy if exists "editors manage assets" on public.assets;
create policy "editors manage assets" on public.assets for all to authenticated
using (public.icssa_role() in ('admin','editor'))
with check (public.icssa_role() in ('admin','editor'));

drop policy if exists "active users read updates" on public.asset_updates;
create policy "active users read updates" on public.asset_updates for select to authenticated
using (public.icssa_is_active());
drop policy if exists "editors write updates" on public.asset_updates;
create policy "editors write updates" on public.asset_updates for insert to authenticated
with check (public.icssa_role() in ('admin','editor'));
drop policy if exists "editors update updates" on public.asset_updates;
create policy "editors update updates" on public.asset_updates for update to authenticated
using (public.icssa_role() in ('admin','editor'))
with check (public.icssa_role() in ('admin','editor'));

drop policy if exists "admins read audit" on public.asset_audit;
create policy "admins read audit" on public.asset_audit for select to authenticated
using (public.icssa_role() = 'admin');

-- Perfil automático: el usuario nuevo inicia como consulta (viewer).
create or replace function public.icssa_new_user_profile()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
 insert into public.profiles(id,full_name,role)
 values(new.id, coalesce(new.raw_user_meta_data->>'full_name',''), 'viewer')
 on conflict (id) do nothing;
 return new;
end; $$;

drop trigger if exists icssa_auth_user_created on auth.users;
create trigger icssa_auth_user_created after insert on auth.users
for each row execute procedure public.icssa_new_user_profile();

-- Activar Realtime para sincronizar cambios entre dispositivos.
do $$ begin
  alter publication supabase_realtime add table public.assets;
exception when duplicate_object then null;
when undefined_object then null;
end $$;
do $$ begin
  alter publication supabase_realtime add table public.asset_updates;
exception when duplicate_object then null;
when undefined_object then null;
end $$;

grant usage on schema public to authenticated;
grant select, insert, update, delete on public.assets to authenticated;
grant select, insert, update, delete on public.asset_updates to authenticated;
grant select on public.profiles, public.asset_audit to authenticated;
grant usage, select on sequence public.asset_audit_id_seq to authenticated;


-- ICSSA multiusuario: extensión de perfiles y control de carga de base.
alter table public.profiles add column if not exists username text unique;
alter table public.profiles add column if not exists must_change_password boolean not null default true;

create table if not exists public.base_imports (
  id bigint generated always as identity primary key,
  file_name text not null,
  row_count integer not null,
  imported_by uuid references auth.users(id),
  imported_at timestamptz not null default now()
);
alter table public.base_imports enable row level security;
drop policy if exists "admins view base imports" on public.base_imports;
create policy "admins view base imports" on public.base_imports for select to authenticated
using (public.icssa_role() = 'admin');
drop policy if exists "admins create base imports" on public.base_imports;
create policy "admins create base imports" on public.base_imports for insert to authenticated
with check (public.icssa_role() = 'admin');
grant select, insert on public.base_imports to authenticated;
grant usage, select on sequence public.base_imports_id_seq to authenticated;

-- El alta de usuarios y el cambio de rol se hace desde una función de servidor,
-- nunca exponiendo service_role en el navegador.


-- Reglas de escritura: solo admin sustituye la base patrimonial.
drop policy if exists "editors manage assets" on public.assets;
drop policy if exists "admins manage master assets" on public.assets;
create policy "admins manage master assets" on public.assets for all to authenticated
using (public.icssa_role() = 'admin')
with check (public.icssa_role() = 'admin');
drop policy if exists "editors create new assets" on public.assets;
create policy "editors create new assets" on public.assets for insert to authenticated
with check (public.icssa_role() = 'editor' and is_new = true);
