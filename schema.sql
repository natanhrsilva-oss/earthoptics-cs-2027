-- EarthOptics CS 2027 · Caderno de Campo + Painel
-- Banco: perfis com papel (vendedor/gestor), clientes, registros, consultorias, amostradores e anexos.
create extension if not exists pgcrypto with schema extensions;

-- ---------- PERFIS ----------
create table if not exists public.profiles(
  id uuid primary key references auth.users on delete cascade,
  nome text not null default '',
  email text,
  papel text not null default 'vendedor' check (papel in ('vendedor','gestor')),
  ativo boolean not null default false,
  trocar_senha boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;

create or replace function public.is_ativo() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from profiles where id=auth.uid() and ativo) $$;
create or replace function public.is_gestor() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from profiles where id=auth.uid() and ativo and papel='gestor') $$;

-- primeiro usuário vira gestor ativo; os demais nascem desativados até o gestor liberar
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare primeiro boolean;
begin
  select not exists(select 1 from profiles) into primeiro;
  insert into profiles(id,nome,email,papel,ativo,trocar_senha)
  values(new.id, coalesce(new.raw_user_meta_data->>'nome',''), new.email,
         case when primeiro then 'gestor' else 'vendedor' end, primeiro, not primeiro);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

create or replace function public.has_users() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from profiles) $$;
grant execute on function public.has_users() to anon, authenticated;

drop policy if exists "perfis: ver" on public.profiles;
create policy "perfis: ver" on public.profiles for select to authenticated using (id=auth.uid() or public.is_gestor());

-- ações do gestor sobre usuários
create or replace function public.admin_setup_user(uid uuid, p_nome text, p_papel text) returns void language plpgsql security definer set search_path=public as $$
begin
  if not is_gestor() then raise exception 'Apenas gestores podem criar usuários'; end if;
  update profiles set nome=p_nome, papel=p_papel, ativo=true, trocar_senha=true where id=uid;
end $$;

create or replace function public.admin_update_user(uid uuid, p_nome text, p_papel text, p_ativo boolean) returns void language plpgsql security definer set search_path=public as $$
begin
  if not is_gestor() then raise exception 'Apenas gestores podem editar usuários'; end if;
  if uid=auth.uid() and (not p_ativo or p_papel<>'gestor') then raise exception 'Você não pode remover o seu próprio acesso de gestor'; end if;
  update profiles set nome=p_nome, papel=p_papel, ativo=p_ativo where id=uid;
end $$;

create or replace function public.admin_set_password(uid uuid, senha text) returns void language plpgsql security definer set search_path=public, extensions as $$
begin
  if not is_gestor() then raise exception 'Apenas gestores podem redefinir senhas'; end if;
  if length(senha)<6 then raise exception 'A senha precisa de pelo menos 6 caracteres'; end if;
  update auth.users set encrypted_password=extensions.crypt(senha, extensions.gen_salt('bf')), updated_at=now() where id=uid;
  update profiles set trocar_senha=true where id=uid;
end $$;

create or replace function public.senha_trocada() returns void language sql security definer set search_path=public as
$$ update profiles set trocar_senha=false where id=auth.uid() $$;

-- ---------- CLIENTES ----------
create table if not exists public.clients(
  id bigint primary key,
  seller_id uuid not null references public.profiles(id),
  data jsonb not null default '{}',
  cs jsonb not null default '{}',
  updated_at timestamptz not null default now()
);
alter table public.clients enable row level security;

create or replace function public.can_see_client(cid bigint) returns boolean language sql stable security definer set search_path=public as
$$ select is_ativo() and (is_gestor() or exists(select 1 from clients where id=cid and seller_id=auth.uid())) $$;

drop policy if exists "clientes: ver" on public.clients;
drop policy if exists "clientes: criar" on public.clients;
drop policy if exists "clientes: editar" on public.clients;
drop policy if exists "clientes: excluir" on public.clients;
create policy "clientes: ver" on public.clients for select to authenticated using (public.is_ativo() and (public.is_gestor() or seller_id=auth.uid()));
create policy "clientes: criar" on public.clients for insert to authenticated with check (public.is_ativo() and (public.is_gestor() or seller_id=auth.uid()));
create policy "clientes: editar" on public.clients for update to authenticated using (public.is_ativo() and (public.is_gestor() or seller_id=auth.uid())) with check (public.is_gestor() or seller_id=auth.uid());
create policy "clientes: excluir" on public.clients for delete to authenticated using (public.is_gestor());

-- o vendedor não altera campos do CS, o vendedor responsável nem os links
create or replace function public.protect_client() returns trigger language plpgsql security definer set search_path=public as $$
begin
  new.updated_at=now();
  if is_gestor() then return new; end if;
  if tg_op='INSERT' then new.seller_id=auth.uid(); new.cs='{}'::jsonb; return new; end if;
  new.seller_id=old.seller_id; new.cs=old.cs;
  new.data = new.data || jsonb_build_object(
    'plat', coalesce(old.data->'plat','""'::jsonb),
    'sf',   coalesce(old.data->'sf','""'::jsonb),
    'csAt', coalesce(old.data->'csAt','null'::jsonb));
  return new;
end $$;
drop trigger if exists protect_client on public.clients;
create trigger protect_client before insert or update on public.clients for each row execute function public.protect_client();

create or replace function public.admin_transfer(de uuid, para uuid) returns integer language plpgsql security definer set search_path=public as $$
declare n integer;
begin
  if not is_gestor() then raise exception 'Apenas gestores podem transferir clientes'; end if;
  update clients set seller_id=para where seller_id=de; get diagnostics n = row_count; return n;
end $$;

-- ---------- REGISTROS ----------
create table if not exists public.records(
  id text primary key,
  client_id bigint not null references public.clients(id) on delete cascade,
  data jsonb not null default '{}',
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);
alter table public.records enable row level security;
drop policy if exists "registros: ver" on public.records;
drop policy if exists "registros: criar" on public.records;
drop policy if exists "registros: editar" on public.records;
drop policy if exists "registros: excluir" on public.records;
create policy "registros: ver" on public.records for select to authenticated using (public.can_see_client(client_id));
create policy "registros: criar" on public.records for insert to authenticated with check (public.can_see_client(client_id));
create policy "registros: editar" on public.records for update to authenticated using (public.is_gestor() or created_by=auth.uid());
create policy "registros: excluir" on public.records for delete to authenticated using (public.is_gestor());

-- ---------- CONSULTORIAS E AMOSTRADORES ----------
create table if not exists public.consultorias(id text primary key, data jsonb not null default '{}', created_by uuid default auth.uid());
create table if not exists public.samplers(id text primary key, data jsonb not null default '{}');
alter table public.consultorias enable row level security;
alter table public.samplers enable row level security;
drop policy if exists "consultorias: ver" on public.consultorias;
drop policy if exists "consultorias: criar" on public.consultorias;
drop policy if exists "consultorias: editar" on public.consultorias;
drop policy if exists "consultorias: excluir" on public.consultorias;
create policy "consultorias: ver" on public.consultorias for select to authenticated using (public.is_ativo());
create policy "consultorias: criar" on public.consultorias for insert to authenticated with check (public.is_ativo());
create policy "consultorias: editar" on public.consultorias for update to authenticated using (public.is_gestor());
create policy "consultorias: excluir" on public.consultorias for delete to authenticated using (public.is_gestor());
drop policy if exists "amostradores: ver" on public.samplers;
drop policy if exists "amostradores: gestor" on public.samplers;
create policy "amostradores: ver" on public.samplers for select to authenticated using (public.is_ativo());
create policy "amostradores: gestor" on public.samplers for all to authenticated using (public.is_gestor()) with check (public.is_gestor());

-- ---------- ANEXOS (fotos, áudios, PDFs) ----------
insert into storage.buckets(id,name,public) values('anexos','anexos',false) on conflict (id) do nothing;
drop policy if exists "anexos: ver" on storage.objects;
drop policy if exists "anexos: enviar" on storage.objects;
create policy "anexos: ver" on storage.objects for select to authenticated
  using (bucket_id='anexos' and public.can_see_client(((storage.foldername(name))[1])::bigint));
create policy "anexos: enviar" on storage.objects for insert to authenticated
  with check (bucket_id='anexos' and public.can_see_client(((storage.foldername(name))[1])::bigint));

-- ---------- BASE INICIAL (exemplos: substitua pela base real no painel) ----------
insert into public.samplers(id,data) values
 ('s1','{"nome":"Amostra Certa Agro (exemplo)","cidade":"Sorriso","uf":"MT","lat":-12.55,"lon":-55.71,"contato":"(66) 0000-0000"}'),
 ('s2','{"nome":"SoloTech Amostragens (exemplo)","cidade":"Rio Verde","uf":"GO","lat":-17.79,"lon":-50.92,"contato":"(64) 0000-0000"}'),
 ('s3','{"nome":"Campo Fértil Serviços (exemplo)","cidade":"Cascavel","uf":"PR","lat":-24.95,"lon":-53.46,"contato":"(45) 0000-0000"}'),
 ('s4','{"nome":"AgroPonto Coletas (exemplo)","cidade":"Balsas","uf":"MA","lat":-7.53,"lon":-46.04,"contato":"(99) 0000-0000"}'),
 ('s5','{"nome":"Cerrado Amostras (exemplo)","cidade":"Luís Eduardo Magalhães","uf":"BA","lat":-12.09,"lon":-45.80,"contato":"(77) 0000-0000"}'),
 ('s6','{"nome":"Terra Norte Amostragem (exemplo)","cidade":"Palmas","uf":"TO","lat":-10.18,"lon":-48.33,"contato":"(63) 0000-0000"}'),
 ('s7','{"nome":"MS Solo (exemplo)","cidade":"Dourados","uf":"MS","lat":-22.22,"lon":-54.81,"contato":"(67) 0000-0000"}'),
 ('s8','{"nome":"Minas Agro Coleta (exemplo)","cidade":"Uberlândia","uf":"MG","lat":-18.92,"lon":-48.28,"contato":"(34) 0000-0000"}')
on conflict (id) do nothing;
insert into public.consultorias(id,data) values
 ('a1','{"nome":"AgroConsult Cerrado (exemplo)","cidade":"Sorriso","uf":"MT","contato":"Marcos Lima","tel":"(66) 0000-0000","email":"","by":"CS"}'),
 ('a2','{"nome":"Plantar 4.0 (exemplo)","cidade":"Goiânia","uf":"GO","contato":"Paula Reis","tel":"(62) 0000-0000","email":"","by":"CS"}'),
 ('a3','{"nome":"Sul Agro Assessoria (exemplo)","cidade":"Cascavel","uf":"PR","contato":"Diego Kunz","tel":"(45) 0000-0000","email":"","by":"CS"}')
on conflict (id) do nothing;

-- ---------- PERMISSÕES DA API (as regras acima decidem o que cada um vê) ----------
grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.clients, public.records, public.consultorias, public.samplers to authenticated;
revoke all on public.profiles, public.clients, public.records, public.consultorias, public.samplers from anon;
