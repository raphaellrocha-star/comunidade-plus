-- ============================================================
-- Comunidade+  |  Esquema multi-igreja para Supabase (Postgres)
-- Cole no Supabase: SQL Editor > New query > Run
-- Cada igreja e um "espaco" isolado. As regras de seguranca (RLS)
-- garantem no proprio banco que uma igreja nunca ve dados de outra.
-- ============================================================

create extension if not exists pgcrypto;

-- ---------- Tabelas ----------
create table public.churches (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null check (slug ~ '^[a-z0-9]{3,30}$'),
  name text not null,
  cnpj text,
  city text,
  pix_key text,
  profile text not null default 'evangelica' check (profile in ('evangelica','catolica','generico')),
  daily_message text,
  join_mode text not null default 'approval' check (join_mode in ('approval','open')),
  plan text not null default 'trial' check (plan in ('trial','essencial','completo','suspenso')),
  created_at timestamptz not null default now()
);

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  email text,
  is_platform_admin boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.memberships (
  id uuid primary key default gen_random_uuid(),
  church_id uuid not null references public.churches(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  role text not null default 'member' check (role in ('admin','treasurer','secretary','leader','member')),
  status text not null default 'pending' check (status in ('pending','active','inactive')),
  ministry text,
  created_at timestamptz not null default now(),
  unique (church_id, user_id)
);

create table public.announcements (
  id uuid primary key default gen_random_uuid(),
  church_id uuid not null references public.churches(id) on delete cascade,
  title text not null,
  body text not null,
  tag text,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);

create table public.events (
  id uuid primary key default gen_random_uuid(),
  church_id uuid not null references public.churches(id) on delete cascade,
  title text not null,
  starts_at timestamptz,
  date_label text,
  location text,
  spots int not null default 100 check (spots > 0),
  created_at timestamptz not null default now()
);

create table public.registrations (
  event_id uuid not null references public.events(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (event_id, user_id)
);

create table public.schedules (
  id uuid primary key default gen_random_uuid(),
  church_id uuid not null references public.churches(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  event_label text not null,
  ministry text not null,
  status text not null default 'pending' check (status in ('pending','confirmed','swap')),
  created_at timestamptz not null default now()
);

create table public.prayers (
  id uuid primary key default gen_random_uuid(),
  church_id uuid not null references public.churches(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  anonymous boolean not null default false,
  is_private boolean not null default false,
  text text not null,
  status text not null default 'new' check (status in ('new','praying','answered')),
  created_at timestamptz not null default now()
);

create table public.prayer_supports (
  prayer_id uuid not null references public.prayers(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  primary key (prayer_id, user_id)
);

create table public.contributions (
  id uuid primary key default gen_random_uuid(),
  church_id uuid not null references public.churches(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  category text not null check (category in ('tithe','offering','missions')),
  amount numeric(12,2) not null check (amount > 0),
  txid text not null,
  status text not null default 'pending_check' check (status in ('pending_check','confirmed')),
  confirmed_by uuid references public.profiles(id),
  confirmed_at timestamptz,
  created_at timestamptz not null default now()
);

create table public.activity_log (
  id bigint generated always as identity primary key,
  church_id uuid not null references public.churches(id) on delete cascade,
  actor_id uuid references public.profiles(id),
  text text not null,
  created_at timestamptz not null default now()
);

create index on public.memberships (user_id);
create index on public.announcements (church_id, created_at desc);
create index on public.events (church_id);
create index on public.schedules (church_id, user_id);
create index on public.prayers (church_id, created_at desc);
create index on public.contributions (church_id, created_at desc);
create index on public.activity_log (church_id, created_at desc);

-- ---------- Funcoes de permissao ----------
create or replace function public.my_role(c uuid) returns text
language sql stable security definer set search_path = public as $$
  select m.role from memberships m join churches ch on ch.id = m.church_id
  where m.church_id = c and m.user_id = auth.uid() and m.status = 'active' and ch.plan <> 'suspenso'
$$;

create or replace function public.is_member(c uuid) returns boolean
language sql stable as $$ select public.my_role(c) is not null $$;

create or replace function public.has_role(c uuid, roles text[]) returns boolean
language sql stable as $$ select coalesce(public.my_role(c) = any(roles), false) $$;

create or replace function public.is_platform_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_platform_admin from profiles where id = auth.uid()), false)
$$;

-- Perfil criado automaticamente no cadastro (Supabase Auth)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, name, email) values (new.id, coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)), new.email);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Criar igreja: quem cria vira admin
create or replace function public.create_church(p_name text, p_slug text, p_profile text, p_cnpj text, p_city text, p_pix_key text)
returns uuid language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if auth.uid() is null then raise exception 'login necessario'; end if;
  insert into churches (name, slug, profile, cnpj, city, pix_key)
  values (p_name, lower(p_slug), coalesce(p_profile, 'evangelica'), p_cnpj, p_city, p_pix_key) returning id into cid;
  insert into memberships (church_id, user_id, role, status) values (cid, auth.uid(), 'admin', 'active');
  insert into activity_log (church_id, actor_id, text) values (cid, auth.uid(), 'Igreja criada no Comunidade+');
  return cid;
end $$;

-- Entrar pelo codigo/link de convite (status depende do modo de entrada da igreja)
create or replace function public.join_church(p_slug text) returns text
language plpgsql security definer set search_path = public as $$
declare ch churches; st text;
begin
  if auth.uid() is null then raise exception 'login necessario'; end if;
  select * into ch from churches where slug = lower(p_slug) and plan <> 'suspenso';
  if not found then raise exception 'igreja nao encontrada'; end if;
  st := case when ch.join_mode = 'open' then 'active' else 'pending' end;
  insert into memberships (church_id, user_id, role, status) values (ch.id, auth.uid(), 'member', st)
  on conflict (church_id, user_id) do nothing;
  insert into activity_log (church_id, actor_id, text)
  values (ch.id, auth.uid(), case when st = 'active' then 'Novo membro entrou pelo link' else 'Novo pedido para entrar na igreja' end);
  return st;
end $$;

-- Tela de convite: mostra so nome e tipo da igreja, sem expor o resto
create or replace function public.church_public_info(p_slug text)
returns table (name text, profile text, join_mode text)
language sql stable security definer set search_path = public as $$
  select name, profile, join_mode from churches where slug = lower(p_slug) and plan <> 'suspenso'
$$;

-- So o admin pode mudar funcoes; a igreja nunca fica sem admin
create or replace function public.guard_membership() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.role <> old.role and not public.has_role(old.church_id, array['admin']) then
    raise exception 'apenas o admin pode alterar funcoes';
  end if;
  if old.role = 'admin' and (new.role <> 'admin' or new.status <> 'active')
     and (select count(*) from memberships where church_id = old.church_id and role = 'admin' and status = 'active') < 2 then
    raise exception 'a igreja precisa de pelo menos um admin';
  end if;
  return new;
end $$;
create trigger membership_guard before update on public.memberships
  for each row execute function public.guard_membership();

-- O fiel so pode mudar o status da propria escala (confirmar / pedir troca)
create or replace function public.guard_schedule() returns trigger
language plpgsql as $$
begin
  if not public.has_role(old.church_id, array['admin','leader'])
     and (new.user_id <> old.user_id or new.event_label <> old.event_label or new.ministry <> old.ministry or new.church_id <> old.church_id) then
    raise exception 'voce so pode confirmar ou pedir troca';
  end if;
  return new;
end $$;
create trigger schedule_guard before update on public.schedules
  for each row execute function public.guard_schedule();

-- Tesouraria registra quem deu baixa no Pix e quando
create or replace function public.stamp_confirmation() returns trigger
language plpgsql as $$
begin
  if new.status = 'confirmed' and old.status <> 'confirmed' then
    new.confirmed_by := auth.uid(); new.confirmed_at := now();
  end if;
  return new;
end $$;
create trigger contribution_stamp before update on public.contributions
  for each row execute function public.stamp_confirmation();

-- Mural de oracao: esconde o autor dos pedidos anonimos
create view public.prayer_wall with (security_invoker = true) as
  select p.id, p.church_id, case when p.anonymous then null else p.user_id end as user_id,
         case when p.anonymous then 'Anonimo' else pr.name end as author,
         p.is_private, p.text, p.status, p.created_at,
         (select count(*) from prayer_supports s where s.prayer_id = p.id) as praying_count
  from prayers p join profiles pr on pr.id = p.user_id;

-- Painel do dono da plataforma: so numeros por igreja (LGPD)
create or replace function public.platform_overview()
returns table (church_id uuid, name text, slug text, city text, profile text, plan text, active_members bigint)
language sql stable security definer set search_path = public as $$
  select c.id, c.name, c.slug, c.city, c.profile, c.plan,
         (select count(*) from memberships m where m.church_id = c.id and m.status = 'active')
  from churches c where public.is_platform_admin()
$$;

-- ---------- RLS: ativar em todas as tabelas ----------
alter table public.churches enable row level security;
alter table public.profiles enable row level security;
alter table public.memberships enable row level security;
alter table public.announcements enable row level security;
alter table public.events enable row level security;
alter table public.registrations enable row level security;
alter table public.schedules enable row level security;
alter table public.prayers enable row level security;
alter table public.prayer_supports enable row level security;
alter table public.contributions enable row level security;
alter table public.activity_log enable row level security;

-- Igrejas
create policy church_read on public.churches for select using (public.is_member(id));
create policy church_update on public.churches for update using (public.has_role(id, array['admin'])) with check (public.has_role(id, array['admin']));
create policy church_platform on public.churches for update using (public.is_platform_admin());

-- Perfis: cada um ve o seu e o de quem esta nas mesmas igrejas
create policy profile_self on public.profiles for select using (id = auth.uid());
create or replace function public.shares_church(other uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from memberships a join memberships b on a.church_id = b.church_id
                 where a.user_id = auth.uid() and a.status = 'active' and b.user_id = other)
$$;
create policy profile_same_church on public.profiles for select using (public.shares_church(id));
create policy profile_update_self on public.profiles for update using (id = auth.uid()) with check (id = auth.uid() and is_platform_admin = false);

-- Membros
create policy membership_read on public.memberships for select using (
  user_id = auth.uid() or public.has_role(church_id, array['admin','secretary','leader','treasurer']));
create policy membership_manage on public.memberships for update using (public.has_role(church_id, array['admin','secretary']));
create policy membership_delete on public.memberships for delete using (public.has_role(church_id, array['admin','secretary']) or user_id = auth.uid());

-- Avisos e eventos
create policy ann_read on public.announcements for select using (public.is_member(church_id));
create policy ann_write on public.announcements for all using (public.has_role(church_id, array['admin','secretary'])) with check (public.has_role(church_id, array['admin','secretary']));
create policy ev_read on public.events for select using (public.is_member(church_id));
create policy ev_write on public.events for all using (public.has_role(church_id, array['admin','secretary'])) with check (public.has_role(church_id, array['admin','secretary']));

-- Inscricoes em eventos
create policy reg_read on public.registrations for select using (
  user_id = auth.uid() or exists (select 1 from events e where e.id = event_id and public.has_role(e.church_id, array['admin','secretary'])));
create policy reg_insert on public.registrations for insert with check (
  user_id = auth.uid() and exists (select 1 from events e where e.id = event_id and public.is_member(e.church_id)));
create policy reg_delete on public.registrations for delete using (user_id = auth.uid());

-- Escalas
create policy sch_read on public.schedules for select using (user_id = auth.uid() or public.has_role(church_id, array['admin','leader']));
create policy sch_write on public.schedules for insert with check (public.has_role(church_id, array['admin','leader']));
create policy sch_delete on public.schedules for delete using (public.has_role(church_id, array['admin','leader']));
create policy sch_update on public.schedules for update using (user_id = auth.uid() or public.has_role(church_id, array['admin','leader']));

-- Oracao: privados so para autor e lideranca
create policy pr_read on public.prayers for select using (
  public.is_member(church_id) and (not is_private or user_id = auth.uid() or public.has_role(church_id, array['admin','leader'])));
create policy pr_insert on public.prayers for insert with check (user_id = auth.uid() and public.is_member(church_id) and status = 'new');
create policy pr_update on public.prayers for update using (public.has_role(church_id, array['admin','leader']));
create policy pr_delete on public.prayers for delete using (user_id = auth.uid() or public.has_role(church_id, array['admin','leader']));
create policy ps_read on public.prayer_supports for select using (
  exists (select 1 from prayers p where p.id = prayer_id and public.is_member(p.church_id)));
create policy ps_insert on public.prayer_supports for insert with check (
  user_id = auth.uid() and exists (select 1 from prayers p where p.id = prayer_id and public.is_member(p.church_id) and not p.is_private));
create policy ps_delete on public.prayer_supports for delete using (user_id = auth.uid());

-- Contribuicoes: o fiel ve as suas; so admin e tesouraria veem todas e dao baixa
create policy k_read on public.contributions for select using (user_id = auth.uid() or public.has_role(church_id, array['admin','treasurer']));
create policy k_insert on public.contributions for insert with check (user_id = auth.uid() and public.is_member(church_id) and status = 'pending_check');
create policy k_update on public.contributions for update using (public.has_role(church_id, array['admin','treasurer']));

-- Log de atividades: so a equipe
create policy log_read on public.activity_log for select using (public.has_role(church_id, array['admin','secretary','leader','treasurer']));
create policy log_insert on public.activity_log for insert with check (public.is_member(church_id) and actor_id = auth.uid());

-- Tempo real: o app atualiza sozinho quando algo muda
alter publication supabase_realtime add table public.announcements, public.events, public.memberships, public.contributions, public.prayers, public.schedules;

-- Vagas: total de inscritos por evento (sem expor quem se inscreveu)
create or replace function public.event_counts(c uuid)
returns table (event_id uuid, total bigint)
language sql stable security definer set search_path = public as $$
  select e.id, count(r.user_id) from events e left join registrations r on r.event_id = e.id
  where e.church_id = c and public.is_member(c) group by e.id
$$;

-- Nome das igrejas do usuario (inclusive quando ainda aguarda aprovacao)
create or replace function public.my_church_names()
returns table (id uuid, name text, slug text)
language sql stable security definer set search_path = public as $$
  select c.id, c.name, c.slug from churches c join memberships m on m.church_id = c.id where m.user_id = auth.uid()
$$;

-- Acesso pela API (as regras RLS acima continuam valendo)
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant usage, select on all sequences in schema public to authenticated;
grant execute on all functions in schema public to authenticated;
revoke execute on all functions in schema public from anon;
grant execute on function public.church_public_info(text) to anon;
