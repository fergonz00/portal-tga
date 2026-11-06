-- =============================================================================
-- Registro de ingresos al ecosistema TGA.
--
-- POR QUE: hasta hoy no quedaba rastro de quien entraba. `tasador_usuarios` no
-- tiene fecha de ultimo acceso, `login_tasador` no escribia nada al salir bien,
-- y `login_intentos` guarda SOLO los fallidos (y los borra apenas la persona
-- acierta). Resultado: a "¿como estuvo el acceso esta semana?" no se le podia
-- contestar con datos. Lo pidio Matias el 06/11/2026.
--
-- Se eligio una TABLA y no una columna "ultimo_acceso" porque una columna solo
-- dice "la ultima vez": no deja contar ingresos por dia, ni ver si alguien dejo
-- de entrar, ni distinguir desde donde. Con la tabla, el ultimo acceso sigue
-- saliendo con un max(at), asi que no se pierde nada.
--
-- VOLUMEN: ~36 usuarios y la sesion dura 7 dias, o sea unos pocos ingresos por
-- dia. No necesita limpieza automatica; si alguna vez molesta, un delete por
-- antiguedad alcanza.
-- =============================================================================

create table if not exists public.login_accesos (
  id      bigserial primary key,
  usuario text        not null,
  ip      text,
  at      timestamptz not null default now()
);

create index if not exists login_accesos_usuario_at on public.login_accesos (usuario, at desc);
create index if not exists login_accesos_at         on public.login_accesos (at desc);

-- Igual que login_intentos: la tabla NO se lee ni se escribe con la anon key.
-- Solo entra por dentro de login_tasador, que es SECURITY DEFINER.
alter table public.login_accesos enable row level security;
revoke all on public.login_accesos from anon, authenticated;
revoke all on sequence public.login_accesos_id_seq from anon, authenticated;


-- -----------------------------------------------------------------------------
-- login_tasador: identica a la version anterior salvo el bloque de registro.
-- OJO: si esta funcion se rompe, NADIE entra a NADA (7 apps). El insert va en su
-- PROPIO bloque con exception-when-others: si la tabla no existiera, o faltaran
-- permisos, o lo que sea, el ingreso igual sigue adelante. Registrar no puede
-- ser motivo para que alguien no pueda trabajar.
-- -----------------------------------------------------------------------------
create or replace function public.login_tasador(p_usuario text, p_clave text)
returns table(id uuid, usuario text, nombre text, rol text, roles text[], activo boolean,
              email text, telefono_wa text, callmebot_key text, debe_cambiar_clave boolean,
              notificaciones_wa boolean, session_exp bigint, session_sig text)
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_ip       text;
  v_max      int;
  v_ventana  int;
  v_fallidos int;
  v_ok       boolean;
  v_exp      bigint;
  v_secret   text;
begin
  -- IP real del cliente segun PostgREST. Puede venir vacia (llamada interna).
  begin
    v_ip := nullif(split_part(coalesce(
      current_setting('request.headers', true)::json ->> 'x-forwarded-for', ''), ',', 1), '');
  exception when others then
    v_ip := null;
  end;

  select coalesce((select c.valor::int from public.app_config c where c.clave='login_max_intentos'), 10)
    into v_max;
  select coalesce((select c.valor::int from public.app_config c where c.clave='login_ventana_min'), 15)
    into v_ventana;

  -- Freno por el par (usuario, IP), no por usuario solo: asi un atacante de
  -- afuera no puede dejar afuera a nadie del salon tirandole claves malas, y un
  -- tipeo repetido en el salon no bloquea al resto (comparten IP publica).
  select count(*) into v_fallidos
    from public.login_intentos li
   where li.usuario = p_usuario
     and li.ip is not distinct from v_ip
     and li.at > now() - (v_ventana * interval '1 minute');

  if v_fallidos >= v_max then
    return;  -- sin filas; el front pregunta a login_bloqueado y avisa el motivo
  end if;

  select exists (
    select 1
      from public.tasador_usuarios u
     where u.usuario = p_usuario and u.activo = true
       and exists (select 1 from public.app_credenciales c
                    where c.scope = 'tasador' and c.usuario = u.usuario
                      and c.password_hash = extensions.crypt(p_clave, c.password_hash))
  ) into v_ok;

  if not v_ok then
    insert into public.login_intentos (usuario, ip) values (p_usuario, v_ip);
    return;
  end if;

  delete from public.login_intentos li
   where li.usuario = p_usuario and li.ip is not distinct from v_ip;

  -- Registro del ingreso. En su propio bloque a proposito: que esto falle NO
  -- puede impedir que la persona entre.
  begin
    insert into public.login_accesos (usuario, ip) values (p_usuario, v_ip);
  exception when others then
    null;
  end;

  select c.valor into v_secret from public.app_config c where c.clave='tga_session_secret';
  v_exp := extract(epoch from now())::bigint + 7*24*3600;

  return query
    select u.id, u.usuario, u.nombre, u.rol, u.roles, u.activo, u.email,
           u.telefono_wa, u.callmebot_key, u.debe_cambiar_clave, u.notificaciones_wa,
           v_exp,
           encode(extensions.hmac(u.usuario || '.' || v_exp::text, v_secret, 'sha256'), 'hex')
      from public.tasador_usuarios u
     where u.usuario = p_usuario and u.activo = true;
end;
$function$;


-- -----------------------------------------------------------------------------
-- Para mirarlo despues (ejemplos, no hace falta correrlos):
--
--   -- quien entro y cuando, por persona
--   select a.usuario, u.nombre, max(a.at at time zone 'America/Argentina/Buenos_Aires') as ultimo,
--          count(*) as ingresos
--     from public.login_accesos a
--     left join public.tasador_usuarios u on u.usuario = a.usuario
--    where a.at > now() - interval '30 days'
--    group by a.usuario, u.nombre order by ultimo desc;
--
--   -- quien NO entro nunca / hace mucho (cuentas activas)
--   select u.usuario, u.nombre,
--          (select max(a.at) from public.login_accesos a where a.usuario = u.usuario) as ultimo
--     from public.tasador_usuarios u where u.activo order by ultimo nulls first;
--
--   -- ingresos por dia
--   select (a.at at time zone 'America/Argentina/Buenos_Aires')::date as dia,
--          count(*) as ingresos, count(distinct a.usuario) as personas
--     from public.login_accesos a where a.at > now() - interval '30 days'
--    group by 1 order by 1 desc;
-- -----------------------------------------------------------------------------
