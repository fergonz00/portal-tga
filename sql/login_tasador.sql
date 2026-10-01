-- =============================================================================
-- login_tasador - login de TODO el ecosistema TGA (portal, tasador, consulta-0km,
-- postventa, envios, contenido, formularios, gestion y 2 edge functions: 11
-- archivos en 9 apps). Si esta funcion se rompe, NADIE entra a NADA.
--
-- 01/10/2026: se le agrego freno de fuerza bruta. Antes se podia llamar sin
-- limite con la anon key (que esta a la vista en el HTML del portal), y como
-- `tasador_usuarios.usuario` tambien es legible con esa llave, se podian
-- enumerar los usuarios y despues probarles claves sin tope.
--
-- El freno cuenta por el par (usuario, IP), NO por usuario solo:
--   * un atacante de afuera no puede dejar afuera a nadie del salon
--     tirandole claves malas, porque su IP es otra;
--   * y un tipeo repetido desde el salon no bloquea al resto, aunque
--     compartan la IP publica.
-- Al bloquear devuelve CERO FILAS, que es lo mismo que una clave incorrecta:
-- las 9 apps ya lo muestran como "usuario o contrasena incorrectos" sin tocar
-- una linea de su codigo.
--
-- Se ajusta por SQL, sin deploy:
--   update app_config set valor='10' where clave='login_max_intentos';
--   update app_config set valor='15' where clave='login_ventana_min';
--
-- Tabla de apoyo (ya creada):
--   create table public.login_intentos (
--     id bigserial primary key, usuario text not null, ip text,
--     at timestamptz not null default now());
--   create index login_intentos_lookup on public.login_intentos (usuario, ip, at desc);
--   alter table public.login_intentos enable row level security;
--   revoke all on public.login_intentos from anon, authenticated;
--
-- VERIFICADO el 01/10 contra produccion llamando al RPC con la anon key:
--   clave correcta -> 1 fila | 10 fallidos -> bloquea aunque la clave sea correcta
--   otro usuario desde la MISMA IP -> entra igual | pasada la ventana -> entra
--   login real (cgonzalez) -> sesion completa con firma HMAC y 7 dias
-- =============================================================================

create or replace function public.login_tasador(p_usuario text, p_clave text)
returns table(id uuid, usuario text, nombre text, rol text, roles text[], activo boolean,
              email text, telefono_wa text, callmebot_key text, debe_cambiar_clave boolean,
              notificaciones_wa boolean, session_exp bigint, session_sig text)
language plpgsql
security definer
set search_path to ''
as $fn$
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
    return;  -- sin filas: las apps ya lo muestran como usuario o clave incorrectos
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
$fn$;

-- =============================================================================
-- REVERT: si algo sale mal, correr esto y el login vuelve al comportamiento
-- anterior (sin freno). No hace falta deploy de ninguna app.
-- =============================================================================
/*
CREATE OR REPLACE FUNCTION public.login_tasador(p_usuario text, p_clave text)
 RETURNS TABLE(id uuid, usuario text, nombre text, rol text, roles text[], activo boolean, email text, telefono_wa text, callmebot_key text, debe_cambiar_clave boolean, notificaciones_wa boolean, session_exp bigint, session_sig text)
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  with cfg as (select valor as secret from public.app_config where clave='tga_session_secret'),
       ex  as (select (extract(epoch from now())::bigint + 7*24*3600) as e)
  select u.id, u.usuario, u.nombre, u.rol, u.roles, u.activo, u.email,
         u.telefono_wa, u.callmebot_key, u.debe_cambiar_clave, u.notificaciones_wa,
         ex.e,
         encode(extensions.hmac(u.usuario || '.' || ex.e::text, cfg.secret, 'sha256'), 'hex')
  from public.tasador_usuarios u cross join cfg cross join ex
  where u.usuario = p_usuario and u.activo = true
    and exists (select 1 from public.app_credenciales c
                where c.scope='tasador' and c.usuario = u.usuario
                  and c.password_hash = extensions.crypt(p_clave, c.password_hash));
$function$
*/
