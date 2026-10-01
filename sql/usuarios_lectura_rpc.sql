-- ============================================================================
-- RPCs de LECTURA de tasador_usuarios (01-oct-2026)
-- ============================================================================
-- Problema que cierran: la llave `anon` (que esta escrita en el HTML de todas
-- las apps del ecosistema) tenia SELECT sobre 11 de las 12 columnas de
-- `tasador_usuarios`. Cualquiera que copiara la llave del navegador se bajaba
-- el directorio completo del personal: nombre, usuario, email, telefono de
-- WhatsApp y rol de las 30 cuentas. No hay credenciales ahi (viven en
-- `app_credenciales`), pero alcanza para armar un phishing dirigido.
--
-- El portal ya movio su panel de usuarios a RPCs firmadas (listar_usuarios,
-- alta_usuario, editar_usuario, resetear_clave, set_activo_usuario,
-- eliminar_usuario), todas gateadas por `es_superadmin_firmado`. Lo que
-- faltaba eran las lecturas NO administrativas que hacen tasador-tga,
-- consulta-0km y contenido-tga: los selectores de vendedor, el refresco de la
-- propia sesion y la busqueda del mail del vendedor. Para esas tres cosas no
-- sirve `listar_usuarios` (es superadmin-only y devuelve la tabla entera), asi
-- que van estas tres funciones, cada una con el minimo de datos posible.
--
-- Todas verifican la MISMA firma que emite `login_tasador`:
--   session_sig = hmac_sha256(lower(usuario) || '.' || session_exp, secret)
-- con el secreto en app_config.tga_session_secret. El navegador ya guarda esos
-- tres valores despues del login (localStorage + cookie tga_session), asi que
-- no hace falta volver a pedir la clave.
--
-- Una vez migrados los paneles se revoca el grant (ver REVOKE al pie).
-- ============================================================================


-- ---------------------------------------------------------------------------
-- 1) Helper: la firma es valida y pertenece a un usuario activo.
--    Es `es_superadmin_firmado` sin la lista de superadmins.
-- ---------------------------------------------------------------------------
create or replace function public.sesion_firmada_valida(p_actor text, p_exp bigint, p_sig text)
 returns boolean
 language sql
 security definer
 set search_path to ''
as $fn$
  select
    p_actor is not null and p_sig is not null and p_exp is not null
    and p_exp >= extract(epoch from now())::bigint
    and p_sig = encode(extensions.hmac(lower(p_actor) || '.' || p_exp::text,
        (select valor from public.app_config where clave='tga_session_secret'), 'sha256'), 'hex')
    and exists (select 1 from public.tasador_usuarios where usuario = lower(p_actor) and activo);
$fn$;


-- ---------------------------------------------------------------------------
-- 2) directorio_vendedores - para los selectores "elegi el vendedor".
--    Lo usan tasador-tga (tasacion presencial cargada por admin/Fazzini) y
--    consulta-0km (wizard del gerente). Devuelve SOLO los activos con rol
--    vendedor, y SOLO id/usuario/nombre/rol/roles: nada de email, telefono ni
--    callmebot_key. El filtro replica exactamente el que hacia el navegador
--    (roles si tiene, si no el rol suelto).
-- ---------------------------------------------------------------------------
create or replace function public.directorio_vendedores(p_actor text, p_actor_exp bigint, p_actor_sig text)
 returns table(id uuid, usuario text, nombre text, rol text, roles text[], activo boolean)
 language plpgsql
 security definer
 set search_path to ''
as $fn$
begin
  if not public.sesion_firmada_valida(p_actor, p_actor_exp, p_actor_sig) then
    raise exception 'no autorizado';
  end if;
  return query
    select u.id, u.usuario, u.nombre, u.rol, u.roles, u.activo
      from public.tasador_usuarios u
     where u.activo
       and 'vendedor' = any(
             case when u.roles is not null and array_length(u.roles, 1) > 0
                  then u.roles
                  else array[u.rol] end)
     order by u.nombre asc;
end;
$fn$;


-- ---------------------------------------------------------------------------
-- 3) mi_usuario - refrescar la propia fila al restaurar la sesion.
--    Lo usan consulta-0km (init) y contenido-tga (arrancar). Sin p_id devuelve
--    la fila del dueno de la firma. Con p_id solo la deja pasar si el firmante
--    es superadmin: ese es el caso de la impersonacion, donde la firma es del
--    operador real y la fila pedida es la del usuario impersonado.
--    No devuelve callmebot_key.
-- ---------------------------------------------------------------------------
create or replace function public.mi_usuario(
  p_actor text, p_actor_exp bigint, p_actor_sig text, p_id uuid default null)
 returns table(id uuid, usuario text, nombre text, rol text, roles text[], activo boolean,
               email text, telefono_wa text, debe_cambiar_clave boolean, notificaciones_wa boolean)
 language plpgsql
 security definer
 set search_path to ''
as $fn$
declare v_propio uuid;
begin
  if not public.sesion_firmada_valida(p_actor, p_actor_exp, p_actor_sig) then
    raise exception 'no autorizado';
  end if;
  select u.id into v_propio from public.tasador_usuarios u where u.usuario = lower(p_actor);
  if p_id is not null and p_id <> v_propio
     and not public.es_superadmin_firmado(p_actor, p_actor_exp, p_actor_sig) then
    raise exception 'no autorizado';
  end if;
  return query
    select u.id, u.usuario, u.nombre, u.rol, u.roles, u.activo,
           u.email, u.telefono_wa, u.debe_cambiar_clave, u.notificaciones_wa
      from public.tasador_usuarios u
     where u.id = coalesce(p_id, v_propio)
       and u.activo;
end;
$fn$;


-- ---------------------------------------------------------------------------
-- 4) email_de_usuario - una sola fila, para mandarle el mail de cierre de
--    tasacion al vendedor (tasador-tga, enviarMailVendedor). Cualquier sesion
--    valida puede pedirlo, pero de a uno y por id: no se puede barrer la
--    tabla. Devuelve usuario + email y nada mas.
-- ---------------------------------------------------------------------------
create or replace function public.email_de_usuario(
  p_actor text, p_actor_exp bigint, p_actor_sig text, p_id uuid)
 returns table(usuario text, email text)
 language plpgsql
 security definer
 set search_path to ''
as $fn$
begin
  if not public.sesion_firmada_valida(p_actor, p_actor_exp, p_actor_sig) then
    raise exception 'no autorizado';
  end if;
  return query
    select u.usuario, u.email
      from public.tasador_usuarios u
     where u.id = p_id and u.activo;
end;
$fn$;


grant execute on function public.sesion_firmada_valida(text, bigint, text) to anon, authenticated;
grant execute on function public.directorio_vendedores(text, bigint, text) to anon, authenticated;
grant execute on function public.mi_usuario(text, bigint, text, uuid) to anon, authenticated;
grant execute on function public.email_de_usuario(text, bigint, text, uuid) to anon, authenticated;


-- ============================================================================
-- REVOKE - correr SOLO despues de verificar los paneles migrados en produccion
-- ============================================================================
-- revoke select on public.tasador_usuarios from anon, authenticated;
--
-- Para volver atras si algo quedo colgado (deja la tabla como estaba el
-- 01-oct-2026: todo menos callmebot_key):
-- grant select (id, usuario, nombre, email, telefono_wa, roles, rol, activo,
--               created_at, debe_cambiar_clave, notificaciones_wa)
--   on public.tasador_usuarios to anon, authenticated;
