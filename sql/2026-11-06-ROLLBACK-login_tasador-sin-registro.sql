CREATE OR REPLACE FUNCTION public.login_tasador(p_usuario text, p_clave text)
 RETURNS TABLE(id uuid, usuario text, nombre text, rol text, roles text[], activo boolean, email text, telefono_wa text, callmebot_key text, debe_cambiar_clave boolean, notificaciones_wa boolean, session_exp bigint, session_sig text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
$function$
;
