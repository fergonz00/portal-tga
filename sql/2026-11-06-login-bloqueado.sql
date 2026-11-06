-- =============================================================================
-- login_bloqueado - dice si el que esta intentando entrar quedo frenado por el
-- tope de intentos fallidos, y cuantos minutos le faltan.
--
-- POR QUE: el freno de fuerza bruta de login_tasador (ver login_tasador.sql)
-- devuelve CERO FILAS al bloquear, que es exactamente lo mismo que devuelve una
-- clave incorrecta. Era deliberado -- no habia que tocar ninguna app --, pero en
-- la practica confunde: la persona tiene la clave BIEN y la pantalla le dice
-- "usuario o contrasena incorrectos", asi que la cambia, reintenta y se hunde
-- mas. Le paso a tbandiera el 19/10/2026 (llego a 10 intentos desde dos
-- conexiones distintas). Lo pidio Matias el 06/11/2026.
--
-- COMO: esta funcion es SOLO DE LECTURA y no toca login_tasador, asi que el
-- camino de entrar no cambia en nada. Las apps la llaman UNICAMENTE cuando el
-- login ya devolvio cero filas, para elegir que mensaje mostrar.
--
-- NO FILTRA NADA: cuenta los fallidos del par (usuario, IP DEL QUE LLAMA), igual
-- que el freno. Preguntar por un usuario ajeno desde otra conexion devuelve
-- siempre "no bloqueado", exista ese usuario o no, asi que no sirve para
-- enumerar cuentas. Y a quien si esta frenado no se le revela nada que no sepa:
-- es el que acaba de fallar los intentos.
--
-- Se ajusta por los mismos parametros, sin deploy:
--   update app_config set valor='10' where clave='login_max_intentos';
--   update app_config set valor='15' where clave='login_ventana_min';
-- =============================================================================

create or replace function public.login_bloqueado(p_usuario text)
returns table(bloqueado boolean, minutos int)
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_ip      text;
  v_max     int;
  v_ventana int;
  v_corte   timestamptz;
begin
  -- IP real del cliente segun PostgREST, idem login_tasador.
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

  -- login_tasador frena cuando hay v_max o mas fallidos dentro de la ventana.
  -- Entonces el freno se levanta cuando el intento numero v_max (contando del
  -- mas nuevo al mas viejo) termina de salir de la ventana: ese es el corte.
  -- Si ese intento no existe, es que hay menos de v_max y no esta frenado.
  select li.at into v_corte
    from public.login_intentos li
   where li.usuario = p_usuario
     and li.ip is not distinct from v_ip
     and li.at > now() - (v_ventana * interval '1 minute')
   order by li.at desc
   offset (v_max - 1) limit 1;

  if v_corte is null then
    return query select false, 0;
    return;
  end if;

  -- Redondeado para arriba y con piso de 1: decirle "esperá 0 minutos" a alguien
  -- que todavia esta frenado lo manda a reintentar y a sumar otro fallido.
  return query select true, greatest(1, ceil(
    extract(epoch from (v_corte + (v_ventana * interval '1 minute')) - now()) / 60.0)::int);
end;
$function$;

-- Mismos permisos que login_tasador: la pantalla de login no esta autenticada,
-- asi que la llama con la anon key. Fuera de PUBLIC, como el resto.
revoke all on function public.login_bloqueado(text) from public;
grant execute on function public.login_bloqueado(text) to anon, authenticated, service_role;
