-- ============================================================================
-- ARREGLO: cambiar_clave buscaba columnas que ya no existen
-- 14-10-2026
-- ============================================================================
-- Sintoma: al entrar al portal, a quien le toca el cambio de clave obligatorio
-- le aparece "Error al guardar: column u.password_hash does not exist" (42703)
-- y no puede entrar. Lo reporto Gisela Buena, pero habia 24 usuarios activos
-- con debe_cambiar_clave = true, o sea 24 personas trabadas.
--
-- Causa: el 01-10-2026, cuando las claves se movieron a `app_credenciales`, se
-- dropearon `tasador_usuarios.password_hash` y `.clave`. Se reescribio
-- `login_tasador` pero NO `cambiar_clave`, que seguia teniendo una rama de
-- compatibilidad mirando esas dos columnas. Postgres planifica la consulta
-- entera al ejecutarla, asi que la funcion fallaba SIEMPRE, incluso para quien
-- ya tenia su credencial migrada: nunca llegaba a evaluar la rama buena.
--
-- Es el mismo patron que ya nos mordio al sacar `clave` del login: cambiar
-- donde vive un dato obliga a revisar TODOS los que lo leen, no solo el
-- principal.
--
-- Revisadas las 13 funciones que nombran tasador_usuarios: esta era la unica
-- que quedaba rota.
-- ============================================================================

create or replace function public.cambiar_clave(
  p_usuario text, p_clave_actual text, p_clave_nueva text)
 returns text
 language plpgsql
 security definer
 set search_path to ''
as $fn$
declare v_ok boolean; v_hash text; v_u text := lower(p_usuario);
begin
  -- La clave vive SOLO en app_credenciales. No hay fallback: las columnas
  -- viejas de tasador_usuarios no existen mas.
  select exists (
    select 1
      from public.app_credenciales c
      join public.tasador_usuarios u
        on u.usuario = c.usuario and u.activo
     where c.scope = 'tasador'
       and c.usuario = v_u
       and c.password_hash = extensions.crypt(p_clave_actual, c.password_hash)
  ) into v_ok;

  if not v_ok then
    raise exception 'La clave actual es incorrecta';
  end if;

  v_hash := extensions.crypt(p_clave_nueva, extensions.gen_salt('bf', 10));
  insert into public.app_credenciales(scope, usuario, password_hash)
    values ('tasador', v_u, v_hash)
    on conflict (scope, usuario)
      do update set password_hash = excluded.password_hash, updated_at = now();

  update public.tasador_usuarios set debe_cambiar_clave = false where usuario = v_u;
  return 'ok';
end;
$fn$;

grant execute on function public.cambiar_clave(text, text, text) to anon, authenticated;
