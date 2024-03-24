-- -*- sql-product: postgres; -*-

-- create role anon with nosuperuser inherit nocreaterole nocreatedb nologin noreplication nobypassrls;

-- create role authenticator with nosuperuser noinherit nocreaterole nocreatedb nologin noreplication nobypassrls;

create extension if not exists xml2 with schema public;

create table public.param (
    id integer primary key generated always as identity,
    name text unique,
    val text
);

create or replace view resource as
  select
    oid,
    ((obj_description(oid, 'pg_largeobject'::name))::jsonb ->> 'name') as slug,
    encode(lo_get(oid), 'escape') as content
    from pg_largeobject_metadata
   where true
     and obj_description(oid, 'pg_largeobject'::name)::jsonb->>'content-type' not in ('image/jpeg');

create domain "text/html" as text;

create or replace function index ()
  returns "text/html"
  language sql
  stable parallel safe
as $function$
  select
  xslt_process(
    xmlroot(
      xmlconcat(
        xmlpi(
          name "xml-stylesheet",
          format('href="%s" type="text/xsl"', (select val from public.param where name = 'xml-stylesheet'))),
          xmlelement(
            name index,
            xmlelement(
              name request,
              xmlelement(
                name headers,
                current_setting('request.headers', true)::json
              ),
              xmlelement(
                name claims,
                current_setting('request.jwt.claims', true)::json
              ),
              xmlelement(
                name cookies,
                current_setting('request.cookies', true)::json
              ),
              xmlelement(
                name path,
                current_setting('request.path', true)
              ),
              xmlelement(
                name method,
                current_setting('request.method', true)
              )
            ),
            xmlelement(
              name loginurl,
              current_setting('custom.loginurl', true)
            )
          )
      ),
      version '1.0',
      standalone yes
    )::text,
    content::text
  )
  from resource where slug = 'demo.xsl';
  $function$;

grant select on all tables in schema public to anon;

notify pgrst, 'reload schema';

\lo_import /docker-entrypoint-initdb.d/demo.xsl '{"name": "demo.xsl", "content-type": "application/xslt+xml"}'

do $$
declare
  grant_statement text;
begin
  for grant_statement in select format('grant select on large object %s to anon', oid) from pg_largeobject_metadata loop
    raise notice 'performing grant: %', grant_statement;
    execute grant_statement;
  end loop;
end;
$$;

insert into public.param (name, val) values ('xml-stylesheet', '/resource/demo.xsl');
