-- -*- sql-product: postgres; -*-

create schema if not exists basic_auth;

create table if not exists
  basic_auth.users (
    email    text primary key check ( email ~* '^.+@.+\..+$' ),
    pass     text not null check (length(pass) < 512),
    role     name not null check (length(role) < 512)
  );

create or replace function basic_auth.check_role_exists () returns trigger as $$
  begin
    if not exists (select 1 from pg_roles as r where r.rolname = new.role) then
      raise foreign_key_violation using message =
      'unknown database role: ' || new.role;
      return null;
    end if;
    return new;
  end
$$ language plpgsql;

drop trigger if exists ensure_user_role_exists on basic_auth.users;

create constraint trigger ensure_user_role_exists
  after insert or update on basic_auth.users
  for each row
  execute procedure basic_auth.check_role_exists();

create extension if not exists pgcrypto;

create or replace function basic_auth.encrypt_pass () returns trigger as $$
  begin
    if tg_op = 'INSERT' or new.pass <> old.pass then
      new.pass = crypt(new.pass, gen_salt('bf'));
    end if;
    return new;
  end
$$ language plpgsql;

drop trigger if exists encrypt_pass on basic_auth.users;

create trigger encrypt_pass
  before insert or update on basic_auth.users
  for each row
  execute procedure basic_auth.encrypt_pass();

create or replace function basic_auth.user_role (email text, pass text) returns name
  language plpgsql
as $$
  begin
    return (
      select role from basic_auth.users
       where users.email = user_role.email
	 and users.pass = crypt(user_role.pass, users.pass)
    );
  end;
$$;

create role anon noinherit;

create role authenticator noinherit;

grant anon to authenticator;

create type jwt_token as (
  token text
);

create or replace function url_encode (data bytea) returns text language sql as $$
  select translate(encode(data, 'base64'), e'+/=\n', '-_');
$$ immutable;

create or replace function url_decode (data text) returns bytea language sql as $$
  with t as (select translate(data, '-_', '+/') as trans),
  rem as (select length(t.trans) % 4 as remainder from t)
  select decode(
    t.trans ||
    case when rem.remainder > 0
    then repeat('=', (4 - rem.remainder))
    else '' end,
    'base64') from t, rem;
$$ immutable;

create or replace function algorithm_sign (signables text, secret text, algorithm text)
  returns text language sql as $$
  with
  alg as (
    select case
	   when algorithm = 'hs256' then 'sha256'
	   when algorithm = 'hs384' then 'sha384'
	   when algorithm = 'hs512' then 'sha512'
	   else '' end as id)
  select url_encode(hmac(signables, secret, alg.id)) from alg;
$$ immutable;

create or replace function sign (payload json, secret text, algorithm text default 'hs256')
  returns text language sql as $$
  with
  header as (
    select url_encode(convert_to('{"alg":"' || algorithm || '","typ":"jwt"}', 'utf8')) as data
  ),
  payload as (
    select url_encode(convert_to(payload::text, 'utf8')) as data
  ),
  signables as (
    select header.data || '.' || payload.data as data from header, payload
  )
  select
  signables.data || '.' ||
  algorithm_sign(signables.data, secret, algorithm) from signables;
$$ immutable;

create or replace function verify (token text, secret text, algorithm text default 'hs256')
  returns table(header json, payload json, valid boolean) language sql as $$
  select
  convert_from(url_decode(r[1]), 'utf8')::json as header,
  convert_from(url_decode(r[2]), 'utf8')::json as payload,
  r[3] = algorithm_sign(r[1] || '.' || r[2], secret, algorithm) as valid
  from regexp_split_to_array(token, '\.') r;
$$ immutable;

create function jwt_test () returns public.jwt_token as $$
  select public.sign(
    row_to_json(r), 'reallyreallyreallyreallyverysafe'
  ) as token
  from (
    select
      'my_role'::text as role,
      extract(epoch from now())::integer + 300 as exp
  ) r;
$$ language sql;

alter database postgres set "app.jwt_secret" to 'reallyreallyreallyreallyverysafe';

create type basic_auth.jwt_token as (
  token text
);

create or replace function login (email text, pass text) returns basic_auth.jwt_token as $$
  declare
    _role name;
    result basic_auth.jwt_token;
  begin
    select basic_auth.user_role(email, pass) into _role;
    if _role is null then
      raise invalid_password using message = 'invalid user or password';
    end if;
    select sign(
      row_to_json(r), current_setting('app.jwt_secret')
    ) as token
      from (
	select _role as role, login.email as email,
               extract(epoch from now())::integer + 60*60 as exp
      ) r
      into result;
    return result;
  end;
$$ language plpgsql security definer;

grant execute on function login(text,text) to anon;
