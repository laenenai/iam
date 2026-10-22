-- 00001_init.sql creates only the shared primitives every later `iam`
-- migration depends on: the iam schema itself and the iam.ulid domain
-- every id column uses. No entity tables belong here.
--
-- The schema is `iam`, separate from any consumer's, because this module's
-- tables live in the same Postgres instance as the consumer's own (design
-- §4/A1: "one Postgres instance, with this module's tables in their own
-- schema") and a shared instance with colliding table names is not a
-- deployment option.

-- +goose Up
CREATE SCHEMA IF NOT EXISTS iam;

-- Every id column in every later migration is iam.ulid: a Crockford
-- base32 ULID string of exactly 26 characters, which is what
-- internal/domain's id types encode to. There are no UUIDs anywhere in
-- this system, so the domain's check constraint is what turns a malformed
-- id into a database-level error instead of a silently stored bad value.
--
-- The constraint also means a column of this type cannot hold an id
-- derived from an external subject string, which is the invariant design
-- §8.1 rests on: an internal id is minted, never computed from anything a
-- directory controls.
CREATE DOMAIN iam.ulid AS text
    CHECK (VALUE ~ '^[0-9A-HJKMNP-TV-Z]{26}$');

-- +goose Down
DROP DOMAIN IF EXISTS iam.ulid;

DROP SCHEMA IF EXISTS iam;
