// Package postgres implements the pinned Salt postgres execution surface.
//
// R9.2b registers postgres.version, the psql-backed server version probe
// from salt/modules/postgres.py:309-332. R9.2c adds the five read-only
// catalog primitives db_list, db_exists, tablespace_list,
// tablespace_exists, and user_list (postgres.py:530-598, 768-837,
// 986-1101) on the internal COPY-to-CSV query transport ported from the
// pinned psql_query (postgres.py:433-524). R9.2d adds the eight read-only
// extension and language catalog functions available_extensions,
// installed_extensions, get_available_extension, get_installed_extension,
// is_available_extension, is_installed_extension, language_list, and
// language_exists (postgres.py:1654-1846, 2602-2695) on the same transport.
// R9.2e adds the three read-only schema catalog functions schema_exists,
// schema_get, and schema_list (postgres.py:2444-2599), keeping the pinned
// schema-family connection signature (dbname plus the db_* tuple with user
// as the system-user argument) and matching every schema name client-side.
// R9.2f adds the three read-only role and privilege checks role_get,
// user_exists, and has_privileges (postgres.py:1104-1170, 3574-3711):
// role_get/user_exists reuse the pinned user_list catalog, and
// has_privileges keeps the pinned owner and ACL catalogs, filters, and
// orderings as fixed queries whose pinned interpolated equality literals
// are matched client-side, so no caller string reaches SQL. R9.2g exposes
// the read-only ACL listing privileges_list (postgres.py:3335-3432) on the
// same R9.2f privilege catalogs: the pinned argument contract is the
// object name and type (no role, no privileges argument), and the pinned
// ACL decode ladder returns each grantee's privilege bool-map (or each
// group member's admin_option boolean). R9.2h adds the family's first
// write paths, db_create and db_remove (postgres.py:601-607, 610-673,
// 727-762): db_create builds the pinned CREATE DATABASE statement with the
// pinned _quote_ddl_value quoting in the pinned option order and returns
// the retcode boolean, and db_remove runs the pinned three-statement
// REVOKE, backend-termination, and DROP sequence with its first-nonzero
// abort. The identifier positions the pinned source interpolates raw —
// the database name and the unquoted TEMPLATE option — are validated
// fail-closed, so no caller string can alter either fixed statement, and
// every such rejection is value-free: the error names only the fixed
// argument key under the shared invalid-argument category, so a rejected
// value carrying a caller secret cannot leak through the CLI exit path
// where it is raised (before any Runner invocation, and therefore before
// any Command.Redact or redactedError pass runs).
// R9.2i adds the role mutation family user_create, user_update, and
// user_remove (postgres.py:1368-1431, 1487-1610, 1613-1651, 2066-2092
// through the pinned _role_create/_role_update/_role_remove flow and the
// pinned _role_cmd_args/_add_role_flag clause machine): create and update
// build the pinned CREATE/ALTER ROLE statements with the pinned INHERIT,
// CREATEDB, CREATEROLE, SUPERUSER, REPLICATION, LOGIN, CONNECTION LIMIT,
// ENCRYPTED, PASSWORD, VALID UNTIL clause order, the pinned user-typed
// inherit/login defaults on create (and their pinned absence on update),
// the pinned superuser skip when the stored role already carries the
// requested boolean, and the pinned md5, plaintext, and SCRAM-SHA-256
// password verifiers (the exact pinned SCRAM-SHA-256$iterations:salt$
// stored:server rendering) with quote doubling; remove keeps the pinned
// preflight, DROP ROLE, and post-check flow with the DROP retcode
// ignored. The role name and every GRANT group entry are the identifier
// positions the pinned source interpolates raw; they are validated
// fail-closed with value-free errors, and the plaintext rolepassword,
// its quote-doubled form, and the generated md5/SCRAM verifier actually
// placed in the SQL (plus that verifier's quote-escaped literal) are all
// Redact secrets that never appear in a rendered command, captured
// output, or returned error.
// R9.2j adds the group mutation family group_create, group_update, and
// group_remove (postgres.py:2098-2225 through the same
// _role_create/_role_update/_role_remove flow with typ_="group"): the
// pinned group signatures carry neither connlimit nor valid_until, create
// applies the pinned group-typed INHERIT NOLOGIN defaults (update applies
// none, exactly like the user family), and the identifier rejection names
// the groupname argument key for the group family.
// R9.2k adds the privilege mutations privileges_grant and
// privileges_revoke (postgres.py:4009-4297 through the shared
// _mod_priv_opts/_validate_privileges head and the has_privileges
// preflight): the pinned preflight runs without grant_option so the
// membership/subset check decides the no-op — an already-granted grant and
// a not-yet-held revoke return False without any mutation statement — and
// the statements keep the pinned quoting exactly (the schema-qualified
// double-quoted on-part for table/sequence/function, the ALL
// TABLES/SEQUENCES/FUNCTIONS IN SCHEMA variants, the raw group
// membership forms with WITH ADMIN OPTION on the grant side, WITH GRANT
// OPTION on the object side, and the pinned raw role name of the REVOKE
// tail). The identifier positions the pinned format strings interpolate
// raw or quote without escaping — the role name, the object name, and
// the schema prefix — are validated fail-closed with value-free errors
// before any Runner invocation: quoted positions may not carry the
// double quote, and raw positions (the revoke role name, the group name,
// and every schema prefix) must be bare PostgreSQL identifiers.
// R9.2l adds the default-privilege family default_privileges_list,
// default_privileges_grant, and default_privileges_revoke
// (postgres.py:3238-3332, 3435-3571, 3714-3877, 3880-4006 through the
// pinned _make_default_privileges_list_query pg_default_acl catalogs and
// the _mod_defpriv_opts/_validate_default_privileges head): the list keeps
// the pinned pg_default_acl/pg_namespace/pg_auth_members catalogs with the
// pinned defaclobjtype filters and orderings as fixed queries whose
// interpolated nspname/rolname equalities move client-side, the mutations
// keep the pinned ALTER DEFAULT PRIVILEGES statement construction exactly
// (including the pinned asymmetry where the grant_option non-ALL branch
// interpolates the on-part into IN SCHEMA while every other branch uses
// the bare schema prefix, and the pinned revoke's computed-but-unused
// on-part), and the has_default_privileges preflight the pinned mutations
// issue without their own grant_option decides the logged-and-False no-op.
// The pinned has_default_privileges ALL comparison evaluates
// list.sort() == dict.keys().sort(), which Python rejects with
// AttributeError before any boolean, so that branch is a fixed value-free
// execution error here. The identifier positions the pinned format
// strings interpolate raw or quote without escaping — the grantee role
// name, the group name, the schema prefix, and the on-part object
// positions of the grant_option branch — are validated fail-closed with
// value-free errors before any Runner invocation.
// R9.2m adds the schema, extension, and language mutation families
// schema_create and schema_remove (postgres.py:2316-2366, 2369-2441),
// create_extension and drop_extension (postgres.py:1895-1962, 1965-2063
// through the pinned create_metadata lifecycle flags), and
// language_create and language_remove (postgres.py:2698-2750, 2753-2805):
// the pinned CREATE/DROP SCHEMA, CREATE/ALTER/DROP EXTENSION, and
// CREATE/DROP LANGUAGE statements with the pinned existence preflights,
// post-checks, retcode booleans, and no-op semantics, including the
// pinned schema_remove preflight that drops the system-user argument and
// the pinned language preflights that drop every connection argument but
// the maintenance database. The identifier positions the pinned format
// strings interpolate raw or double-quote without escaping — the schema
// name and owner, the extension name and schema, the raw extension name
// of DROP EXTENSION, the raw ext_version/from_version tokens, and the raw
// language name — are validated fail-closed with value-free errors
// before any Runner invocation; create_metadata itself stays pending
// exactly like a later name and exists only as the internal lifecycle
// helper create_extension consumes.
// R9.2n adds the database mutation db_alter (postgres.py:676-724): the
// pinned any((tablespace, owner)) head (a no-op True with no Runner
// invocation when neither carries a truthy value), then the pinned
// statement sequence — ALTER DATABASE "name" OWNER TO "owner" before
// ALTER DATABASE "name" SET TABLESPACE "tablespace" — each through the
// central maintenance-database connection. The pinned owner+owner_recurse
// branch delegates to owner_to, which stays pending, so that branch is a
// deterministic value-free UnsupportedError raised before any mutation
// rather than a silent shallow ALTER OWNER; the port also checks every
// statement's retcode instead of only the pinned loop's last-overwritten
// ret, stopping at the first failure with the pinned False. The three
// double-quoted identifier positions the pinned format strings interpolate
// unescaped are validated fail-closed with the shared value-free
// rejections before any Runner invocation.
// R9.2o adds the tablespace mutation family tablespace_create,
// tablespace_alter, and tablespace_remove (postgres.py:840-886, 889-947,
// 950-980): tablespace_create builds the pinned CREATE TABLESPACE
// statement (the truthy OWNER clause, the LOCATION literal, and the
// pinned WITH ( k = v, ... ) options join) and answers the pinned retcode
// boolean; tablespace_alter keeps the pinned any([...]) no-op head, the
// pinned RENAME/OWNER TO/SET/RESET clause order, and the pinned
// first-nonzero False abort; tablespace_remove runs the pinned single
// DROP TABLESPACE statement with the pinned retcode boolean and, exactly
// like the pinned source, no existence preflight. The identifier and
// literal positions the pinned format strings interpolate raw — the
// tablespace name, the owner, the new names, the option tokens, and the
// LOCATION path (whose single-quoted literal the pinned source never
// escapes) — are validated fail-closed with value-free errors before any
// Runner invocation, and the LOCATION boundary additionally requires an
// absolute, clean, control-free path so no traversal or escape can reach
// the fixed statement.
// R9.2q registers the read-only default-privilege check
// has_default_privileges (postgres.py:3435-3571) on the exact internal
// decision core the R9.2l mutations already run as their preflight: the
// pinned (name, object_name, object_type, defprivileges, grant_option,
// prepend="public", maintenance_db, user, host, port, password, runas)
// signature, the shared _mod_defpriv_opts/_validate_default_privileges
// head, the owner shortcut, the default-ACL decode, and the pinned group
// admin_option, grant-option dict-equality, ALL, and strict-subset
// comparisons. The caller's own grant_option reaches the check here —
// unlike the mutation preflights, which always drop theirs — and the
// pinned ALL dict_keys.sort() AttributeError stays the fixed value-free
// execution error of the R9.2l port. The fixed owner and pg_default_acl
// catalogs remain the only SQL with every lookup matched client-side,
// so like has_privileges this read-only path needs no identifier
// boundary: no caller string can reach a statement.
// Like Salt, every invocation is a shell-free psql argv executed through
// the central Runner; this package links no database driver or protocol
// client and never contacts a live server by itself. The catalog queries
// are fixed SQL fragments — no caller-controlled SQL or identifier is
// interpolated — and the R9.2h write paths construct only the pinned
// CREATE DATABASE and REVOKE/terminate/DROP statements, the R9.2n path
// only the pinned ALTER DATABASE OWNER/TABLESPACE statements, the R9.2o
// paths only the pinned CREATE/ALTER/DROP TABLESPACE statements, and the
// R9.2i role paths construct only the pinned CREATE/ALTER/DROP ROLE and
// GRANT statements with the same validated identifiers, so the generic
// psql_query surface stays
// pending for a later round. The pinned module's private helpers (_run_psql 179-235,
// _parsed_version 334-361, _psql_cmd 386-432, psql_query's CSV parse,
// _role_cmd_args 1271-1365, _add_role_flag 1173-1184,
// _maybe_encrypt_password 1187-1206, _md5_password 1242-1247,
// _scram_sha_256 1250-1268)
// are ported as internal functions without public registration.
package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	// psqlCommand is the canonical client binary. Salt resolves it through
	// _find_pg_binary (PATH plus the postgres.bins_dir config option);
	// StateKit has no module config surface, so resolution stays with the
	// Runner's PATH discovery and fails closed when psql is absent.
	psqlCommand = "psql"
	// initdbCommand is the pinned datadir_init executable (_find_pg_binary
	// ("initdb"), postgres.py:260-262); like psql it resolves through the
	// Runner's PATH discovery only and fails closed when absent.
	initdbCommand = "initdb"
	// commandTimeout bounds every psql execution. Salt's postgres.timeout
	// option defaults to 0 (unbounded); StateKit keeps a finite ceiling as
	// a resource control, matching the R9.1 rabbitmq CLI bound.
	commandTimeout = 30 * time.Second
	// outputLimit bounds captured stdout and stderr independently.
	outputLimit = 4 << 20
	// defaultMaintenanceDB mirrors the pinned _psql_cmd fallback when no
	// maintenance database is configured or supplied.
	defaultMaintenanceDB = "postgres"
	// defaultPasswordsEncryption ports the pinned
	// _DEFAULT_PASSWORDS_ENCRYPTION (postgres.py:74): the md5 verifier Salt
	// applies when the encrypted argument is omitted.
	defaultPasswordsEncryption = "md5"
	// scramIterations and scramSaltLen are the pinned _scram_sha_256
	// verifier parameters (postgres.py:1250-1268).
	scramIterations = 4096
	scramSaltLen    = 16
	// serverVersionQuery is the exact SQL of the pinned version().
	serverVersionQuery = "SELECT setting FROM pg_catalog.pg_settings WHERE name = 'server_version'"
	// dbListQuery is the exact SQL of the pinned db_list()
	// (postgres.py:545-552): the Name-keyed catalog join over pg_database,
	// pg_roles, and pg_tablespace.
	dbListQuery = `SELECT datname as "Name", pga.rolname as "Owner", ` +
		`pg_encoding_to_char(encoding) as "Encoding", ` +
		`datcollate as "Collate", datctype as "Ctype", ` +
		`datacl as "Access privileges", spcname as "Tablespace" ` +
		`FROM pg_database pgd, pg_roles pga, pg_tablespace pgts ` +
		`WHERE pga.oid = pgd.datdba AND pgts.oid = pgd.dattablespace`
	// tablespaceListQuery is the exact SQL of the pinned tablespace_list()
	// (postgres.py:785-789).
	tablespaceListQuery = `SELECT spcname as "Name", pga.rolname as "Owner", spcacl as "ACL", ` +
		`spcoptions as "Opts", pg_tablespace_location(pgts.oid) as "Location" ` +
		`FROM pg_tablespace pgts, pg_roles pga WHERE pga.oid = pgts.spcowner`
	// userListQueryPrefix is the fixed head of the pinned user_list() query
	// (postgres.py:1034-1051) before the two version-dependent columns are
	// substituted for {0} (rolcatupdate) and {1} (rolreplication).
	userListQueryPrefix = `SELECT pg_roles.rolname as "name",pg_roles.rolsuper as "superuser",` +
		` pg_roles.rolinherit as "inherits privileges", pg_roles.rolcreaterole as` +
		` "can create roles", pg_roles.rolcreatedb as "can create databases", {0}` +
		` as "can update system catalogs", pg_roles.rolcanlogin as "can login", {1}` +
		` as "replication", pg_roles.rolconnlimit as "connections", (SELECT` +
		` array_agg(pg_roles2.rolname)    FROM pg_catalog.pg_auth_members    JOIN` +
		` pg_catalog.pg_roles pg_roles2 ON (pg_auth_members.roleid = pg_roles2.oid)` +
		`    WHERE pg_auth_members.member = pg_roles.oid) as` +
		` "groups",pg_roles.rolvaliduntil::timestamp(0) as "expiry time",` +
		` pg_roles.rolconfig  as "defaults variables" `
	// userListPasswordSelect/Joins are appended verbatim when Salt's
	// return_password=True sets the _x() segments (postgres.py:1030-1050).
	userListPasswordSelect = `, COALESCE(pg_shadow.passwd, pg_authid.rolpassword) as "password" `
	userListAuthidJoin     = `LEFT JOIN pg_authid ON pg_roles.oid = pg_authid.oid `
	userListShadowJoin     = `LEFT JOIN pg_shadow ON pg_roles.oid = pg_shadow.usesysid`
	// userFromClause is the pinned FROM segment closing the user_list query.
	userFromClause = `FROM pg_roles `
	// availableExtensionsQuery is the exact SQL of the pinned
	// available_extensions() (postgres.py:1668).
	availableExtensionsQuery = "select * from pg_available_extensions();"
	// installedExtensionsQuery is the exact SQL of the pinned
	// installed_extensions() (postgres.py:1699-1702), byte-for-byte
	// including the pinned double space after "pg_extension a,".
	installedExtensionsQuery = "select a.*, b.nspname as schema_name " +
		"from pg_extension a,  pg_namespace b where a.extnamespace = b.oid;"
	// languageListQuery is the exact SQL of the pinned language_list()
	// (postgres.py:2636).
	languageListQuery = `SELECT lanname AS "Name" FROM pg_language`
	// schemaListQuery is the exact SQL of the pinned schema_list()
	// (postgres.py:2572-2581), byte-for-byte including the pinned
	// trailing space (psql_query strips it before the COPY wrap).
	schemaListQuery = `SELECT pg_namespace.nspname as "name",` +
		`pg_namespace.nspacl as "acl", ` +
		`pg_roles.rolname as "owner" ` +
		`FROM pg_namespace ` +
		`LEFT JOIN pg_roles ON pg_roles.oid = pg_namespace.nspowner `
	// expiryTimeLayout is the pinned strptime format for "expiry time".
	expiryTimeLayout = "2006-01-02 15:04:05"
	// defaultPrependSchema is the pinned has_privileges prepend default
	// ("public"); an explicit empty prepend keeps Salt's empty-schema match.
	defaultPrependSchema = "public"
	// The R9.2f owner and privilege catalogs. The pinned
	// _get_object_owner (postgres.py:3003-3123) and
	// _make_privileges_list_query (postgres.py:2891-3000) interpolate the
	// caller's object name and schema prefix into single-quoted SQL string
	// literals. StateKit keeps the pinned catalogs, join shapes, and
	// orderings but drops the interpolated WHERE equalities: the key
	// column is selected alongside the pinned value column and matched
	// client-side, so no caller string ever reaches SQL. Each fixed query
	// enumerates the same rows the pinned catalog scan visits.
	ownerTableQuery    = `SELECT schemaname, tablename, tableowner AS name FROM pg_tables`
	ownerSequenceQuery = `SELECT nspname, relname, rolname AS name FROM pg_catalog.pg_class c ` +
		`JOIN pg_roles r ON c.relowner = r.oid ` +
		`JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE relkind='S'`
	ownerSchemaQuery = `SELECT nspname, rolname AS name FROM pg_namespace n ` +
		`JOIN pg_roles r ON n.nspowner = r.oid`
	ownerFunctionQuery = `SELECT nspname, p.oid::regprocedure::text AS regprocedure, rolname AS name ` +
		`FROM pg_catalog.pg_proc p ` +
		`JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace ` +
		`JOIN pg_catalog.pg_roles r ON p.proowner = r.oid ` +
		`ORDER BY proname, proargtypes`
	ownerTablespaceQuery = `SELECT spcname, rolname AS name FROM pg_tablespace t ` +
		`JOIN pg_roles r ON t.spcowner = r.oid`
	ownerLanguageQuery = `SELECT lanname, rolname AS name FROM pg_language l ` +
		`JOIN pg_roles r ON l.lanowner = r.oid`
	ownerDatabaseQuery = `SELECT datname, rolname AS name FROM pg_database d ` +
		`JOIN pg_roles r ON d.datdba = r.oid`
	// privilegesTableQuery keeps the pinned relkind in ('r', 'v') filter
	// and ORDER BY relname; the nspname/relname equalities move client-side.
	privilegesTableQuery = `SELECT nspname, relname, relkind, relacl AS name ` +
		`FROM pg_catalog.pg_class c ` +
		`JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace ` +
		`WHERE relkind in ('r', 'v') ORDER BY relname`
	// privilegesSequenceQuery keeps the pinned relkind = 'S' filter.
	privilegesSequenceQuery = `SELECT nspname, relname, relkind, relacl AS name ` +
		`FROM pg_catalog.pg_class c ` +
		`JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace ` +
		`WHERE relkind = 'S' ORDER BY relname`
	privilegesSchemaQuery   = `SELECT nspname, nspacl AS name FROM pg_catalog.pg_namespace ORDER BY nspname`
	privilegesFunctionQuery = `SELECT nspname, p.oid::regprocedure::text AS regprocedure, proacl AS name ` +
		`FROM pg_catalog.pg_proc p ` +
		`JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace ` +
		`ORDER BY proname, proargtypes`
	privilegesTablespaceQuery = `SELECT spcname, spcacl AS name FROM pg_catalog.pg_tablespace ORDER BY spcname`
	privilegesLanguageQuery   = `SELECT lanname, lanacl AS name FROM pg_catalog.pg_language ORDER BY lanname`
	privilegesDatabaseQuery   = `SELECT datname, datacl AS name FROM pg_catalog.pg_database ORDER BY datname`
	// privilegesGroupQuery exposes the group role's name as member_of so
	// the pinned roleid IN (SELECT oid ... WHERE rolname='{0}') membership
	// filter becomes a client-side exact match on that column.
	privilegesGroupQuery = `SELECT (SELECT rolname FROM pg_catalog.pg_roles rr WHERE rr.oid = m.roleid) ` +
		`AS member_of, rolname, admin_option ` +
		`FROM pg_catalog.pg_auth_members m ` +
		`JOIN pg_catalog.pg_roles r ON m.member=r.oid ORDER BY rolname`
	// The R9.2l default-privilege catalogs. The pinned
	// _make_default_privileges_list_query (postgres.py:2808-2888)
	// interpolates the schema prefix into the single-quoted nspname
	// equality of the table/sequence/function pg_default_acl scans.
	// StateKit keeps the pinned catalogs, join shapes, constant
	// defaclobjtype filters, and orderings — byte-for-byte including the
	// pinned double spaces the " ".join leaves after "aid.oid " and
	// "nsp " and the pinned "defaclobjtype ='x'" spacing — but drops the
	// interpolated equality: nspname is selected alongside the pinned
	// value column and matched client-side, so no caller string reaches
	// SQL. The pinned schema and group branches are the same fixed
	// queries privilegesList already runs, so those are reused.
	defPrivTableQuery = `SELECT nspname, defacl.defaclacl AS name ` +
		`FROM pg_default_acl defacl ` +
		`JOIN pg_authid aid ` +
		`ON defacl.defaclrole = aid.oid  ` +
		`JOIN pg_namespace nsp  ` +
		`ON nsp.oid = defacl.defaclnamespace ` +
		`WHERE defaclobjtype ='r' ORDER BY nspname`
	defPrivSequenceQuery = `SELECT nspname, defacl.defaclacl AS name ` +
		`FROM pg_default_acl defacl ` +
		`JOIN pg_authid aid ` +
		`ON defacl.defaclrole = aid.oid  ` +
		`JOIN pg_namespace nsp  ` +
		`ON nsp.oid = defacl.defaclnamespace ` +
		`WHERE defaclobjtype ='S' ORDER BY nspname`
	defPrivFunctionQuery = `SELECT nspname, defacl.defaclacl AS name ` +
		`FROM pg_default_acl defacl ` +
		`JOIN pg_authid aid ` +
		`ON defacl.defaclrole = aid.oid  ` +
		`JOIN pg_namespace nsp  ` +
		`ON nsp.oid = defacl.defaclnamespace ` +
		`WHERE defaclobjtype ='f' ORDER BY nspname`
)

var (
	errPostgresRunnerUnavailable = errors.New("postgres: runner unavailable")
	errPostgresPsqlUnavailable   = errors.New("postgres: psql is unavailable")
	errPostgresRunas             = errors.New("postgres: runas is not supported by statekit")
	errPostgresInvalidArgument   = errors.New("postgres: invalid argument")
	errPostgresInvalidACL        = errors.New("postgres: invalid acl entry")
	errPostgresSaslprep          = errors.New("postgres: saslprep: unsupported non-ASCII password")
	// errPostgresUnknownPasswordAlgorithm is the fixed, value-free form of
	// the pinned _maybe_encrypt_password ValueError: the rejected algorithm
	// value never enters the error because the encrypted argument is
	// union-typed and may carry (or overlap) a credential, asserted by the
	// synthetic secret-overlap tests.
	errPostgresUnknownPasswordAlgorithm = fmt.Errorf("%w: unknown password algorithm", errPostgresInvalidArgument)
	// errPostgresDefprivilegesAllCompare is the fixed, value-free form of
	// the pinned has_default_privileges ALL comparison
	// (postgres.py:3564-3566): Python evaluates
	// defperms.sort() == _defprivileges[name].keys().sort(), and dict_keys
	// carries no sort method, so the branch raises AttributeError before
	// producing a boolean. StateKit maps that deterministic pinned failure
	// to this execution error; no caller value ever enters it.
	errPostgresDefprivilegesAllCompare = fmt.Errorf("%w: default privileges all comparison unavailable", errPostgresInvalidArgument)
	// errPostgresInvalidLocation is the fixed, value-free rejection for a
	// tablespace LOCATION that is not an absolute, clean, control-free
	// path: the pinned format string interpolates the location raw into a
	// single-quoted literal with no escaping, so the boundary refuses
	// relative paths, traversal or dot segments, redundant separators, and
	// control bytes — naming no value so a rejected path cannot leak.
	errPostgresInvalidLocation = fmt.Errorf("%w: invalid tablespace location", errPostgresInvalidArgument)
	// errPostgresInvalidOptionName and errPostgresInvalidOptionValue are
	// the fixed, value-free rejections for tablespace option tokens: the
	// pinned source interpolates both the option key and value raw into
	// the WITH/SET clause with no quoting, so keys must be bare
	// PostgreSQL identifiers and values bare version-class tokens, and
	// neither error names the rejected token.
	errPostgresInvalidOptionName  = fmt.Errorf("%w: unsupported tablespace option name", errPostgresInvalidArgument)
	errPostgresInvalidOptionValue = fmt.Errorf("%w: unsupported tablespace option value", errPostgresInvalidArgument)
	// errPostgresTablespaceSetOption is the fixed, value-free rejection
	// for a multi-entry set_option map: the pinned tablespace_alter reads
	// only next(iter(set_option.items())) — the first inserted pair — but
	// a Go map carries no insertion order, so more than one entry is
	// ambiguous and refused rather than silently applying one of them.
	errPostgresTablespaceSetOption = fmt.Errorf("%w: set_option must carry exactly one tablespace option", errPostgresInvalidArgument)
	// errPostgresInitdbUnavailable is the fail-closed answer when the
	// Runner cannot resolve the initdb binary (the pinned _find_pg_binary
	// CommandExecutionError has no StateKit fallback discovery).
	errPostgresInitdbUnavailable = errors.New("postgres: initdb is unavailable")
	// errPostgresFSUnavailable guards the datadir family's Runtime.FS
	// dependency the way errPostgresRunnerUnavailable guards the Runner.
	errPostgresFSUnavailable = errors.New("postgres: filesystem unavailable")
	// errPostgresInvalidDataDirPath and errPostgresInvalidWalDirPath are
	// the fixed, value-free rejections for the datadir family's path
	// arguments: both reach initdb as paths it creates or writes under, so
	// like the tablespace LOCATION they must be absolute, clean
	// (path.Clean equality), and control-free; neither error names the
	// rejected path so it cannot leak.
	errPostgresInvalidDataDirPath = fmt.Errorf("%w: invalid data directory path", errPostgresInvalidArgument)
	errPostgresInvalidWalDirPath  = fmt.Errorf("%w: invalid wal directory path", errPostgresInvalidArgument)
	// errPostgresPwfileCleanup is the fixed, value-free fail-closed error
	// for a password file that cannot be removed after initdb ran: the
	// pinned source only logs a warning, but StateKit modules have no
	// logging surface, and silently leaving credential bytes on disk is
	// the strictly worse outcome, so the cleanup failure is surfaced.
	errPostgresPwfileCleanup = errors.New("postgres: password file cleanup failed")
	// errPostgresPwfileTempDir and errPostgresPwfileWrite are the fixed,
	// value-free fail-closed errors for the pwfile transport's
	// preparation half: the raw MkdirTemp/WriteFile errors are
	// *fs.PathError values whose Op/Path fields name the
	// credential-holding temp location, and a faulting filesystem may
	// fold any bytes (path echoes, captured stderr) into its error
	// strings, so only the stable category travels onward — the same
	// redaction boundary errPostgresPwfileCleanup holds for the removal.
	errPostgresPwfileTempDir = errors.New("postgres: password file temp directory failed")
	errPostgresPwfileWrite   = errors.New("postgres: password file write failed")
)

// validateDataDirPath enforces the datadir family's path boundary shared
// with the tablespace LOCATION: an absolute, already-clean path
// (path.Clean equality rejects dot and dot-dot segments, redundant
// separators, and trailing slashes) carrying no control bytes. The
// rejection is value-free.
func validateDataDirPath(name string, rejection error) error {
	if name == "" || !strings.HasPrefix(name, "/") || name != path.Clean(name) {
		return rejection
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return rejection
		}
	}
	return nil
}

// privilegesMap ports the pinned _PRIVILEGES_MAP (postgres.py:86-101): the
// ACL privilege characters to their privilege names, including "*" → GRANT
// which _process_priv_part treats specially.
var privilegesMap = map[string]string{
	"a": "INSERT",
	"C": "CREATE",
	"D": "TRUNCATE",
	"c": "CONNECT",
	"t": "TRIGGER",
	"r": "SELECT",
	"U": "USAGE",
	"T": "TEMPORARY",
	"w": "UPDATE",
	"X": "EXECUTE",
	"x": "REFERENCES",
	"d": "DELETE",
	"m": "MAINTAIN",
	"*": "GRANT",
}

// privilegeTypeMap ports the pinned _PRIVILEGE_TYPE_MAP
// (postgres.py:136-144): the ACL characters valid for each object type.
// Its keys are exactly the pinned _PRIVILEGES_OBJECTS minus group.
var privilegeTypeMap = map[string]string{
	"table":      "arwdDxtm",
	"tablespace": "C",
	"language":   "U",
	"sequence":   "rwU",
	"schema":     "UC",
	"database":   "CTc",
	"function":   "X",
}

// defPrivilegesMap ports the pinned _DEFAULT_PRIVILEGES_MAP
// (postgres.py:102-114): the default-ACL privilege characters to their
// privilege names. It is the pinned _PRIVILEGES_MAP minus CONNECT,
// TEMPORARY, and MAINTAIN, so those characters are unknown on default
// ACLs exactly like the pinned KeyError.
var defPrivilegesMap = map[string]string{
	"a": "INSERT",
	"C": "CREATE",
	"D": "TRUNCATE",
	"t": "TRIGGER",
	"r": "SELECT",
	"U": "USAGE",
	"w": "UPDATE",
	"X": "EXECUTE",
	"x": "REFERENCES",
	"d": "DELETE",
	"*": "GRANT",
}

// defPrivilegeTypeMap ports the pinned _DEFAULT_PRIVILEGE_TYPE_MAP
// (postgres.py:145-150): the default-ACL characters valid for each object
// type. Its keys are exactly the pinned _DEFAULT_PRIVILEGES_OBJECTS minus
// group (postgres.py:115-123).
var defPrivilegeTypeMap = map[string]string{
	"table":    "arwdDxt",
	"sequence": "rwU",
	"schema":   "UC",
	"function": "X",
}

// privSplitRE ports the pinned re.split(r"\s?,\s?", ...) separator: an
// optional single ASCII whitespace on either side of the comma. Python's
// str \s class is [ \t\n\r\f\v] for ASCII; Go's \s omits \v, so the class
// is spelled out.
var privSplitRE = regexp.MustCompile(`[ \t\n\r\f\v]?,[ \t\n\r\f\v]?`)

// ---------------------------------------------------------------------------
// version — salt/modules/postgres.py:309-332 @ pinned revision.

// VersionArgs are the canonical postgres.version arguments, mirroring the
// pinned version(user, host, port, maintenance_db, password, runas)
// signature. Pointer fields keep Salt's None defaults: nil omits the
// corresponding psql flag or environment variable.
type VersionArgs struct {
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

// connection projects the version signature onto the shared connection
// arguments consumed by the psql transport.
func (a *VersionArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type versionFunc struct{}

func (versionFunc) Name() string { return "postgres.version" }
func (versionFunc) Args() any    { return VersionArgs{} }

func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[VersionArgs](args, "postgres.version")
	if err != nil {
		return nil, err
	}
	return serverVersion(ctx, rt, a.connection())
}

// serverVersion preserves the invocation's secret inventory through the
// internal preflight path without adding public arguments.
func serverVersion(ctx context.Context, rt *runtime.Runtime, conn *pgConnection) (any, error) {
	// The pinned version() calls _psql_cmd("-c", query, "-t", ...) and then
	// _run_psql with the same connection arguments.
	argv := psqlArgv(
		pointerString(conn.User),
		pointerString(conn.Host),
		pointerString(conn.Port),
		pointerString(conn.MaintenanceDB),
		"-c", serverVersionQuery, "-t",
	)
	result, err := runPsql(ctx, rt, argv, conn)
	if err != nil {
		return nil, err
	}
	return firstOutputLine(string(result.Stdout)), nil
}

// firstOutputLine ports the pinned version() consumption of
// salt.utils.itertools.split(stdout, "\n"): with an explicit separator the
// generator yields the pre-newline prefix of the first match (possibly the
// empty string), but an exhausted string yields nothing at all, so an empty
// stdout makes the pinned function fall through to None.
func firstOutputLine(stdout string) any {
	if stdout == "" {
		return nil
	}
	if index := strings.IndexByte(stdout, '\n'); index >= 0 {
		return stdout[:index]
	}
	return stdout
}

// ---------------------------------------------------------------------------
// _psql_cmd — salt/modules/postgres.py:386-432 @ pinned revision.

// psqlArgv ports the pinned _psql_cmd: the fixed never-prompt flags, the
// optional connection flags, the maintenance database with its "postgres"
// fallback, and finally the caller's trailing arguments. With every
// connection argument supplied, the version query lands at argv index 14
// exactly as the pinned test_postgres.py test_version asserts. The pinned
// _connection_defaults config.option lookups have no StateKit equivalent,
// so empty arguments keep Salt's None meaning here.
func psqlArgv(user, host, port, maintenanceDB string, args ...string) []string {
	argv := []string{
		psqlCommand,
		"--no-align",
		"--no-readline",
		"--no-psqlrc",
		"--no-password", // Never prompt; credentials travel out of band.
	}
	if user != "" {
		argv = append(argv, "--username", user)
	}
	if host != "" {
		argv = append(argv, "--host", host)
	}
	if port != "" {
		argv = append(argv, "--port", port)
	}
	if maintenanceDB == "" {
		maintenanceDB = defaultMaintenanceDB
	}
	argv = append(argv, "--dbname", maintenanceDB)
	return append(argv, args...)
}

// ---------------------------------------------------------------------------
// _run_psql — salt/modules/postgres.py:179-235 @ pinned revision.

// pgConnection is the connection half shared by every postgres function
// signature: the pinned (user, host, port, maintenance_db, password,
// runas) tuple. Pointer fields keep Salt's None defaults: nil omits the
// corresponding psql flag or environment variable.
type pgConnection struct {
	User          *string
	Host          *string
	Port          *string
	MaintenanceDB *string
	Password      *string
	// Raw caller secrets travel through every preflight without generating
	// a verifier or changing the pinned statement-construction timing.
	Secrets []string
	Runas   *string
}

// runPsql ports the pinned _run_psql execution half: a shell-free,
// centrally executed psql command with bounded output. The password half is
// adapted: Salt writes a temporary PGPASSFILE and chowns it to the runas
// user, but the StateKit runtime is single-user and has no elevation or
// file-chown contract, so credentials travel through psql's native
// PGPASSWORD (with PGUSER/PGHOST/PGPORT for the resolved connection) in an
// otherwise clean environment, matching Salt's clean_env=True. The password
// is a Redact secret: it never appears in the rendered command, captured
// output, or returned errors. A non-zero psql exit stays compatibility
// data, like Salt's logged-but-returned retcode.
func runPsql(ctx context.Context, rt *runtime.Runtime, argv []string, conn *pgConnection) (process.CommandResult, error) {
	return runPsqlSecrets(ctx, rt, argv, conn, nil)
}

// runPsqlSecrets is runPsql plus the extra Redact secrets a statement
// carries inside its argv: the R9.2i role paths embed the rolepassword in
// the SQL argument — the plaintext, its quote-doubled form, and the
// generated md5/SCRAM verifier actually placed there (plus that
// verifier's quoted literal form) — so every form joins the connection
// password in the Redact list and in the error-redaction pass, keeping
// the rendered argv, captured output, and returned errors secret-free.
func runPsqlSecrets(ctx context.Context, rt *runtime.Runtime, argv []string, conn *pgConnection, extraSecrets []string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errPostgresRunnerUnavailable
	}
	if conn == nil {
		conn = &pgConnection{}
	}
	// Salt defaults runas to "postgres" for local-socket connections; the
	// central runtime is single-user, so an explicit runas is rejected
	// before any Runner invocation instead of being silently dropped.
	if err := rejectRunas(conn.Runas); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if err := validateArgv(argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if available, ok := rt.Runner.(process.CommandAvailability); ok && !available.CommandAvailable(psqlCommand) {
		// Fail closed: psql discovery has no package-manager or other
		// fallback in this module.
		return process.CommandResult{ExitCode: -1}, errPostgresPsqlUnavailable
	}

	secrets := append([]string(nil), extraSecrets...)
	secrets = append(secrets, conn.Secrets...)
	if conn.Password != nil {
		secrets = append(secrets, *conn.Password)
	}
	// Include SQL-escaped forms only when present in the actual SQL.
	for _, secret := range secretList(secrets...) {
		doubled := strings.ReplaceAll(secret, "'", "''")
		for i := 1; i < len(argv); i++ {
			if argv[i-1] == "-c" {
				for _, form := range []string{doubled, "'" + doubled + "'"} {
					if strings.Contains(argv[i], form) {
						secrets = append(secrets, form)
					}
				}
			}
		}
	}
	secrets = secretList(secrets...)
	command := process.Command{
		Name:           argv[0],
		Args:           append([]string(nil), argv[1:]...),
		Timeout:        commandTimeout,
		MaxStdoutBytes: outputLimit,
		MaxStderrBytes: outputLimit,
		Env:            psqlEnvironment(conn),
	}
	if len(secrets) > 0 {
		command.Redact = secretList(secrets...)
	}
	result := rt.Runner.Run(ctx, command)
	outputExceeded := len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit
	// Defend against custom Runners that do not sanitize their own results.
	result.Stdout = process.RedactBytes(secrets, result.Stdout)
	result.Stderr = process.RedactBytes(secrets, result.Stderr)
	if result.Err != nil {
		result.Err = redactedError(result.Err, secrets...)
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		outputExceeded {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

// psqlEnvironment builds the clean child environment for psql. Salt runs
// psql with clean_env=True and passes credentials out of band, so only the
// resolved connection variables are exported; an empty result leaves the
// child with no inherited environment at all.
func psqlEnvironment(conn *pgConnection) []string {
	env := make([]string, 0, 4)
	if conn.Password != nil {
		env = append(env, "PGPASSWORD="+*conn.Password)
	}
	if value := pointerString(conn.User); value != "" {
		env = append(env, "PGUSER="+value)
	}
	if value := pointerString(conn.Host); value != "" {
		env = append(env, "PGHOST="+value)
	}
	if value := pointerString(conn.Port); value != "" {
		env = append(env, "PGPORT="+value)
	}
	return env
}

// ---------------------------------------------------------------------------
// _parsed_version — salt/modules/postgres.py:334-361 @ pinned revision.

// parsedVersion is the internal LooseVersion-equivalent returned by
// parsedServerVersion (the pinned _parsed_version helper). It tokenizes
// like LooseVersion — digit runs become integers, dots are discarded,
// and other pieces remain strings. Salt's override compares entire lists
// as strings (integers zero-filled to width 8) if either contains a string;
// otherwise it compares numeric lists. It is deliberately not registered:
// like the pinned helper it exists for internal callers only.
type parsedVersion struct {
	vstring    string
	components []looseToken
}

// looseToken is one LooseVersion component: an integer run or a literal
// string piece.
type looseToken struct {
	isInt bool
	num   *big.Int
	str   string
}

// looseSplitRE is distutils' _component_re: digit runs, lowercase alpha
// runs, and dots split the string; every unmatched chunk stays literal.
var looseSplitRE = regexp.MustCompile(`(\d+|[a-z]+|\.)`)

// parseLooseVersion tokenizes like distutils LooseVersion.parse: digit runs
// become integers (so "04" compares as 4), dots are discarded, and other
// chunks stay literal strings. Python integers have no fixed-width limit.
func parseLooseVersion(vstring string) parsedVersion {
	indices := looseSplitRE.FindAllStringIndex(vstring, -1)
	tokens := make([]looseToken, 0, len(indices)+1)
	appendPiece := func(piece string) {
		if piece == "" || piece == "." {
			return
		}
		if isASCIIDigits(piece) {
			num, _ := new(big.Int).SetString(piece, 10)
			tokens = append(tokens, looseToken{isInt: true, num: num})
			return
		}
		tokens = append(tokens, looseToken{str: piece})
	}
	prev := 0
	for _, loc := range indices {
		appendPiece(vstring[prev:loc[0]])
		appendPiece(vstring[loc[0]:loc[1]])
		prev = loc[1]
	}
	appendPiece(vstring[prev:])
	return parsedVersion{vstring: vstring, components: tokens}
}

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// String keeps the original version string, as distutils LooseVersion does.
func (v parsedVersion) String() string { return v.vstring }

// compare mirrors salt/utils/versions.py:73-101, including the whole-list
// string fallback and zfill(8), not generic distutils mixed-type behavior.
// The boolean remains true for all parsed versions; strict prefixes sort first.
func (v parsedVersion) compare(other parsedVersion) (int, bool) {
	stringMode := false
	for _, parts := range [][]looseToken{v.components, other.components} {
		for _, part := range parts {
			if !part.isInt {
				stringMode = true
			}
		}
	}
	stringPart := func(part looseToken) string {
		if !part.isInt {
			return part.str
		}
		s := part.num.String()
		if len(s) < 8 {
			s = strings.Repeat("0", 8-len(s)) + s
		}
		return s
	}
	shared := len(v.components)
	if len(other.components) < shared {
		shared = len(other.components)
	}
	for i := 0; i < shared; i++ {
		a, b := v.components[i], other.components[i]
		var order int
		if stringMode {
			order = strings.Compare(stringPart(a), stringPart(b))
		} else {
			order = a.num.Cmp(b.num)
		}
		if order != 0 {
			if order < 0 {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case len(v.components) < len(other.components):
		return -1, true
	case len(v.components) > len(other.components):
		return 1, true
	}
	return 0, true
}

// parsedServerVersion ports the pinned _parsed_version: it runs the public
// version probe and parses the reply, returning nil (Salt: None) when the
// server does not answer with a non-empty version. The pinned helper logs a
// warning in that case; StateKit modules do not log, so the nil result is
// the signal. Internal-only, with no registry entry.
func parsedServerVersion(ctx context.Context, rt *runtime.Runtime, conn *pgConnection) (*parsedVersion, error) {
	value, err := serverVersion(ctx, rt, conn)
	if err != nil {
		return nil, err
	}
	version, ok := value.(string)
	if !ok || version == "" {
		return nil, nil
	}
	parsed := parseLooseVersion(version)
	return &parsed, nil
}

// ---------------------------------------------------------------------------
// psql_query (read-only transport) — salt/modules/postgres.py:433-524 @
// pinned revision, restricted to the write=False shape.

// psqlQueryRows ports the pinned psql_query reader for this module's fixed
// catalog queries: the query is wrapped in "COPY (...) TO STDOUT WITH CSV
// HEADER", run through the same _psql_cmd/_run_psql transport as version()
// with the pinned datestyle variable, and the CSV stdout is parsed with the
// pinned csv.reader semantics (comma delimiter, double-quote quotechar,
// empty rows skipped, first row the header, dict(zip(header,row)) rows).
// A positive psql retcode keeps Salt's empty-list compatibility data; only
// Runner failures, cancellation, and output-limit violations are errors.
// The generic query surface stays unregistered: callers pass fixed SQL
// fragments only.
func psqlQueryRows(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, query string) ([]map[string]string, error) {
	csvQuery := "COPY (" + strings.TrimRight(strings.TrimSpace(query), ";") + ") TO STDOUT WITH CSV HEADER"
	argv := psqlArgv(
		pointerString(conn.User),
		pointerString(conn.Host),
		pointerString(conn.Port),
		pointerString(conn.MaintenanceDB),
		"-v", "datestyle=ISO,MDY", "-c", csvQuery,
	)
	result, err := runPsql(ctx, rt, argv, conn)
	if err != nil {
		return nil, err
	}
	if result.ExitCode > 0 {
		return []map[string]string{}, nil
	}
	return parseCSVRows(string(result.Stdout))
}

// parseCSVRows ports the pinned io.StringIO + csv.reader loop
// (postgres.py:506-518). Rows shorter than the header keep only their zipped
// prefix and rows longer are truncated at the header, exactly like
// dict(zip(header, row)); empty records are skipped. The reader itself is the
// pyCSVReader port of the pinned Python csv module described below.
func parseCSVRows(stdout string) ([]map[string]string, error) {
	rows := []map[string]string{}
	reader := newPyCSVReader(stdout)
	var header []string
	for {
		record, err := reader.next()
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			// Salt propagates csv.Error as a module exception.
			return nil, fmt.Errorf("postgres: csv parse: %w", err)
		}
		if len(record) == 0 {
			continue
		}
		if header == nil {
			header = record
			continue
		}
		shared := len(header)
		if len(record) < shared {
			shared = len(record)
		}
		row := make(map[string]string, shared)
		for i := 0; i < shared; i++ {
			row[header[i]] = record[i]
		}
		rows = append(rows, row)
	}
}

// ---------------------------------------------------------------------------
// pinned csv.reader — CPython Modules/_csv.c @ default dialect, non-strict.

// pyCSVFieldLimit mirrors the Python csv module's default field_size_limit:
// 131072 characters per field, beyond which the reader raises csv.Error.
const pyCSVFieldLimit = 131072

var (
	errPyCSVFieldLimit = errors.New("field larger than field limit (131072)")
	errPyCSVNewline    = errors.New("new-line character seen in unquoted field")
)

// pyCSVState names the reader states of the pinned CPython _csv.c state
// machine for the default dialect (comma delimiter, double-quote quotechar,
// doublequote, no escapechar, no skipinitialspace, strict=False).
type pyCSVState uint8

const (
	pyCSVStartRecord pyCSVState = iota
	pyCSVStartField
	pyCSVInField
	pyCSVInQuotedField
	pyCSVQuoteInQuotedField
	pyCSVEatCRNL
)

// pyCSVReader is a bounded port of the pinned Python csv.reader as the pinned
// psql_query and user_list use it: iteration over io.StringIO(stdout)
// (newline='\n', so lines split on '\n' only and '\r' stays a line
// character) and, for groups, a single-element [value] iterable. Both feeds
// share one char-level state machine:
//
//   - Inside a quoted field every character — comma, quote-backslash
//     sequences, lone '\r', '\r\n', '\n', and NUL — is literal data, so an
//     embedded CRLF survives byte-exact (Go's encoding/csv would normalize it
//     to LF, which is why it cannot be used here).
//   - A backslash is an ordinary character (escapechar is None), and after a
//     closing quote any regular character is appended without unquoting
//     (strict=False), so PostgreSQL's backslash-escaped array elements like
//     {"a\"b","x\\y"} decode exactly as the pinned Python reader decodes
//     them (["a\b\"", "x\\y"]) instead of being rejected.
//   - '\r' or '\n' outside a quoted field ends the record; a non-EOL
//     character after it is the pinned csv.Error "new-line character seen in
//     unquoted field".
//   - A record is returned at the end of any line that leaves the machine in
//     a record-complete state, and end of input saves the pending field —
//     even when empty ("db1," is ["db1", ""]) — unless no record is in
//     progress.
//
// The only bound beyond the already size-capped psql stdout is the pinned
// per-field limit of 131072 characters. Errors never embed input or field
// content, so no source, query, or credential material can leak through
// them.
type pyCSVReader struct {
	input    string
	pos      int
	single   bool
	state    pyCSVState
	fields   []string
	field    []byte
	fieldLen int
}

// newPyCSVReader mirrors csv.reader(io.StringIO(stdout)): the input is a
// '\n'-split line stream, and records are yielded until end of input.
func newPyCSVReader(input string) *pyCSVReader {
	return &pyCSVReader{input: input, state: pyCSVStartRecord}
}

// newPyCSVRecordReader mirrors csv.reader([value]): the whole string is one
// line — even when empty or containing '\n' — so exactly one record (or one
// error) is always produced.
func newPyCSVRecordReader(line string) *pyCSVReader {
	return &pyCSVReader{input: line, single: true, state: pyCSVStartRecord}
}

// next returns the next record. It mirrors the pinned Reader iteration: feed
// one '\n'-terminated line at a time, return a record whenever a line leaves
// the machine record-complete, and at end of input finish the pending record
// the way the non-strict Python reader does.
func (r *pyCSVReader) next() ([]string, error) {
	if r.single {
		return r.nextRecord()
	}
	for {
		if r.pos >= len(r.input) {
			if r.state == pyCSVStartRecord {
				return nil, io.EOF
			}
			r.saveField()
			return r.emit(), nil
		}
		lineEnd := strings.IndexByte(r.input[r.pos:], '\n')
		if lineEnd < 0 {
			lineEnd = len(r.input) - r.pos
		} else {
			lineEnd++ // the line keeps its '\n' terminator
		}
		segment := r.input[r.pos : r.pos+lineEnd]
		r.pos += lineEnd
		for _, c := range segment {
			if err := r.step(c); err != nil {
				return nil, err
			}
		}
		switch r.state {
		case pyCSVStartRecord, pyCSVEatCRNL:
			return r.emit(), nil
		}
		// The line ended inside an open record (quoted data or a final line
		// without its terminator); the next line continues the record.
	}
}

// nextRecord decodes the single-line feed: the entire input is one line, and
// its record — empty or not — is the one record the pinned one-element list
// iteration returns.
func (r *pyCSVReader) nextRecord() ([]string, error) {
	for _, c := range r.input {
		if err := r.step(c); err != nil {
			return nil, err
		}
	}
	switch r.state {
	case pyCSVStartRecord, pyCSVEatCRNL:
		return r.emit(), nil
	default:
		r.saveField()
		return r.emit(), nil
	}
}

// step advances the machine by one character.
func (r *pyCSVReader) step(c rune) error {
	switch r.state {
	case pyCSVStartRecord:
		if c == '\r' || c == '\n' {
			r.state = pyCSVEatCRNL
			return nil
		}
		r.state = pyCSVStartField
		fallthrough
	case pyCSVStartField:
		switch {
		case c == '"':
			r.state = pyCSVInQuotedField
		case c == ',':
			r.saveField()
		case c == '\r' || c == '\n':
			r.saveField()
			r.state = pyCSVEatCRNL
		default:
			if err := r.add(c); err != nil {
				return err
			}
			r.state = pyCSVInField
		}
	case pyCSVInField:
		switch {
		case c == ',':
			r.saveField()
			r.state = pyCSVStartField
		case c == '\r' || c == '\n':
			r.saveField()
			r.state = pyCSVEatCRNL
		default:
			return r.add(c)
		}
	case pyCSVInQuotedField:
		if c == '"' {
			r.state = pyCSVQuoteInQuotedField
			return nil
		}
		return r.add(c)
	case pyCSVQuoteInQuotedField:
		switch {
		case c == '"':
			// Doubled quote: "" inside a quoted field is one literal '"'.
			if err := r.add('"'); err != nil {
				return err
			}
			r.state = pyCSVInQuotedField
		case c == ',':
			r.saveField()
			r.state = pyCSVStartField
		case c == '\r' || c == '\n':
			r.saveField()
			r.state = pyCSVEatCRNL
		default:
			// Non-strict: keep appending after the closing quote.
			if err := r.add(c); err != nil {
				return err
			}
			r.state = pyCSVInField
		}
	case pyCSVEatCRNL:
		if c == '\r' || c == '\n' {
			return nil
		}
		return errPyCSVNewline
	}
	return nil
}

func (r *pyCSVReader) add(c rune) error {
	if r.fieldLen >= pyCSVFieldLimit {
		return errPyCSVFieldLimit
	}
	r.field = utf8.AppendRune(r.field, c)
	r.fieldLen++
	return nil
}

func (r *pyCSVReader) saveField() {
	r.fields = append(r.fields, string(r.field))
	r.field = r.field[:0]
	r.fieldLen = 0
}

// emit finishes the current record and resets the machine to a fresh one,
// returning a non-nil record like the Python reader's fresh list per row.
func (r *pyCSVReader) emit() []string {
	record := r.fields
	if record == nil {
		record = []string{}
	}
	r.fields = nil
	r.field = r.field[:0]
	r.fieldLen = 0
	r.state = pyCSVStartRecord
	return record
}

// ---------------------------------------------------------------------------
// db_list / db_exists — salt/modules/postgres.py:530-598 @ pinned revision.

// ListArgs are the canonical postgres.db_list and postgres.tablespace_list
// arguments, mirroring the pinned (user, host, port, maintenance_db,
// password, runas) signatures.
type ListArgs struct {
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *ListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// ExistsArgs are the canonical postgres.db_exists and
// postgres.tablespace_exists arguments: the pinned name positional plus
// the shared connection tuple.
type ExistsArgs struct {
	Name          string  `statekit:"name=name,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *ExistsArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type dbListFunc struct{}

func (dbListFunc) Name() string { return "postgres.db_list" }
func (dbListFunc) Args() any    { return ListArgs{} }

func (dbListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListArgs](args, "postgres.db_list")
	if err != nil {
		return nil, err
	}
	return nameKeyedCatalog(ctx, rt, a.connection(), dbListQuery, "postgres.db_list")
}

type dbExistsFunc struct{}

func (dbExistsFunc) Name() string { return "postgres.db_exists" }
func (dbExistsFunc) Args() any    { return ExistsArgs{} }

func (dbExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.db_exists")
	if err != nil {
		return nil, err
	}
	// The pinned db_exists is exactly `name in db_list(...)`: the name is
	// matched client-side against the catalog and never reaches SQL.
	databases, err := nameKeyedCatalog(ctx, rt, a.connection(), dbListQuery, "postgres.db_exists")
	if err != nil {
		return nil, err
	}
	_, exists := databases[a.Name]
	return exists, nil
}

// nameKeyedCatalog ports the shared db_list/tablespace_list tail
// (postgres.py:564-568, 801-805): every row is stored under its "Name"
// column with that column removed, like the pinned
// ret[row["Name"]] = row; ret[row["Name"]].pop("Name").
func nameKeyedCatalog(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, query, name string) (map[string]map[string]string, error) {
	rows, err := psqlQueryRows(ctx, rt, conn, query)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]string, len(rows))
	for _, row := range rows {
		key, ok := row["Name"]
		if !ok {
			// Salt raises KeyError('Name') on a short row.
			return nil, fmt.Errorf(`%s: missing column "Name"`, name)
		}
		entry := make(map[string]string, len(row)-1)
		for column, value := range row {
			if column != "Name" {
				entry[column] = value
			}
		}
		out[key] = entry
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// db_create / db_remove — salt/modules/postgres.py:601-607, 610-673, 727-762
// @ pinned revision.

// quoteDDLValue ports the pinned _quote_ddl_value (postgres.py:601-607) for
// a non-None value: a value carrying the quote character is the pinned
// SaltInvocationError and any other value is wrapped in that character.
// Salt's own TODO admits this is not full escaping; the None-omission half
// stays at the pinned with_args loop below, and the identifier positions
// the pinned source interpolates raw (the database name and the unquoted
// TEMPLATE option) are validated fail-closed here instead of passing the
// injection the pinned format strings permit. The rejection error carries
// only the fixed argument key, never the rejected value: it is raised
// before any Runner invocation, where no redaction pass could strip a
// caller secret the value embeds.
func quoteDDLValue(value, quote, key string) (string, error) {
	if strings.Contains(value, quote) {
		return "", ddlValidationError(key)
	}
	return quote + value + quote, nil
}

// ddlValidationError is the stable, value-free rejection shared by every
// db_create/db_remove identifier and DDL-literal validation: the fixed
// argument key under the exact pinned invalid-argument category, with no
// rejected value, SQL fragment, or wrapped error, so the message is a
// constant for a given key.
func ddlValidationError(key string) error {
	return fmt.Errorf("%w: unsupported quote character in %s",
		errPostgresInvalidArgument, key)
}

// bareIdentifierRE is the PostgreSQL unquoted-identifier class the pinned
// db_create interpolates the TEMPLATE option into without any quoting: a
// non-empty run of ASCII letters, digits, underscores, and dollar signs.
// Nothing outside it can alter the fixed statement shape.
var bareIdentifierRE = regexp.MustCompile(`^[A-Za-z0-9_$]+$`)

// bareVersionRE is the version-token class the pinned CREATE/ALTER
// EXTENSION statements interpolate raw (VERSION {ext_version},
// FROM {from_version}): the bare identifier class plus the dot separators
// real extension version strings carry (pg_available_extensions
// default_version values such as "1.4"). Nothing outside it can alter the
// fixed statement shape, so the pinned format string's injection is
// refused value-free before any Runner invocation.
var bareVersionRE = regexp.MustCompile(`^[A-Za-z0-9_.$]+$`)

// DbCreateArgs are the canonical postgres.db_create arguments, mirroring
// the pinned db_create(name, user, host, port, maintenance_db, password,
// tablespace, encoding, lc_collate, lc_ctype, owner, template, runas)
// signature (postgres.py:610-624). Pointer fields keep Salt's None
// defaults: nil omits the option (or psql flag) entirely, while an explicit
// empty string keeps the pinned quoted empty value.
type DbCreateArgs struct {
	Name          string  `statekit:"name=name,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Tablespace    *string `statekit:"name=tablespace"`
	Encoding      *string `statekit:"name=encoding"`
	LcCollate     *string `statekit:"name=lc_collate"`
	LcCtype       *string `statekit:"name=lc_ctype"`
	Owner         *string `statekit:"name=owner"`
	Template      *string `statekit:"name=template"`
	Runas         *string `statekit:"name=runas"`
}

func (a *DbCreateArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// dbCreateQuery ports the pinned statement construction
// (postgres.py:638-661): the CREATE DATABASE head, then the pinned
// OrderedDict option order TABLESPACE, OWNER, TEMPLATE, ENCODING,
// LC_COLLATE, LC_CTYPE joined as " WITH KEY = VALUE" chunks for every
// non-None value. Values keep the pinned quoting exactly: double quotes
// for the tablespace and owner identifiers, single quotes for the encoding
// and locale literals, and the template stays the pinned bare identifier.
// The whole statement (and therefore every SaltInvocationError) is built
// before any Runner invocation, exactly like the pinned function formats
// first and executes once, and every rejection is value-free.
func dbCreateQuery(a *DbCreateArgs) (string, error) {
	if strings.Contains(a.Name, `"`) {
		// The pinned head formats the name into double quotes unescaped;
		// StateKit fails closed on the only character that can escape a
		// double-quoted identifier.
		return "", ddlValidationError("name")
	}
	query := `CREATE DATABASE "` + a.Name + `"`
	var chunks []string
	for _, opt := range []struct {
		key   string
		arg   string // statekit argument name for the value-free error
		value *string
		quote string // "" marks the pinned raw unquoted TEMPLATE position
	}{
		{"TABLESPACE", "tablespace", a.Tablespace, `"`},
		{"OWNER", "owner", a.Owner, `"`},
		{"TEMPLATE", "template", a.Template, ""},
		{"ENCODING", "encoding", a.Encoding, "'"},
		{"LC_COLLATE", "lc_collate", a.LcCollate, "'"},
		{"LC_CTYPE", "lc_ctype", a.LcCtype, "'"},
	} {
		if opt.value == nil {
			// Salt's with_args loop keeps None options out entirely.
			continue
		}
		if opt.quote == "" {
			if !bareIdentifierRE.MatchString(*opt.value) {
				// Value-free like every identifier/DDL rejection: the fixed
				// argument key only, never the rejected template value.
				return "", fmt.Errorf("%w: unsupported template identifier",
					errPostgresInvalidArgument)
			}
			chunks = append(chunks, opt.key, "=", *opt.value)
			continue
		}
		quoted, err := quoteDDLValue(*opt.value, opt.quote, opt.arg)
		if err != nil {
			return "", err
		}
		chunks = append(chunks, opt.key, "=", quoted)
	}
	if len(chunks) > 0 {
		query += " WITH " + strings.Join(chunks, " ")
	}
	return query, nil
}

type dbCreateFunc struct{}

func (dbCreateFunc) Name() string { return "postgres.db_create" }
func (dbCreateFunc) Args() any    { return DbCreateArgs{} }

func (dbCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbCreateArgs](args, "postgres.db_create")
	if err != nil {
		return nil, err
	}
	// The pinned source runs one fixed CREATE DATABASE statement over the
	// central maintenance-database connection with no test mode and no
	// db_exists preflight, so exactly that exists here.
	query, err := dbCreateQuery(a)
	if err != nil {
		return nil, err
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	// The pinned tail is exactly ret["retcode"] == 0: a rejected CREATE is
	// the boolean false, never an exception.
	return result.ExitCode == 0, nil
}

// DbRemoveArgs are the canonical postgres.db_remove arguments, mirroring
// the pinned db_remove(name, user, host, port, maintenance_db, password,
// runas) signature (postgres.py:727-735).
type DbRemoveArgs struct {
	Name          string  `statekit:"name=name,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *DbRemoveArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type dbRemoveFunc struct{}

func (dbRemoveFunc) Name() string { return "postgres.db_remove" }
func (dbRemoveFunc) Args() any    { return DbRemoveArgs{} }

// Execute ports the pinned db_remove flow (postgres.py:745-762): exactly
// three fixed statements in the pinned order — the public CONNECT
// revocation, the pg_stat_activity backend termination keyed by the datname
// literal, and the DROP — each through the same central
// maintenance-database connection, aborting on the first nonzero retcode
// and returning true only after the DROP, with no statement after it (no
// existence re-check, no cleanup query). The name is validated for both of
// its quote contexts up front because the pinned format strings interpolate
// it raw, and that rejection — like every db_create/db_remove validation —
// is value-free: it names the argument key only, so a name carrying a
// caller secret cannot leak through the error raised before any Runner
// invocation. The flow keeps the pinned non-transactional statement sequence
// and has no test mode, and the pinned source has no maintenance-database
// guard, so the maintenance name is not special-cased — PostgreSQL itself
// rejects dropping the database psql is connected to.
func (dbRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbRemoveArgs](args, "postgres.db_remove")
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(a.Name, `"'`) {
		// The name reaches both a double-quoted identifier and the pinned
		// single-quoted datname literal; neither context has an escaping
		// escape in the pinned source, so both quote characters are
		// rejected before any Runner invocation, with the value-free
		// stable error.
		return nil, ddlValidationError("name")
	}
	for _, query := range []string{
		`REVOKE CONNECT ON DATABASE "` + a.Name + `" FROM public;`,
		"SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '" +
			a.Name + "' AND pid <> pg_backend_pid();",
		`DROP DATABASE "` + a.Name + `";`,
	} {
		argv := psqlArgv(
			pointerString(a.User),
			pointerString(a.Host),
			pointerString(a.Port),
			pointerString(a.MaintenanceDB),
			"-c", query,
		)
		result, err := runPsql(ctx, rt, argv, a.connection())
		if err != nil {
			return nil, err
		}
		if result.ExitCode != 0 {
			// The pinned raise Exception(f"Failed: ret={ret}") aborts the
			// flow; the port carries the retcode only, so captured server
			// output and credentials can never travel through the error.
			return nil, fmt.Errorf("postgres.db_remove: Failed: retcode=%d", result.ExitCode)
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// db_alter — salt/modules/postgres.py:676-724 @ pinned revision.

// DbAlterArgs are the canonical postgres.db_alter arguments, mirroring the
// pinned db_alter(name, user, host, port, maintenance_db, password,
// tablespace, owner, owner_recurse, runas) signature
// (postgres.py:676-687). Pointer fields keep Salt's None defaults: nil
// omits the value entirely, and owner_recurse nil keeps the pinned False.
type DbAlterArgs struct {
	Name          string  `statekit:"name=name,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Tablespace    *string `statekit:"name=tablespace"`
	Owner         *string `statekit:"name=owner"`
	OwnerRecurse  *bool   `statekit:"name=owner_recurse"`
	Runas         *string `statekit:"name=runas"`
}

func (a *DbAlterArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type dbAlterFunc struct{}

func (dbAlterFunc) Name() string { return "postgres.db_alter" }
func (dbAlterFunc) Args() any    { return DbAlterArgs{} }

// Execute ports the pinned db_alter flow (postgres.py:697-724): the
// any((tablespace, owner)) head answers the pinned no-op True with no
// Runner invocation when neither argument carries a truthy value (Python
// truthiness makes an explicit empty string the same as None, so both omit
// the statement), the owner+owner_recurse branch delegates to owner_to —
// which stays pending exactly like a later name, so the branch surfaces a
// deterministic value-free UnsupportedError before any mutation instead of
// silently degrading to the shallow ALTER OWNER the else branch would run —
// and otherwise the pinned statements run in the pinned order, the OWNER
// change before the TABLESPACE change, each through the same central
// maintenance-database connection. The identifier boundary is the
// StateKit addition: the pinned format strings interpolate the name, the
// owner, and the tablespace into double-quoted identifier positions
// without escaping, so each is rejected fail-closed before any Runner
// invocation with the shared value-free error naming only the argument
// key. The pinned tail reads only the loop's last-overwritten ret, so a
// failed OWNER change followed by a successful TABLESPACE change answers
// True; the port instead checks every retcode — a rejected statement is
// the pinned boolean false and stops the flow, never an error, and no
// later statement runs after a failed one.
func (dbAlterFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbAlterArgs](args, "postgres.db_alter")
	if err != nil {
		return nil, err
	}
	// The pinned any((tablespace, owner)): only truthy values select a
	// statement, so None and the explicit empty string are the same here.
	owner := a.Owner != nil && *a.Owner != ""
	tablespace := a.Tablespace != nil && *a.Tablespace != ""
	if !owner && !tablespace {
		// The pinned "Nothing todo?" early True: no Runner invocation.
		return true, nil
	}
	if strings.Contains(a.Name, `"`) {
		// The name reaches the double-quoted identifier position of both
		// pinned statements (and owner_to's own statements); the only
		// character that can escape that context is rejected value-free.
		return nil, ddlValidationError("name")
	}
	if owner && strings.Contains(*a.Owner, `"`) {
		return nil, ddlValidationError("owner")
	}
	if tablespace && strings.Contains(*a.Tablespace, `"`) {
		return nil, ddlValidationError("tablespace")
	}
	if owner && pointerBool(a.OwnerRecurse) {
		// The pinned branch calls owner_to(name, owner, user=..., host=...,
		// port=..., password=..., runas=...) — the recursive REASSIGN OWNED
		// flow. owner_to is not registered in this phase, so the branch
		// cannot run its pinned flow; failing with the fixed UnsupportedError
		// (never a value from the arguments) keeps the unsupported surface
		// explicit instead of silently performing the shallow ALTER OWNER.
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "postgres.owner_to"}
	}
	// The pinned statement order: OWNER before TABLESPACE, each statement
	// on the full pinned psql argv exactly as the pinned test asserts.
	var queries []string
	if owner {
		queries = append(queries, `ALTER DATABASE "`+a.Name+`" OWNER TO "`+*a.Owner+`"`)
	}
	if tablespace {
		queries = append(queries, `ALTER DATABASE "`+a.Name+`" SET TABLESPACE "`+*a.Tablespace+`"`)
	}
	for _, query := range queries {
		argv := psqlArgv(
			pointerString(a.User),
			pointerString(a.Host),
			pointerString(a.Port),
			pointerString(a.MaintenanceDB),
			"-c", query,
		)
		result, err := runPsql(ctx, rt, argv, a.connection())
		if err != nil {
			return nil, err
		}
		if result.ExitCode != 0 {
			// The pinned ret["retcode"] != 0 → False, compatibility data:
			// a rejected ALTER is the boolean false, never an error, and
			// the flow stops so no later mutation follows a failed one.
			return false, nil
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// tablespace_list / tablespace_exists — salt/modules/postgres.py:768-837 @
// pinned revision.

type tablespaceListFunc struct{}

func (tablespaceListFunc) Name() string { return "postgres.tablespace_list" }
func (tablespaceListFunc) Args() any    { return ListArgs{} }

func (tablespaceListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListArgs](args, "postgres.tablespace_list")
	if err != nil {
		return nil, err
	}
	return nameKeyedCatalog(ctx, rt, a.connection(), tablespaceListQuery, "postgres.tablespace_list")
}

type tablespaceExistsFunc struct{}

func (tablespaceExistsFunc) Name() string { return "postgres.tablespace_exists" }
func (tablespaceExistsFunc) Args() any    { return ExistsArgs{} }

func (tablespaceExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.tablespace_exists")
	if err != nil {
		return nil, err
	}
	tablespaces, err := nameKeyedCatalog(ctx, rt, a.connection(), tablespaceListQuery, "postgres.tablespace_exists")
	if err != nil {
		return nil, err
	}
	_, exists := tablespaces[a.Name]
	return exists, nil
}

// ---------------------------------------------------------------------------
// tablespace_create / tablespace_alter / tablespace_remove —
// salt/modules/postgres.py:840-886, 889-947, 950-980 @ pinned revision.

// TablespaceCreateArgs are the canonical postgres.tablespace_create
// arguments, mirroring the pinned tablespace_create(name, location,
// options=None, owner=None, user, host, port, maintenance_db, password,
// runas) signature (postgres.py:840-851). options keeps Salt's None
// default as a nil map (an explicit empty map is the pinned falsy empty
// dict and omits the WITH clause entirely), and owner keeps the pinned
// truthiness: nil and the explicit empty string both omit the clause.
type TablespaceCreateArgs struct {
	Name          string            `statekit:"name=name,required"`
	Location      string            `statekit:"name=location,required"`
	Options       map[string]string `statekit:"name=options"`
	Owner         *string           `statekit:"name=owner"`
	User          *string           `statekit:"name=user"`
	Host          *string           `statekit:"name=host"`
	Port          *string           `statekit:"name=port"`
	MaintenanceDB *string           `statekit:"name=maintenance_db"`
	Password      *string           `statekit:"name=password"`
	Runas         *string           `statekit:"name=runas"`
}

func (a *TablespaceCreateArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// validateTablespaceLocation enforces the StateKit LOCATION boundary. The
// pinned format string interpolates the location raw into a single-quoted
// SQL literal with no escaping, so beyond the shared quote rejection the
// port requires an absolute path that is already clean (path.Clean
// equality rejects dot and dot-dot segments, redundant separators, and
// trailing slashes) and carries no control bytes, keeping the fixed
// statement shape unalterable. The rejection is value-free.
func validateTablespaceLocation(location string) error {
	if !strings.HasPrefix(location, "/") || location != path.Clean(location) {
		return errPostgresInvalidLocation
	}
	for i := 0; i < len(location); i++ {
		if location[i] < 0x20 || location[i] == 0x7f {
			return errPostgresInvalidLocation
		}
	}
	if strings.Contains(location, "'") {
		// The single-quoted literal context has no escaping in the pinned
		// source; the only character that can escape it is rejected with
		// the shared quote error naming the argument key.
		return ddlValidationError("location")
	}
	return nil
}

// tablespaceOptionsQuery renders the pinned options tail: the pinned
// "WITH ( {} )".format(", ".join("{k} = {v}")) — byte-for-byte including
// the spaces inside the parentheses. Python joins dict items in insertion
// order; a Go map has none, so the port fixes the deterministic sorted-key
// order instead (the only ordering deviation, shared with the mdadm and
// extfs options maps). The pinned source interpolates every key and value
// raw with no quoting, so both must stay inside the bare token classes —
// keys are bare PostgreSQL identifiers like db_create's TEMPLATE, values
// bare version-class tokens like the extension version strings — and each
// rejection is value-free.
func tablespaceOptionsQuery(options map[string]string) (string, error) {
	if len(options) == 0 {
		// The pinned truthy-dict gate: None and the empty dict both keep
		// the tail empty.
		return "", nil
	}
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	chunks := make([]string, 0, len(keys))
	for _, key := range keys {
		if !bareIdentifierRE.MatchString(key) {
			return "", errPostgresInvalidOptionName
		}
		if !bareVersionRE.MatchString(options[key]) {
			return "", errPostgresInvalidOptionValue
		}
		chunks = append(chunks, key+" = "+options[key])
	}
	return "WITH ( " + strings.Join(chunks, ", ") + " )", nil
}

// tablespaceCreateQuery ports the pinned statement construction
// (postgres.py:863-874): the fixed head, the truthy OWNER clause, the
// LOCATION literal, and the truthy WITH options tail, joined by the
// pinned format string exactly — including the double space before
// LOCATION when the OWNER clause is absent and the trailing space when
// the options tail is empty, both of which the pinned test asserts. Every
// validation runs here, before any Runner invocation, and every rejection
// is value-free.
func tablespaceCreateQuery(a *TablespaceCreateArgs) (string, error) {
	if strings.Contains(a.Name, `"`) {
		// The pinned head formats the name into double quotes unescaped.
		return "", ddlValidationError("name")
	}
	if err := validateTablespaceLocation(a.Location); err != nil {
		return "", err
	}
	ownerQuery := ""
	if a.Owner != nil && *a.Owner != "" {
		// The pinned if owner: gate — Python truthiness makes the explicit
		// empty string the same as None.
		if strings.Contains(*a.Owner, `"`) {
			return "", ddlValidationError("owner")
		}
		ownerQuery = `OWNER "` + *a.Owner + `"`
	}
	optionsQuery, err := tablespaceOptionsQuery(a.Options)
	if err != nil {
		return "", err
	}
	return `CREATE TABLESPACE "` + a.Name + `" ` + ownerQuery +
		` LOCATION '` + a.Location + `' ` + optionsQuery, nil
}

type tablespaceCreateFunc struct{}

func (tablespaceCreateFunc) Name() string { return "postgres.tablespace_create" }
func (tablespaceCreateFunc) Args() any    { return TablespaceCreateArgs{} }

// Execute ports the pinned tablespace_create flow (postgres.py:876-886):
// exactly one fixed CREATE TABLESPACE statement over the central
// maintenance-database connection with no test mode and no existence
// preflight (tablespace_exists is never consulted), and the pinned tail
// ret["retcode"] == 0 — a rejected CREATE is the boolean false, never an
// exception.
func (tablespaceCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[TablespaceCreateArgs](args, "postgres.tablespace_create")
	if err != nil {
		return nil, err
	}
	query, err := tablespaceCreateQuery(a)
	if err != nil {
		return nil, err
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// TablespaceAlterArgs are the canonical postgres.tablespace_alter
// arguments, mirroring the pinned tablespace_alter(name, user, host,
// port, maintenance_db, password, new_name, new_owner, set_option,
// reset_option, runas) signature (postgres.py:889-901). Pointer fields
// keep Salt's None defaults and the map keeps the None dict default; the
// pinned truthiness head treats nil and explicit empty values alike.
type TablespaceAlterArgs struct {
	Name          string            `statekit:"name=name,required"`
	User          *string           `statekit:"name=user"`
	Host          *string           `statekit:"name=host"`
	Port          *string           `statekit:"name=port"`
	MaintenanceDB *string           `statekit:"name=maintenance_db"`
	Password      *string           `statekit:"name=password"`
	NewName       *string           `statekit:"name=new_name"`
	NewOwner      *string           `statekit:"name=new_owner"`
	SetOption     map[string]string `statekit:"name=set_option"`
	ResetOption   *string           `statekit:"name=reset_option"`
	Runas         *string           `statekit:"name=runas"`
}

func (a *TablespaceAlterArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type tablespaceAlterFunc struct{}

func (tablespaceAlterFunc) Name() string { return "postgres.tablespace_alter" }
func (tablespaceAlterFunc) Args() any    { return TablespaceAlterArgs{} }

// Execute ports the pinned tablespace_alter flow (postgres.py:916-947):
// the pinned any([new_name, new_owner, set_option, reset_option]) head
// answers the no-op True with no Runner invocation when no argument
// carries a truthy value (Python truthiness: nil, the explicit empty
// string, and the empty map all select nothing); otherwise the pinned
// clause order — RENAME TO, OWNER TO, SET, RESET — runs one statement per
// truthy argument, each through the same central maintenance-database
// connection, and the pinned ret["retcode"] != 0 return False aborts at
// the first failed statement so no later mutation follows a failed one.
// The pinned set_option branch reads only next(iter(set_option.items()))
// — the first inserted pair — which a Go map cannot reproduce, so exactly
// one entry is accepted and more is the fixed value-free ambiguity
// rejection above. The identifier positions the pinned format strings
// interpolate into double quotes without escaping (name, new_name,
// new_owner) and the raw option tokens are validated fail-closed with
// value-free errors before any Runner invocation, exactly like the
// create-side boundary.
func (tablespaceAlterFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[TablespaceAlterArgs](args, "postgres.tablespace_alter")
	if err != nil {
		return nil, err
	}
	newName := a.NewName != nil && *a.NewName != ""
	newOwner := a.NewOwner != nil && *a.NewOwner != ""
	setOption := len(a.SetOption) > 0
	resetOption := a.ResetOption != nil && *a.ResetOption != ""
	if !newName && !newOwner && !setOption && !resetOption {
		// The pinned "Nothing todo?" early True of the any([...]) head: no
		// Runner invocation.
		return true, nil
	}
	if strings.Contains(a.Name, `"`) {
		return nil, ddlValidationError("name")
	}
	var queries []string
	if newName {
		if strings.Contains(*a.NewName, `"`) {
			return nil, ddlValidationError("new_name")
		}
		queries = append(queries, `ALTER TABLESPACE "`+a.Name+`" RENAME TO "`+*a.NewName+`"`)
	}
	if newOwner {
		if strings.Contains(*a.NewOwner, `"`) {
			return nil, ddlValidationError("new_owner")
		}
		queries = append(queries, `ALTER TABLESPACE "`+a.Name+`" OWNER TO "`+*a.NewOwner+`"`)
	}
	if setOption {
		if len(a.SetOption) != 1 {
			return nil, errPostgresTablespaceSetOption
		}
		var key, value string
		for k, v := range a.SetOption {
			key, value = k, v
		}
		if !bareIdentifierRE.MatchString(key) {
			return nil, errPostgresInvalidOptionName
		}
		if !bareVersionRE.MatchString(value) {
			return nil, errPostgresInvalidOptionValue
		}
		queries = append(queries, `ALTER TABLESPACE "`+a.Name+`" SET (`+key+` = `+value+`)`)
	}
	if resetOption {
		if !bareIdentifierRE.MatchString(*a.ResetOption) {
			return nil, errPostgresInvalidOptionName
		}
		queries = append(queries, `ALTER TABLESPACE "`+a.Name+`" RESET (`+*a.ResetOption+`)`)
	}
	for _, query := range queries {
		argv := psqlArgv(
			pointerString(a.User),
			pointerString(a.Host),
			pointerString(a.Port),
			pointerString(a.MaintenanceDB),
			"-c", query,
		)
		result, err := runPsql(ctx, rt, argv, a.connection())
		if err != nil {
			return nil, err
		}
		if result.ExitCode != 0 {
			// The pinned ret["retcode"] != 0 → False, compatibility data:
			// a rejected ALTER is the boolean false, never an error, and
			// the flow stops so no later mutation follows a failed one.
			return false, nil
		}
	}
	return true, nil
}

// TablespaceRemoveArgs are the canonical postgres.tablespace_remove
// arguments, mirroring the pinned tablespace_remove(name, user, host,
// port, maintenance_db, password, runas) signature
// (postgres.py:950-958).
type TablespaceRemoveArgs struct {
	Name          string  `statekit:"name=name,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *TablespaceRemoveArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type tablespaceRemoveFunc struct{}

func (tablespaceRemoveFunc) Name() string { return "postgres.tablespace_remove" }
func (tablespaceRemoveFunc) Args() any    { return TablespaceRemoveArgs{} }

// Execute ports the pinned tablespace_remove flow
// (postgres.py:970-980): exactly one fixed DROP TABLESPACE statement —
// the pinned form carries no trailing semicolon — over the central
// maintenance-database connection with no existence preflight
// (tablespace_exists/tablespace_list are never consulted, so a missing
// tablespace is a server-side rejection that lands in the retcode
// boolean), and the pinned tail ret["retcode"] == 0: a rejected DROP is
// the boolean false, never an exception. The name is validated for its
// double-quoted identifier context up front because the pinned format
// string interpolates it raw, with the shared value-free rejection.
func (tablespaceRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[TablespaceRemoveArgs](args, "postgres.tablespace_remove")
	if err != nil {
		return nil, err
	}
	if strings.Contains(a.Name, `"`) {
		return nil, ddlValidationError("name")
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", `DROP TABLESPACE "`+a.Name+`"`,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// datadir_exists / datadir_init — salt/modules/postgres.py:4300-4393 @
// pinned revision (_run_initdb: postgres.py:236-306).

// DataDirExistsArgs are the canonical postgres.datadir_exists arguments:
// the pinned datadir_exists(name) signature (postgres.py:4375-4393).
type DataDirExistsArgs struct {
	Name string `statekit:"name=name,required"`
}

// datadirMarkerFiles are the two regular files the pinned datadir_exists
// requires (postgres.py:4390-4393): PG_VERSION and postgresql.conf, joined
// onto the caller's name with os.path.join.
var datadirMarkerFiles = []string{"PG_VERSION", "postgresql.conf"}

type datadirExistsFunc struct{}

func (datadirExistsFunc) Name() string { return "postgres.datadir_exists" }
func (datadirExistsFunc) Args() any    { return DataDirExistsArgs{} }

// Execute ports the pinned datadir_exists
// (postgres.py:4390-4393): os.path.isfile over name/PG_VERSION and
// name/postgresql.conf, both required. The probe is read-only, runs
// entirely through Runtime.FS, and never touches a Runner or a live
// PostgreSQL. StateKit replaces the follow-symlink os.path.isfile with a
// no-follow Lstat plus the regular-file mode check: the marker must be a
// regular file itself, not a symlink to one, so a planted link cannot
// satisfy the preflight datadir_init gates on. Every Lstat outcome the
// caller cannot distinguish from a miss — absent path, non-directory
// parent, permission error — answers the pinned boolean False exactly like
// os.path.isfile swallows OSError, never an error. Only the value-free
// path validation rejects before the filesystem.
func (datadirExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, err := typedArgs[DataDirExistsArgs](args, "postgres.datadir_exists")
	if err != nil {
		return nil, err
	}
	if err := validateDataDirPath(a.Name, errPostgresInvalidDataDirPath); err != nil {
		return nil, err
	}
	return dataDirExists(rt, a.Name), nil
}

// dataDirExists answers the pinned marker-file question over Runtime.FS.
// The nil-FS guard keeps the probe fail-closed like the Runner
// unavailability guard instead of panicking on a misbuilt runtime.
func dataDirExists(rt *runtime.Runtime, name string) bool {
	if rt == nil || rt.FS == nil {
		return false
	}
	for _, marker := range datadirMarkerFiles {
		info, err := rt.FS.Lstat(path.Join(name, marker))
		if err != nil || !info.Mode().IsRegular() {
			// The pinned os.path.isfile maps every stat failure to False.
			return false
		}
	}
	return true
}

// DataDirInitArgs are the canonical postgres.datadir_init arguments,
// mirroring the pinned datadir_init(name, auth="password", user=None,
// password=None, encoding="UTF8", locale=None, waldir=None,
// checksums=False, runas=None) signature (postgres.py:4300-4310). Pointer
// fields keep Salt's None defaults: nil auth/encoding keep the pinned
// literal defaults, nil locale/waldir/password omit their argv entries,
// and nil checksums is the pinned False.
type DataDirInitArgs struct {
	Name      string  `statekit:"name=name,required"`
	Auth      *string `statekit:"name=auth"`
	User      *string `statekit:"name=user"`
	Password  *string `statekit:"name=password"`
	Encoding  *string `statekit:"name=encoding"`
	Locale    *string `statekit:"name=locale"`
	WalDir    *string `statekit:"name=waldir"`
	Checksums *bool   `statekit:"name=checksums"`
	Runas     *string `statekit:"name=runas"`
}

type datadirInitFunc struct{}

func (datadirInitFunc) Name() string { return "postgres.datadir_init" }
func (datadirInitFunc) Args() any    { return DataDirInitArgs{} }

// Execute ports the pinned datadir_init flow (postgres.py:4356-4372): the
// datadir_exists preflight answers the logged-and-False no-op for an
// initialized directory with no initdb invocation, and otherwise one
// initdb execution through the central shell-free Runner whose pinned
// tail ret["retcode"] == 0 makes a rejected initdb the boolean false,
// never an error. initdb itself — never a live PostgreSQL — is the only
// executable; no psql, driver, or network egress exists on this path.
// runas is rejected before any observable action (the single-user runtime
// has no elevation contract, so Salt's implicit runas elevation does not
// apply — the pinned kernel-mapped runas default still names the
// --username superuser through initdbDefaultUser), and the process-wide
// test mode is the no-mutation
// contract: it answers nil (Salt's postgres_initdb state renders that as
// "set to be initialized") after the read-only preflight, with no pwfile
// written and no Runner invocation.
func (datadirInitFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, err := typedArgs[DataDirInitArgs](args, "postgres.datadir_init")
	if err != nil {
		return nil, err
	}
	if err := validateDataDirPath(a.Name, errPostgresInvalidDataDirPath); err != nil {
		return nil, err
	}
	if a.WalDir != nil && *a.WalDir != "" {
		if err := validateDataDirPath(*a.WalDir, errPostgresInvalidWalDirPath); err != nil {
			return nil, err
		}
	}
	// runas is rejected before the read-only preflight: no observable
	// action may run on behalf of another user.
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	if rt == nil || rt.FS == nil {
		return nil, errPostgresFSUnavailable
	}
	if dataDirExists(rt, a.Name) {
		// The pinned datadir_exists(name) head: "%s already exists",
		// return False — a logged no-op, never an error.
		return false, nil
	}
	if rt.Options.Test {
		// Dry-run: the pinned flow would initialize; nil is the tri-state
		// "would change" answer (the pkg/file test-mode convention), with
		// no pwfile write and no Runner invocation.
		return nil, nil
	}
	argv, cleanup, err := datadirInitArgv(rt, a)
	if err != nil {
		return nil, err
	}
	result, err := runInitdb(ctx, rt, argv, a.Password)
	if cleanup != nil {
		// The pinned flow removes the password file after initdb runs
		// (postgres.py:303-304) on every path. The pinned source only
		// logs a removal failure; StateKit has no logging surface and
		// silently leaving credential bytes on disk is the strictly worse
		// outcome, so a cleanup failure is the fail-closed
		// errPostgresPwfileCleanup — superseded only by a primary Runner
		// error, whose sentinel semantics (cancellation, output limits)
		// must stay observable.
		if cleanupErr := cleanup(); err == nil {
			err = cleanupErr
		}
	}
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// datadirInitArgv ports the pinned _run_initdb argv construction
// (postgres.py:263-288) in the pinned order: --pgdata, --username,
// --auth, --encoding, then the optional --locale, the pinned short -X
// waldir pair (the long option was renamed xlogdir→waldir in PostgreSQL
// 10, which is why the source pins -X), --data-checksums, and finally
// --pwfile. user keeps the pinned resolution: the pinned helper defaults
// runas per kernel (postgres everywhere except OpenBSD's _postgresql
// service account) and user to runas, so an omitted user is that
// kernel-mapped superuser name (the explicit runas itself is rejected by
// the single-user runtime before this point). The pinned waldir is not
// None gate appends the -X pair for an explicit empty string too, exactly
// like the source. When a password is supplied its bytes travel through a
// Runtime.FS temp file — the pinned pwfile transport — and the returned
// cleanup removes it; the password itself never enters argv, the
// environment, or the rendered command.
func datadirInitArgv(rt *runtime.Runtime, a *DataDirInitArgs) ([]string, func() error, error) {
	// user keeps the pinned is-None resolution: the pinned helper defaults
	// runas per kernel and user to runas, so an omitted user is the
	// kernel-mapped superuser name while an explicit empty string keeps
	// the pinned --username= shape.
	user := initdbDefaultUser(rt)
	if a.User != nil {
		user = *a.User
	}
	// The pinned signature defaults apply only to an omitted argument; an
	// explicit empty string keeps Salt's --auth=/--encoding= shape.
	auth := "password"
	if a.Auth != nil {
		auth = *a.Auth
	}
	encoding := "UTF8"
	if a.Encoding != nil {
		encoding = *a.Encoding
	}
	argv := []string{
		initdbCommand,
		"--pgdata=" + a.Name,
		"--username=" + user,
		"--auth=" + auth,
		"--encoding=" + encoding,
	}
	if a.Locale != nil {
		argv = append(argv, "--locale="+*a.Locale)
	}
	if a.WalDir != nil {
		// The pinned short option, deliberately: see the function comment.
		argv = append(argv, "-X", *a.WalDir)
	}
	if pointerBool(a.Checksums) {
		argv = append(argv, "--data-checksums")
	}
	var cleanup func() error
	if a.Password != nil {
		pwfile, remove, err := writeInitdbPwfile(rt, *a.Password)
		if err != nil {
			return nil, nil, err
		}
		argv = append(argv, "--pwfile="+pwfile)
		cleanup = remove
	}
	return argv, cleanup, nil
}

// initdbDefaultUser ports the pinned runas default resolution of
// _run_initdb (postgres.py:250-256): FreeBSD and every unlisted kernel
// resolve postgres while OpenBSD resolves its _postgresql service
// account, and the pinned user then defaults to that runas. The
// runtime's Facts OS family is the StateKit equivalent of the pinned
// os_family grain; a runtime without Facts falls back to the compile-time
// GOOS the platform helper exposes — on a real OpenBSD host both answer
// openbsd. The mapping is argv-only: no native initdb execution is
// claimed for any kernel, and an explicit user argument always overrides
// the default.
func initdbDefaultUser(rt *runtime.Runtime) string {
	family := runtime.CurrentGOOS()
	if rt != nil && rt.Facts != nil {
		family = rt.Facts.OS().Family
	}
	if family == facts.FamilyOpenBSD {
		return "_postgresql"
	}
	return "postgres"
}

// writeInitdbPwfile ports the pinned pwfile half of _run_initdb
// (postgres.py:283-288): the password is written to a fresh private temp
// location and removed after initdb runs. Salt writes a mkstemp file and
// chowns it to the runas user; the StateKit runtime is single-user, so
// the file keeps its 0600 mode inside a 0700 temp directory owned by the
// runtime user and no chown exists. The file holds exactly the password
// bytes the pinned fp_.write(f"{password}") leaves — no trailing newline.
// Every preparation failure surfaces as a fixed value-free category
// (errPostgresPwfileTempDir/errPostgresPwfileWrite): the raw filesystem
// errors name the temp path and a faulting filesystem may echo arbitrary
// bytes, so neither can travel through the returned error. A partial
// write whose RemoveAll cleanup also fails joins the write category with
// errPostgresPwfileCleanup so the stranded credential stays observable
// without hiding the primary category.
func writeInitdbPwfile(rt *runtime.Runtime, password string) (string, func() error, error) {
	dir, err := rt.FS.MkdirTemp("", "statekit-postgres-pwfile-")
	if err != nil {
		return "", nil, errPostgresPwfileTempDir
	}
	pwfile := path.Join(dir, "pwfile")
	if err := rt.FS.WriteFile(pwfile, []byte(password), 0o600); err != nil {
		if rmErr := rt.FS.RemoveAll(dir); rmErr != nil {
			return "", nil, errors.Join(errPostgresPwfileWrite, errPostgresPwfileCleanup)
		}
		return "", nil, errPostgresPwfileWrite
	}
	remove := func() error {
		if err := rt.FS.RemoveAll(dir); err != nil {
			return errPostgresPwfileCleanup
		}
		return nil
	}
	return pwfile, remove, nil
}

// runInitdb ports the pinned _run_initdb execution half
// (postgres.py:290-298): the argv travels through the central shell-free
// Runner (Salt's shlex.join string plus python_shell=False becomes the
// direct argv the Runner contract already enforces) with the pinned
// clean_env=True — a clean empty environment, because initdb reads its
// credentials from the pwfile, not the environment — the finite 30s
// timeout ceiling, bounded output, and the password as a Redact secret so
// neither the rendered command, captured output, nor returned errors can
// leak it. A non-zero initdb exit stays compatibility data exactly like
// the pinned retcode return.
func runInitdb(ctx context.Context, rt *runtime.Runtime, argv []string, password *string) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errPostgresRunnerUnavailable
	}
	if err := validateArgv(argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if available, ok := rt.Runner.(process.CommandAvailability); ok && !available.CommandAvailable(initdbCommand) {
		// Fail closed: like psql, initdb has no package-manager or other
		// fallback discovery in this module.
		return process.CommandResult{ExitCode: -1}, errPostgresInitdbUnavailable
	}
	var secrets []string
	if password != nil {
		secrets = append(secrets, *password)
	}
	secrets = secretList(secrets...)
	command := process.Command{
		Name:           argv[0],
		Args:           append([]string(nil), argv[1:]...),
		Timeout:        commandTimeout,
		MaxStdoutBytes: outputLimit,
		MaxStderrBytes: outputLimit,
		Env:            []string{},
	}
	if len(secrets) > 0 {
		command.Redact = secretList(secrets...)
	}
	result := rt.Runner.Run(ctx, command)
	outputExceeded := len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit
	// Defend against custom Runners that do not sanitize their own results.
	result.Stdout = process.RedactBytes(secrets, result.Stdout)
	result.Stderr = process.RedactBytes(secrets, result.Stderr)
	if result.Err != nil {
		result.Err = redactedError(result.Err, secrets...)
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated || outputExceeded {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// user_list — salt/modules/postgres.py:986-1101 @ pinned revision.

// UserListArgs are the canonical postgres.user_list arguments, mirroring
// the pinned signature including return_password=False.
type UserListArgs struct {
	User           *string `statekit:"name=user"`
	Host           *string `statekit:"name=host"`
	Port           *string `statekit:"name=port"`
	MaintenanceDB  *string `statekit:"name=maintenance_db"`
	Password       *string `statekit:"name=password"`
	Runas          *string `statekit:"name=runas"`
	ReturnPassword bool    `statekit:"name=return_password"`
}

func (a *UserListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type userListFunc struct{}

func (userListFunc) Name() string { return "postgres.user_list" }
func (userListFunc) Args() any    { return UserListArgs{} }

func (userListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserListArgs](args, "postgres.user_list")
	if err != nil {
		return nil, err
	}
	return userCatalog(ctx, rt, a.connection(), a.ReturnPassword)
}

// userCatalog keeps the same connection (including preflight secrets)
// for both the version and catalog commands.
func userCatalog(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, returnPassword bool) (any, error) {
	ver, err := parsedServerVersion(ctx, rt, conn)
	if err != nil {
		return nil, err
	}
	if ver == nil {
		// The pinned user_list returns False when the version probe cannot
		// reach a server (after logging an error); the boolean is the
		// compatibility result, not an exception.
		return false, nil
	}
	replicationColumn := "NULL"
	if order, ok := ver.compare(parseLooseVersion("9.1")); ok && order >= 0 {
		replicationColumn = "pg_roles.rolreplication"
	}
	rolcatupdateColumn := "pg_roles.rolcatupdate"
	if order, ok := ver.compare(parseLooseVersion("9.5")); ok && order >= 0 {
		rolcatupdateColumn = "NULL"
	}
	query := strings.Replace(userListQueryPrefix, "{0}", rolcatupdateColumn, 1)
	query = strings.Replace(query, "{1}", replicationColumn, 1)
	if returnPassword {
		// Salt's _x() appends the password select and its two LEFT JOINs
		// only when return_password is set, before and after FROM.
		query += userListPasswordSelect
	}
	query += userFromClause
	if returnPassword {
		query += userListAuthidJoin + userListShadowJoin
	}
	rows, err := psqlQueryRows(ctx, rt, conn, query)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(rows))
	for _, row := range rows {
		retrow := map[string]any{}
		for _, key := range []string{
			"superuser",
			"inherits privileges",
			"can create roles",
			"can create databases",
			"can update system catalogs",
			"can login",
			"replication",
			"connections",
		} {
			value, err := rowString(row, key, "postgres.user_list")
			if err != nil {
				return nil, err
			}
			retrow[key] = looseBool(value)
		}
		expiry, err := rowString(row, "expiry time", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		// The pinned strptime except ValueError maps any unparseable
		// value to None rather than an error.
		retrow["expiry time"] = nil
		if parsed, perr := time.Parse(expiryTimeLayout, expiry); perr == nil {
			retrow["expiry time"] = parsed
		}
		defaults, err := rowString(row, "defaults variables", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		retrow["defaults variables"] = defaults
		if returnPassword {
			password, err := rowString(row, "password", "postgres.user_list")
			if err != nil {
				return nil, err
			}
			retrow["password"] = password
		}
		groups, err := rowString(row, "groups", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		// use csv reader to handle quoted roles correctly
		retrow["groups"], err = parseGroups(groups)
		if err != nil {
			return nil, err
		}
		name, err := rowString(row, "name", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		out[name] = retrow
	}
	return out, nil
}

// rowString fetches a column, mapping Salt's KeyError to an error.
func rowString(row map[string]string, key, name string) (string, error) {
	value, ok := row[key]
	if !ok {
		return "", fmt.Errorf("%s: missing column %q", name, key)
	}
	return value, nil
}

// looseBool ports the pinned get_bool: "t" is true, "f" is false, and
// anything else (including NULL's empty CSV field) is None.
func looseBool(value string) any {
	switch value {
	case "t":
		return true
	case "f":
		return false
	default:
		return nil
	}
}

// parseGroups ports the pinned groups decode (postgres.py:1097-1098):
// strip the PostgreSQL array braces with the pinned str.strip("{}")
// semantics, then decode the first csv.reader record over that single line.
// The pinned reader is the non-strict Python machine (pyCSVReader), so
// backslash-escaped array elements decode exactly like the pinned
// list(csv.reader([row["groups"].strip("{}")]))[0]: {"a\"b","x\\y"} is
// ["a\b\"", "x\\y"], doubled quotes collapse, NUL bytes are data, and a bare
// CR/LF outside quotes is the pinned csv.Error. An empty literal ({}, or a
// NULL groups column) is the empty list, matching the empty first record the
// pinned single-line reader returns.
func parseGroups(value string) ([]string, error) {
	record, err := newPyCSVRecordReader(strings.Trim(value, "{}")).next()
	if err != nil {
		return nil, fmt.Errorf("postgres: csv parse: %w", err)
	}
	return record, nil
}

// ---------------------------------------------------------------------------
// available_extensions / installed_extensions and views —
// salt/modules/postgres.py:1654-1846 @ pinned revision.

// availableExtensions ports the pinned available_extensions tail
// (postgres.py:1679-1682): every row carrying both the "name" and
// "default_version" columns is stored under its name with the whole row
// preserved — no column is removed, unlike db_list's Name pop.
func availableExtensions(ctx context.Context, rt *runtime.Runtime, conn *pgConnection) (map[string]map[string]string, error) {
	return extensionCatalog(ctx, rt, conn, availableExtensionsQuery,
		"name", "default_version", "postgres.available_extensions")
}

// installedExtensions ports the pinned installed_extensions tail
// (postgres.py:1712-1716): every row carrying both the "extname" and
// "extversion" columns is stored under its extension name.
func installedExtensions(ctx context.Context, rt *runtime.Runtime, conn *pgConnection) (map[string]map[string]string, error) {
	return extensionCatalog(ctx, rt, conn, installedExtensionsQuery,
		"extname", "extversion", "postgres.installed_extensions")
}

// extensionCatalog is the shared pinned loop behind available_extensions
// and installed_extensions: rows whose dict(zip(header,row)) shape lacks
// either key column are skipped exactly like the pinned
// `if "..." in row and "..." in row` guard; matching rows keep every
// column under their name value.
func extensionCatalog(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, query, nameColumn, versionColumn, name string) (map[string]map[string]string, error) {
	rows, err := psqlQueryRows(ctx, rt, conn, query)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]string, len(rows))
	for _, row := range rows {
		key, hasName := row[nameColumn]
		if _, hasVersion := row[versionColumn]; !hasName || !hasVersion {
			continue
		}
		out[key] = row
	}
	return out, nil
}

type availableExtensionsFunc struct{}

func (availableExtensionsFunc) Name() string { return "postgres.available_extensions" }
func (availableExtensionsFunc) Args() any    { return ListArgs{} }

func (availableExtensionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListArgs](args, "postgres.available_extensions")
	if err != nil {
		return nil, err
	}
	return availableExtensions(ctx, rt, a.connection())
}

type installedExtensionsFunc struct{}

func (installedExtensionsFunc) Name() string { return "postgres.installed_extensions" }
func (installedExtensionsFunc) Args() any    { return ListArgs{} }

func (installedExtensionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListArgs](args, "postgres.installed_extensions")
	if err != nil {
		return nil, err
	}
	return installedExtensions(ctx, rt, a.connection())
}

type getAvailableExtensionFunc struct{}

func (getAvailableExtensionFunc) Name() string { return "postgres.get_available_extension" }
func (getAvailableExtensionFunc) Args() any    { return ExistsArgs{} }

func (getAvailableExtensionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.get_available_extension")
	if err != nil {
		return nil, err
	}
	// The pinned function is available_extensions(...).get(name, None): an
	// exact-case key lookup whose miss is None, never an error.
	extensions, err := availableExtensions(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	if row, ok := extensions[a.Name]; ok {
		return row, nil
	}
	return nil, nil
}

type getInstalledExtensionFunc struct{}

func (getInstalledExtensionFunc) Name() string { return "postgres.get_installed_extension" }
func (getInstalledExtensionFunc) Args() any    { return ExistsArgs{} }

func (getInstalledExtensionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.get_installed_extension")
	if err != nil {
		return nil, err
	}
	// The pinned .get(name, None) over the installed catalog.
	installed, err := installedExtensions(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	if row, ok := installed[a.Name]; ok {
		return row, nil
	}
	return nil, nil
}

type isAvailableExtensionFunc struct{}

func (isAvailableExtensionFunc) Name() string { return "postgres.is_available_extension" }
func (isAvailableExtensionFunc) Args() any    { return ExistsArgs{} }

func (isAvailableExtensionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.is_available_extension")
	if err != nil {
		return nil, err
	}
	// The pinned membership test lowercases both sides —
	// name.lower() in [a.lower() for a in exts] — so the lookup is
	// case-insensitive over the catalog keys, client-side only.
	extensions, err := availableExtensions(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	want := strings.ToLower(a.Name)
	for key := range extensions {
		if strings.ToLower(key) == want {
			return true, nil
		}
	}
	return false, nil
}

type isInstalledExtensionFunc struct{}

func (isInstalledExtensionFunc) Name() string { return "postgres.is_installed_extension" }
func (isInstalledExtensionFunc) Args() any    { return ExistsArgs{} }

func (isInstalledExtensionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.is_installed_extension")
	if err != nil {
		return nil, err
	}
	// The pinned bool(get_installed_extension(...)) is the exact-case
	// lookup's truthiness: bool(None) is false and a stored row is never
	// empty (the pinned filter guarantees both key columns), so len>0 is
	// the bool(dict) port.
	return extensionInstalled(ctx, rt, a.connection(), a.Name)
}

// extensionInstalled is the shared bool(get_installed_extension(...))
// preflight and post-check of the extension mutations: the exact-case
// installed-catalog lookup's truthiness over one catalog call.
func extensionInstalled(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, name string) (bool, error) {
	installed, err := installedExtensions(ctx, rt, conn)
	if err != nil {
		return false, err
	}
	return len(installed[name]) > 0, nil
}

// ---------------------------------------------------------------------------
// create_extension / drop_extension / create_metadata —
// salt/modules/postgres.py:1895-1962, 1965-2063, 1849-1892 @ pinned
// revision.

// The pinned extension lifecycle flags (postgres.py:76-84): the exact
// strings create_metadata returns and create_extension tests against.
const (
	extFlagNotInstalled = "EXTENSION NOT INSTALLED"
	extFlagInstalled    = "EXTENSION INSTALLED"
	extFlagToUpgrade    = "EXTENSION TO UPGRADE"
	extFlagToMove       = "EXTENSION TO MOVE"
)

// extFlagIn is the pinned `flag in mtdata` list membership.
func extFlagIn(flags []string, flag string) bool {
	for _, candidate := range flags {
		if candidate == flag {
			return true
		}
	}
	return false
}

// isOlderExtVer ports the pinned _pg_is_older_ext_ver
// (postgres.py:1809-1815): LooseVersion(a) < LooseVersion(b) on the
// internal LooseVersion port, whose comparison is defined for every
// string pair like Salt's.
func isOlderExtVer(a, b string) bool {
	order, _ := parseLooseVersion(a).compare(parseLooseVersion(b))
	return order < 0
}

// createMetadata ports the pinned create_metadata (postgres.py:1849-1892):
// the exact-case installed-catalog lookup whose miss is the single
// NOT_INSTALLED flag, and whose hit starts from INSTALLED and appends
// TO_UPGRADE when the caller's ext_version is a LooseVersion-newer one and
// TO_MOVE when the installed row is relocatable and its schema differs.
// The .get fallbacks keep the pinned defaults: a missing extversion column
// falls back to the caller's ext_version and a missing schema_name column
// to the caller's schema, and both comparisons only run when the caller
// argument is not None (not when it is an empty string). Internal-only:
// the public name stays pending exactly like a later registered name, and
// create_extension and drop_extension are its only callers.
func createMetadata(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, name string, extVersion, schema *string) ([]string, error) {
	installed, err := installedExtensions(ctx, rt, conn)
	if err != nil {
		return nil, err
	}
	row, ok := installed[name]
	if !ok {
		return []string{extFlagNotInstalled}, nil
	}
	ret := []string{extFlagInstalled}
	if extVersion != nil {
		current := *extVersion
		if value, has := row["extversion"]; has {
			current = value
		}
		if isOlderExtVer(current, *extVersion) {
			ret = append(ret, extFlagToUpgrade)
		}
	}
	if schema != nil {
		relocatable := "f"
		if value, has := row["extrelocatable"]; has {
			relocatable = value
		}
		currentSchema := *schema
		if value, has := row["schema_name"]; has {
			currentSchema = value
		}
		if relocatable == "t" && currentSchema != *schema {
			ret = append(ret, extFlagToMove)
		}
	}
	return ret, nil
}

// CreateExtensionArgs are the canonical postgres.create_extension
// arguments, mirroring the pinned create_extension(name, if_not_exists,
// schema, ext_version, from_version, user, host, port, maintenance_db,
// password, runas) signature (postgres.py:1965-1977). Pointer fields keep
// Salt's None defaults: nil if_not_exists applies the pinned True default,
// and a nil schema/ext_version/from_version never triggers its metadata
// branch while an explicit empty string keeps the pinned falsy-string
// behavior (no clause, but the is-not-None metadata checks still run).
type CreateExtensionArgs struct {
	Name          string  `statekit:"name=name,required"`
	IfNotExists   *bool   `statekit:"name=if_not_exists"`
	Schema        *string `statekit:"name=schema"`
	ExtVersion    *string `statekit:"name=ext_version"`
	FromVersion   *string `statekit:"name=from_version"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *CreateExtensionArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type createExtensionFunc struct{}

func (createExtensionFunc) Name() string { return "postgres.create_extension" }
func (createExtensionFunc) Args() any    { return CreateExtensionArgs{} }

// Execute ports the pinned create_extension flow (postgres.py:1988-2063):
// the pinned if_not_exists=True default, the create_metadata preflight,
// the is_available_extension gate whose miss skips every statement, the
// CREATE branch (IF NOT EXISTS, the quoted name, and the WITH SCHEMA/
// VERSION/FROM clauses for every truthy option in the pinned order, all
// joined with the pinned space before the semicolon) or the ALTER branch
// (SET SCHEMA for TO_MOVE, UPDATE TO for TO_UPGRADE, each clause carrying
// its own semicolon), the statement's retcode ignored exactly like the
// pinned discarded return, and the final flag check answering False when
// the recomputed metadata carries any flag other than INSTALLED. The
// identifier boundary is the StateKit addition, checked before any Runner
// invocation.
func (createExtensionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[CreateExtensionArgs](args, "postgres.create_extension")
	if err != nil {
		return nil, err
	}
	if strings.Contains(a.Name, `"`) {
		return nil, ddlValidationError("name")
	}
	if a.Schema != nil && strings.Contains(*a.Schema, `"`) {
		// The schema reaches both the CREATE WITH clause and the ALTER
		// SET SCHEMA clause inside double quotes without escaping.
		return nil, ddlValidationError("schema")
	}
	if truthyString(a.ExtVersion) && !bareVersionRE.MatchString(*a.ExtVersion) {
		return nil, privIdentifierValidationError("ext_version")
	}
	if truthyString(a.FromVersion) && !bareVersionRE.MatchString(*a.FromVersion) {
		return nil, privIdentifierValidationError("from_version")
	}
	conn := a.connection()
	ifNotExists := pointerBool(a.IfNotExists) || a.IfNotExists == nil
	mtdata, err := createMetadata(ctx, rt, conn, a.Name, a.ExtVersion, a.Schema)
	if err != nil {
		return nil, err
	}
	installed := !extFlagIn(mtdata, extFlagNotInstalled)
	available, err := availableExtensions(ctx, rt, conn)
	if err != nil {
		return nil, err
	}
	// The pinned is_available_extension lowercases both sides.
	want := strings.ToLower(a.Name)
	installable := false
	for key := range available {
		if strings.ToLower(key) == want {
			installable = true
			break
		}
	}
	if installable {
		var cmd string
		if !installed {
			parts := []string{"CREATE EXTENSION"}
			if ifNotExists {
				parts = append(parts, "IF NOT EXISTS")
			}
			parts = append(parts, `"`+a.Name+`"`)
			var withArgs []string
			if truthyString(a.Schema) {
				withArgs = append(withArgs, `SCHEMA "`+*a.Schema+`"`)
			}
			if truthyString(a.ExtVersion) {
				withArgs = append(withArgs, "VERSION "+*a.ExtVersion)
			}
			if truthyString(a.FromVersion) {
				withArgs = append(withArgs, "FROM "+*a.FromVersion)
			}
			if len(withArgs) > 0 {
				parts = append(parts, "WITH")
				parts = append(parts, withArgs...)
			}
			parts = append(parts, ";")
			cmd = strings.Join(parts, " ")
		} else {
			var clauses []string
			if truthyString(a.Schema) && extFlagIn(mtdata, extFlagToMove) {
				clauses = append(clauses, `ALTER EXTENSION "`+a.Name+`" SET SCHEMA "`+*a.Schema+`";`)
			}
			if truthyString(a.ExtVersion) && extFlagIn(mtdata, extFlagToUpgrade) {
				clauses = append(clauses, `ALTER EXTENSION "`+a.Name+`" UPDATE TO `+*a.ExtVersion+`;`)
			}
			cmd = strings.Join(clauses, " ")
		}
		cmd = strings.TrimSpace(cmd)
		if cmd != "" {
			argv := psqlArgv(
				pointerString(a.User),
				pointerString(a.Host),
				pointerString(a.Port),
				pointerString(a.MaintenanceDB),
				"-c", cmd,
			)
			if _, err := runPsql(ctx, rt, argv, conn); err != nil {
				return nil, err
			}
		}
	}
	mtdata, err = createMetadata(ctx, rt, conn, a.Name, a.ExtVersion, a.Schema)
	if err != nil {
		return nil, err
	}
	ret := true
	for _, flag := range mtdata {
		if flag != extFlagInstalled {
			// The pinned loop answers False when any lifecycle flag
			// other than INSTALLED survives in the recomputed metadata.
			ret = false
		}
	}
	return ret, nil
}

// DropExtensionArgs are the canonical postgres.drop_extension arguments,
// mirroring the pinned drop_extension(name, if_exists, restrict, cascade,
// user, host, port, maintenance_db, password, runas) signature
// (postgres.py:1895-1906). Pointer fields keep Salt's None defaults: nil
// cascade applies the pinned True default while nil if_exists and
// restrict apply the pinned False defaults.
type DropExtensionArgs struct {
	Name          string  `statekit:"name=name,required"`
	IfExists      *bool   `statekit:"name=if_exists"`
	Restrict      *bool   `statekit:"name=restrict"`
	Cascade       *bool   `statekit:"name=cascade"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *DropExtensionArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type dropExtensionFunc struct{}

func (dropExtensionFunc) Name() string { return "postgres.drop_extension" }
func (dropExtensionFunc) Args() any    { return DropExtensionArgs{} }

// Execute ports the pinned drop_extension flow (postgres.py:1917-1962):
// the None defaults (cascade True, if_exists and restrict False), the
// statement built first — DROP EXTENSION, the optional IF EXISTS, the raw
// unquoted extension name, CASCADE, RESTRICT, and the pinned space before
// the semicolon, so the nonsensical default carries CASCADE — the
// is_installed_extension preflight guarding the DROP, the discarded DROP
// result, and the pinned not is_installed_extension(...) post-check
// deciding the boolean (a never-installed extension is therefore True).
// The raw-name identifier boundary is the StateKit addition, checked
// before any Runner invocation.
func (dropExtensionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DropExtensionArgs](args, "postgres.drop_extension")
	if err != nil {
		return nil, err
	}
	if !bareIdentifierRE.MatchString(a.Name) {
		// The pinned statement interpolates the extension name raw and
		// unquoted; StateKit admits only bare PostgreSQL identifiers.
		return nil, privIdentifierValidationError("name")
	}
	cascade := a.Cascade == nil || *a.Cascade
	ifExists := pointerBool(a.IfExists)
	restrict := pointerBool(a.Restrict)
	parts := []string{"DROP EXTENSION"}
	if ifExists {
		parts = append(parts, "IF EXISTS")
	}
	parts = append(parts, a.Name)
	if cascade {
		parts = append(parts, "CASCADE")
	}
	if restrict {
		parts = append(parts, "RESTRICT")
	}
	parts = append(parts, ";")
	cmd := strings.Join(parts, " ")
	conn := a.connection()
	installed, err := extensionInstalled(ctx, rt, conn, a.Name)
	if err != nil {
		return nil, err
	}
	if installed {
		argv := psqlArgv(
			pointerString(a.User),
			pointerString(a.Host),
			pointerString(a.Port),
			pointerString(a.MaintenanceDB),
			"-c", cmd,
		)
		if _, err := runPsql(ctx, rt, argv, conn); err != nil {
			return nil, err
		}
	}
	installed, err = extensionInstalled(ctx, rt, conn, a.Name)
	if err != nil {
		return nil, err
	}
	if installed {
		// The pinned "Failed to drop ext" log line has no module logging
		// surface; the False answer is the observable contract.
		return false, nil
	}
	return true, nil
}

// truthyString is the Python truthiness of Salt's optional string
// arguments: None (nil) and the empty string are both falsy, so the
// pinned `if schema:` and `if ext_version:` clause guards render no
// clause for either.
func truthyString(value *string) bool {
	return value != nil && *value != ""
}

// ---------------------------------------------------------------------------
// language_list / language_exists — salt/modules/postgres.py:2602-2695 @
// pinned revision.

// LanguageListArgs are the canonical postgres.language_list arguments,
// mirroring the pinned (maintenance_db, user, host, port, password, runas)
// signature: maintenance_db is the required positional naming the database
// to inspect.
type LanguageListArgs struct {
	MaintenanceDB string  `statekit:"name=maintenance_db,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *LanguageListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	maintenanceDB := a.MaintenanceDB
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: &maintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// LanguageExistsArgs are the canonical postgres.language_exists arguments:
// the pinned name and maintenance_db positionals plus the shared connection
// tuple.
type LanguageExistsArgs struct {
	Name          string  `statekit:"name=name,required"`
	MaintenanceDB string  `statekit:"name=maintenance_db,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *LanguageExistsArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	maintenanceDB := a.MaintenanceDB
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: &maintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// languageList ports the pinned language_list tail
// (postgres.py:2648-2651): every row is stored under its "Name" column
// mapped to itself — ret[row["Name"]] = row["Name"] — a plain name→name
// dictionary, not a row shape. Salt's KeyError on a row without the column
// maps to an error like the other catalog loops.
func languageList(ctx context.Context, rt *runtime.Runtime, conn *pgConnection) (map[string]string, error) {
	rows, err := psqlQueryRows(ctx, rt, conn, languageListQuery)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		name, ok := row["Name"]
		if !ok {
			return nil, errors.New(`postgres.language_list: missing column "Name"`)
		}
		out[name] = name
	}
	return out, nil
}

type languageListFunc struct{}

func (languageListFunc) Name() string { return "postgres.language_list" }
func (languageListFunc) Args() any    { return LanguageListArgs{} }

func (languageListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[LanguageListArgs](args, "postgres.language_list")
	if err != nil {
		return nil, err
	}
	return languageList(ctx, rt, a.connection())
}

type languageExistsFunc struct{}

func (languageExistsFunc) Name() string { return "postgres.language_exists" }
func (languageExistsFunc) Args() any    { return LanguageExistsArgs{} }

func (languageExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[LanguageExistsArgs](args, "postgres.language_exists")
	if err != nil {
		return nil, err
	}
	// The pinned `name in languages` is an exact-case membership over the
	// name→name dictionary, client-side only.
	languages, err := languageList(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	_, exists := languages[a.Name]
	return exists, nil
}

// ---------------------------------------------------------------------------
// language_create / language_remove — salt/modules/postgres.py:2698-2750,
// 2753-2805 @ pinned revision.

// LanguageMutationArgs are the canonical postgres.language_create and
// postgres.language_remove arguments: the pinned name and maintenance_db
// positionals plus the shared (user, host, port, password, runas)
// connection tuple (postgres.py:2698-2699, 2753-2754).
type LanguageMutationArgs struct {
	Name          string  `statekit:"name=name,required"`
	MaintenanceDB string  `statekit:"name=maintenance_db,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *LanguageMutationArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	maintenanceDB := a.MaintenanceDB
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: &maintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// languageMutationPreflight runs the pinned language_exists(name,
// maintenance_db) preflight of both mutations: the pinned calls pass only
// the two positionals, so every other connection argument — including the
// mutation's own user and runas — is dropped and the catalog call runs on
// the maintenance database alone.
func languageMutationPreflight(ctx context.Context, rt *runtime.Runtime, a *LanguageMutationArgs) (map[string]string, error) {
	maintenanceDB := a.MaintenanceDB
	// Retain the caller secret for redaction only, not authentication: the
	// pinned preflight drops the password along with the connection flags.
	return languageList(ctx, rt, &pgConnection{
		MaintenanceDB: &maintenanceDB,
		Secrets:       secretList(pointerString(a.Password)),
	})
}

type languageCreateFunc struct{}

func (languageCreateFunc) Name() string { return "postgres.language_create" }
func (languageCreateFunc) Args() any    { return LanguageMutationArgs{} }

// Execute ports the pinned language_create flow (postgres.py:2734-2750):
// the connection-less language_exists preflight whose hit is the
// logged-and-False no-op, the pinned CREATE LANGUAGE statement with the
// raw unquoted language name, and the ret["retcode"] == 0 boolean. The
// raw-name identifier boundary is the StateKit addition, checked before
// any Runner invocation.
func (languageCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[LanguageMutationArgs](args, "postgres.language_create")
	if err != nil {
		return nil, err
	}
	if !bareIdentifierRE.MatchString(a.Name) {
		// The pinned statement interpolates the language name raw and
		// unquoted; StateKit admits only bare PostgreSQL identifiers.
		return nil, privIdentifierValidationError("name")
	}
	languages, err := languageMutationPreflight(ctx, rt, a)
	if err != nil {
		return nil, err
	}
	if _, exists := languages[a.Name]; exists {
		// The pinned "Language %s already exists in %s" log-and-False.
		return false, nil
	}
	query := "CREATE LANGUAGE " + a.Name
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		a.MaintenanceDB,
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

type languageRemoveFunc struct{}

func (languageRemoveFunc) Name() string { return "postgres.language_remove" }
func (languageRemoveFunc) Args() any    { return LanguageMutationArgs{} }

// Execute ports the pinned language_remove flow (postgres.py:2789-2805):
// the connection-less language_exists preflight whose miss is the
// logged-and-False no-op, the pinned DROP LANGUAGE statement with the raw
// unquoted language name, and the ret["retcode"] == 0 boolean (no
// post-check exists in the pinned flow). The raw-name identifier boundary
// is the StateKit addition, checked before any Runner invocation.
func (languageRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[LanguageMutationArgs](args, "postgres.language_remove")
	if err != nil {
		return nil, err
	}
	if !bareIdentifierRE.MatchString(a.Name) {
		return nil, privIdentifierValidationError("name")
	}
	languages, err := languageMutationPreflight(ctx, rt, a)
	if err != nil {
		return nil, err
	}
	if _, exists := languages[a.Name]; !exists {
		// The pinned "Language %s does not exist in %s" log-and-False.
		return false, nil
	}
	query := "DROP LANGUAGE " + a.Name
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		a.MaintenanceDB,
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// schema_list / schema_exists / schema_get — salt/modules/postgres.py:2444-2599
// @ pinned revision.

// SchemaListArgs are the canonical postgres.schema_list arguments, mirroring
// the pinned schema-family signature (postgres.py:2539-2541): dbname is the
// required database positional, user is the pinned system-user argument
// (the psql_query runas), and db_user/db_password/db_host/db_port are the
// connection tuple. Pointer fields keep Salt's None defaults: nil omits the
// corresponding psql flag or environment variable.
type SchemaListArgs struct {
	DBName     string  `statekit:"name=dbname,required"`
	User       *string `statekit:"name=user"`
	DBUser     *string `statekit:"name=db_user"`
	DBPassword *string `statekit:"name=db_password"`
	DBHost     *string `statekit:"name=db_host"`
	DBPort     *string `statekit:"name=db_port"`
}

// connection projects the schema-family signature onto the shared psql
// transport tuple, mirroring the pinned psql_query(runas=user,
// host=db_host, user=db_user, port=db_port, maintenance_db=dbname,
// password=db_password) call (postgres.py:2583-2591).
func (a *SchemaListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	dbname := a.DBName
	return &pgConnection{
		User:          a.DBUser,
		Host:          a.DBHost,
		Port:          a.DBPort,
		MaintenanceDB: &dbname,
		Password:      a.DBPassword,
		Runas:         a.User,
	}
}

// SchemaArgs are the canonical postgres.schema_get and
// postgres.schema_exists arguments: the pinned dbname and name positionals
// plus the schema-family connection tuple.
type SchemaArgs struct {
	DBName     string  `statekit:"name=dbname,required"`
	Name       string  `statekit:"name=name,required"`
	User       *string `statekit:"name=user"`
	DBUser     *string `statekit:"name=db_user"`
	DBPassword *string `statekit:"name=db_password"`
	DBHost     *string `statekit:"name=db_host"`
	DBPort     *string `statekit:"name=db_port"`
}

func (a *SchemaArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	dbname := a.DBName
	return &pgConnection{
		User:          a.DBUser,
		Host:          a.DBHost,
		Port:          a.DBPort,
		MaintenanceDB: &dbname,
		Password:      a.DBPassword,
		Runas:         a.User,
	}
}

// schemaCatalog ports the pinned schema_list tail
// (postgres.py:2593-2597): every row is reduced to exactly the
// ("owner", "acl") pair and stored under its "name" column —
// ret[row["name"]] = retrow. Salt's KeyError on a row missing any of the
// three columns maps to an execution error in the pinned iteration order
// (owner, then acl, then the name key).
func schemaCatalog(ctx context.Context, rt *runtime.Runtime, conn *pgConnection) (map[string]map[string]string, error) {
	rows, err := psqlQueryRows(ctx, rt, conn, schemaListQuery)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]string, len(rows))
	for _, row := range rows {
		retrow := make(map[string]string, 2)
		for _, key := range [...]string{"owner", "acl"} {
			value, ok := row[key]
			if !ok {
				return nil, fmt.Errorf("postgres.schema_list: missing column %q", key)
			}
			retrow[key] = value
		}
		name, ok := row["name"]
		if !ok {
			return nil, fmt.Errorf(`postgres.schema_list: missing column "name"`)
		}
		out[name] = retrow
	}
	return out, nil
}

type schemaListFunc struct{}

func (schemaListFunc) Name() string { return "postgres.schema_list" }
func (schemaListFunc) Args() any    { return SchemaListArgs{} }

func (schemaListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SchemaListArgs](args, "postgres.schema_list")
	if err != nil {
		return nil, err
	}
	return schemaCatalog(ctx, rt, a.connection())
}

type schemaGetFunc struct{}

func (schemaGetFunc) Name() string { return "postgres.schema_get" }
func (schemaGetFunc) Args() any    { return SchemaArgs{} }

func (schemaGetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SchemaArgs](args, "postgres.schema_get")
	if err != nil {
		return nil, err
	}
	// The pinned function is schema_list(...).get(name, None)
	// (postgres.py:2532-2533): an exact-case key lookup whose miss is
	// None, never an error. The pinned AttributeError branch (a non-dict
	// schema_list) is unreachable through the fixed transport, which
	// returns an error instead of Salt's logged False.
	schemas, err := schemaCatalog(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	if row, ok := schemas[a.Name]; ok {
		return row, nil
	}
	return nil, nil
}

type schemaExistsFunc struct{}

func (schemaExistsFunc) Name() string { return "postgres.schema_exists" }
func (schemaExistsFunc) Args() any    { return SchemaArgs{} }

func (schemaExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SchemaArgs](args, "postgres.schema_exists")
	if err != nil {
		return nil, err
	}
	// The pinned bool(schema_get(...)) (postgres.py:2478-2488) is the
	// stored row's truthiness: a hit always carries both pinned columns
	// (possibly as empty strings), so len>0 is the bool(dict) port with
	// the same exact-case lookup as schema_get.
	schemas, err := schemaCatalog(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	return len(schemas[a.Name]) > 0, nil
}

// ---------------------------------------------------------------------------
// schema_create / schema_remove — salt/modules/postgres.py:2316-2366,
// 2369-2441 @ pinned revision.

// SchemaCreateArgs are the canonical postgres.schema_create arguments,
// mirroring the pinned schema_create(dbname, name, owner, user, db_user,
// db_password, db_host, db_port) signature (postgres.py:2316-2325): the
// required dbname and name positionals, the optional owner of the pinned
// AUTHORIZATION clause, and the schema-family connection tuple where user
// is the pinned system-user argument (the psql runas).
type SchemaCreateArgs struct {
	DBName     string  `statekit:"name=dbname,required"`
	Name       string  `statekit:"name=name,required"`
	Owner      *string `statekit:"name=owner"`
	User       *string `statekit:"name=user"`
	DBUser     *string `statekit:"name=db_user"`
	DBPassword *string `statekit:"name=db_password"`
	DBHost     *string `statekit:"name=db_host"`
	DBPort     *string `statekit:"name=db_port"`
}

func (a *SchemaCreateArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	dbname := a.DBName
	return &pgConnection{
		User:          a.DBUser,
		Host:          a.DBHost,
		Port:          a.DBPort,
		MaintenanceDB: &dbname,
		Password:      a.DBPassword,
		Runas:         a.User,
	}
}

type schemaCreateFunc struct{}

func (schemaCreateFunc) Name() string { return "postgres.schema_create" }
func (schemaCreateFunc) Args() any    { return SchemaCreateArgs{} }

// Execute ports the pinned schema_create flow (postgres.py:2339-2366):
// the schema_exists preflight with the full pinned connection signature —
// the system user included, so a set user rejects like every runas
// surface — whose hit is the logged-and-False no-op, the pinned
// CREATE SCHEMA statement with the double-quoted name and the optional
// double-quoted AUTHORIZATION owner, and the ret["retcode"] == 0 boolean.
// The identifier boundary is the StateKit addition, checked before any
// Runner invocation.
func (schemaCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SchemaCreateArgs](args, "postgres.schema_create")
	if err != nil {
		return nil, err
	}
	if strings.Contains(a.Name, `"`) {
		// The pinned format interpolates the schema name into double
		// quotes unescaped; StateKit fails closed on the only character
		// that can escape a double-quoted identifier.
		return nil, ddlValidationError("name")
	}
	if a.Owner != nil && strings.Contains(*a.Owner, `"`) {
		return nil, ddlValidationError("owner")
	}
	schemas, err := schemaCatalog(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	if len(schemas[a.Name]) > 0 {
		// The pinned "'%s' already exists in '%s'" log-and-False.
		return false, nil
	}
	subCmd := `CREATE SCHEMA "` + a.Name + `"`
	if a.Owner != nil {
		subCmd += ` AUTHORIZATION "` + *a.Owner + `"`
	}
	argv := psqlArgv(
		pointerString(a.DBUser),
		pointerString(a.DBHost),
		pointerString(a.DBPort),
		a.DBName,
		"-c", subCmd,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// SchemaRemoveArgs are the canonical postgres.schema_remove arguments,
// mirroring the pinned schema_remove(dbname, name, user, db_user,
// db_password, db_host, db_port) signature (postgres.py:2369-2370).
type SchemaRemoveArgs struct {
	DBName     string  `statekit:"name=dbname,required"`
	Name       string  `statekit:"name=name,required"`
	User       *string `statekit:"name=user"`
	DBUser     *string `statekit:"name=db_user"`
	DBPassword *string `statekit:"name=db_password"`
	DBHost     *string `statekit:"name=db_host"`
	DBPort     *string `statekit:"name=db_port"`
}

func (a *SchemaRemoveArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	dbname := a.DBName
	return &pgConnection{
		User:          a.DBUser,
		Host:          a.DBHost,
		Port:          a.DBPort,
		MaintenanceDB: &dbname,
		Password:      a.DBPassword,
		Runas:         a.User,
	}
}

type schemaRemoveFunc struct{}

func (schemaRemoveFunc) Name() string { return "postgres.schema_remove" }
func (schemaRemoveFunc) Args() any    { return SchemaRemoveArgs{} }

// Execute ports the pinned schema_remove flow (postgres.py:2404-2441):
// the first existence check drops the system user exactly like the pinned
// user=None call while keeping the db_* tuple, the pinned DROP SCHEMA
// statement with the double-quoted name and no CASCADE clause, the
// discarded DROP result (no retcode check in the pinned flow), and the
// second schema_exists post-check — this one carrying the user — deciding
// the boolean. The identifier boundary is the StateKit addition, checked
// before any Runner invocation.
func (schemaRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[SchemaRemoveArgs](args, "postgres.schema_remove")
	if err != nil {
		return nil, err
	}
	if strings.Contains(a.Name, `"`) {
		return nil, ddlValidationError("name")
	}
	preflight := a.connection()
	preflight.Runas = nil
	schemas, err := schemaCatalog(ctx, rt, preflight)
	if err != nil {
		return nil, err
	}
	if len(schemas[a.Name]) == 0 {
		// The pinned "Schema '%s' does not exist in '%s'" log-and-False.
		return false, nil
	}
	subCmd := `DROP SCHEMA "` + a.Name + `"`
	conn := a.connection()
	argv := psqlArgv(
		pointerString(a.DBUser),
		pointerString(a.DBHost),
		pointerString(a.DBPort),
		a.DBName,
		"-c", subCmd,
	)
	if _, err := runPsql(ctx, rt, argv, conn); err != nil {
		return nil, err
	}
	schemas, err = schemaCatalog(ctx, rt, conn)
	if err != nil {
		return nil, err
	}
	if len(schemas[a.Name]) > 0 {
		// The pinned "Failed to delete schema '%s'." log-and-False.
		return false, nil
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// role_get / user_exists — salt/modules/postgres.py:1104-1170 @ pinned
// revision.

// RoleGetArgs are the canonical postgres.role_get arguments, mirroring the
// pinned role_get(name, user, host, port, maintenance_db, password, runas,
// return_password=False) signature.
type RoleGetArgs struct {
	Name           string  `statekit:"name=name,required"`
	User           *string `statekit:"name=user"`
	Host           *string `statekit:"name=host"`
	Port           *string `statekit:"name=port"`
	MaintenanceDB  *string `statekit:"name=maintenance_db"`
	Password       *string `statekit:"name=password"`
	Runas          *string `statekit:"name=runas"`
	ReturnPassword bool    `statekit:"name=return_password"`
}

func (a *RoleGetArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// roleGet ports the pinned role_get tail (postgres.py:1125-1138): the
// shared user_list catalog followed by .get(name, None). When user_list
// answers Salt's False (an unanswered version probe), the pinned .get
// raises AttributeError, is logged, and returns None — mapped here to nil.
// The exact-case lookup miss is None, never an error.
func roleGet(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, name string, returnPassword bool) (any, error) {
	users, err := userCatalog(ctx, rt, conn, returnPassword)
	if err != nil {
		return nil, err
	}
	catalog, ok := users.(map[string]map[string]any)
	if !ok {
		// The pinned AttributeError branch: a False catalog is None here.
		return nil, nil
	}
	if row, ok := catalog[name]; ok {
		return row, nil
	}
	return nil, nil
}

type roleGetFunc struct{}

func (roleGetFunc) Name() string { return "postgres.role_get" }
func (roleGetFunc) Args() any    { return RoleGetArgs{} }

func (roleGetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[RoleGetArgs](args, "postgres.role_get")
	if err != nil {
		return nil, err
	}
	return roleGet(ctx, rt, a.connection(), a.Name, a.ReturnPassword)
}

type userExistsFunc struct{}

func (userExistsFunc) Name() string { return "postgres.user_exists" }
func (userExistsFunc) Args() any    { return ExistsArgs{} }

func (userExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.user_exists")
	if err != nil {
		return nil, err
	}
	// The pinned user_exists is bool(role_get(..., return_password=False))
	// (postgres.py:1159-1170): None (miss or False catalog) is false and a
	// stored role row always carries the pinned columns, so the bool is
	// the row's presence — len>0 is the bool(dict) port.
	row, err := roleGet(ctx, rt, a.connection(), a.Name, false)
	if err != nil {
		return nil, err
	}
	entry, ok := row.(map[string]any)
	if !ok {
		return false, nil
	}
	return len(entry) > 0, nil
}

// ---------------------------------------------------------------------------
// user_create / user_update / user_remove — salt/modules/postgres.py
// 1368-1431, 1487-1610, 1613-1651, 2066-2092 @ pinned revision, through the
// pinned _role_create/_role_update/_role_remove flow,
// _role_cmd_args (1271-1365), and _add_role_flag (1173-1184).

// saltScalarKind names the Python value shapes the pinned union-typed
// encrypted/rolepassword arguments take: None, bool, str, and (degenerately,
// through structured input) any other truthiness-carrying scalar.
type saltScalarKind uint8

const (
	saltNone saltScalarKind = iota
	saltBool
	saltString
	saltOther
)

// saltScalar is one normalized pinned union value. For saltOther, b carries
// the Python truthiness; numZero marks the numeric-zero shapes Python's
// tuple membership compares equal to False.
type saltScalar struct {
	kind    saltScalarKind
	b       bool
	s       string
	numZero bool
}

// normalizeSaltScalar maps a decoded argument onto the pinned value shapes
// without any implicit retyping: a bool stays a bool, and a string stays
// the exact string — boolean spellings included, so the string "true" keeps
// the pinned string semantics (a literal password for rolepassword, an
// unknown algorithm for encrypted) exactly like a programmatic caller of
// the pinned module. Only the CLI decoder translates typed bool flags to
// bools; numeric and other shapes keep their Python truthiness, with the
// numeric zeros recorded because Python compares 0 == False in the pinned
// algorithm tuple membership.
func normalizeSaltScalar(value any) saltScalar {
	switch t := value.(type) {
	case nil:
		return saltScalar{kind: saltNone}
	case bool:
		return saltScalar{kind: saltBool, b: t}
	case string:
		return saltScalar{kind: saltString, s: t}
	case int:
		return saltScalar{kind: saltOther, b: t != 0, numZero: t == 0}
	case int64:
		return saltScalar{kind: saltOther, b: t != 0, numZero: t == 0}
	case float64:
		return saltScalar{kind: saltOther, b: t != 0, numZero: t == 0}
	default:
		return saltScalar{kind: saltOther, b: true}
	}
}

// truthy is the pinned bool() of the value.
func (s saltScalar) truthy() bool {
	switch s.kind {
	case saltNone:
		return false
	case saltBool, saltOther:
		return s.b
	default: // str
		return s.s != ""
	}
}

// isStr and isBool are the pinned isinstance tests of _role_cmd_args.
func (s saltScalar) isStr() bool { return s.kind == saltString }
func (s saltScalar) isBool() bool {
	return s.kind == saltBool
}

// md5Password ports the pinned _md5_password (postgres.py:1242-1247):
// "md5" followed by the hex MD5 of the password and role name concatenated
// in that order. Salt logs a deprecation warning for the algorithm; modules
// do not log, so the verifier itself is the whole behavior.
func md5Password(role, password string) string {
	digest := md5.Sum([]byte(password + role)) // nosec: pinned verifier
	return "md5" + hex.EncodeToString(digest[:])
}

// saslprepASCII is the bounded port of the pinned salt.ext.saslprep call in
// _scram_sha_256: for a printable-ASCII password SASLprep is the identity
// (no mapped-to-nothing or non-ASCII space characters, NFKC is a no-op, the
// bidi and prohibited-output checks pass), so those passwords are returned
// unchanged. Anything outside printable ASCII fails closed with a
// value-free error instead of guessing at the RFC 3454 tables; the upgrade
// path is a full stringprep implementation, not a silent approximation.
func saslprepASCII(password string) (string, error) {
	for i := 0; i < len(password); i++ {
		if password[i] < 0x20 || password[i] > 0x7e {
			return "", errPostgresSaslprep
		}
	}
	return password, nil
}

// scramSHA256Password ports the pinned _scram_sha_256
// (postgres.py:1250-1268): a random 16-byte salt, PBKDF2-HMAC-SHA256 with
// the pinned 4096 iterations over the SASLprep'ed password, the SHA-256 of
// the HMAC'd Client Key as the stored key, the HMAC'd Server Key, and the
// pinned SCRAM-SHA-256$iterations:salt$stored:server rendering — the `$`
// before the stored key, exactly like the pinned
// "SCRAM-SHA-256${}:{}${}:{}" format the pinned _verify_password regex
// also parses. The random salt makes each generated verifier unique,
// exactly like the pinned helper; callers pass an already-prefixed
// verifier through untouched.
func scramSHA256Password(password string) (string, error) {
	prepped, err := saslprepASCII(password)
	if err != nil {
		return "", err
	}
	salt := make([]byte, scramSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("postgres: scram salt: %w", err)
	}
	salted, err := pbkdf2.Key(sha256.New, prepped, salt, scramIterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("postgres: scram kdf: %w", err)
	}
	clientHMAC := hmac.New(sha256.New, salted)
	clientHMAC.Write([]byte("Client Key"))
	storedKey := sha256.Sum256(clientHMAC.Sum(nil))
	serverHMAC := hmac.New(sha256.New, salted)
	serverHMAC.Write([]byte("Server Key"))
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		scramIterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(storedKey[:]),
		base64.StdEncoding.EncodeToString(serverHMAC.Sum(nil)),
	), nil
}

// maybeEncryptPassword ports the pinned _maybe_encrypt_password
// (postgres.py:1187-1206) for a non-None password: True normalizes to the
// md5 algorithm first, an algorithm outside False/"md5"/"scram-sha-256"
// (with the numeric zeros Python compares equal to False) is the
// unknown-algorithm rejection, the scram algorithm generates — or passes
// through an already-prefixed — SCRAM-SHA-256 verifier, the md5 algorithm
// passes through an md5-prefixed value and otherwise hashes password+role,
// and False returns the plaintext (Salt logs the removed-unencrypted
// warning; modules do not log). Unlike the pinned ValueError, the returned
// error is value-free: the union-typed algorithm argument may itself carry
// or overlap a credential, so a fixed error key travels instead.
func maybeEncryptPassword(role, password string, encrypted saltScalar) (string, error) {
	if encrypted.kind == saltBool && encrypted.b {
		encrypted = saltScalar{kind: saltString, s: "md5"}
	}
	valid := encrypted.kind == saltBool ||
		(encrypted.kind == saltString &&
			(encrypted.s == "md5" || encrypted.s == "scram-sha-256")) ||
		(encrypted.kind == saltOther && encrypted.numZero)
	if !valid {
		return "", errPostgresUnknownPasswordAlgorithm
	}
	switch {
	case encrypted.kind == saltString && encrypted.s == "scram-sha-256":
		if !strings.HasPrefix(password, "SCRAM-SHA-256") {
			return scramSHA256Password(password)
		}
	case encrypted.kind == saltString && encrypted.s == "md5":
		if !strings.HasPrefix(password, "md5") {
			return md5Password(role, password), nil
		}
	}
	return password, nil
}

// roleFlagSpec is one pinned _add_role_flag tuple (postgres.py:1323-1355).
// A nil test is Python's None: the flag clause is omitted entirely while an
// addtxt still appends; a nil cond inherits the test; skip suppresses the
// whole tuple.
type roleFlagSpec struct {
	flag   string
	test   *bool
	cond   *bool
	prefix string
	addtxt string
	skip   bool
}

// addRoleFlag ports the pinned _add_role_flag (postgres.py:1173-1184)
// including the pinned default NO prefix.
func addRoleFlag(cmd string, f roleFlagSpec) string {
	if f.skip {
		return cmd
	}
	cond := f.cond
	if cond == nil {
		cond = f.test
	}
	if f.test != nil {
		if *cond {
			cmd += " " + f.flag
		} else {
			cmd += " " + f.prefix + f.flag
		}
	}
	if f.addtxt != "" {
		cmd += " " + f.addtxt
	}
	return cmd
}

// roleGroupsKind is the pinned groups argument shape: absent, one string,
// or one list.
type roleGroupsKind uint8

const (
	roleGroupsNone roleGroupsKind = iota
	roleGroupsString
	roleGroupsList
)

// roleGroups is the type-preserving pinned groups union. A string input
// stays the exact string; a list input keeps its exact elements and order
// (copied, so the caller's slice is never mutated or aliased).
type roleGroups struct {
	kind  roleGroupsKind
	raw   string
	items []string
}

// normalizeRoleGroups maps a decoded groups argument onto the pinned union
// without retyping: nil is absent, a string stays the exact string, and a
// list (typed or decoded) keeps its exact elements and order. Anything
// else — a non-string list element included — fails closed with the
// value-free invalid-argument error before any Runner invocation, the
// StateKit boundary for the pinned join/split AttributeError and
// TypeError shapes.
func normalizeRoleGroups(value any) (roleGroups, error) {
	switch t := value.(type) {
	case nil:
		return roleGroups{kind: roleGroupsNone}, nil
	case string:
		return roleGroups{kind: roleGroupsString, raw: t}, nil
	case []string:
		return roleGroups{kind: roleGroupsList, items: append([]string(nil), t...)}, nil
	case []any:
		items := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return roleGroups{}, errPostgresInvalidArgument
			}
			items = append(items, s)
		}
		return roleGroups{kind: roleGroupsList, items: items}, nil
	default:
		return roleGroups{}, errPostgresInvalidArgument
	}
}

// grantEntries reproduces the pinned group suffix of _role_cmd_args
// exactly: the truthiness gate (an empty string or empty list renders
// nothing), the list joined with "," first, then the split on "," with no
// trimming and no empty-element dropping — so a trailing space survives
// inside its identifier and an empty comma slot renders its own empty
// GRANT, byte-for-byte like the pinned source.
func (g roleGroups) grantEntries() []string {
	switch g.kind {
	case roleGroupsString:
		if g.raw == "" {
			return nil
		}
		return strings.Split(g.raw, ",")
	case roleGroupsList:
		if len(g.items) == 0 {
			return nil
		}
		return strings.Split(strings.Join(g.items, ","), ",")
	default:
		return nil
	}
}

// roleOptions carries the pinned _role_cmd_args inputs for one statement.
// typ keeps the pinned typ_: "user" or "group" for the create paths (whose
// inherit and login defaults apply — INHERIT and NOLOGIN for groups), and
// "role" for the update paths (whose _role_cmd_args call passes no typ_, so
// no defaults apply). dbRole is the update path's stored role row for the
// pinned superuser skip; nil on create. The group family's pinned
// signatures carry neither connlimit nor valid_until, so those stay nil
// there.
type roleOptions struct {
	name         string
	typ          string
	encrypted    saltScalar
	login        *bool
	connlimit    *int64
	inherit      *bool
	createdb     *bool
	createroles  *bool
	superuser    *bool
	groups       roleGroups
	replication  *bool
	rolepassword saltScalar
	validUntil   *string
	dbRole       map[string]any
}

// roleCmdArgs ports the pinned _role_cmd_args (postgres.py:1271-1365)
// exactly: the typ_-keyed inherit/login defaults, the md5 encryption
// default, the skip_passwd rule over the rolepassword shapes, the
// quote-doubled password and valid-until literals, the update-only
// superuser skip against the stored role, the pinned ten-clause order,
// and the join-then-split group GRANT suffix. The pinned WITH-strip tail
// is dead code for these call paths (the inner sub_cmd is always ""), so
// it is not ported. Errors are the value-free unknown-algorithm and
// saslprep bounds. Alongside the clause string it returns every secret the
// rendered statement carries — the plaintext rolepassword, its
// quote-doubled form, the generated md5/SCRAM verifier actually placed in
// the SQL, and that verifier's single-quoted escaped form — longest form
// first, so runPsqlSecrets receives them all for the Redact list and the
// error-redaction pass.
func roleCmdArgs(o roleOptions) (string, []string, error) {
	inherit := o.inherit
	if inherit == nil && (o.typ == "user" || o.typ == "group") {
		value := true
		inherit = &value
	}
	login := o.login
	if login == nil {
		if o.typ == "user" {
			value := true
			login = &value
		}
		if o.typ == "group" {
			value := false
			login = &value
		}
	}
	// defaults to encrypted passwords
	encrypted := o.encrypted
	if encrypted.kind == saltNone {
		encrypted = saltScalar{kind: saltString, s: defaultPasswordsEncryption}
	}
	skipPasswd := !((o.rolepassword.kind != saltNone && o.rolepassword.isStr() &&
		o.rolepassword.s != "") || o.rolepassword.isBool())
	escapedPassword := ""
	secrets := []string(nil)
	if o.rolepassword.isStr() && o.rolepassword.s != "" {
		doubled := strings.ReplaceAll(o.rolepassword.s, "'", "''")
		verifier, err := maybeEncryptPassword(o.name, doubled, encrypted)
		if err != nil {
			return "", nil, err
		}
		escapedPassword = "'" + verifier + "'"
		// Longest forms first so a partial overlap can never leave a
		// fragment of a longer secret behind the placeholder.
		secrets = append(secrets, escapedPassword, verifier)
		if doubled != o.rolepassword.s && strings.Contains(verifier, doubled) {
			secrets = append(secrets, doubled)
		}
		secrets = append(secrets, o.rolepassword.s)
	}
	escapedValidUntil := ""
	if o.validUntil != nil && *o.validUntil != "" {
		escapedValidUntil = "'" + strings.ReplaceAll(*o.validUntil, "'", "''") + "'"
	}
	skipSuperuser := false
	if o.dbRole != nil && pointerBool(o.superuser) == rowLooseBool(o.dbRole["superuser"]) {
		skipSuperuser = true
	}

	cmd := ""
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "INHERIT", prefix: "NO", test: inherit})
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "CREATEDB", prefix: "NO", test: o.createdb})
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "CREATEROLE", prefix: "NO", test: o.createroles})
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "SUPERUSER", prefix: "NO", test: o.superuser, skip: skipSuperuser})
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "REPLICATION", prefix: "NO", test: o.replication})
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "LOGIN", prefix: "NO", test: login})
	connlimitSet := new(bool)
	connlimitTxt := ""
	if o.connlimit != nil {
		*connlimitSet = *o.connlimit != 0
		connlimitTxt = strconv.FormatInt(*o.connlimit, 10)
	}
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "CONNECTION LIMIT", prefix: "NO", test: connlimitSet,
		addtxt: connlimitTxt, skip: o.connlimit == nil})
	encryptedTest := encrypted.kind != saltNone && o.rolepassword.truthy()
	encryptedCond := encrypted.truthy()
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "ENCRYPTED", test: &encryptedTest,
		cond: &encryptedCond, prefix: "UN",
		skip: skipPasswd || o.rolepassword.isBool()})
	passwordTest := o.rolepassword.truthy()
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "PASSWORD", prefix: "NO", test: &passwordTest,
		skip: skipPasswd, addtxt: escapedPassword})
	validUntilTest := o.validUntil != nil && *o.validUntil != ""
	cmd = addRoleFlag(cmd, roleFlagSpec{flag: "VALID UNTIL", prefix: "NO", test: &validUntilTest,
		skip: o.validUntil == nil, addtxt: escapedValidUntil})

	// The pinned list handling joins then splits, so every element of
	// the joined rendering becomes its own GRANT — no trimming and no
	// empty-element dropping, exactly like the pinned split.
	for _, group := range o.groups.grantEntries() {
		cmd += `; GRANT "` + group + `" TO "` + o.name + `"`
	}
	return cmd, secrets, nil
}

// rowLooseBool is the pinned bool() over a stored role's looseBool column
// (true, false, or None): None is false.
func rowLooseBool(value any) bool {
	truthy, ok := value.(bool)
	return ok && truthy
}

// roleStatement assembles the pinned statement head and the "{} {}"
// joining of _role_create/_role_update: the head keeps its WITH and the
// rendered clauses join after one space, so a clause-less update keeps the
// pinned trailing space and any clause renders the pinned double space
// after WITH. It also returns the full Redact secret list the statement
// carries: the quote-escaped and bare generated md5/SCRAM verifiers, the
// quote-doubled plaintext, and the plaintext rolepassword itself.
func roleStatement(verb string, o roleOptions) (string, []string, error) {
	built, secrets, err := roleCmdArgs(o)
	if err != nil {
		return "", nil, err
	}
	return verb + ` "` + o.name + `" WITH` + " " + built, secrets, nil
}

// validateRoleIdentifiers fails closed on the double quote at the
// identifier positions the pinned source interpolates raw — the role name
// of every CREATE/ALTER/DROP ROLE and GRANT statement and each GRANT group
// entry the pinned split produces — with the shared value-free rejection
// naming only the fixed argument key (username for the user family,
// groupname for the group family), before any Runner invocation.
func validateRoleIdentifiers(name, nameKey string, groups []string) error {
	if strings.Contains(name, `"`) {
		return ddlValidationError(nameKey)
	}
	for _, group := range groups {
		if strings.Contains(group, `"`) {
			return ddlValidationError("groups")
		}
	}
	return nil
}

// roleUserExists is the pinned user_exists preflight of _role_create and
// _role_remove: bool(role_get(..., return_password=False)) over the shared
// user_list catalog.
func roleUserExists(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, name string) (bool, error) {
	row, err := roleGet(ctx, rt, conn, name, false)
	if err != nil {
		return false, err
	}
	return row != nil, nil
}

// UserCreateArgs are the canonical postgres.user_create arguments,
// mirroring the pinned user_create(username, user, host, port,
// maintenance_db, password, createdb, createroles, encrypted, superuser,
// login, connlimit, inherit, replication, rolepassword, valid_until,
// groups, runas) signature (postgres.py:1433-1452). Pointer and union
// fields keep Salt's None defaults: nil or an absent value omits the
// clause (or applies the pinned user-typed inherit/login default), while
// an explicit empty string keeps the pinned falsy-string behavior.
// Encrypted, Rolepassword, and Groups are type-preserving unions: bools
// stay bools and strings stay the exact strings (a string groups value
// splits on the comma without trimming, like the pinned source), with the
// CLI decoder the only translator of typed bool flags.
type UserCreateArgs struct {
	Username      string  `statekit:"name=username,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Createdb      *bool   `statekit:"name=createdb"`
	Createroles   *bool   `statekit:"name=createroles"`
	Encrypted     any     `statekit:"name=encrypted"`
	Superuser     *bool   `statekit:"name=superuser"`
	Login         *bool   `statekit:"name=login"`
	Connlimit     *int64  `statekit:"name=connlimit"`
	Inherit       *bool   `statekit:"name=inherit"`
	Replication   *bool   `statekit:"name=replication"`
	Rolepassword  any     `statekit:"name=rolepassword"`
	ValidUntil    *string `statekit:"name=valid_until"`
	Groups        any     `statekit:"name=groups"`
	Runas         *string `statekit:"name=runas"`
}

func (a *UserCreateArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// roleOptionsFromCreate projects the create arguments onto the statement
// builder with the pinned typ_="user". The groups union normalizes
// separately so Execute can validate the exact GRANT entries the pinned
// split produces before any Runner invocation.
func (a *UserCreateArgs) roleOptions(groups roleGroups) roleOptions {
	return roleOptions{
		name:         a.Username,
		typ:          "user",
		encrypted:    normalizeSaltScalar(a.Encrypted),
		login:        a.Login,
		connlimit:    a.Connlimit,
		inherit:      a.Inherit,
		createdb:     a.Createdb,
		createroles:  a.Createroles,
		superuser:    a.Superuser,
		groups:       groups,
		replication:  a.Replication,
		rolepassword: normalizeSaltScalar(a.Rolepassword),
		validUntil:   a.ValidUntil,
	}
}

type userCreateFunc struct{}

func (userCreateFunc) Name() string { return "postgres.user_create" }
func (userCreateFunc) Args() any    { return UserCreateArgs{} }

// Execute ports the pinned _role_create flow for typ_="user"
// (postgres.py:1368-1431): the user_exists preflight whose hit is the
// logged-and-False no-op, the pinned CREATE ROLE statement (Salt spells the
// verb CREATE ROLE for users too), and the pinned ret["retcode"] == 0
// boolean. The identifier boundary is checked before any Runner
// invocation; statement-construction errors (the pinned unknown-algorithm
// ValueError and the saslprep bound) surface after the read-only
// preflight exactly where the pinned format raises.
func (userCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserCreateArgs](args, "postgres.user_create")
	if err != nil {
		return nil, err
	}
	groups, err := normalizeRoleGroups(a.Groups)
	if err != nil {
		return nil, err
	}
	if err := validateRoleIdentifiers(a.Username, "username", groups.grantEntries()); err != nil {
		return nil, err
	}
	conn := a.connection()
	if password := normalizeSaltScalar(a.Rolepassword); password.isStr() {
		conn.Secrets = secretList(password.s)
	}
	exists, err := roleUserExists(ctx, rt, conn, a.Username)
	if err != nil {
		return nil, err
	}
	if exists {
		// The pinned "User 'x' already exists" log-and-False.
		return false, nil
	}
	statement, secrets, err := roleStatement("CREATE ROLE", a.roleOptions(groups))
	if err != nil {
		return nil, err
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", statement,
	)
	result, err := runPsqlSecrets(ctx, rt, argv, conn, secrets)
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// UserUpdateArgs are the canonical postgres.user_update arguments,
// mirroring the pinned user_update(username, user, host, port,
// maintenance_db, password, createdb, createroles, encrypted, superuser,
// inherit, login, connlimit, replication, rolepassword, valid_until,
// groups, runas) signature (postgres.py:1559-1578). Encrypted,
// Rolepassword, and Groups keep the same type-preserving union contract
// as user_create.
type UserUpdateArgs struct {
	Username      string  `statekit:"name=username,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Createdb      *bool   `statekit:"name=createdb"`
	Createroles   *bool   `statekit:"name=createroles"`
	Encrypted     any     `statekit:"name=encrypted"`
	Superuser     *bool   `statekit:"name=superuser"`
	Inherit       *bool   `statekit:"name=inherit"`
	Login         *bool   `statekit:"name=login"`
	Connlimit     *int64  `statekit:"name=connlimit"`
	Replication   *bool   `statekit:"name=replication"`
	Rolepassword  any     `statekit:"name=rolepassword"`
	ValidUntil    *string `statekit:"name=valid_until"`
	Groups        any     `statekit:"name=groups"`
	Runas         *string `statekit:"name=runas"`
}

func (a *UserUpdateArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// roleOptionsFromUpdate projects the update arguments onto the statement
// builder with the pinned update-path typ_: _role_update passes no typ_, so
// _role_cmd_args defaults to "role" and applies no inherit/login defaults.
func (a *UserUpdateArgs) roleOptions(dbRole map[string]any, groups roleGroups) roleOptions {
	return roleOptions{
		name:         a.Username,
		typ:          "role",
		encrypted:    normalizeSaltScalar(a.Encrypted),
		login:        a.Login,
		connlimit:    a.Connlimit,
		inherit:      a.Inherit,
		createdb:     a.Createdb,
		createroles:  a.Createroles,
		superuser:    a.Superuser,
		groups:       groups,
		replication:  a.Replication,
		rolepassword: normalizeSaltScalar(a.Rolepassword),
		validUntil:   a.ValidUntil,
		dbRole:       dbRole,
	}
}

type userUpdateFunc struct{}

func (userUpdateFunc) Name() string { return "postgres.user_update" }
func (userUpdateFunc) Args() any    { return UserUpdateArgs{} }

// Execute ports the pinned _role_update flow for typ_="user"
// (postgres.py:1487-1556): the role_get preflight whose miss is the
// logged-and-False no-op, the pinned ALTER ROLE statement with the
// db_role-keyed superuser skip, and the pinned ret["retcode"] == 0
// boolean. The identifier boundary is checked before any Runner
// invocation; statement-construction errors surface after the read-only
// preflight exactly where the pinned format raises.
func (userUpdateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserUpdateArgs](args, "postgres.user_update")
	if err != nil {
		return nil, err
	}
	groups, err := normalizeRoleGroups(a.Groups)
	if err != nil {
		return nil, err
	}
	if err := validateRoleIdentifiers(a.Username, "username", groups.grantEntries()); err != nil {
		return nil, err
	}
	conn := a.connection()
	if password := normalizeSaltScalar(a.Rolepassword); password.isStr() {
		conn.Secrets = secretList(password.s)
	}
	row, err := roleGet(ctx, rt, conn, a.Username, false)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// The pinned "User 'x' could not be found" log-and-False.
		return false, nil
	}
	dbRole, _ := row.(map[string]any)
	statement, secrets, err := roleStatement("ALTER ROLE", a.roleOptions(dbRole, groups))
	if err != nil {
		return nil, err
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", statement,
	)
	result, err := runPsqlSecrets(ctx, rt, argv, conn, secrets)
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// UserRemoveArgs are the canonical postgres.user_remove arguments,
// mirroring the pinned user_remove(username, user, host, port,
// maintenance_db, password, runas) signature (postgres.py:2066-2074).
type UserRemoveArgs struct {
	Username      string  `statekit:"name=username,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *UserRemoveArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type userRemoveFunc struct{}

func (userRemoveFunc) Name() string { return "postgres.user_remove" }
func (userRemoveFunc) Args() any    { return UserRemoveArgs{} }

// Execute ports the pinned _role_remove flow (postgres.py:1613-1651): the
// user_exists preflight whose miss is the logged-and-False no-op, the fixed
// DROP ROLE statement whose retcode the pinned source ignores (only Runner
// failures, cancellation, and output-limit violations are errors here, like
// Salt's raised transport exceptions), and the final user_exists
// re-check that decides the boolean — true only when the role is gone.
// The identifier boundary is checked before any Runner invocation.
func (userRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserRemoveArgs](args, "postgres.user_remove")
	if err != nil {
		return nil, err
	}
	if strings.Contains(a.Username, `"`) {
		return nil, ddlValidationError("username")
	}
	conn := a.connection()
	exists, err := roleUserExists(ctx, rt, conn, a.Username)
	if err != nil {
		return nil, err
	}
	if !exists {
		// The pinned "User 'x' does not exist" log-and-False.
		return false, nil
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", `DROP ROLE "`+a.Username+`"`,
	)
	if _, err := runPsql(ctx, rt, argv, conn); err != nil {
		return nil, err
	}
	exists, err = roleUserExists(ctx, rt, conn, a.Username)
	if err != nil {
		return nil, err
	}
	if exists {
		// The pinned "Failed to delete user 'x'." log-and-False.
		return false, nil
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// group_create/group_update/group_remove — salt/modules/postgres.py:2098-2225
// @ pinned revision, delegating to the same _role_create/_role_update/
// _role_remove flows as the user family with typ_="group": the pinned
// group-typed inherit/login defaults (INHERIT NOLOGIN) on create, the
// pinned no-default update clause machine with the db_role superuser skip,
// and the pinned DROP ROLE post-check flow.

// GroupCreateArgs are the canonical postgres.group_create arguments,
// mirroring the pinned group_create(groupname, user, host, port,
// maintenance_db, password, createdb, createroles, encrypted, login,
// inherit, superuser, replication, rolepassword, groups, runas) signature
// (postgres.py:2098-2115). The pinned group signature carries neither
// connlimit nor valid_until, so neither argument exists here. Pointer and
// union fields keep Salt's None defaults: nil or an absent value omits the
// clause (or applies the pinned group-typed INHERIT/NOLOGIN defaults),
// while an explicit empty string keeps the pinned falsy-string behavior.
// Encrypted, Rolepassword, and Groups are type-preserving unions exactly
// like the user family.
type GroupCreateArgs struct {
	Groupname     string  `statekit:"name=groupname,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Createdb      *bool   `statekit:"name=createdb"`
	Createroles   *bool   `statekit:"name=createroles"`
	Encrypted     any     `statekit:"name=encrypted"`
	Login         *bool   `statekit:"name=login"`
	Inherit       *bool   `statekit:"name=inherit"`
	Superuser     *bool   `statekit:"name=superuser"`
	Replication   *bool   `statekit:"name=replication"`
	Rolepassword  any     `statekit:"name=rolepassword"`
	Groups        any     `statekit:"name=groups"`
	Runas         *string `statekit:"name=runas"`
}

func (a *GroupCreateArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// roleOptions projects the create arguments onto the statement builder
// with the pinned typ_="group" whose inherit/login defaults render
// INHERIT NOLOGIN. The groups union normalizes separately so Execute can
// validate the exact GRANT entries the pinned split produces before any
// Runner invocation.
func (a *GroupCreateArgs) roleOptions(groups roleGroups) roleOptions {
	return roleOptions{
		name:         a.Groupname,
		typ:          "group",
		encrypted:    normalizeSaltScalar(a.Encrypted),
		login:        a.Login,
		inherit:      a.Inherit,
		createdb:     a.Createdb,
		createroles:  a.Createroles,
		superuser:    a.Superuser,
		groups:       groups,
		replication:  a.Replication,
		rolepassword: normalizeSaltScalar(a.Rolepassword),
	}
}

type groupCreateFunc struct{}

func (groupCreateFunc) Name() string { return "postgres.group_create" }
func (groupCreateFunc) Args() any    { return GroupCreateArgs{} }

// Execute ports the pinned _role_create flow for typ_="group"
// (postgres.py:1368-1431 through group_create at 2098-2146): the
// user_exists preflight whose hit is the logged-and-False no-op, the
// pinned CREATE ROLE statement with the group-typed INHERIT NOLOGIN
// defaults, and the pinned ret["retcode"] == 0 boolean. The identifier
// boundary is checked before any Runner invocation;
// statement-construction errors (the pinned unknown-algorithm ValueError
// and the saslprep bound) surface after the read-only preflight exactly
// where the pinned format raises.
func (groupCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[GroupCreateArgs](args, "postgres.group_create")
	if err != nil {
		return nil, err
	}
	groups, err := normalizeRoleGroups(a.Groups)
	if err != nil {
		return nil, err
	}
	if err := validateRoleIdentifiers(a.Groupname, "groupname", groups.grantEntries()); err != nil {
		return nil, err
	}
	conn := a.connection()
	if password := normalizeSaltScalar(a.Rolepassword); password.isStr() {
		conn.Secrets = secretList(password.s)
	}
	exists, err := roleUserExists(ctx, rt, conn, a.Groupname)
	if err != nil {
		return nil, err
	}
	if exists {
		// The pinned "Group 'x' already exists" log-and-False.
		return false, nil
	}
	statement, secrets, err := roleStatement("CREATE ROLE", a.roleOptions(groups))
	if err != nil {
		return nil, err
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", statement,
	)
	result, err := runPsqlSecrets(ctx, rt, argv, conn, secrets)
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// GroupUpdateArgs are the canonical postgres.group_update arguments,
// mirroring the pinned group_update(groupname, user, host, port,
// maintenance_db, password, createdb, createroles, encrypted, inherit,
// login, superuser, replication, rolepassword, groups, runas) signature
// (postgres.py:2149-2166). Like group_create, the pinned group signature
// carries neither connlimit nor valid_until. Encrypted, Rolepassword, and
// Groups keep the same type-preserving union contract as the user family.
type GroupUpdateArgs struct {
	Groupname     string  `statekit:"name=groupname,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Createdb      *bool   `statekit:"name=createdb"`
	Createroles   *bool   `statekit:"name=createroles"`
	Encrypted     any     `statekit:"name=encrypted"`
	Inherit       *bool   `statekit:"name=inherit"`
	Login         *bool   `statekit:"name=login"`
	Superuser     *bool   `statekit:"name=superuser"`
	Replication   *bool   `statekit:"name=replication"`
	Rolepassword  any     `statekit:"name=rolepassword"`
	Groups        any     `statekit:"name=groups"`
	Runas         *string `statekit:"name=runas"`
}

func (a *GroupUpdateArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// roleOptions projects the update arguments onto the statement builder
// with the pinned update-path typ_: _role_update passes typ_="group" only
// to its log line, so its _role_cmd_args call defaults to "role" and no
// inherit/login defaults apply.
func (a *GroupUpdateArgs) roleOptions(dbRole map[string]any, groups roleGroups) roleOptions {
	return roleOptions{
		name:         a.Groupname,
		typ:          "role",
		encrypted:    normalizeSaltScalar(a.Encrypted),
		login:        a.Login,
		inherit:      a.Inherit,
		createdb:     a.Createdb,
		createroles:  a.Createroles,
		superuser:    a.Superuser,
		groups:       groups,
		replication:  a.Replication,
		rolepassword: normalizeSaltScalar(a.Rolepassword),
		dbRole:       dbRole,
	}
}

type groupUpdateFunc struct{}

func (groupUpdateFunc) Name() string { return "postgres.group_update" }
func (groupUpdateFunc) Args() any    { return GroupUpdateArgs{} }

// Execute ports the pinned _role_update flow for typ_="group"
// (postgres.py:1487-1556 through group_update at 2149-2196): the role_get
// preflight whose miss is the logged-and-False no-op, the pinned ALTER
// ROLE statement with the db_role-keyed superuser skip and no
// inherit/login defaults, and the pinned ret["retcode"] == 0 boolean.
// The identifier boundary is checked before any Runner invocation;
// statement-construction errors surface after the read-only preflight
// exactly where the pinned format raises.
func (groupUpdateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[GroupUpdateArgs](args, "postgres.group_update")
	if err != nil {
		return nil, err
	}
	groups, err := normalizeRoleGroups(a.Groups)
	if err != nil {
		return nil, err
	}
	if err := validateRoleIdentifiers(a.Groupname, "groupname", groups.grantEntries()); err != nil {
		return nil, err
	}
	conn := a.connection()
	if password := normalizeSaltScalar(a.Rolepassword); password.isStr() {
		conn.Secrets = secretList(password.s)
	}
	row, err := roleGet(ctx, rt, conn, a.Groupname, false)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// The pinned "Group 'x' could not be found" log-and-False.
		return false, nil
	}
	dbRole, _ := row.(map[string]any)
	statement, secrets, err := roleStatement("ALTER ROLE", a.roleOptions(dbRole, groups))
	if err != nil {
		return nil, err
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", statement,
	)
	result, err := runPsqlSecrets(ctx, rt, argv, conn, secrets)
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// GroupRemoveArgs are the canonical postgres.group_remove arguments,
// mirroring the pinned group_remove(groupname, user, host, port,
// maintenance_db, password, runas) signature (postgres.py:2199-2207).
type GroupRemoveArgs struct {
	Groupname     string  `statekit:"name=groupname,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *GroupRemoveArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type groupRemoveFunc struct{}

func (groupRemoveFunc) Name() string { return "postgres.group_remove" }
func (groupRemoveFunc) Args() any    { return GroupRemoveArgs{} }

// Execute ports the pinned _role_remove flow through group_remove
// (postgres.py:1613-1651, 2199-2225): the user_exists preflight whose
// miss is the logged-and-False no-op, the fixed DROP ROLE statement whose
// retcode the pinned source ignores (only Runner failures, cancellation,
// and output-limit violations are errors here, like Salt's raised
// transport exceptions), and the final user_exists re-check that decides
// the boolean — true only when the role is gone. The identifier boundary
// is checked before any Runner invocation.
func (groupRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[GroupRemoveArgs](args, "postgres.group_remove")
	if err != nil {
		return nil, err
	}
	if strings.Contains(a.Groupname, `"`) {
		return nil, ddlValidationError("groupname")
	}
	conn := a.connection()
	exists, err := roleUserExists(ctx, rt, conn, a.Groupname)
	if err != nil {
		return nil, err
	}
	if !exists {
		// The pinned "User 'x' does not exist" log-and-False.
		return false, nil
	}
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", `DROP ROLE "`+a.Groupname+`"`,
	)
	if _, err := runPsql(ctx, rt, argv, conn); err != nil {
		return nil, err
	}
	exists, err = roleUserExists(ctx, rt, conn, a.Groupname)
	if err != nil {
		return nil, err
	}
	if exists {
		// The pinned "Failed to delete user 'x'." log-and-False.
		return false, nil
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// has_privileges — salt/modules/postgres.py:3574-3711 @ pinned revision,
// with the pinned _mod_priv_opts/_validate_privileges/_process_priv_parts
// helpers (postgres.py:3184-3235) and the owner/privilege catalog queries
// of _get_object_owner and privileges_list as client-side-filtered fixed
// SQL.

// HasPrivilegesArgs are the canonical postgres.has_privileges arguments,
// mirroring the pinned (name, object_name, object_type, privileges=None,
// grant_option=None, prepend="public", maintenance_db=None, user, host,
// port, password, runas) signature. Privileges keeps Salt's None default
// as the empty string because the pinned _mod_priv_opts collapses None to
// "" before any use; grant_option is only ever truthiness-tested, so a
// plain bool is exact; prepend nil means the pinned "public" default while
// an explicit empty string keeps Salt's empty-schema match.
type HasPrivilegesArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectName    string  `statekit:"name=object_name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	Privileges    string  `statekit:"name=privileges"`
	GrantOption   bool    `statekit:"name=grant_option"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *HasPrivilegesArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// modPrivOpts ports the pinned _mod_priv_opts (postgres.py:3208-3216): the
// object type is lowercased and the privileges string is uppercased and
// split on optional single spaces around commas.
func modPrivOpts(objectType, privileges string) (string, []string) {
	return strings.ToLower(objectType), privSplitRE.Split(strings.ToUpper(privileges), -1)
}

// validatePrivileges ports the pinned _validate_privileges
// (postgres.py:3184-3205) for has_privileges. The pinned function raises
// KeyError on an object_type missing from _PRIVILEGE_TYPE_MAP (whose keys
// are exactly the pinned _PRIVILEGES_OBJECTS minus group, so the separate
// SaltInvocationError object check is subsumed) before the privilege
// subset test; both Salt failure modes map to execution errors here, and
// the check always precedes any Runner invocation.
func validatePrivileges(objectType string, privs []string, privileges string) error {
	if objectType == "group" {
		if privileges != "" {
			return fmt.Errorf("%w: the privileges option should not be set for object_type group",
				errPostgresInvalidArgument)
		}
		return nil
	}
	typePerms, ok := privilegeTypeMap[objectType]
	if !ok {
		return fmt.Errorf("%w: invalid object_type", errPostgresInvalidArgument)
	}
	allowed := map[string]bool{"ALL": true}
	for _, c := range typePerms {
		allowed[privilegesMap[string(c)]] = true
	}
	for _, priv := range privs {
		if !allowed[priv] {
			return fmt.Errorf("%w: invalid privileges", errPostgresInvalidArgument)
		}
	}
	return nil
}

// privCatalogQuery is one fixed catalog query plus the client-side port of
// the pinned WHERE equality: match reports whether a row is one the pinned
// query's interpolated literals would have selected. Missing key columns
// never match, exactly like a server-side equality against real rows.
type privCatalogQuery struct {
	query string
	match func(row map[string]string, objectName, prepend string) bool
}

// rowEquals is the exact-match helper for one key column.
func rowEquals(row map[string]string, key, want string) bool {
	value, ok := row[key]
	return ok && value == want
}

// ownerQueries ports the pinned _get_object_owner queries
// (postgres.py:3017-3107) as fixed SQL with client-side equality filters.
var ownerQueries = map[string]privCatalogQuery{
	"table": {ownerTableQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "schemaname", prepend) && rowEquals(row, "tablename", objectName)
	}},
	"sequence": {ownerSequenceQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend) && rowEquals(row, "relname", objectName)
	}},
	"schema": {ownerSchemaQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "nspname", objectName)
	}},
	"function": {ownerFunctionQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend) && rowEquals(row, "regprocedure", objectName)
	}},
	"tablespace": {ownerTablespaceQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "spcname", objectName)
	}},
	"language": {ownerLanguageQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "lanname", objectName)
	}},
	"database": {ownerDatabaseQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "datname", objectName)
	}},
}

// privilegesQueries ports the pinned _make_privileges_list_query queries
// (postgres.py:2895-2998) as fixed SQL with client-side equality filters;
// the group membership filter matches the group role's name.
var privilegesQueries = map[string]privCatalogQuery{
	"table": {privilegesTableQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend) && rowEquals(row, "relname", objectName)
	}},
	"sequence": {privilegesSequenceQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend) && rowEquals(row, "relname", objectName)
	}},
	"schema": {privilegesSchemaQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "nspname", objectName)
	}},
	"function": {privilegesFunctionQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend) && rowEquals(row, "regprocedure", objectName)
	}},
	"tablespace": {privilegesTablespaceQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "spcname", objectName)
	}},
	"language": {privilegesLanguageQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "lanname", objectName)
	}},
	"database": {privilegesDatabaseQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "datname", objectName)
	}},
	"group": {privilegesGroupQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "member_of", objectName)
	}},
}

// getObjectOwner ports the pinned _get_object_owner tail
// (postgres.py:3109-3123): the first matching catalog row's owner column,
// and Salt's IndexError None when no row matches. The pinned rows[0]
// KeyError on a short row maps to an execution error. caller names the
// public function whose row-shape errors are attributed.
func getObjectOwner(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, caller, objectName, objectType, prepend string) (*string, error) {
	spec, ok := ownerQueries[objectType]
	if !ok {
		// Unreachable behind validatePrivileges; kept fail-closed.
		return nil, fmt.Errorf("%w: invalid object_type %q provided", errPostgresInvalidArgument, objectType)
	}
	rows, err := psqlQueryRows(ctx, rt, conn, spec.query)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !spec.match(row, objectName, prepend) {
			continue
		}
		owner, err := rowString(row, "name", caller)
		if err != nil {
			return nil, err
		}
		return &owner, nil
	}
	return nil, nil
}

// processPrivPart ports the pinned _process_priv_part
// (postgres.py:3219-3235): each ACL character adds its mapped privilege
// with False, and a following "*" flips the previous privilege to True
// (the grant option). A leading "*" takes the first-branch map lookup, so
// the mapped GRANT name is stored exactly like the pinned dictionary. An
// unknown character is the pinned KeyError.
func processPrivPart(perms string) (map[string]bool, error) {
	return processACLPart(perms, privilegesMap)
}

// processDefPrivPart ports the pinned _process_defpriv_part
// (postgres.py:3165-3181): the identical ladder over the default-ACL
// map, whose missing CONNECT/TEMPORARY/MAINTAIN characters make those the
// pinned KeyError here.
func processDefPrivPart(perms string) (map[string]bool, error) {
	return processACLPart(perms, defPrivilegesMap)
}

// processACLPart is the shared _process_priv_part ladder parameterized on
// the ACL character map.
func processACLPart(perms string, table map[string]string) (map[string]bool, error) {
	out := map[string]bool{}
	previous := ""
	for _, perm := range perms {
		name, ok := table[string(perm)]
		if !ok {
			return nil, errPostgresInvalidACL
		}
		if previous != "" && perm == '*' {
			out[previous] = true
			continue
		}
		out[name] = false
		previous = name
	}
	return out, nil
}

// parseACLGrants ports the pinned ACL ladder (postgres.py:3414-3423):
// strip the PostgreSQL array braces, split entries on commas, require
// exactly one "/" (the grantor) and one "=" (grantee=perms) per entry, map
// the empty grantee to public, and decode the permission characters with
// the pinned _process_priv_part. A NULL acl (the empty CSV field) and any
// malformed entry are the pinned ValueError.
func parseACLGrants(acl string) (map[string]map[string]bool, error) {
	return parseACLGrantsWith(acl, processPrivPart)
}

// parseDefACLGrants is the same pinned ladder decoding through the
// default-ACL _process_defpriv_part map.
func parseDefACLGrants(acl string) (map[string]map[string]bool, error) {
	return parseACLGrantsWith(acl, processDefPrivPart)
}

// parseACLGrantsWith is the pinned ACL ladder parameterized on the
// per-entry permission decoder.
func parseACLGrantsWith(acl string, decode func(string) (map[string]bool, error)) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	for _, part := range strings.Split(strings.Trim(acl, "{}"), ",") {
		slash := strings.Split(part, "/")
		if len(slash) != 2 {
			return nil, errPostgresInvalidACL
		}
		eq := strings.Split(slash[0], "=")
		if len(eq) != 2 {
			return nil, errPostgresInvalidACL
		}
		rolename := eq[0]
		if rolename == "" {
			rolename = "public"
		}
		perms, err := decode(eq[1])
		if err != nil {
			return nil, err
		}
		out[rolename] = perms
	}
	return out, nil
}

// privilegesList ports the pinned privileges_list tail
// (postgres.py:3410-3432) for both has_privileges and the public
// privileges_list: object ACL rows decode through the pinned ladder, and
// group rows map the member rolname to the pinned admin_option == "t"
// boolean. Rows are matched client-side, so the caller's object name never
// reaches SQL; caller names the public function for row-shape errors.
func privilegesList(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, caller, objectName, objectType, prepend string) (map[string]any, error) {
	spec, ok := privilegesQueries[objectType]
	if !ok {
		// Unreachable behind validatePrivileges and the privileges_list
		// object-type check; kept fail-closed.
		return nil, fmt.Errorf("%w: invalid object_type %q provided", errPostgresInvalidArgument, objectType)
	}
	rows, err := psqlQueryRows(ctx, rt, conn, spec.query)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(rows))
	for _, row := range rows {
		if !spec.match(row, objectName, prepend) {
			continue
		}
		if objectType == "group" {
			rolname, err := rowString(row, "rolname", caller)
			if err != nil {
				return nil, err
			}
			adminOption, err := rowString(row, "admin_option", caller)
			if err != nil {
				return nil, err
			}
			out[rolname] = adminOption == "t"
			continue
		}
		acl, err := rowString(row, "name", caller)
		if err != nil {
			return nil, err
		}
		grants, err := parseACLGrants(acl)
		if err != nil {
			return nil, err
		}
		for rolename, perms := range grants {
			out[rolename] = perms
		}
	}
	return out, nil
}

type hasPrivilegesFunc struct{}

func (hasPrivilegesFunc) Name() string { return "postgres.has_privileges" }
func (hasPrivilegesFunc) Args() any    { return HasPrivilegesArgs{} }

func (hasPrivilegesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[HasPrivilegesArgs](args, "postgres.has_privileges")
	if err != nil {
		return nil, err
	}
	// The pinned head (postgres.py:3660-3662): validation before any
	// query, with the object type lowercased and the privileges split.
	objectType, privs := modPrivOpts(a.ObjectType, a.Privileges)
	if err := validatePrivileges(objectType, privs, a.Privileges); err != nil {
		return nil, err
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	return hasPrivileges(ctx, rt, a.connection(), "postgres.has_privileges",
		a.Name, a.ObjectName, objectType, privs, a.GrantOption, prepend)
}

// hasPrivileges is the shared decision core of the public
// postgres.has_privileges and the privileges_grant/privileges_revoke
// preflight (postgres.py:3664-3711): the owner shortcut, the ACL catalog
// decode, and the pinned membership, grant-option, ALL, and subset
// comparisons. The object type arrives lowercased and the privileges split
// from a completed modPrivOpts/validatePrivileges pass, exactly the state
// the pinned function is in after its own head.
func hasPrivileges(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, caller, name, objectName, objectType string, privs []string, grantOption bool, prepend string) (bool, error) {
	if objectType != "group" {
		owner, err := getObjectOwner(ctx, rt, conn, caller, objectName, objectType, prepend)
		if err != nil {
			return false, err
		}
		if owner != nil && name == *owner {
			return true, nil
		}
	}
	grants, err := privilegesList(ctx, rt, conn, caller, objectName, objectType, prepend)
	if err != nil {
		return false, err
	}
	entry, ok := grants[name]
	if !ok {
		return false, nil
	}
	if objectType == "group" {
		// The pinned group tail: membership is True, and the grant-option
		// check is the member's admin_option boolean itself.
		if grantOption {
			return entry.(bool), nil
		}
		return true, nil
	}
	rolePerms := entry.(map[string]bool)
	typePerms := privilegeTypeMap[objectType]
	if grantOption {
		// perms == _privileges[name]: every type privilege present with
		// the grant option and nothing else.
		perms := make(map[string]bool, len(typePerms))
		for _, c := range typePerms {
			perms[privilegesMap[string(c)]] = true
		}
		return privMapEqual(perms, rolePerms), nil
	}
	hasAll := false
	for _, priv := range privs {
		if priv == "ALL" {
			hasAll = true
			break
		}
	}
	if hasAll {
		// sorted(perms) == sorted(_privileges[name]): exactly the type's
		// privileges regardless of grant flags.
		want := make([]string, 0, len(typePerms))
		for _, c := range typePerms {
			want = append(want, privilegesMap[string(c)])
		}
		have := make([]string, 0, len(rolePerms))
		for permName := range rolePerms {
			have = append(have, permName)
		}
		sort.Strings(want)
		sort.Strings(have)
		if len(want) != len(have) {
			return false, nil
		}
		for i := range want {
			if want[i] != have[i] {
				return false, nil
			}
		}
		return true, nil
	}
	// set(_privs).issubset(set(_privileges[name])): every requested
	// privilege present, grant flag irrelevant.
	for _, priv := range privs {
		if _, ok := rolePerms[priv]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// privMapEqual is Python dict equality for the privilege dictionaries:
// same keys and same grant-option values.
func privMapEqual(x, y map[string]bool) bool {
	if len(x) != len(y) {
		return false
	}
	for key, value := range x {
		if y[key] != value {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// privileges_list — salt/modules/postgres.py:3335-3432 @ pinned revision.

// PrivilegesListArgs are the canonical postgres.privileges_list arguments,
// mirroring the pinned privileges_list(name, object_type, prepend="public",
// maintenance_db=None, user=None, host=None, port=None, password=None,
// runas=None) signature (postgres.py:3335-3345). The pinned function lists
// an object's ACL: name is the object, and the signature has no role and no
// privileges argument (those belong to has_privileges).
type PrivilegesListArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *PrivilegesListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type privilegesListFunc struct{}

func (privilegesListFunc) Name() string { return "postgres.privileges_list" }
func (privilegesListFunc) Args() any    { return PrivilegesListArgs{} }

func (privilegesListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[PrivilegesListArgs](args, "postgres.privileges_list")
	if err != nil {
		return nil, err
	}
	// The pinned head (postgres.py:3394-3398): the object type is
	// lowercased, then unknown types are rejected before any query. Salt
	// reaches the same failure one statement earlier — its query builder
	// returns an unbound local for an unmatched branch, so the following
	// SaltInvocationError is dead code for unknown types — and both pinned
	// failure shapes map to this one execution error, raised before any
	// Runner invocation.
	objectType := strings.ToLower(a.ObjectType)
	if _, ok := privilegesQueries[objectType]; !ok {
		return nil, fmt.Errorf("%w: invalid object_type %q provided", errPostgresInvalidArgument, objectType)
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	return privilegesList(ctx, rt, a.connection(), "postgres.privileges_list", a.Name, objectType, prepend)
}

// ---------------------------------------------------------------------------
// privileges_grant / privileges_revoke — salt/modules/postgres.py:4009-4297
// @ pinned revision, with the shared _mod_priv_opts/_validate_privileges
// head (postgres.py:3184-3216) and the has_privileges preflight.

// PrivilegesGrantArgs are the canonical postgres.privileges_grant
// arguments, mirroring the pinned privileges_grant(name, object_name,
// object_type, privileges=None, grant_option=None, prepend="public",
// maintenance_db=None, user, host, port, password, runas) signature
// (postgres.py:4009-4022). Privileges keeps Salt's None default as the
// empty string because the pinned _mod_priv_opts collapses None to ""
// before any use; grant_option is only ever truthiness-tested, so a plain
// bool is exact; prepend nil means the pinned "public" default while an
// explicit empty string keeps Salt's empty-schema handling.
type PrivilegesGrantArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectName    string  `statekit:"name=object_name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	Privileges    string  `statekit:"name=privileges"`
	GrantOption   bool    `statekit:"name=grant_option"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *PrivilegesGrantArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// PrivilegesRevokeArgs are the canonical postgres.privileges_revoke
// arguments, mirroring the pinned privileges_revoke(name, object_name,
// object_type, privileges=None, prepend="public", maintenance_db=None,
// user, host, port, password, runas) signature (postgres.py:4170-4182):
// the pinned revoke signature carries no grant_option, so none exists
// here either.
type PrivilegesRevokeArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectName    string  `statekit:"name=object_name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	Privileges    string  `statekit:"name=privileges"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *PrivilegesRevokeArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// privSchemaQualified marks the object types whose on-part the pinned
// format strings qualify with the raw schema prefix
// (postgres.py:4123-4126, 4275-4278).
func privSchemaQualified(objectType string) bool {
	return objectType == "table" || objectType == "sequence" || objectType == "function"
}

// privIdentifierValidationError is the stable, value-free rejection for
// the raw identifier positions of the pinned GRANT/REVOKE statements: the
// fixed argument key under the shared invalid-argument category, with no
// rejected value, so a value carrying (or overlapping) a caller secret
// cannot leak through the error raised before any Runner invocation.
func privIdentifierValidationError(key string) error {
	return fmt.Errorf("%w: unsupported identifier in %s", errPostgresInvalidArgument, key)
}

// validatePrivMutationIdentifiers fails closed on every position the
// pinned GRANT/REVOKE format strings interpolate raw, before any Runner
// invocation (postgres.py:4121-4155, 4273-4285). The quoted positions —
// the grant role name and the non-group object name — may not carry the
// double quote that escapes their identifier context, like the role
// family's shared rejection. The raw positions — the revoke role name in
// both statements, the group object name in both statements, and the
// schema prefix of every table/sequence/function statement including the
// ALL-variants' IN SCHEMA — must be bare PostgreSQL identifiers
// ([A-Za-z0-9_$]+), the same class db_create applies to its unquoted
// TEMPLATE option. The pinned source interpolates every one of these
// positions unescaped, which StateKit refuses; the grant ALL-variant
// carries no object name at all, so only its raw schema prefix is
// checked. Every rejection is value-free.
func validatePrivMutationIdentifiers(name, objectName, objectType string, revoke bool, prepend string) error {
	if revoke {
		// The pinned REVOKE statements leave the role name raw in both
		// variants: REVOKE {object_name} FROM {name} and
		// REVOKE {} ON {} {} FROM {name}.
		if !bareIdentifierRE.MatchString(name) {
			return privIdentifierValidationError("name")
		}
	} else if strings.Contains(name, `"`) {
		return ddlValidationError("name")
	}
	if objectType == "group" {
		// The pinned group statements interpolate the group name raw in
		// both directions.
		if !bareIdentifierRE.MatchString(objectName) {
			return privIdentifierValidationError("object_name")
		}
		return nil
	}
	if privSchemaQualified(objectType) {
		// The schema prefix lands raw in the on-part and in the
		// ALL-variant's IN SCHEMA clause.
		if !bareIdentifierRE.MatchString(prepend) {
			return privIdentifierValidationError("prepend")
		}
		if !revoke && strings.ToUpper(objectName) == "ALL" {
			// The grant ALL-variant statement carries no object name.
			return nil
		}
	}
	if strings.Contains(objectName, `"`) {
		return ddlValidationError("object_name")
	}
	return nil
}

// privilegesGrantQuery ports the pinned statement construction
// (postgres.py:4121-4155): the comma-joined uppercased privileges, the
// schema-qualified double-quoted on-part for table/sequence/function and
// the plain double-quoted on-part otherwise, and the four pinned
// variants per grant-option branch — group membership (WITH ADMIN
// OPTION), the ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA form (WITH GRANT
// OPTION), and the plain object form — with the role name double-quoted
// in every variant. Callers must have passed
// validatePrivMutationIdentifiers first; the builder itself never
// validates so it can stay an exact port of the pinned format strings.
func privilegesGrantQuery(name, objectName, objectType string, privs []string, grantOption bool, prepend string) string {
	grants := strings.Join(privs, ",")
	allObjects := privSchemaQualified(objectType) && strings.ToUpper(objectName) == "ALL"
	typeKeyword := strings.ToUpper(objectType)
	var onPart string
	if privSchemaQualified(objectType) {
		onPart = prepend + `."` + objectName + `"`
	} else {
		onPart = `"` + objectName + `"`
	}
	switch {
	case objectType == "group" && grantOption:
		return `GRANT ` + objectName + ` TO "` + name + `" WITH ADMIN OPTION`
	case objectType == "group":
		return `GRANT ` + objectName + ` TO "` + name + `"`
	case allObjects && grantOption:
		return `GRANT ` + grants + ` ON ALL ` + typeKeyword + `S IN SCHEMA ` + prepend + ` TO "` + name + `" WITH GRANT OPTION`
	case allObjects:
		return `GRANT ` + grants + ` ON ALL ` + typeKeyword + `S IN SCHEMA ` + prepend + ` TO "` + name + `"`
	case grantOption:
		return `GRANT ` + grants + ` ON ` + typeKeyword + ` ` + onPart + ` TO "` + name + `" WITH GRANT OPTION`
	default:
		return `GRANT ` + grants + ` ON ` + typeKeyword + ` ` + onPart + ` TO "` + name + `"`
	}
}

// privilegesRevokeQuery ports the pinned statement construction
// (postgres.py:4273-4285): the same on-part rule as the grant path, the
// group membership form with both names raw, and the object form with
// the raw role name the pinned REVOKE interpolates — there is no
// ALL-variant and no grant_option in the pinned revoke flow. Callers
// must have passed validatePrivMutationIdentifiers first.
func privilegesRevokeQuery(name, objectName, objectType string, privs []string, prepend string) string {
	grants := strings.Join(privs, ",")
	var onPart string
	if privSchemaQualified(objectType) {
		onPart = prepend + `."` + objectName + `"`
	} else {
		onPart = `"` + objectName + `"`
	}
	if objectType == "group" {
		return `REVOKE ` + objectName + ` FROM ` + name
	}
	return `REVOKE ` + grants + ` ON ` + strings.ToUpper(objectType) + ` ` + onPart + ` FROM ` + name
}

type privilegesGrantFunc struct{}

func (privilegesGrantFunc) Name() string { return "postgres.privileges_grant" }
func (privilegesGrantFunc) Args() any    { return PrivilegesGrantArgs{} }

// Execute ports the pinned privileges_grant flow (postgres.py:4096-4167):
// the shared _mod_priv_opts/_validate_privileges head, the has_privileges
// preflight the pinned source issues without its own grant_option
// argument (so the membership/subset check — never the admin/grant-option
// variant — decides the no-op), the logged-and-False already-granted
// short circuit with no mutation statement, the pinned GRANT statement,
// and the pinned ret["retcode"] == 0 boolean. The identifier boundary is
// the StateKit addition, checked before any Runner invocation.
func (privilegesGrantFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[PrivilegesGrantArgs](args, "postgres.privileges_grant")
	if err != nil {
		return nil, err
	}
	objectType, privs := modPrivOpts(a.ObjectType, a.Privileges)
	if err := validatePrivileges(objectType, privs, a.Privileges); err != nil {
		return nil, err
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	if err := validatePrivMutationIdentifiers(a.Name, a.ObjectName, objectType, false, prepend); err != nil {
		return nil, err
	}
	has, err := hasPrivileges(ctx, rt, a.connection(), "postgres.privileges_grant",
		a.Name, a.ObjectName, objectType, privs, false, prepend)
	if err != nil {
		return nil, err
	}
	if has {
		// The pinned "The object: %s of type: %s already has
		// privileges: %s set" log-and-False no-op.
		return false, nil
	}
	query := privilegesGrantQuery(a.Name, a.ObjectName, objectType, privs, a.GrantOption, prepend)
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

type privilegesRevokeFunc struct{}

func (privilegesRevokeFunc) Name() string { return "postgres.privileges_revoke" }
func (privilegesRevokeFunc) Args() any    { return PrivilegesRevokeArgs{} }

// Execute ports the pinned privileges_revoke flow (postgres.py:4248-4297):
// the shared head, the has_privileges preflight (again without any
// grant_option) whose miss is the logged-and-False no-op with no mutation
// statement, the pinned REVOKE statement, and the pinned
// ret["retcode"] == 0 boolean. The identifier boundary is the StateKit
// addition, checked before any Runner invocation.
func (privilegesRevokeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[PrivilegesRevokeArgs](args, "postgres.privileges_revoke")
	if err != nil {
		return nil, err
	}
	objectType, privs := modPrivOpts(a.ObjectType, a.Privileges)
	if err := validatePrivileges(objectType, privs, a.Privileges); err != nil {
		return nil, err
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	if err := validatePrivMutationIdentifiers(a.Name, a.ObjectName, objectType, true, prepend); err != nil {
		return nil, err
	}
	has, err := hasPrivileges(ctx, rt, a.connection(), "postgres.privileges_revoke",
		a.Name, a.ObjectName, objectType, privs, false, prepend)
	if err != nil {
		return nil, err
	}
	if !has {
		// The pinned "The object: %s of type: %s does not have
		// privileges: %s set" log-and-False no-op.
		return false, nil
	}
	query := privilegesRevokeQuery(a.Name, a.ObjectName, objectType, privs, prepend)
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// default_privileges — salt/modules/postgres.py:3238-3332, 3435-3571,
// 3714-3877, 3880-4006 @ pinned revision, with the shared
// _mod_defpriv_opts/_validate_default_privileges head (postgres.py:3126-3162).

// defPrivilegesQueries ports the pinned _make_default_privileges_list_query
// branches (postgres.py:2808-2888) as fixed SQL with client-side equality
// filters: table/sequence/function match the schema prefix against nspname
// (the pinned {0} receives prepend on those branches), schema matches the
// object name against nspname (the pinned {0} receives the name), and group
// matches the group role's name on the shared membership catalog.
var defPrivilegesQueries = map[string]privCatalogQuery{
	"table": {defPrivTableQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend)
	}},
	"sequence": {defPrivSequenceQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend)
	}},
	"schema": {privilegesSchemaQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "nspname", objectName)
	}},
	"function": {defPrivFunctionQuery, func(row map[string]string, objectName, prepend string) bool {
		return rowEquals(row, "nspname", prepend)
	}},
	"group": {privilegesGroupQuery, func(row map[string]string, objectName, _ string) bool {
		return rowEquals(row, "member_of", objectName)
	}},
}

// validateDefaultPrivileges ports the pinned _validate_default_privileges
// (postgres.py:3126-3151). The pinned function indexes
// _DEFAULT_PRIVILEGE_TYPE_MAP first, so an object type outside that map
// (whose keys are exactly the pinned _DEFAULT_PRIVILEGES_OBJECTS minus
// group) raises KeyError before the separate SaltInvocationError object
// check — both failure modes map to execution errors here, and the check
// always precedes any Runner invocation. Like the R9.2f convention the
// privilege rejection is value-free: the pinned message interpolates the
// rejected defprivileges value, which may carry or overlap a caller
// secret, so the port names only the fixed failure.
func validateDefaultPrivileges(objectType string, privs []string, privileges string) error {
	if objectType == "group" {
		if privileges != "" {
			return fmt.Errorf("%w: the default privileges option should not be set for object_type group",
				errPostgresInvalidArgument)
		}
		return nil
	}
	typePerms, ok := defPrivilegeTypeMap[objectType]
	if !ok {
		return fmt.Errorf("%w: invalid object_type", errPostgresInvalidArgument)
	}
	allowed := map[string]bool{"ALL": true}
	for _, c := range typePerms {
		allowed[defPrivilegesMap[string(c)]] = true
	}
	for _, priv := range privs {
		if !allowed[priv] {
			return fmt.Errorf("%w: invalid default privileges", errPostgresInvalidArgument)
		}
	}
	return nil
}

// defaultPrivilegesList ports the pinned default_privileges_list tail
// (postgres.py:3310-3332): object pg_default_acl rows decode through the
// pinned ladder with the default-ACL _process_defpriv_part map, and group
// rows map the member rolname to the pinned admin_option == "t" boolean.
// Rows are matched client-side, so the caller's schema prefix and object
// name never reach SQL; caller names the public function for row-shape
// errors.
func defaultPrivilegesList(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, caller, objectName, objectType, prepend string) (map[string]any, error) {
	spec, ok := defPrivilegesQueries[objectType]
	if !ok {
		// Unreachable behind the public object-type check and
		// validateDefaultPrivileges; kept fail-closed.
		return nil, fmt.Errorf("%w: invalid object_type %q provided", errPostgresInvalidArgument, objectType)
	}
	rows, err := psqlQueryRows(ctx, rt, conn, spec.query)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(rows))
	for _, row := range rows {
		if !spec.match(row, objectName, prepend) {
			continue
		}
		if objectType == "group" {
			rolname, err := rowString(row, "rolname", caller)
			if err != nil {
				return nil, err
			}
			adminOption, err := rowString(row, "admin_option", caller)
			if err != nil {
				return nil, err
			}
			out[rolname] = adminOption == "t"
			continue
		}
		acl, err := rowString(row, "name", caller)
		if err != nil {
			return nil, err
		}
		grants, err := parseDefACLGrants(acl)
		if err != nil {
			return nil, err
		}
		for rolename, perms := range grants {
			out[rolename] = perms
		}
	}
	return out, nil
}

// DefaultPrivilegesListArgs are the canonical
// postgres.default_privileges_list arguments, mirroring the pinned
// default_privileges_list(name, object_type, prepend="public",
// maintenance_db=None, user, host, port, password, runas) signature
// (postgres.py:3238-3248): name is the object whose default privileges are
// listed (the group role name for object_type group, the schema name for
// object_type schema, and otherwise the object whose owning schema the
// prepend prefix names).
type DefaultPrivilegesListArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *DefaultPrivilegesListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type defaultPrivilegesListFunc struct{}

func (defaultPrivilegesListFunc) Name() string { return "postgres.default_privileges_list" }
func (defaultPrivilegesListFunc) Args() any    { return DefaultPrivilegesListArgs{} }

func (defaultPrivilegesListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DefaultPrivilegesListArgs](args, "postgres.default_privileges_list")
	if err != nil {
		return nil, err
	}
	// The pinned head (postgres.py:3294-3298): the object type is
	// lowercased, then unknown types are rejected before any query. Salt
	// reaches the same failure one statement earlier — its query builder
	// returns an unbound local for an unmatched branch, so the following
	// SaltInvocationError is dead code for unknown types — and both pinned
	// failure shapes map to this one execution error, raised before any
	// Runner invocation.
	objectType := strings.ToLower(a.ObjectType)
	if _, ok := defPrivilegesQueries[objectType]; !ok {
		return nil, fmt.Errorf("%w: invalid object_type", errPostgresInvalidArgument)
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	return defaultPrivilegesList(ctx, rt, a.connection(), "postgres.default_privileges_list", a.Name, objectType, prepend)
}

// hasDefaultPrivileges is the internal decision core of the pinned
// has_default_privileges (postgres.py:3516-3571) shared by the public
// postgres.has_default_privileges registration and the default-privilege
// mutations' preflight: the owner shortcut over the shared owner catalog,
// the default-ACL decode, and the pinned membership, grant-option, ALL,
// and subset comparisons. The object type arrives lowercased and the
// privileges split from a completed modPrivOpts/validateDefaultPrivileges
// pass, exactly the state the pinned function is in after its own head.
// The pinned ALL comparison
// defperms.sort() == _defprivileges[name].keys().sort() evaluates
// list.sort() == dict_keys.sort(): dict_keys carries no sort method, so
// Python raises AttributeError before producing a boolean — StateKit maps
// that deterministic pinned failure to this fixed value-free error.
func hasDefaultPrivileges(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, caller, name, objectName, objectType string, privs []string, grantOption bool, prepend string) (bool, error) {
	if objectType != "group" {
		owner, err := getObjectOwner(ctx, rt, conn, caller, objectName, objectType, prepend)
		if err != nil {
			return false, err
		}
		if owner != nil && name == *owner {
			return true, nil
		}
	}
	grants, err := defaultPrivilegesList(ctx, rt, conn, caller, objectName, objectType, prepend)
	if err != nil {
		return false, err
	}
	entry, ok := grants[name]
	if !ok {
		return false, nil
	}
	if objectType == "group" {
		// The pinned group tail: membership is True, and the grant-option
		// check is the member's admin_option boolean itself.
		if grantOption {
			return entry.(bool), nil
		}
		return true, nil
	}
	rolePerms := entry.(map[string]bool)
	typePerms := defPrivilegeTypeMap[objectType]
	if grantOption {
		// defperms == _defprivileges[name]: every type privilege present
		// with the grant option and nothing else.
		perms := make(map[string]bool, len(typePerms))
		for _, c := range typePerms {
			perms[defPrivilegesMap[string(c)]] = true
		}
		return privMapEqual(perms, rolePerms), nil
	}
	for _, priv := range privs {
		if priv == "ALL" {
			return false, errPostgresDefprivilegesAllCompare
		}
	}
	// set(_defprivs).issubset(set(_defprivileges[name])): every requested
	// privilege present, grant flag irrelevant.
	for _, priv := range privs {
		if _, ok := rolePerms[priv]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// HasDefaultPrivilegesArgs are the canonical
// postgres.has_default_privileges arguments, mirroring the pinned
// has_default_privileges(name, object_name, object_type,
// defprivileges=None, grant_option=None, prepend="public",
// maintenance_db=None, user, host, port, password, runas) signature
// (postgres.py:3435-3448). DefPrivileges keeps Salt's None default as the
// empty string because the pinned _mod_defpriv_opts collapses None to ""
// before any use; grant_option is only ever truthiness-tested, so a plain
// bool is exact; prepend nil means the pinned "public" default while an
// explicit empty string keeps Salt's empty-schema handling.
type HasDefaultPrivilegesArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectName    string  `statekit:"name=object_name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	DefPrivileges string  `statekit:"name=defprivileges"`
	GrantOption   bool    `statekit:"name=grant_option"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *HasDefaultPrivilegesArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type hasDefaultPrivilegesFunc struct{}

func (hasDefaultPrivilegesFunc) Name() string { return "postgres.has_default_privileges" }
func (hasDefaultPrivilegesFunc) Args() any    { return HasDefaultPrivilegesArgs{} }

// Execute ports the pinned has_default_privileges flow
// (postgres.py:3516-3571): the shared _mod_defpriv_opts/
// _validate_default_privileges head with validation before any query,
// then the R9.2l decision core — with the caller's own grant_option,
// unlike the mutation preflights that always drop theirs, so the
// grant-option dict equality and the group admin_option boolean are
// reachable here exactly like the pinned public function. The fixed owner
// and pg_default_acl catalogs stay the only SQL, with every lookup
// matched client-side, so no caller string reaches a statement and no
// identifier boundary exists on this read-only path.
func (hasDefaultPrivilegesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[HasDefaultPrivilegesArgs](args, "postgres.has_default_privileges")
	if err != nil {
		return nil, err
	}
	objectType, privs := modPrivOpts(a.ObjectType, a.DefPrivileges)
	if err := validateDefaultPrivileges(objectType, privs, a.DefPrivileges); err != nil {
		return nil, err
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	return hasDefaultPrivileges(ctx, rt, a.connection(), "postgres.has_default_privileges",
		a.Name, a.ObjectName, objectType, privs, a.GrantOption, prepend)
}

// DefaultPrivilegesGrantArgs are the canonical
// postgres.default_privileges_grant arguments, mirroring the pinned
// default_privileges_grant(name, object_name, object_type,
// defprivileges=None, grant_option=None, prepend="public", maintenance_db,
// user, host, port, password, runas) signature (postgres.py:3714-3727).
// DefPrivileges keeps Salt's None default as the empty string because the
// pinned _mod_defpriv_opts collapses None to "" before any use;
// grant_option is only ever truthiness-tested, so a plain bool is exact;
// prepend nil means the pinned "public" default while an explicit empty
// string keeps Salt's empty-schema handling.
type DefaultPrivilegesGrantArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectName    string  `statekit:"name=object_name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	DefPrivileges string  `statekit:"name=defprivileges"`
	GrantOption   bool    `statekit:"name=grant_option"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *DefaultPrivilegesGrantArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// DefaultPrivilegesRevokeArgs are the canonical
// postgres.default_privileges_revoke arguments, mirroring the pinned
// default_privileges_revoke(name, object_name, object_type,
// defprivileges=None, prepend="public", maintenance_db, user, host, port,
// password, runas) signature (postgres.py:3880-3892): the pinned revoke
// signature carries no grant_option, so none exists here either.
type DefaultPrivilegesRevokeArgs struct {
	Name          string  `statekit:"name=name,required"`
	ObjectName    string  `statekit:"name=object_name,required"`
	ObjectType    string  `statekit:"name=object_type,required"`
	DefPrivileges string  `statekit:"name=defprivileges"`
	Prepend       *string `statekit:"name=prepend"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *DefaultPrivilegesRevokeArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// validateDefPrivIdentifiers fails closed on every position the pinned
// ALTER DEFAULT PRIVILEGES format strings interpolate raw or quote without
// escaping, before any Runner invocation (postgres.py:3825-3865,
// 3987-3994). The grantee role name is quoted in every grant statement but
// raw in the REVOKE tail, the group object name is raw in both directions,
// and the schema prefix lands raw in every IN SCHEMA clause. The
// grant_option non-ALL grant branch is the pinned asymmetry: its {2}
// receives the on-part — prepend."object" for table/sequence, the bare
// object name for function, and the plain quoted object name for schema —
// instead of the schema prefix, so those object positions reach SQL only
// there and are checked only there; the plain statements interpolate no
// object name at all (the pinned revoke even computes an on_part it never
// uses). Quoted positions may not carry the double quote; raw positions
// must be bare PostgreSQL identifiers. Every rejection is value-free.
func validateDefPrivIdentifiers(name, objectName, objectType string, revoke, grantOption bool, prepend string) error {
	if revoke {
		// The pinned REVOKE tail interpolates the role name raw in both
		// variants.
		if !bareIdentifierRE.MatchString(name) {
			return privIdentifierValidationError("name")
		}
	} else if strings.Contains(name, `"`) {
		return ddlValidationError("name")
	}
	if objectType == "group" {
		// The pinned group statements interpolate the group name raw in
		// both directions.
		if !bareIdentifierRE.MatchString(objectName) {
			return privIdentifierValidationError("object_name")
		}
		return nil
	}
	if privSchemaQualified(objectType) && strings.ToUpper(objectName) == "ALL" {
		// The ALL-variant statements carry no object name; only their raw
		// schema prefix reaches SQL.
		if !bareIdentifierRE.MatchString(prepend) {
			return privIdentifierValidationError("prepend")
		}
		return nil
	}
	if grantOption && !revoke {
		// The pinned grant_option else-branch interpolates the on-part
		// raw into IN SCHEMA (postgres.py:3849-3852).
		switch objectType {
		case "table", "sequence":
			if !bareIdentifierRE.MatchString(prepend) {
				return privIdentifierValidationError("prepend")
			}
			if strings.Contains(objectName, `"`) {
				return ddlValidationError("object_name")
			}
		case "function":
			if !bareIdentifierRE.MatchString(objectName) {
				return privIdentifierValidationError("object_name")
			}
		default:
			// schema: the on-part is the plain double-quoted object name.
			if strings.Contains(objectName, `"`) {
				return ddlValidationError("object_name")
			}
		}
		return nil
	}
	// The plain statements interpolate only the raw schema prefix; the
	// revoke role name was checked above.
	if !bareIdentifierRE.MatchString(prepend) {
		return privIdentifierValidationError("prepend")
	}
	return nil
}

// defaultPrivilegesGrantQuery ports the pinned statement construction
// (postgres.py:3823-3865): the comma-joined uppercased privileges, the
// on-part (schema-qualified double-quoted for table/sequence, bare for
// function, plain double-quoted otherwise), and the pinned variants —
// group membership with WITH ADMIN OPTION, the ALL
// TABLES/SEQUENCES/FUNCTIONS IN SCHEMA form, and the plain forms — with
// the role name double-quoted in every variant and WITH GRANT OPTION
// confined to the grant side. The pinned asymmetry is preserved exactly:
// the grant_option non-ALL branch interpolates the on-part into IN SCHEMA
// while every other branch interpolates the bare schema prefix, and the
// no-option ALL and non-ALL branches are byte-identical. Callers must have
// passed validateDefPrivIdentifiers first; the builder itself never
// validates so it can stay an exact port of the pinned format strings.
func defaultPrivilegesGrantQuery(name, objectName, objectType string, privs []string, grantOption bool, prepend string) string {
	grants := strings.Join(privs, ",")
	typeKeyword := strings.ToUpper(objectType)
	var onPart string
	switch objectType {
	case "table", "sequence":
		onPart = prepend + `."` + objectName + `"`
	case "function":
		onPart = objectName
	default:
		onPart = `"` + objectName + `"`
	}
	switch {
	case objectType == "group" && grantOption:
		return `ALTER DEFAULT PRIVILEGES GRANT ` + objectName + ` TO "` + name + `" WITH ADMIN OPTION`
	case objectType == "group":
		return `ALTER DEFAULT PRIVILEGES GRANT ` + objectName + ` TO "` + name + `"`
	case privSchemaQualified(objectType) && strings.ToUpper(objectName) == "ALL" && grantOption:
		return `ALTER DEFAULT PRIVILEGES IN SCHEMA ` + prepend + ` GRANT ` + grants + ` ON ` + typeKeyword + `S TO "` + name + `" WITH GRANT OPTION`
	case grantOption:
		return `ALTER DEFAULT PRIVILEGES IN SCHEMA ` + onPart + ` GRANT ` + grants + ` ON ` + typeKeyword + `S TO "` + name + `" WITH GRANT OPTION`
	default:
		return `ALTER DEFAULT PRIVILEGES IN SCHEMA ` + prepend + ` GRANT ` + grants + ` ON ` + typeKeyword + `S TO "` + name + `"`
	}
}

// defaultPrivilegesRevokeQuery ports the pinned statement construction
// (postgres.py:3980-3994): the group membership form with both names raw,
// and the object form with the bare schema prefix in IN SCHEMA and the raw
// role name the pinned REVOKE interpolates — there is no ALL-variant and
// no grant_option in the pinned revoke flow (the on_part the pinned source
// computes at postgres.py:3982-3985 is never used and is not ported).
// Callers must have passed validateDefPrivIdentifiers first.
func defaultPrivilegesRevokeQuery(name, objectName, objectType string, privs []string, prepend string) string {
	grants := strings.Join(privs, ",")
	if objectType == "group" {
		return `ALTER DEFAULT PRIVILEGES REVOKE ` + objectName + ` FROM ` + name
	}
	return `ALTER DEFAULT PRIVILEGES IN SCHEMA ` + prepend + ` REVOKE ` + grants + ` ON ` + strings.ToUpper(objectType) + `S FROM ` + name
}

type defaultPrivilegesGrantFunc struct{}

func (defaultPrivilegesGrantFunc) Name() string { return "postgres.default_privileges_grant" }
func (defaultPrivilegesGrantFunc) Args() any    { return DefaultPrivilegesGrantArgs{} }

// Execute ports the pinned default_privileges_grant flow
// (postgres.py:3796-3877): the shared _mod_defpriv_opts/
// _validate_default_privileges head, the has_default_privileges preflight
// the pinned source issues without its own grant_option argument (so the
// membership/subset check — never the admin/grant-option or ALL variant —
// decides the no-op), the logged-and-False already-granted short circuit
// with no mutation statement, the pinned ALTER DEFAULT PRIVILEGES
// statement, and the pinned ret["retcode"] == 0 boolean. The identifier
// boundary is the StateKit addition, checked before any Runner invocation.
func (defaultPrivilegesGrantFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DefaultPrivilegesGrantArgs](args, "postgres.default_privileges_grant")
	if err != nil {
		return nil, err
	}
	objectType, privs := modPrivOpts(a.ObjectType, a.DefPrivileges)
	if err := validateDefaultPrivileges(objectType, privs, a.DefPrivileges); err != nil {
		return nil, err
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	if err := validateDefPrivIdentifiers(a.Name, a.ObjectName, objectType, false, a.GrantOption, prepend); err != nil {
		return nil, err
	}
	has, err := hasDefaultPrivileges(ctx, rt, a.connection(), "postgres.default_privileges_grant",
		a.Name, a.ObjectName, objectType, privs, false, prepend)
	if err != nil {
		return nil, err
	}
	if has {
		// The pinned "The object: %s of type: %s already has default
		// privileges: %s set" log-and-False no-op.
		return false, nil
	}
	query := defaultPrivilegesGrantQuery(a.Name, a.ObjectName, objectType, privs, a.GrantOption, prepend)
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

type defaultPrivilegesRevokeFunc struct{}

func (defaultPrivilegesRevokeFunc) Name() string { return "postgres.default_privileges_revoke" }
func (defaultPrivilegesRevokeFunc) Args() any    { return DefaultPrivilegesRevokeArgs{} }

// Execute ports the pinned default_privileges_revoke flow
// (postgres.py:3953-4006): the shared head, the has_default_privileges
// preflight (again without any grant_option) whose miss is the
// logged-and-False no-op with no mutation statement, the pinned ALTER
// DEFAULT PRIVILEGES REVOKE statement, and the pinned ret["retcode"] == 0
// boolean. The identifier boundary is the StateKit addition, checked
// before any Runner invocation.
func (defaultPrivilegesRevokeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DefaultPrivilegesRevokeArgs](args, "postgres.default_privileges_revoke")
	if err != nil {
		return nil, err
	}
	objectType, privs := modPrivOpts(a.ObjectType, a.DefPrivileges)
	if err := validateDefaultPrivileges(objectType, privs, a.DefPrivileges); err != nil {
		return nil, err
	}
	prepend := defaultPrependSchema
	if a.Prepend != nil {
		prepend = *a.Prepend
	}
	if err := validateDefPrivIdentifiers(a.Name, a.ObjectName, objectType, true, false, prepend); err != nil {
		return nil, err
	}
	has, err := hasDefaultPrivileges(ctx, rt, a.connection(), "postgres.default_privileges_revoke",
		a.Name, a.ObjectName, objectType, privs, false, prepend)
	if err != nil {
		return nil, err
	}
	if !has {
		// The pinned "The object: %s of type: %s does not have default
		// privileges: %s set" log-and-False no-op.
		return false, nil
	}
	query := defaultPrivilegesRevokeQuery(a.Name, a.ObjectName, objectType, privs, prepend)
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", query,
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return result.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// shared helpers (rabbitmq-module conventions).

func typedArgs[T any](args any, name string) (*T, error) {
	value, ok := args.(*T)
	if !ok || value == nil {
		return nil, fmt.Errorf("%s: expected *arguments, got %T", name, args)
	}
	return value, nil
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// pointerBool is the pinned bool() over an optional argument: nil (Python
// None) is false.
func pointerBool(value *bool) bool {
	return value != nil && *value
}

func rejectRunas(runas *string) error {
	if runas == nil || *runas == "" {
		return nil
	}
	if strings.IndexByte(*runas, 0) >= 0 || strings.ContainsAny(*runas, "\r\n") {
		return errPostgresInvalidArgument
	}
	return errPostgresRunas
}

func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return errPostgresInvalidArgument
	}
	total := 0
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 || strings.ContainsAny(arg, "\r\n") {
			return errPostgresInvalidArgument
		}
		total += len(arg)
		if total > runtime.MaxCommandInputBytes {
			return runtime.ErrCommandInputLimit
		}
	}
	return nil
}

func secretList(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// redactedError strips every given secret (the connection password plus
// any statement-carried rolepassword forms) from a Runner error, so no
// credential travels through returned errors. Empty secrets leave the
// error untouched.
func redactedError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	list := secretList(secrets...)
	if len(list) == 0 {
		return err
	}
	message := process.RedactString(list, err.Error())
	if message == err.Error() {
		return err
	}
	return errors.New(message)
}

// Register installs the R9.2o postgres slice: the version probe, the five
// R9.2c read-only catalog primitives, the R9.2h write paths db_create and
// db_remove, the eight R9.2d extension and language catalog functions,
// the three R9.2e schema catalog functions, the three R9.2f role and
// privilege checks, the R9.2g ACL listing privileges_list, the R9.2i
// role mutations user_create, user_update, and user_remove, the R9.2j
// group mutations group_create, group_update, and group_remove, the R9.2k
// privilege mutations privileges_grant and privileges_revoke, the R9.2l
// default-privilege family default_privileges_list,
// default_privileges_grant, and default_privileges_revoke, the R9.2m
// schema, extension, and language mutations schema_create,
// schema_remove, create_extension, drop_extension, language_create, and
// language_remove, the R9.2n database mutation db_alter (whose
// owner_recurse branch answers the pending owner_to name with the fixed
// UnsupportedError instead of a shallow ALTER OWNER), and the R9.2o
// tablespace mutations tablespace_create, tablespace_alter, and
// tablespace_remove (the pinned CREATE/ALTER/DROP TABLESPACE statements
// with the pinned truthiness no-op head, clause order, and retcode
// booleans), and the R9.2p datadir pair datadir_exists and datadir_init
// (the pinned PG_VERSION/postgresql.conf marker probe over Runtime.FS and
// the pinned initdb argv with the pwfile credential transport and the
// pinned kernel-mapped OpenBSD _postgresql runas default), plus the
// R9.2q read-only default-privilege check has_default_privileges (the
// decision core the R9.2l mutations already run as their preflight, now
// registered under its canonical public name with the caller's own
// grant_option). The remainder of the
// postgres family needs the generic psql query surface (psql_query itself
// stays pending; no arbitrary-query registration exists in this phase) and
// stays pending for later R9 rounds; the internal parsed-version,
// psql-query, role-statement, and create-metadata helpers are
// intentionally not registered, exactly like
// the pinned private functions (create_metadata keeps its pending public
// name until a later round registers it).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		dbListFunc{},
		dbExistsFunc{},
		dbCreateFunc{},
		dbRemoveFunc{},
		dbAlterFunc{},
		tablespaceListFunc{},
		tablespaceExistsFunc{},
		tablespaceCreateFunc{},
		tablespaceAlterFunc{},
		tablespaceRemoveFunc{},
		datadirExistsFunc{},
		datadirInitFunc{},
		userListFunc{},
		availableExtensionsFunc{},
		installedExtensionsFunc{},
		getAvailableExtensionFunc{},
		getInstalledExtensionFunc{},
		isAvailableExtensionFunc{},
		isInstalledExtensionFunc{},
		createExtensionFunc{},
		dropExtensionFunc{},
		languageListFunc{},
		languageExistsFunc{},
		languageCreateFunc{},
		languageRemoveFunc{},
		schemaExistsFunc{},
		schemaGetFunc{},
		schemaListFunc{},
		schemaCreateFunc{},
		schemaRemoveFunc{},
		roleGetFunc{},
		userExistsFunc{},
		hasPrivilegesFunc{},
		privilegesListFunc{},
		privilegesGrantFunc{},
		privilegesRevokeFunc{},
		defaultPrivilegesListFunc{},
		hasDefaultPrivilegesFunc{},
		defaultPrivilegesGrantFunc{},
		defaultPrivilegesRevokeFunc{},
		userCreateFunc{},
		userUpdateFunc{},
		userRemoveFunc{},
		groupCreateFunc{},
		groupUpdateFunc{},
		groupRemoveFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
