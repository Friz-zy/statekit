package differential

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/runtime"

	"gopkg.in/yaml.v3"
)

// R9 is the services-tier round. R9.1 reconciled the complete rabbitmq
// catalog against bootstrap registration without starting a broker (the
// module's untagged fake-runner suite supplies the command, parser, error,
// cancellation, bounds, and CLI evidence). R9.2a adds the mysql family's
// driver-free pure slice: quote_identifier and tokenize_grant, pinned by
// source-derived lexer vectors. R9.2b adds the postgres family's CLI-first
// slice: the psql-backed version probe plus the internal LooseVersion-
// equivalent parsed-version helper. R9.2c extends that slice with the five
// read-only catalog primitives db_list, db_exists, tablespace_list,
// tablespace_exists, and user_list, pinned against the pinned pytest CSV
// and row fixtures through the same fake-Runner transport. R9.2d adds the
// eight read-only extension and language catalog functions
// available_extensions, installed_extensions, get_available_extension,
// get_installed_extension, is_available_extension, is_installed_extension,
// language_list, and language_exists (postgres.py:1654-1846, 2602-2695),
// with every extension and language lookup matched client-side so no
// caller string reaches SQL. R9.2e adds the three read-only schema catalog
// functions schema_exists, schema_get, and schema_list
// (postgres.py:2444-2599) with the pinned schema-family connection
// signature and the same client-side name matching. R9.2f adds the three
// read-only role and privilege checks role_get, user_exists, and
// has_privileges (postgres.py:1104-1170, 3574-3711): role_get reuses the
// user_list catalog with the pinned .get(name, None) and
// bool(role_get(...)) shapes, and has_privileges keeps the pinned owner
// and ACL catalogs as fixed queries whose interpolated equality literals
// are matched client-side, reproducing the pinned table, group, and
// function privilege outcomes. R9.2g exposes the read-only ACL listing
// privileges_list (postgres.py:3335-3432) on the R9.2f privilege catalogs
// and ACL decode ladder, reproducing the pinned
// test_privileges_list_table and test_privileges_list_group dictionaries
// verbatim. R9.2h adds the family's first write paths, db_create and
// db_remove (postgres.py:601-607, 610-673, 727-762): the pinned CREATE
// DATABASE statement with the pinned _quote_ddl_value quoting and option
// order, and the pinned three-statement REVOKE, backend-termination, and
// DROP flow with its first-nonzero-retcode abort, with the raw-interpolated
// identifier positions validated fail-closed. R9.2i adds the role mutation
// family user_create, user_update, and user_remove (postgres.py:1368-1431,
// 1487-1610, 1613-1651, 2066-2092 through _role_create/_role_update/
// _role_remove and the pinned _role_cmd_args/_add_role_flag clause
// machine): the pinned CREATE/ALTER/DROP ROLE and GRANT statements with
// the pinned clause order, user-typed defaults, superuser skip, md5,
// plaintext, and SCRAM-SHA-256 verifiers, and the pinned preflight and
// post-check flow, with the role name and GRANT groups validated
// fail-closed and the rolepassword redacted. R9.2j adds the group mutation
// family group_create, group_update, and group_remove (postgres.py:2098-
// 2225 through the same flows with typ_="group"): the pinned group
// signatures without connlimit or valid_until, the group-typed INHERIT
// NOLOGIN defaults on create (and their pinned absence on update), and
// the same identifier and redaction boundaries. R9.2k adds the privilege
// mutations privileges_grant and privileges_revoke (postgres.py:4009-
// 4297 through the shared _mod_priv_opts/_validate_privileges head and
// the has_privileges preflight the pinned source issues without its own
// grant_option argument): the pinned GRANT/REVOKE statements with the
// schema-qualified double-quoted on-part for table/sequence/function,
// the ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA variants, the raw group
// membership forms with WITH ADMIN OPTION on the grant side and WITH
// GRANT OPTION on the object side, and the pinned raw role name of the
// REVOKE tail, with every raw or unescaped identifier position validated
// fail-closed before any Runner invocation. R9.2l adds the
// default-privilege family default_privileges_list,
// default_privileges_grant, and default_privileges_revoke
// (postgres.py:3238-3332, 3435-3571, 3714-3877, 3880-4006 through the
// pinned pg_default_acl catalogs and the _mod_defpriv_opts/
// _validate_default_privileges head): the fixed
// ALTER DEFAULT PRIVILEGES statements with the pinned grant_option
// on-part asymmetry, the has_default_privileges preflight without its own
// grant_option, and the pinned dict_keys.sort() ALL comparison mapped to
// a fixed value-free error. R9.2m adds the schema, extension, and
// language mutation families schema_create and schema_remove
// (postgres.py:2316-2366, 2369-2441), create_extension and drop_extension
// (postgres.py:1895-1962, 1965-2063 through the pinned create_metadata
// lifecycle flags), and language_create and language_remove
// (postgres.py:2698-2750, 2753-2805): the pinned CREATE/DROP SCHEMA,
// CREATE/ALTER/DROP EXTENSION, and CREATE/DROP LANGUAGE statements with
// the pinned existence preflights, retcode booleans, and no-op semantics,
// with every raw or unescaped identifier position validated fail-closed
// before any Runner invocation. R9.2n adds the database mutation db_alter
// (postgres.py:676-724): the pinned any((tablespace, owner)) no-op head,
// the pinned OWNER-before-TABLESPACE statement sequence of test_db_alter,
// and the owner+owner_recurse branch whose pinned owner_to delegation
// stays pending — surfaced as a deterministic value-free UnsupportedError
// before any mutation instead of a silent shallow ALTER OWNER — with the
// name, owner, and tablespace double-quoted identifier positions
// validated fail-closed. R9.2o adds the tablespace mutation family
// tablespace_create, tablespace_alter, and tablespace_remove
// (postgres.py:840-886, 889-947, 950-980): the pinned CREATE TABLESPACE
// statement with its truthy OWNER clause, LOCATION literal, and WITH
// options tail; the pinned any([...]) no-op head, RENAME/OWNER TO/SET/
// RESET clause order, and first-nonzero False abort of tablespace_alter;
// and the pinned single DROP TABLESPACE statement with its retcode
// boolean and no existence preflight — with the name, owner, and new-name
// identifier positions, the raw option tokens, and the LOCATION literal
// (absolute, clean, control-free, quote-free) validated fail-closed
// before any Runner invocation. R9.2p adds the datadir pair
// datadir_exists and datadir_init (postgres.py:4300-4393 through
// _run_initdb postgres.py:236-306): the pinned PG_VERSION and
// postgresql.conf marker probe answered read-only over Runtime.FS with a
// no-follow regular-file check, and the pinned initdb argv with its
// --pgdata/--username/--auth/--encoding head, the pinned short -X waldir
// pair, --data-checksums, and the pwfile credential transport — the
// password written to a private Runtime.FS temp file, never argv or the
// environment, and removed after the run — with the runas rejection, the
// value-free path boundary, the value-free pwfile preparation categories
// (the joined write-plus-cleanup sentinel when both fail), the pinned
// kernel-mapped OpenBSD _postgresql runas default, the process-wide
// test-mode no-mutation contract, and the retcode boolean. The generic
// psql_query surface and the remaining mysql and postgres surfaces need
// their client protocol boundaries and stay pending.
type r9FamilySpec struct {
	Source             string
	SourceTests        string
	Platform           string
	Scenarios          []string
	Evidence           []string
	CompatibilityNotes []string
	// RegisteredSubset is nil when every public catalog function must be
	// registered (R9.1 rabbitmq). Otherwise it names the exact partial
	// slice this round registers; all other public functions stay pending.
	RegisteredSubset []string
}

var r9FamilySpecs = map[string]r9FamilySpec{
	"rabbitmq": {
		Source:      "salt/modules/rabbitmq.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_rabbitmq.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform CLI wrapper",
		Scenarios: []string{
			"rabbitmq.users-vhosts-permissions",
			"rabbitmq.password-check-and-status",
			"rabbitmq.policy-list-set-delete",
			"rabbitmq.plugin-list-enable-disable",
			"rabbitmq.federation-upstream-list-set-delete",
		},
		Evidence: []string{
			"fake Runner tests reject temporary-user creation before execution and preserve replacements after successful non-atomic authentication without destructive cleanup",
			"source-derived helper/version/layout vectors run without package installation or a live broker",
			"Windows batch quoting is builder-tested on a non-Windows host; no native Windows runtime claim is made",
		},
		CompatibilityNotes: []string{
			"runas is rejected before Runner invocation because the central runtime is single-user and has no elevation contract",
			"DefaultRunner follows Salt PATH/registry discovery; Unix plugin fallback uses pkg.version(rabbitmq-server) and the exact versioned /usr/lib layout",
			"list_policies uses pkg.version(rabbitmq-server), or pkg.version(rabbitmq) on FreeBSD; no status/glob guess is used",
			"Windows .bat helpers pass a final cmd.exe /D /S /C line via SysProcAttr.CmdLine with an 8191 UTF-16-unit limit and injection rejection; native helpers remain direct argv",
			"Windows .bat transport is fail-closed for embedded double quotes and command metacharacters; rejected values never fall back to shell execution",
			"Therefore set_upstream JSON, nonempty JSON set_policy definitions, and legacy check_password Erlang eval paths may be rejected through batch transport",
			"37/37 means the registered/mock contract only; it does not mean successful native Windows batch execution",
			"Future support requires a separately gated Windows-safe transport, not weakening validation",
			"add_user without password is unsupported: no atomic ownership-conditioned cleanup exists; explicit-password add_user and join_cluster do not create temporary accounts",
			"policy layout follows Salt package-version hyphen splitting then PEP 440 comparison with 3.7, including prerelease/dev/local ordering",
			"list_upstreams redacts AMQP URI user-info before returning CLI-visible parameter data",
		},
	},
	"mysql": {
		Source:      "salt/modules/mysql.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_mysql.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform pure functions",
		Scenarios: []string{
			"mysql.identifier-quoting",
			"mysql.grant-lexer-shapes",
		},
		Evidence: []string{
			"source-derived quoting and lexer vectors from the pinned mysql.py, including the three _grant_to_tokens docstring split examples run verbatim",
			"direct, registry, and CLI mock tests execute with a nil Runner and no filesystem access; no MySQL driver or protocol client is linked",
			"the pinned pytests map the module but do not cover the tokenizer; coverage here is algorithm-derived, not test-file-derived",
		},
		CompatibilityNotes: []string{
			"R9.2a registers only the two driver-free pure functions quote_identifier and tokenize_grant; the remaining public surface requires the MySQL client protocol boundary (E5) and stays pending",
			"the tokenizer keeps the pinned shlex configuration (quotes apostrophe/backtick, double-quote folded into wordchars, non-posix inert escape) so backslash separates tokens instead of escaping",
			"read-ahead edge behavior is preserved: shlex ValueError(No closing quotation) and the grants/user IndexError map to execution errors, the db-phrase IndexError ends parsing, and a missing host after @ degrades to an empty host",
			"PROXY-style grants concatenate every post-ON token into database without separators because the pinned phrase machine never leaves the db phase",
			"column privileges keep the pinned current_grant prefixing, including the empty-prefix .token shape after multi-word privileges",
			"quote_identifier keeps the pinned replacement order: backtick doubling first, underscore escaping only for for_grants, then percent doubling",
			"grant values render as a JSON array ([] never null) and dict-mode qry input unescapes MySQLdb %% while leaving string-mode %% untouched",
			"no MySQL driver, live server, network egress, or new dependency is claimed or added",
		},
		RegisteredSubset: []string{
			"mysql.quote_identifier",
			"mysql.tokenize_grant",
		},
	},
	"postgres": {
		Source:      "salt/modules/postgres.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		SourceTests: "tests/pytests/unit/modules/test_postgres.py @ 8b63e700637e40d76f80a00d95c60471797c73b9",
		Platform:    "cross-platform CLI wrapper",
		Scenarios: []string{
			"postgres.server-version-probe",
			"postgres.read-only-catalog-lists",
			"postgres.database-alter",
			"postgres.database-create-remove",
			"postgres.default-privileges-list-grant-revoke",
			"postgres.role-user-create-update-remove",
			"postgres.role-group-create-update-remove",
			"postgres.privileges-grant-revoke",
			"postgres.extension-and-language-catalogs",
			"postgres.extension-create-drop",
			"postgres.language-create-remove",
			"postgres.schema-catalogs",
			"postgres.schema-create-remove",
			"postgres.tablespace-create-alter-remove",
			"postgres.datadir-exists-init",
			"postgres.role-and-privilege-checks",
		},
		Evidence: []string{
			"direct, registry, and CLI fake-Runner tests pin the exact psql argv (SQL at index 14 as the pinned test_version asserts), the clean PG environment, first-line split semantics, and the None fallthrough for empty stdout",
			"db_list, db_exists, tablespace_list, and tablespace_exists run the pinned get_test_list_db_csv and tablespace fixtures verbatim through the COPY-to-CSV transport and match the pinned expected dictionaries",
			"user_list pins the pinned test_user_list row shape (t/f/None booleans, strptime expiry, CSV-decoded groups array, connections None) and the version-dependent 9.1/9.5 column selection including the return_password joins",
			"the two CSV decoders are pinned by vectors generated from the pinned Python csv.reader itself (python:3.12): PostgreSQL array text with backslash-escaped elements decodes like list(csv.reader([row[\"groups\"].strip(\"{}\")]))[0] (for example {\"a\\\"b\",\"x\\\\y\"} yields [a\\b\", x\\y]), and COPY CSV rows keep embedded CRLF byte-exact inside quoted fields where Go's encoding/csv would normalize it to LF",
			"available_extensions and installed_extensions reproduce the pinned test_available_extensions/test_installed_extensions dictionaries verbatim (the whole row stored under its name/extname key) plus realistic pg_available_extensions and pg_extension COPY CSV fixtures with the pinned short-row column filtering",
			"get_available_extension and get_installed_extension keep the pinned .get(name, None) exact-case row-or-None shape, is_available_extension keeps the pinned case-insensitive name.lower() key membership, is_installed_extension keeps the pinned bool(get_installed_extension(...)) exact-case truthiness, and language_exists keeps the pinned exact-case `name in languages` membership",
			"language_list runs the pinned get_test_list_language_csv fixture verbatim to the pinned name→name dictionary with the pinned SELECT lanname AS \"Name\" FROM pg_language SQL, and maintenance_db stays the pinned required positional",
			"schema_list runs the pinned get_test_list_schema_csv fixture verbatim to the pinned {public, pg_toast} dictionary with only the owner and acl pair per row (the pinned SELECT pg_namespace.nspname ... LEFT JOIN pg_roles SQL byte-for-byte), schema_get keeps the pinned .get(name, None) exact-case row-or-None shape with the empty-acl pg_toast row still a hit, and schema_exists keeps the pinned bool(schema_get(...)) truthiness",
			"role_get and user_exists keep the pinned user_list(...).get(name, None) and bool(role_get(..., return_password=False)) shapes including Salt's False-catalog AttributeError-to-None fallthrough after one psql call, and has_privileges reproduces the pinned test_has_privileges_on_table, test_has_privileges_on_group, and test_has_privileges_with_function outcomes verbatim: the pinned table ACL fixture decodes to the pinned three-role privilege dictionary, the owner shortcut, the grant-option dict equality, the ALL sorted-key equality, the strict-subset check, and the group admin_option boolean",
			"privileges_list reproduces the pinned test_privileges_list_table and test_privileges_list_group dictionaries verbatim on the R9.2f fixed privilege catalogs: the pinned table ACL fixture decodes to the pinned three-role grant-option dictionary and the pinned group fixture maps every member rolname to its admin_option boolean, with the public grantee, grant stars, the leading GRANT star, the pinned NULL/malformed-ACL ValueError shape, the prepend schema qualification, and the per-object-type fixed SQL asserted for all eight object types",
			"the pinned _get_object_owner and _make_privileges_list_query interpolate caller names into SQL string literals; StateKit keeps the pinned catalogs, join shapes, and orderings as fixed COPY-wrapped queries and matches the object name, schema prefix, and group membership client-side, so no caller string reaches SQL (asserted by leak checks with names that collide with no SQL keyword or column)",
			"db_create reproduces the pinned test_db_create and test_db_create_empty_string_param statements byte-for-byte (the pinned runas argument is rejected before execution by the single-user runtime) including the pinned OrderedDict option order and the pinned bare TEMPLATE identifier, db_remove reproduces the pinned three-call REVOKE, pg_terminate_backend, and DROP sequence of test_db_remove with each statement on the full pinned argv, and the pinned test_db_create_with_trivial_sql_injection SaltInvocationError plus the name, template, owner, and tablespace injection attempts are rejected before any Runner invocation",
			"db_create answers exactly the pinned retcode boolean (a rejected CREATE is false, never an error) and db_remove aborts on the first nonzero retcode like the pinned raise Exception(f\"Failed: ret={ret}\"), never reaching the DROP for a missing database and returning true immediately after a successful DROP with no post-query",
			"db_alter reproduces the pinned test_db_alter statements byte-for-byte on the full pinned argv (ALTER DATABASE \"dbname\" OWNER TO \"otheruser\" before ALTER DATABASE \"dbname\" SET TABLESPACE \"testspace\", SQL at index 14) and the pinned test_db_alter_owner_recurse delegation shape: the owner+owner_recurse branch carries only the pinned owner_to arguments (name, owner, user, host, port, password, runas — no maintenance_db), and because owner_to stays pending exactly like a later pending name, the branch answers the deterministic value-free unsupported function \"postgres.owner_to\" error raised before any Runner invocation instead of silently degrading to the shallow ALTER OWNER the else branch runs (asserted direct, through the registry, and through the CLI with exit 3)",
			"db_alter keeps the pinned any((tablespace, owner)) head exactly: neither argument (nil or the Python-falsy explicit empty string) is the logged-True no-op with no Runner invocation, owner alone runs only the pinned OWNER statement, tablespace alone only the pinned TABLESPACE statement, and owner_recurse without a truthy owner never selects the unsupported branch",
			"db_alter answers the pinned ret[\"retcode\"] != 0 False as compatibility data (a rejected ALTER is false, never an error) and stops at the first failed statement so no later mutation follows a failed one — the pinned loop overwrites ret per iteration and reads only the last retcode, which the port deliberately refuses to reproduce; each identifier position the pinned format strings double-quote without escaping (name, owner, tablespace) is rejected fail-closed with the shared value-free error before any Runner invocation (asserted by synthetic marker vectors direct, through the registry, and through the CLI)",
			"user_create reproduces the pinned test_user_create statement (CREATE ROLE with the pinned double space after WITH, INHERIT through VALID UNTIL clause order, UNENCRYPTED PASSWORD literal, VALID UNTIL quote doubling, and the GRANT group suffix) and user_update reproduces the pinned test_user_update, test_user_update2, test_user_update3, and test_user_update_encrypted_passwd statements byte-for-byte on the full pinned argv, including the md5 digest md531c27e68d3771c392b52102c01be1da1; the SCRAM-SHA-256 verifier readback is asserted full-value on both create and update (an already-prefixed password is the entire PASSWORD literal) and a generated verifier is asserted against the exact pinned SCRAM-SHA-256$iterations:salt$stored:server rendering with the $ before the stored key, its stored and server keys recomputed from the parsed salt",
			"user_remove reproduces the pinned test_user_remove DROP ROLE argv exactly, and every user flow keeps the pinned preflight and post-check semantics over the registered user_list catalog: an existing role is the logged-and-False create no-op, a missing role is the logged-and-False update and remove no-op, the DROP retcode is ignored like the pinned source, and remove answers true only when the post-check catalog no longer lists the role",
			"the pinned _role_cmd_args clause machine is pinned end to end: the user-typed INHERIT and LOGIN defaults on create and their pinned absence on update, the NO/UN prefixes, the CONNECTION LIMIT zero and value shapes, the boolean rolepassword NOPASSWORD and bare PASSWORD shapes, the falsy valid-until NOVALID UNTIL shape, the db_role-keyed superuser skip, and the join-then-split group GRANT rendering with the pinned type-preserving groups semantics (direct, structured, and CLI vectors): a string splits on the comma without trimming and without dropping empty elements — trailing spaces survive inside identifiers and an empty comma slot renders its own empty GRANT — while a []string keeps its exact elements and order, the falsy shapes (empty string, empty list, absent) render nothing, and the caller's input is never mutated",
			"the password verifiers keep the pinned _maybe_encrypt_password behavior over type-preserving unions: the md5 default (and True/explicit md5) hashes the quote-doubled password plus role name, an md5- or SCRAM-SHA-256-prefixed password passes through, encrypted=False keeps the quote-doubled plaintext behind UNENCRYPTED, the string vs bool distinction is pinned by direct, structured, and CLI vectors (bools stay bools while the strings \"true\"/\"False\" keep their source semantics — a literal hashed password for rolepassword and the unknown-algorithm rejection for encrypted, with only the CLI decoder translating typed bool flags and numeric zeros matching Python's 0 == False membership), and the SCRAM-SHA-256 verifier keeps the pinned random-salt PBKDF2-HMAC-SHA256 construction with its stored and server keys recomputed and asserted in tests",
			"the unknown-algorithm rejection is value-free with a fixed error category asserted by synthetic secret-overlap vectors direct, through the registry, and through the CLI (the algorithm argument equal to the rolepassword and to the connection password): no algorithm string, rolepassword, or connection password appears in the returned error, no statement is issued, and no input is mutated",
			"rolepassword redaction is exercised against raw-command Runner errors by direct and registry mutation tests and by CLI user_create/user_update tests with apostrophe plaintext, its doubled SQL literal, generated md5/SCRAM verifiers, and supplied verifiers; CLI assertions check failure exit, stdout/stderr, RedactedString, and the command secret inventory. Direct and registry tests fail the first and second preflight commands for both functions with synthetic rolepassword overlap in connection password, host, user, maintenance database, or fixed SQL, including supplied verifiers: errors, rendered commands, and configured output redaction hide the marker and no mutation runs. The transport test also checks raw Runner stdout/stderr and result.Err sanitization, deduplication, and longest-first ordering. Only escaped forms present in the actual SQL are added; verifier generation remains after preflight. Role and GRANT group identifiers retain fail-closed value-free validation before any Runner invocation",
			"group_create reproduces the pinned test_group_create statement (the pinned group-typed INHERIT NOLOGIN defaults with the pinned double space after WITH, the UNENCRYPTED PASSWORD literal, and the self-referential groups GRANT suffix) and group_update reproduces the pinned test_group_update shape (ALTER ROLE with NOCREATEDB NOREPLICATION UNENCRYPTED PASSWORD matching the pinned regex, the db_role-keyed superuser skip against the stored non-superuser row, no inherit/login defaults, and the pinned quoted connection user) byte-for-byte on the full pinned argv; group_remove reproduces the pinned test_group_remove 15-element DROP ROLE argv exactly, and every group flow keeps the pinned preflight and post-check semantics over the registered user_list catalog: an existing role is the logged-and-False create no-op, a missing role is the logged-and-False update and remove no-op, the DROP retcode is ignored like the pinned source, and remove answers true only when the post-check catalog no longer lists the role",
			"the group family keeps the pinned argument contracts (postgres.py:2098-2115, 2149-2166, 2199-2207): neither connlimit nor valid_until exists on any group signature, the pinned group-typed inherit/login defaults apply only on create (typ_=\"group\" reaches _role_cmd_args through _role_create), the update path applies no defaults (its _role_cmd_args call passes no typ_), and the identifier rejection names the groupname argument key for the group family while the groups union, verifiers, redaction, cancellation, bounds, and runas rejection stay the shared role machinery asserted by the R9.2i evidence",
			"the identifier positions the pinned GRANT/REVOKE format strings interpolate raw or double-quote without escaping are validated fail-closed before any Runner invocation: the grant role name and the non-group object name may not contain the double quote that escapes their quoted context (the shared value-free quote rejection naming the argument key), while every raw position — the revoke role name in both REVOKE variants, the group object name in both directions, and the schema prefix of every table/sequence/function statement including the ALL-variant's IN SCHEMA — must be a bare PostgreSQL identifier ([A-Za-z0-9_$]+), the same class db_create applies to its unquoted TEMPLATE option; the pinned format strings permit injection in all of these positions, which StateKit refuses, and each rejection names only the fixed argument key (name, object_name, or prepend) so a rejected value carrying or overlapping a caller secret cannot leak through the error (asserted by synthetic marker vectors direct and through the CLI)",
			"the statements keep the pinned construction exactly: the comma-joined uppercased privileges, the schema-qualified double-quoted on-part for table/sequence/function and the plain double-quoted on-part otherwise, the group membership forms (GRANT {group} TO \"{role}\" with WITH ADMIN OPTION on the grant side, REVOKE {group} FROM {role} with both names raw), the ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA variants the pinned object_name.upper() == \"ALL\" comparison selects (so a lowercase \"all\" selects them too and the statement then carries no object name at all), and WITH GRANT OPTION only on the grant side; the pinned revoke flow has no ALL-variant and no grant_option",
			"privileges_grant reproduces the pinned test_privileges_grant_table, test_privileges_grant_function, and test_privileges_grant_group statements byte-for-byte on the full pinned argv (SQL at index 14) and privileges_revoke reproduces the pinned test_privileges_revoke_table, test_privileges_revoke_function, and test_privileges_revoke_group statements the same way — including the pinned raw (unquoted) role name of the REVOKE tail — with direct, registry, and CLI vectors; the pinned tests mock has_privileges and pass runas=\"user\", while StateKit reaches the same preflight answers through the R9.2f fixed catalogs (fixtures where the role holds nothing for grants and everything for revokes) and rejects runas before execution",
			"the pinned preflight semantics are pinned end to end: the grant preflight runs has_privileges without the caller's grant_option (so the membership/subset check, never the admin or grant-option variant, decides the no-op), an already-granted grant and a not-yet-held revoke return False with no mutation statement (exactly the pinned catalog calls and no extra one), the owner shortcut satisfies the preflight after the owner query alone, and both mutations answer the pinned ret[\"retcode\"] == 0 boolean where a rejected statement is compatibility false, never an error",
			"password redaction is asserted on the rendered command, captured output, and returned errors; no real psql, database, or package-manager path exists",
			"cancellation, output limits, runas rejection, nonzero-exit compatibility data, and psql-unavailable fail-closed behavior are covered without any live server",
			"the internal parsed-version helper is pinned by LooseVersion comparison vectors because no existing package consumes it yet",
			"default_privileges_list reproduces the pinned pg_default_acl decode on the R9.2l fixed catalogs: the pinned table/sequence/function scans keep their defaclobjtype constants, join shapes (including the pinned double spaces the pinned \" \".join leaves), and nspname orderings as fixed COPY-wrapped queries with the schema prefix matched client-side, the schema branch keys the object name on the reused pg_namespace catalog, the group branch reuses the R9.2f membership catalog, and the decode ladder runs over the pinned _DEFAULT_PRIVILEGES_MAP (no CONNECT, TEMPORARY, or MAINTAIN, so those characters stay the pinned KeyError) with the public grantee, grant stars, the leading GRANT star, the NULL/malformed ValueError, and the missing-object empty dictionary all asserted; the pinned pytests do not cover the family (only the postgres_default_privileges state maps it), so the vectors are source-derived",
			"the default-privilege mutations keep the pinned statement construction exactly, asserted byte-for-byte on the full pinned argv for every branch: the group membership forms with WITH ADMIN OPTION only on the grant side and both names raw on the revoke side, the ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA variants the pinned object_name.upper() == \"ALL\" comparison selects (a lowercase \"all\" selects them too), the raw role name of the REVOKE tail, and the pinned asymmetry where the grant_option non-ALL branch interpolates the on-part into IN SCHEMA (the schema-qualified double-quoted table/sequence name, the bare function name, the plain quoted schema name) while every other branch interpolates the bare schema prefix — and the pinned revoke's computed-but-unused on_part is not ported",
			"the pinned has_default_privileges preflight semantics are pinned end to end (the function itself stays unregistered exactly like a later pending name): both mutations issue it without their own grant_option so the membership/subset check decides the no-op, the owner shortcut satisfies the preflight after the owner query alone, the grant-option dict equality and the group admin_option boolean are pinned by direct white-box vectors, and the pinned ALL comparison defperms.sort() == _defprivileges[name].keys().sort() evaluates dict_keys.sort(), which raises AttributeError before any boolean — mapped here to a fixed value-free execution error, so an ALL grant or revoke against a grantee already holding a default ACL entry errors while an absent grantee yields preflight False: revoke is a no-op, but grant proceeds to mutation and returns its retcode result (asserted direct and through both mutation preflights)",
			"the identifier positions the pinned ALTER DEFAULT PRIVILEGES format strings interpolate raw or quote without escaping are validated fail-closed before any Runner invocation: the grantee role name (quoted on the grant side, raw on the revoke tail), the group object name in both directions, every schema prefix that reaches an IN SCHEMA clause, and the on-part object positions of the grant_option branch (quote-free for the quoted positions, bare PostgreSQL identifiers for the raw ones); each rejection is value-free naming only the fixed argument key (asserted by synthetic marker vectors direct and through the CLI), and the pinned CONNECT/TEMPORARY/MAINTAIN rejections of the _DEFAULT_PRIVILEGES allowlist are pinned value-free the same way",
			"schema_create reproduces the pinned test_schema_create argv exactly (the pinned runas argument rejected before execution by the single-user runtime) and schema_remove reproduces the pinned test_schema_remove DROP SCHEMA argv, each after the pinned schema_exists catalog preflight over the registered R9.2e catalog, with the pinned logged-and-False no-ops (an existing schema on create, a missing schema on remove), the pinned AUTHORIZATION owner clause, the ignored DROP retcode, and remove answering the second catalog post-check that carries the user the pinned first check drops",
			"create_extension reproduces the pinned test_create_extension_newerthan sequence end to end through the real catalogs the pinned test mocks: the fresh CREATE EXTENSION IF NOT EXISTS statement with the pinned space before the semicolon and the WITH SCHEMA/VERSION/FROM clause order, the installed branch's ALTER EXTENSION SET SCHEMA and UPDATE TO clauses, the failed create/move/upgrade False tails, the is_available_extension gate that skips every statement for an unavailable extension, and the lifecycle-flag post-check; drop_extension reproduces the pinned test_drop_extension1/2/3 trio with the raw unquoted name, the None defaults (cascade True, if_exists and restrict False), the pinned CASCADE/RESTRICT clause joins, and the not is_installed_extension post-check that makes a never-installed extension True",
			"the internal create_metadata ladder is pinned by direct white-box vectors: the exact-case miss, the LooseVersion TO_UPGRADE comparison (including 0.8 < 0.10 numeric ordering), the relocatable TO_MOVE conditions, the pinned .get fallbacks (a missing schema_name column defaults to the caller's schema and therefore never differs), and the is-not-None metadata checks versus the truthiness clause guards that leave an explicit empty string clause-less; create_metadata itself stays unregistered exactly like a later pending name",
			"direct, registry, and CLI empty ext_version/from_version vectors (separately, together, and omitted controls) assert every catalog and statement argv, four calls for fresh CREATE and three for installed no-op, and true results; empty strings skip VERSION/FROM while ext_version remains a non-nil create_metadata argument and nil retains the omitted default; unsafe nonempty versions still fail value-free before any Runner call",
			"direct, registry, and CLI synthetic-marker vectors force the first Runner error of both language mutations, with and without password/maintenance-db overlap: only the catalog runs, errors and CLI stdout/stderr and rendered commands contain no marker, exact pinned argv is unchanged, and the clean environment has no PGPASSWORD; the caller password is retained only in pgConnection.Secrets for preflight redaction",
			"language_create reproduces the pinned test_language_create argv exactly (CREATE LANGUAGE with the raw unquoted name) and language_remove the pinned test_language_remove DROP LANGUAGE argv, each after the pinned language_exists preflight that passes only (name, maintenance_db) — asserted to carry no connection flag even when the mutation carries the full tuple — with the existing/missing logged-and-False no-ops and the retcode boolean",
			"the identifier positions the pinned R9.2m format strings interpolate raw or double-quote without escaping are validated fail-closed before any Runner invocation: the schema name and owner of CREATE/DROP SCHEMA and the extension name and schema of CREATE/ALTER EXTENSION may not carry the double quote, the raw extension name of DROP EXTENSION and the raw language name of CREATE/DROP LANGUAGE must be bare PostgreSQL identifiers ([A-Za-z0-9_$]+), and the raw ext_version/from_version tokens must be bare version tokens (the identifier class plus the dots real version strings carry); each rejection is value-free naming only the fixed argument key (asserted by synthetic marker vectors direct and through the CLI)",
			"tablespace_create reproduces the pinned test_tablespace_create statement byte-for-byte on the full pinned argv (CREATE TABLESPACE \"test_tablespace\" OWNER \"otheruser\" LOCATION '/tmp/postgres_test_tablespace' with the pinned trailing space, SQL at index 14; the pinned runas argument rejected before execution by the single-user runtime) and answers the pinned retcode boolean (a rejected CREATE is false, never an error), with the pinned truthy OWNER clause (nil and the explicit empty string both omit), the pinned double space before LOCATION when the clause is absent, and the pinned WITH ( k = v, ... ) options tail whose multi-key order is the deterministic sorted-key order because a Go map carries no Python dict insertion order",
			"tablespace_alter reproduces the pinned test_tablespace_alter_new_owner and test_tablespace_alter_new_name statements byte-for-byte on the full pinned argv and keeps the pinned clause order RENAME TO, OWNER TO, SET, RESET with one statement per truthy argument; the pinned any([new_name, new_owner, set_option, reset_option]) head answers the no-op True with no Runner invocation for nil, the Python-falsy explicit empty string, and the empty map alike, and the pinned ret[\"retcode\"] != 0 False aborts at the first failed statement so no later mutation follows a failed one; the pinned set_option branch reads only next(iter(set_option.items())) — the first inserted pair — so exactly one entry is accepted and more is the fixed value-free ambiguity rejection raised before any Runner invocation",
			"tablespace_remove reproduces the pinned test_tablespace_remove DROP TABLESPACE statement byte-for-byte (no trailing semicolon) on the full pinned argv, answers the pinned retcode boolean, and — exactly like the pinned source — consults no existence preflight: a missing tablespace is a server-side rejection landing in the boolean false after exactly one statement",
			"the identifier and literal positions the pinned R9.2o format strings interpolate raw are validated fail-closed before any Runner invocation: the tablespace name, owner, and new names may not carry the double quote of their identifier contexts, the option keys and reset_option must be bare PostgreSQL identifiers and the option values bare version tokens because the pinned source interpolates them unquoted into the WITH/SET clause, and the LOCATION literal must be an absolute, clean, control-free path that carries no single quote (the pinned format never escapes it); each rejection is value-free (asserted by synthetic marker vectors direct, through the registry, and through the CLI), and the shared cancellation, runas, psql-unavailability, output-limit, and redacted-Runner-error guards are asserted across all three mutations",
			"datadir_exists reproduces the pinned marker-file probe (postgres.py:4390-4393) read-only over the fake FS: PG_VERSION and postgresql.conf must both be regular files for True, and an absent marker, a marker that is a directory, a name that is a regular file, and even a denied Lstat all answer the pinned os.path.isfile False exactly like the source swallows OSError — asserted direct and through the registry with zero Runner calls on every path",
			"the no-follow boundary is pinned by symlink vectors: the pinned os.path.isfile follows a symlinked marker, but StateKit's Lstat-plus-regular-file check refuses it, so a planted link cannot satisfy the preflight datadir_init gates on (asserted for both markers)",
			"datadir_init reproduces the pinned test__run_initdb_with_timeout argv byte-for-byte (the pinned runas argument rejected before any observable action by the single-user runtime, so the --username=saltuser it contributed is supplied directly, and the pinned relative fakename name becomes the absolute /fakename the datadir path boundary requires — the only two adaptations): initdb --pgdata=... --username=user --auth=password --encoding=UTF8 on the central shell-free Runner with the clean empty environment (initdb reads credentials from the pwfile, not the environment), no stdin, the 30s timeout ceiling, bounded output, and the retcode boolean — plus the full option set (auth=md5, encoding=LATIN1, --locale, the pinned short -X waldir pair, --data-checksums) in the pinned argv order",
			"the pinned argument contracts keep Salt's None semantics exactly: nil auth/encoding/user keep the pinned literal defaults (user resolving through the pinned kernel-mapped runas default — postgres, or _postgresql on OpenBSD) while explicit empty strings keep the pinned --auth=/--encoding=/--username=/-X '' shapes, and the pinned waldir is-not-None gate appends the -X pair for an explicit empty string too",
			"the pwfile transport is pinned end to end: the exact password bytes with no trailing newline (fp_.write(f'{password}')) at 0600 inside a private temp directory, --pwfile last in the argv, the password as the only Redact secret, the file and directory removed after the run on success, nonzero-exit, and Runner-error paths, a failing temp write or MkdirTemp errors before any Runner invocation, and a failing cleanup after a successful run is the fixed value-free errPostgresPwfileCleanup rather than the pinned source's silent warning — with the password leaking into no error, argv, environment, or captured output",
			"the pwfile preparation failures pass through value-free: a failing MkdirTemp or WriteFile surfaces as the fixed errPostgresPwfileTempDir/errPostgresPwfileWrite categories instead of the raw filesystem errors, whose *fs.PathError rendering names the credential-holding temp location and whose fault-injected forms carry synthetic password, path, and stderr markers — asserted direct, through the registry, and through the CLI with the exact sentinel stderr lines, zero Runner invocations, and no temp mutation",
			"the partial-write cleanup precedence is pinned: a failed write whose RemoveAll cleanup succeeds is the write category with the temp directory removed, and a failed write whose cleanup also fails joins the write category with errPostgresPwfileCleanup (errors.Is exposes both; the rendered text is exactly the two sentinels) so the stranded credential stays observable without hiding the primary category — value-free on both paths with no Runner invocation",
			"the pinned kernel-mapped runas default of _run_initdb (postgres.py:250-256) is pinned through the argv: an OpenBSD-facts runtime resolves --username=_postgresql, FreeBSD and Linux-family runtimes keep --username=postgres, a Facts-less runtime falls back to the compile-time GOOS, and an explicit user argument (including the pinned empty-string shape) overrides on every kernel — asserted by direct and CLI argv vectors with injected facts; the mapping is argv-only and no native initdb execution on any kernel is claimed (the openbsd surface is covered by cross-build GOOS=openbsd compilation of the module, not native runs)",
			"the initialized-datadir no-op is pinned: the datadir_exists preflight answers the logged-and-False shape with no initdb invocation and no pwfile write at all, and a rejected initdb keeps the pinned retcode boolean (a failed CREATE is false, never an error) including a stderr that echoes the password staying redacted",
			"the datadir path boundary is pinned value-free: relative, traversal, unclean (double separators, trailing slash), and control-carrying names and waldirs are rejected before any Runner invocation or pwfile write with the fixed invalid data/wal directory path errors naming no rejected value (asserted direct, through the registry, and through the CLI's failed exit), and the shared cancellation, runas, initdb-unavailability, output-limit, and redacted-Runner-error guards are asserted on the single statement",
			"the process-wide test-mode no-mutation contract is pinned: with a missing datadir datadir_init answers the nil would-change prediction (the shape Salt's postgres_initdb state renders as set-to-be-initialized) with no pwfile write and no Runner invocation, while the read-only preflight keeps answering the existing-datadir false",
		},
		CompatibilityNotes: []string{
			"R9.2c registers the version probe plus the five read-only catalog primitives db_list, db_exists, tablespace_list, tablespace_exists, and user_list; R9.2d adds the eight read-only extension and language catalog functions available_extensions, installed_extensions, get_available_extension, get_installed_extension, is_available_extension, is_installed_extension, language_list, and language_exists; R9.2e adds the three read-only schema catalog functions schema_exists, schema_get, and schema_list; R9.2f adds the three read-only role and privilege checks role_get, user_exists, and has_privileges; R9.2g adds the read-only ACL listing privileges_list; R9.2h adds the first write paths db_create and db_remove as fixed pinned statements; R9.2i adds the role mutations user_create, user_update, and user_remove on the pinned _role_create/_role_update/_role_remove flow; R9.2j adds the group mutations group_create, group_update, and group_remove on the same flow with typ_=\"group\"; R9.2k adds the privilege mutations privileges_grant and privileges_revoke as fixed pinned statements; R9.2l adds the default-privilege family default_privileges_list, default_privileges_grant, and default_privileges_revoke as fixed pinned statements; R9.2m adds the schema, extension, and language mutations schema_create, schema_remove, create_extension, drop_extension, language_create, and language_remove as fixed pinned statements; R9.2n adds the database mutation db_alter as the pinned OWNER/TABLESPACE statements; R9.2o adds the tablespace mutations tablespace_create, tablespace_alter, and tablespace_remove as the pinned CREATE/ALTER/DROP TABLESPACE statements; R9.2p adds the datadir pair datadir_exists and datadir_init as the pinned marker probe and initdb wrapper; the generic psql_query surface and every other write path stay pending (no arbitrary-query registration exists in this phase)",
			"the default-privilege family keeps the pinned argument contracts (postgres.py:3238-3248, 3714-3727, 3880-3892): default_privileges_list carries (name, object_type, prepend=\"public\", maintenance_db, user, host, port, password, runas) with no role or privileges argument, the mutations carry (name, object_name, object_type, defprivileges=None, prepend=\"public\", ...) with grant_option existing only on the grant side exactly like the pinned signatures, defprivileges keeping Salt's None default as the empty string the pinned _mod_defpriv_opts collapses to, and prepend nil meaning the pinned \"public\" default while an explicit empty string keeps Salt's empty-schema handling",
			"the pinned _make_default_privileges_list_query interpolates the schema prefix and the group role name into single-quoted SQL literals; StateKit keeps the pinned pg_default_acl catalogs, join shapes, defaclobjtype constants, and orderings as fixed COPY-wrapped queries and matches the schema prefix, the schema object name, and the group membership client-side (reusing the R9.2f schema and membership catalogs on the branches whose pinned SQL is identical), which is result-equivalent for every non-malicious input and refuses the injection the pinned format permits",
			"the pinned has_default_privileges ALL comparison evaluates list.sort() == dict_keys.sort(), an AttributeError before any boolean; StateKit maps that deterministic pinned failure to a fixed value-free execution error (no caller value enters it), and the pinned computed-but-unused on_part of the revoke flow is not ported",
			"the identifier positions the pinned ALTER DEFAULT PRIVILEGES format strings interpolate raw or quote without escaping are validated fail-closed before any Runner invocation with the shared value-free rejections naming only the fixed argument key (name, object_name, or prepend); the on-part object positions reach SQL only on the grant_option branch and are validated only there, because the plain statements interpolate no object name at all",
			"the R9.2m mutations keep the pinned argument contracts (postgres.py:1895-1906, 1965-1977, 2316-2325, 2369-2370, 2698-2699, 2753-2754): schema_create carries (dbname, name, owner, user, db_user, db_password, db_host, db_port) and schema_remove the same without owner, create_extension carries (name, if_not_exists, schema, ext_version, from_version, ...) with if_not_exists keeping Salt's None-True default while nil schema/ext_version/from_version never trigger their metadata branch and explicit empty strings keep the pinned falsy-string clause-less shape, drop_extension carries (name, if_exists, restrict, cascade, ...) with the pinned None defaults (cascade True, if_exists and restrict False), and the language pair carries (name, maintenance_db, user, host, port, password, runas)",
			"the pinned existence-preflight quirks are preserved exactly: schema_remove's first schema_exists call drops the system user (user=None) while its DROP and post-check carry it, and both language preflights pass only (name, maintenance_db) so the catalog call carries no connection argument at all; create_metadata runs before and after the extension statement with the statement's retcode ignored like the pinned discarded return",
			"the pinned is_available_extension gate (case-insensitive) decides whether create_extension issues any statement while the installed-catalog lookups stay exact-case, and the lifecycle post-check answers False when the recomputed metadata carries any flag other than EXTENSION INSTALLED; drop_extension's not is_installed_extension post-check makes a never-installed extension True exactly like the pinned test_drop_extension2",
			"create_metadata stays pending exactly like a later registered name while its ladder runs internally for create_extension; has_default_privileges and psql_query stay pending the same way",
			"privileges_grant and privileges_revoke keep the pinned argument contracts (postgres.py:4009-4022, 4170-4182): the shared (name, object_name, object_type, privileges=None, prepend=\"public\", maintenance_db, user, host, port, password, runas) tuple with grant_option existing only on the grant side exactly like the pinned signatures, privileges keeping Salt's None default as the empty string the pinned _mod_priv_opts collapses to, grant_option only ever truthiness-tested, and prepend nil meaning the pinned \"public\" default while an explicit empty string keeps Salt's empty-schema handling",
			"user_create, user_update, and user_remove keep the pinned argument contracts (postgres.py:1433-1452, 1559-1578, 2066-2074) including the union-typed encrypted, rolepassword, and groups arguments with pinned type preservation: bools stay bools and strings stay the exact strings — the strings \"true\"/\"False\" keep their source semantics (a literal hashed password for rolepassword, the unknown-algorithm rejection for encrypted) instead of being silently retyped, only the CLI decoder translates typed bool flags to bools (so a real boolean reaches these unions through structured input), numeric zeros keep Python's 0 == False tuple membership, and groups keeps its string/list tri-state with the exact pinned split (no trimming, no empty-element dropping) so the CLI flag and structured decoding both retain the raw string",
			"the role statements keep the pinned construction exactly: the clause-less statement keeps the pinned trailing space after WITH and any clause renders the pinned double space, the WITH-strip tail of _role_cmd_args is dead code for these call paths (the inner sub_cmd is always the empty string), Salt spells the verb CREATE ROLE for users too, and _role_update passes no typ_ so the inherit and login defaults genuinely do not apply on update",
			"the identifier positions the pinned source interpolates raw are validated fail-closed before any Runner invocation: the role name of every CREATE/ALTER/DROP ROLE and GRANT statement and each GRANT group entry the pinned split produces may not contain the double quote that escapes the double-quoted identifier context, with the shared value-free invalid-argument error naming only the fixed argument key (username or groups)",
			"the pinned unknown-algorithm ValueError carries the algorithm name in its message, but the union-typed encrypted argument may itself carry or overlap a credential, so the port rejects it with a fixed value-free error category instead (asserted by synthetic secret-overlap vectors where the algorithm equals the rolepassword and the connection password); the saslprep bound of the SCRAM path fails closed value-free the same way: printable-ASCII passwords are SASLprep identities exactly, and anything outside printable ASCII is rejected rather than approximating the RFC 3454 tables — the upgrade path is a full stringprep implementation",
			"Salt's md5 and unencrypted deprecation warnings and its role-already-exists, role-not-found, and failed-delete log lines have no module logging surface, so those branches are observable only through their pinned return values and statements; the SCRAM-SHA-256 verifier keeps the pinned random 16-byte salt, so each generation is unique and tests assert structure plus recomputed keys rather than a fixed literal",
			"db_alter keeps the pinned argument contract (postgres.py:676-687): the (name, user, host, port, maintenance_db, password, tablespace, owner, owner_recurse, runas) signature with owner_recurse keeping Salt's False default and Python truthiness selecting the statements (None and the explicit empty string both omit), and the pinned owner_to delegation drops maintenance_db exactly like the pinned call; because owner_to stays pending, that branch is the fixed value-free unsupported function \"postgres.owner_to\" error (CLI exit 3) raised before any mutation rather than a silent shallow ALTER OWNER",
			"the pinned db_alter loop overwrites ret per iteration and only the last retcode decides the boolean (a failed OWNER change followed by a successful TABLESPACE change answers True); StateKit refuses to reproduce that quirk — every statement's retcode is checked, a rejected statement is the pinned False and stops the flow so no later mutation follows a failed one — and the identifier positions the pinned format strings double-quote without escaping (name, owner, tablespace) are validated fail-closed with the shared value-free rejections before any Runner invocation",
			"db_create and db_remove keep the pinned argument contracts (postgres.py:610-624, 727-735) and the pinned fixed statements: values keep _quote_ddl_value's None omission, quote-character SaltInvocationError, and single/double quoting in the pinned OrderedDict option order (TABLESPACE, OWNER, TEMPLATE, ENCODING, LC_COLLATE, LC_CTYPE), an explicit empty string stays the pinned quoted empty value, and the template stays the pinned bare identifier",
			"the identifier positions the pinned source interpolates raw are validated fail-closed before any Runner invocation: the db_create name may not contain the double quote that escapes its identifier context, the db_remove name may not contain either quote character because the pinned flow uses it as both a double-quoted identifier and the single-quoted datname literal, and the unquoted TEMPLATE option must be a bare PostgreSQL identifier ([A-Za-z0-9_$]+); the pinned format strings permit injection in all three positions (the pinned _quote_ddl_value TODO admits the escaping is unimplemented), which StateKit refuses",
			"db_create returns exactly the pinned ret[\"retcode\"] == 0 boolean (a rejected CREATE is compatibility false, never an error) and db_remove aborts on the first nonzero retcode like the pinned raise Exception(f\"Failed: ret={ret}\"), with the port's error carrying the retcode only so no captured server output or credential travels through exceptions; db_remove returns true immediately after the pinned DROP with no post-query, and a missing database aborts at the pinned REVOKE before any termination or DROP is attempted",
			"neither function has a test mode or an existence preflight in the pinned source (db_exists is not consulted), so neither exists here: db_create issues exactly one statement and db_remove keeps the pinned non-transactional three-statement sequence; the pinned db_remove has no maintenance-database guard, so the maintenance name is not special-cased and PostgreSQL itself is the rejection point for dropping the database psql is connected to",
			"the R9.2o tablespace mutations keep the pinned argument contracts (postgres.py:840-851, 889-901, 950-958): tablespace_create carries (name, location, options=None, owner=None, ...) with options as the structured-input map argument and owner keeping Salt's truthiness (nil and the explicit empty string both omit the clause), tablespace_alter carries (name, ..., new_name, new_owner, set_option, reset_option, runas) exactly like the pinned signature — the pinned function has no location parameter because PostgreSQL ALTER TABLESPACE moves no location — and tablespace_remove carries (name, ...); set_option/reset_option keep the pinned None defaults with the same truthiness",
			"the pinned tablespace_create options join and the set_option clause interpolate every key and value raw with no quoting, and the pinned tablespace_alter reads only the first inserted set_option pair; StateKit fixes the deterministic boundaries: create options render in sorted-key order (the only ordering deviation, shared with the mdadm and extfs options maps), option keys and reset_option must be bare PostgreSQL identifiers, option values bare version tokens covering the pinned numeric forms (string-literal option values such as '2MB' stay outside the accepted class; the upgrade path is full literal quoting in a later round), and set_option must carry exactly one entry — more is the fixed value-free ambiguity rejection rather than silently applying one pair of the caller's dict",
			"the pinned LOCATION literal is interpolated raw into single quotes with no escaping; StateKit requires an absolute, clean (path.Clean equality: no dot or dot-dot segments, no redundant separators, no trailing slash), control-free path carrying no single quote, so no traversal or literal escape can reach the fixed statement — a boundary the pinned format string permits and the port refuses; the semantic judgment (directory existence, emptiness, ownership) stays with the server",
			"the R9.2p datadir pair keeps the pinned argument contracts (postgres.py:4300-4310, 4375-4393): datadir_exists carries only the required name positional, and datadir_init carries (name, auth=\"password\", user=None, password=None, encoding=\"UTF8\", locale=None, waldir=None, checksums=False, runas=None) with nil auth/encoding/user keeping the pinned literal defaults (the nil user resolving through the pinned kernel-mapped runas default: postgres, or _postgresql on OpenBSD) and explicit empty strings keeping Salt's exact --auth=/--encoding=/--username=/-X '' shapes because the pinned gates are is-None, not truthiness",
			"datadir_exists replaces the pinned follow-symlink os.path.isfile with a no-follow Lstat plus the regular-file mode check, so a symlinked PG_VERSION or postgresql.conf answers False where the pinned source would answer True — the deliberate StateKit boundary that keeps the datadir_init preflight unlinkable; every Lstat failure (absent, non-directory parent, permission) keeps the pinned isfile False, never an error",
			"the pinned shlex.join string over cmd.run_all with python_shell=False becomes the direct argv the central shell-free Runner already enforces; the pinned clean_env=True becomes the clean empty environment because initdb reads credentials from the pwfile, not the environment — no PGPASSWORD exists on this path",
			"the pinned mkstemp pwfile plus file.chown to runas becomes a Runtime.FS temp directory (0700) with the password file at 0600 holding exactly the pinned fp_.write bytes: the single-user runtime has no chown contract, the password never enters argv, the environment, or the rendered command, and a cleanup failure after a successful run is the fixed value-free errPostgresPwfileCleanup instead of the pinned source's logged warning — superseded only by a primary Runner error so cancellation and output-limit semantics stay observable; the preparation failures are the same value-free boundary (the fixed temp-directory/write categories for MkdirTemp/WriteFile, joined with errPostgresPwfileCleanup when the partial-write cleanup also fails, so no raw filesystem error, path, or captured output travels)",
			"the pinned runas default resolution (postgres.py:250-256) is kernel-mapped from the existing Facts OS family with the compile-time GOOS as the Facts-less fallback: OpenBSD resolves the _postgresql service account, FreeBSD and every other kernel the postgres default, exactly the pinned os_family branches; the explicit runas elevation itself stays rejected by the single-user runtime, only the --username default carries the mapping, and no native OpenBSD (or any other kernel) initdb execution is claimed — the openbsd surface is verified by cross-build compilation only",
			"the datadir name and waldir share the tablespace LOCATION boundary (absolute, path.Clean equality, control-free) because initdb consumes both as filesystem paths; the pinned source and its test pass relative names (the pinned fakename vector) that a Runner CWD would resolve — the port refuses them, so the pinned vector runs as /fakename; the rejections are value-free (asserted by synthetic marker vectors direct, through the registry, and through the CLI), and runas is rejected before the read-only preflight, so no observable action runs on behalf of another user",
			"the process-wide test mode (RuntimeOptions.Test) is honored for the first time in the postgres family: with a missing datadir datadir_init answers the nil would-change prediction — the shape Salt's postgres_initdb state renders as set-to-be-initialized — after the read-only preflight, with no pwfile write and no Runner invocation; the pinned source has no test mode, so this is a StateKit contract addition, not a ported behavior",
			"has_privileges keeps the pinned argument contract (name, object_name, object_type, privileges=None, grant_option=None, prepend=\"public\", maintenance_db, user, host, port, password, runas) with the pinned _mod_priv_opts object-type lowercasing, comma-split with optional single spaces, and uppercasing; the pinned KeyError on an unknown object type and the SaltInvocationError privilege and group-privilege rejections all map to execution errors raised before any Runner invocation",
			"privileges_list keeps the pinned argument contract (name, object_type, prepend=\"public\", maintenance_db, user, host, port, password, runas) exactly as the pinned signature and docs/catalog/exec/postgres.yaml#privileges_list declare it: the function lists an object's ACL, so name is the object and no role or privileges argument exists (those belong to has_privileges); the pinned head lowercases the object type, and Salt's dead SaltInvocationError after the unbound-local query builder maps to the same invalid-object_type execution error raised before any Runner invocation; a NULL or malformed ACL stays the pinned ValueError and a missing object returns the empty dictionary",
			"the pinned _get_object_owner and _make_privileges_list_query build SQL by formatting the caller's object name and schema prefix into single-quoted literals; StateKit replaces every interpolated equality with a client-side exact match over the same fixed catalog query (key column selected beside the pinned value column, pinned relkind filters and orderings kept, the group membership keyed by the group role's name), which is result-equivalent for every non-malicious input because each pinned equality targets a unique catalog key, and refuses the injection the pinned format permits",
			"ACL text decodes through the pinned strip(\"{}\")/split(\",\")/split(\"/\")/split(\"=\") ladder: exactly one grantor slash and one grantee equals per entry, the empty grantee becomes public, _process_priv_part's grant-star flip and leading-star GRANT key are preserved, and NULL or malformed ACL text is the pinned ValueError mapped to an execution error whose message embeds no input",
			"role_get and user_exists reuse the registered user_list catalog: the exact-case miss is None (never an error), Salt's False catalog from an unanswered version probe maps through the pinned AttributeError branch to None, and bool(role_get(...)) is the row's presence because a stored role row always carries the pinned columns",
			"the schema family keeps the pinned schema_* signature (postgres.py:2444-2599): dbname is the required database positional, user is the pinned system-user argument rejected like every runas surface, and db_user/db_host/db_port/db_password project onto the shared psql connection tuple; schema rows are reduced to exactly the pinned owner/acl pair keyed by name, and schema_get/schema_exists match names client-side so no caller string reaches SQL",
			"extension and language lookups are client-side only: get_*/is_*/language_exists match names against the fetched catalog so no caller string reaches SQL, and the installed_extensions query keeps the pinned double space after \"pg_extension a,\" byte-for-byte",
			"available_extensions/installed_extensions store the full row under its name/extname key (no column removed, unlike db_list's Name pop), rows whose zipped prefix lacks either pinned key column are skipped, and language_list maps each Name column to itself exactly like the pinned ret[row[\"Name\"]] = row[\"Name\"]",
			"the pinned _run_psql PGPASSFILE temp-file credential transport is replaced by psql-native PGPASSWORD (with PGUSER/PGHOST/PGPORT) in an otherwise clean environment because the single-user runtime has no file-chown/elevation contract; the password is a Redact secret and never rendered",
			"a non-zero psql exit stays compatibility data (Salt logs and returns the empty row list), while Runner failures, cancellation, and output-limit violations are errors",
			"Salt's postgres.timeout default of 0 (unbounded) is replaced by a finite 30s ceiling as the R9 resource-control convention",
			"runas is rejected before Runner invocation because the central runtime is single-user and has no elevation contract; Salt's implicit postgres runas default therefore does not apply",
			"the pinned config.option defaults (postgres.user/host/port/maintenance_db/pass/bins_dir) have no StateKit module-config surface yet, so omitted arguments keep Salt's None meaning and psql resolves through PATH only, failing closed when absent",
			"the catalog queries are the pinned fixed SQL fragments wrapped in the pinned COPY (...) TO STDOUT WITH CSV HEADER transport with datestyle=ISO,MDY; db_exists/tablespace_exists match names client-side so no caller string reaches SQL",
			"CSV parsing is a bounded port of the pinned non-strict Python csv.reader state machine: comma delimiter, double-quote quotechar with doubled-quote collapsing, bare quotes and NUL bytes as literal data, and backslash as an ordinary character, so PostgreSQL array text with backslash-escaped elements decodes exactly like the pinned groups expression and no strict-encoding/csv rejection exists; embedded CR, LF, and CRLF survive byte-exact inside quoted fields (a CRLF the Go standard reader would normalize to LF), the 131072-character field limit and the new-line-in-unquoted-field error map to Salt's csv.Error, empty rows are skipped, and rows are dict(zip(header,row)) truncated, with Salt's KeyError on short rows mapped to an execution error",
			"user_list keeps the pinned column contract: rolreplication is real on >=9.1, rolcatupdate is NULL on >=9.5, an unanswered version probe returns False, connections keeps get_bool's None for non-t/f values, and expiry parsing tolerates invalid values as None (Python strptime accepts some non-padded shapes Go rejects; PostgreSQL timestamp(0) output is always padded)",
			"the internal _parsed_version helper follows pinned salt/utils/versions.py:73-101: digit runs become integers, separator dots are discarded, and lists compare numerically unless either contains strings, when all integer components use zfill(8) string comparison; mixed int/string comparison is defined; the helper is deliberately not registered publicly",
			"no postgres driver, live server, network egress, or new dependency is claimed or added",
		},
		RegisteredSubset: []string{
			"postgres.version",
			"postgres.db_list",
			"postgres.db_exists",
			"postgres.db_create",
			"postgres.db_remove",
			"postgres.db_alter",
			"postgres.datadir_exists",
			"postgres.datadir_init",
			"postgres.tablespace_list",
			"postgres.tablespace_exists",
			"postgres.tablespace_create",
			"postgres.tablespace_alter",
			"postgres.tablespace_remove",
			"postgres.user_list",
			"postgres.available_extensions",
			"postgres.installed_extensions",
			"postgres.get_available_extension",
			"postgres.get_installed_extension",
			"postgres.is_available_extension",
			"postgres.is_installed_extension",
			"postgres.create_extension",
			"postgres.drop_extension",
			"postgres.language_list",
			"postgres.language_exists",
			"postgres.language_create",
			"postgres.language_remove",
			"postgres.schema_exists",
			"postgres.schema_get",
			"postgres.schema_list",
			"postgres.schema_create",
			"postgres.schema_remove",
			"postgres.role_get",
			"postgres.user_exists",
			"postgres.has_privileges",
			"postgres.privileges_list",
			"postgres.privileges_grant",
			"postgres.privileges_revoke",
			"postgres.default_privileges_list",
			"postgres.default_privileges_grant",
			"postgres.default_privileges_revoke",
			"postgres.user_create",
			"postgres.user_update",
			"postgres.user_remove",
			"postgres.group_create",
			"postgres.group_update",
			"postgres.group_remove",
		},
	},
}

// r9FamilyOrder keeps generated map emission deterministic.
var r9FamilyOrder = []string{"mysql", "postgres", "rabbitmq"}

type r9FamilyReport struct {
	Catalog            int      `yaml:"catalog_functions"`
	Public             int      `yaml:"public_functions"`
	Private            int      `yaml:"private_functions"`
	Registered         int      `yaml:"registered_public"`
	PendingPublic      []string `yaml:"pending_public,omitempty"`
	Platform           string   `yaml:"platform"`
	Scenarios          []string `yaml:"differential_scenarios"`
	SourceReference    string   `yaml:"source_reference"`
	SourceTests        string   `yaml:"source_tests"`
	Evidence           []string `yaml:"evidence"`
	CompatibilityNotes []string `yaml:"compatibility_notes"`
}

type r9Report struct {
	Round            string                    `yaml:"round"`
	Platform         string                    `yaml:"platform"`
	RuntimeStatus    string                    `yaml:"runtime_status"`
	BehavioralParity string                    `yaml:"behavioral_parity"`
	Families         map[string]r9FamilyReport `yaml:"families"`
	Totals           r9ReportTotals            `yaml:"totals"`
	PriorReports     map[string]string         `yaml:"prior_report_sha256"`
	RepeatStable     bool                      `yaml:"repeat_stable"`
}

type r9ReportTotals struct {
	Catalog    int `yaml:"catalog_functions"`
	Public     int `yaml:"public_functions"`
	Registered int `yaml:"registered_public"`
	Pending    int `yaml:"pending_public"`
}

func TestR9DifferentialScopeReport(t *testing.T) {
	first, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	second, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	firstNames, secondNames := first.Exec.Names(), second.Exec.Names()
	repeatStable := strings.Join(firstNames, "\x00") == strings.Join(secondNames, "\x00")
	registered := registeredNames(first)

	report := r9Report{
		Round:    "R9.2p",
		Platform: "cross-platform",
		RuntimeStatus: "mock-only: RabbitMQ is never started, MySQL is never connected, and PostgreSQL is never contacted; " +
			"shell-free fake Runner tests and pure-function vectors provide the executable contract",
		BehavioralParity: "not claimed: live Salt/broker/database differential execution is prohibited for R9",
		Families:         map[string]r9FamilyReport{},
		PriorReports:     priorR3R8ReportHashes(t),
		RepeatStable:     repeatStable,
	}

	for _, familyName := range r9FamilyOrder {
		spec := r9FamilySpecs[familyName]
		subset := map[string]bool{}
		for _, name := range spec.RegisteredSubset {
			subset[name] = true
		}
		catalogNames := loadCatalogFunctionNames(t, familyName)
		family := r9FamilyReport{
			Catalog:            len(catalogNames),
			Platform:           spec.Platform,
			Scenarios:          append([]string(nil), spec.Scenarios...),
			SourceReference:    spec.Source,
			SourceTests:        spec.SourceTests,
			Evidence:           append([]string(nil), spec.Evidence...),
			CompatibilityNotes: append([]string(nil), spec.CompatibilityNotes...),
		}
		for _, name := range catalogNames {
			if strings.HasPrefix(name, "_") {
				family.Private++
				continue
			}
			family.Public++
			full := familyName + "." + name
			if registered[full] {
				family.Registered++
				continue
			}
			alias := strings.TrimSuffix(name, "_")
			if alias != name && registered[familyName+"."+alias] {
				family.Registered++
				continue
			}
			family.PendingPublic = append(family.PendingPublic, full)
		}

		if spec.RegisteredSubset == nil {
			// Complete families (R9.1 rabbitmq) must register every public
			// catalog function.
			if family.Public != family.Registered || len(family.PendingPublic) != 0 {
				t.Fatalf("R9 %s registration incomplete: %+v", familyName, family)
			}
		} else {
			// Slice families (R9.2a mysql) must register exactly the named
			// subset: nothing more, nothing less.
			for _, name := range spec.RegisteredSubset {
				if !registered[name] {
					t.Fatalf("R9 %s slice member %s not registered", familyName, name)
				}
			}
			if family.Registered != len(spec.RegisteredSubset) {
				t.Fatalf("R9 %s registered %d functions, want exactly the %d slice members: %+v",
					familyName, family.Registered, len(spec.RegisteredSubset), family.PendingPublic)
			}
			wantPending := map[string]bool{}
			for _, name := range family.PendingPublic {
				if subset[name] {
					t.Fatalf("R9 %s slice member %s listed pending", familyName, name)
				}
				wantPending[name] = true
			}
			for _, name := range spec.RegisteredSubset {
				if wantPending[name] {
					t.Fatalf("R9 %s slice member %s listed pending", familyName, name)
				}
			}
		}

		report.Totals.Catalog += family.Catalog
		report.Totals.Public += family.Public
		report.Totals.Registered += family.Registered
		report.Totals.Pending += len(family.PendingPublic)
		report.Families[familyName] = family
	}

	if !repeatStable {
		t.Fatal("R9 registration inventory is not repeat-stable")
	}

	encoded, err := yaml.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "differential", "R9", "report.yaml")
	want := "# Generated by tests/differential (TestR9DifferentialScopeReport); do not edit.\n" + string(encoded)
	existing, readErr := os.ReadFile(path)
	if readErr == nil && string(existing) == want {
		return
	}
	if os.Getenv("UPDATE_DIFFERENTIAL") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("R9 differential scope report stale; run UPDATE_DIFFERENTIAL=1 go test ./tests/differential -run TestR9DifferentialScopeReport")
}

func priorR3R8ReportHashes(t *testing.T) map[string]string {
	t.Helper()
	baseline := map[string]string{
		"R3": "107e2f25863c853efc2e163173fd8590dc299d0e85205f1b153837b4f9e139a6",
		"R4": "d089e09723938b43d4a9e7097d05bd0e3b6ae35d05de42a15dd7a1ae22e2a4e5",
		"R5": "adbd9caef01054add60c7d33a6200ae17aabcb60e32565a26057c93d5584c1c9",
		"R6": "f976d922a1370350733396460e01d7cea74a3d29935ab10548a65b189f3c29ea",
		"R7": "74763e9298e03a7cb714551d34e219ec06d1ecb558da4edc27efc8ddea23a0f5",
		"R8": "5c4908a211ddbec245df73b677a55025678ddf1d345a582c733ba85410553fb1",
	}
	out := make(map[string]string, len(baseline))
	for _, round := range []string{"R3", "R4", "R5", "R6", "R7", "R8"} {
		path := filepath.Join("..", "..", "docs", "differential", round, "report.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s report: %v", round, err)
		}
		digest := sha256.Sum256(data)
		actual := hex.EncodeToString(digest[:])
		if actual != baseline[round] {
			t.Fatalf("%s report hash changed: got %s want baseline", round, actual)
		}
		out[round] = baseline[round]
	}
	return out
}

// Keep the package's R9 platform assertion explicit: no function may acquire
// a Windows-only or Linux-only gate merely because the Salt source contains
// is_windows branching in __virtual__. Slice families check their
// registered subset; unregistered pending names have no gate to check.
func TestR9FunctionsArePlatformNeutral(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for _, familyName := range r9FamilyOrder {
		spec := r9FamilySpecs[familyName]
		for _, name := range loadCatalogFunctionNames(t, familyName) {
			if strings.HasPrefix(name, "_") {
				continue
			}
			full := familyName + "." + name
			fn, ok := rt.Exec.Get(full)
			if !ok {
				if spec.RegisteredSubset == nil {
					t.Fatalf("missing %s", full)
				}
				continue
			}
			if constrained, ok := fn.(runtime.PlatformConstrained); ok {
				t.Fatalf("%s unexpectedly constrained to %v", full, constrained.Platforms())
			}
		}
	}
}

func init() {
	// YAML map emission is deterministic in yaml.v3, but keep the scenario
	// lists and prior hash keys deterministic if this report is inspected
	// manually.
	for _, spec := range r9FamilySpecs {
		sort.Strings(spec.Scenarios)
	}
}
