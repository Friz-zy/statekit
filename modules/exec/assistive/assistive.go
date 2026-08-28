// Package assistive implements Salt's Darwin TCC accessibility database
// surface through the native sqlite3 command. It deliberately does not add a
// Go SQLite driver: the TCC schema is OS-owned and changes across macOS
// releases, so queries and schema selection stay visible at the Runner
// boundary and are covered with schema-aware fixtures.
package assistive

import (
	"context"
	"crypto/sha1" // schema identification only; not a security primitive
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

const defaultTCCDBPath = "/Library/Application Support/com.apple.TCC/TCC.db"

var (
	tccDBPath      = defaultTCCDBPath
	assistiveSleep = time.Sleep
)

type schemaKind string

const (
	schemaMojaveCatalina schemaKind = "mojave-catalina"
	schemaBigSur         schemaKind = "bigsur"
	schemaSonoma         schemaKind = "sonoma"
)

// schemaDetector is injectable only for fixture tests; production always
// hashes sqlite_master's access-table definition like Salt's TccDB.
var schemaDetector = detectSchema

func sqliteQuery(ctx context.Context, rt *runtime.Runtime, query string) ([]map[string]any, error) {
	result := rt.Runner.Run(ctx, runtime.Command("sqlite3", "-json", tccDBPath, query))
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("sqlite3: %s", strings.TrimSpace(string(result.Stderr)))
	}
	if strings.TrimSpace(string(result.Stdout)) == "" {
		return []map[string]any{}, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func sqliteExec(ctx context.Context, rt *runtime.Runtime, query string) error {
	result := rt.Runner.Run(ctx, runtime.Command("sqlite3", tccDBPath, query))
	if result.Err != nil && result.ExitCode == -1 {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("sqlite3: %s", strings.TrimSpace(string(result.Stderr)))
	}
	return nil
}

func detectSchema(ctx context.Context, rt *runtime.Runtime) (schemaKind, error) {
	rows, err := sqliteQuery(ctx, rt, "SELECT sql FROM sqlite_master WHERE name='access' and type='table';")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("TCC access table not found")
	}
	sqlText, _ := rows[0]["sql"].(string)
	digest := sha1.Sum([]byte(sqlText))
	short := hex.EncodeToString(digest[:])[:10]
	switch short {
	case "ecc443615f", "80a4bb6912":
		return schemaMojaveCatalina, nil
	case "3d1c2a0e97", "cef70648de":
		return schemaBigSur, nil
	case "34abf99d20":
		return schemaSonoma, nil
	default:
		return "", fmt.Errorf("TCC Database structure unknown for digest '%s'", short)
	}
}

func columnForSchema(schema schemaKind) (string, error) {
	switch schema {
	case schemaMojaveCatalina:
		return "allowed", nil
	case schemaBigSur, schemaSonoma:
		return "auth_value", nil
	default:
		return "", fmt.Errorf("unknown TCC schema %q", schema)
	}
}

func sqlQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func clientType(appID string) (int, error) {
	if appID == "" {
		return 0, fmt.Errorf("app_id cannot be empty")
	}
	if strings.HasPrefix(appID, "/") {
		return 1, nil
	}
	return 0, nil
}

func queryInstalled(ctx context.Context, rt *runtime.Runtime, appID string) (bool, error) {
	if _, err := schemaDetector(ctx, rt); err != nil {
		return false, err
	}
	query := "SELECT 1 AS present FROM access WHERE client=" + sqlQuote(appID) +
		" AND service='kTCCServiceAccessibility' LIMIT 1;"
	rows, err := sqliteQuery(ctx, rt, query)
	return len(rows) > 0, err
}

func queryEnabled(ctx context.Context, rt *runtime.Runtime, appID string) (bool, error) {
	schema, err := schemaDetector(ctx, rt)
	if err != nil {
		return false, err
	}
	column, err := columnForSchema(schema)
	if err != nil {
		return false, err
	}
	query := "SELECT " + column + " AS enabled FROM access WHERE client=" + sqlQuote(appID) +
		" AND service='kTCCServiceAccessibility' LIMIT 1;"
	rows, err := sqliteQuery(ctx, rt, query)
	if err != nil || len(rows) == 0 {
		return false, err
	}
	value, ok := rows[0]["enabled"]
	if !ok {
		return false, nil
	}
	switch item := value.(type) {
	case float64:
		return item != 0, nil
	case int:
		return item != 0, nil
	case bool:
		return item, nil
	default:
		return fmt.Sprint(item) != "0" && fmt.Sprint(item) != "", nil
	}
}

func installQuery(schema schemaKind, appID string, enabled bool) (string, error) {
	client, err := clientType(appID)
	if err != nil {
		return "", err
	}
	auth := 0
	if enabled {
		auth = 1
	}
	service := sqlQuote("kTCCServiceAccessibility")
	clientSQL := sqlQuote(appID)
	switch schema {
	case schemaBigSur:
		return fmt.Sprintf("INSERT OR REPLACE INTO access VALUES (%s,%s,%d,%d,4,1,NULL,NULL,0,'UNUSED',NULL,0,0);", service, clientSQL, client, auth), nil
	case schemaMojaveCatalina:
		return fmt.Sprintf("INSERT OR REPLACE INTO access VALUES (%s,%s,%d,%d,1,NULL,NULL,NULL,'UNUSED',NULL,0,0);", service, clientSQL, client, auth), nil
	case schemaSonoma:
		return fmt.Sprintf("INSERT OR REPLACE INTO access VALUES (%s,%s,%d,%d,4,1,NULL,NULL,NULL,'UNUSED',NULL,0,0,0,0,'UNUSED',strftime('%%s','now'));", service, clientSQL, client, auth), nil
	default:
		return "", fmt.Errorf("unknown TCC schema %q", schema)
	}
}

func installImpl(ctx context.Context, rt *runtime.Runtime, appID string, enabled bool, tries, wait int) (bool, error) {
	schema, err := schemaDetector(ctx, rt)
	if err != nil {
		return false, err
	}
	query, err := installQuery(schema, appID, enabled)
	if err != nil {
		return false, err
	}
	if tries < 1 {
		tries = 1
	}
	for attempt := 1; attempt <= tries; attempt++ {
		err = sqliteExec(ctx, rt, query)
		if err == nil {
			return true, nil
		}
		if !strings.Contains(strings.ToLower(err.Error()), "readonly database") || attempt == tries {
			return false, err
		}
		assistiveSleep(time.Duration(wait) * time.Second)
	}
	return false, err
}

func updateEnabledQuery(schema schemaKind, appID string, enabled bool) (string, error) {
	column, err := columnForSchema(schema)
	if err != nil {
		return "", err
	}
	value := 0
	if enabled {
		value = 1
	}
	return fmt.Sprintf("UPDATE access SET %s=%d WHERE client=%s AND service IS 'kTCCServiceAccessibility';", column, value, sqlQuote(appID)), nil
}

func enableImpl(ctx context.Context, rt *runtime.Runtime, appID string, enabled bool) (bool, error) {
	installed, err := queryInstalled(ctx, rt, appID)
	if err != nil || !installed {
		return false, err
	}
	schema, err := schemaDetector(ctx, rt)
	if err != nil {
		return false, err
	}
	query, err := updateEnabledQuery(schema, appID, enabled)
	if err != nil {
		return false, err
	}
	if err := sqliteExec(ctx, rt, query); err != nil {
		return false, err
	}
	return true, nil
}

func removeImpl(ctx context.Context, rt *runtime.Runtime, appID string) (bool, error) {
	installed, err := queryInstalled(ctx, rt, appID)
	if err != nil || !installed {
		return false, err
	}
	query := "DELETE FROM access WHERE client IS " + sqlQuote(appID) +
		" AND service IS 'kTCCServiceAccessibility';"
	if err := sqliteExec(ctx, rt, query); err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// public functions

type installArgs struct {
	AppID  string `statekit:"required,name=app_id"`
	Enable *bool  `statekit:"name=enable"`
	Tries  *int   `statekit:"name=tries"`
	Wait   *int   `statekit:"name=wait"`
}
type installFunc struct{}

func (installFunc) Name() string        { return "assistive.install" }
func (installFunc) Args() any           { return installArgs{} }
func (installFunc) Platforms() []string { return []string{"darwin"} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverAssistive(&res, &err)
	a := args.(*installArgs)
	enable := true
	if a.Enable != nil {
		enable = *a.Enable
	}
	tries, wait := 3, 10
	if a.Tries != nil {
		tries = *a.Tries
	}
	if a.Wait != nil {
		wait = *a.Wait
	}
	ok, ierr := installImpl(ctx, rt, a.AppID, enable, tries, wait)
	if ierr != nil {
		return nil, fmt.Errorf("Error installing app(%s): %v", a.AppID, ierr)
	}
	return ok, nil
}

type installedArgs struct {
	AppID string `statekit:"required,name=app_id"`
}
type installedFunc struct{}

func (installedFunc) Name() string        { return "assistive.installed" }
func (installedFunc) Args() any           { return installedArgs{} }
func (installedFunc) Platforms() []string { return []string{"darwin"} }
func (installedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverAssistive(&res, &err)
	a := args.(*installedArgs)
	ok, ierr := queryInstalled(ctx, rt, a.AppID)
	if ierr != nil {
		return nil, fmt.Errorf("Error checking if app(%s) is installed: %v", a.AppID, ierr)
	}
	return ok, nil
}

type enableArgs struct {
	AppID   string `statekit:"required,name=app_id"`
	Enabled *bool  `statekit:"name=enabled"`
}
type enableFunc struct{}

func (enableFunc) Name() string        { return "assistive.enable" }
func (enableFunc) Args() any           { return enableArgs{} }
func (enableFunc) Platforms() []string { return []string{"darwin"} }
func (enableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverAssistive(&res, &err)
	a := args.(*enableArgs)
	enabled := true
	if a.Enabled != nil {
		enabled = *a.Enabled
	}
	ok, ierr := enableImpl(ctx, rt, a.AppID, enabled)
	if ierr != nil {
		return nil, fmt.Errorf("Error setting enable to %v on app(%s): %v", enabled, a.AppID, ierr)
	}
	return ok, nil
}

type enabledArgs struct {
	AppID string `statekit:"required,name=app_id"`
}
type enabledFunc struct{}

func (enabledFunc) Name() string        { return "assistive.enabled" }
func (enabledFunc) Args() any           { return enabledArgs{} }
func (enabledFunc) Platforms() []string { return []string{"darwin"} }
func (enabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverAssistive(&res, &err)
	a := args.(*enabledArgs)
	ok, ierr := queryEnabled(ctx, rt, a.AppID)
	if ierr != nil {
		return nil, fmt.Errorf("Error checking if app(%s) is enabled: %v", a.AppID, ierr)
	}
	return ok, nil
}

type removeArgs struct {
	AppID string `statekit:"required,name=app_id"`
}
type removeFunc struct{}

func (removeFunc) Name() string        { return "assistive.remove" }
func (removeFunc) Args() any           { return removeArgs{} }
func (removeFunc) Platforms() []string { return []string{"darwin"} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverAssistive(&res, &err)
	a := args.(*removeArgs)
	ok, ierr := removeImpl(ctx, rt, a.AppID)
	if ierr != nil {
		return nil, fmt.Errorf("Error removing app(%s): %v", a.AppID, ierr)
	}
	return ok, nil
}

func recoverAssistive(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Darwin assistive functions; enable_ is exposed as
// assistive.enable through the same alias the Salt module declares.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		installFunc{}, installedFunc{}, enableFunc{}, enabledFunc{}, removeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
