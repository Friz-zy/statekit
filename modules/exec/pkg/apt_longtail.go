package pkg

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

// These structs intentionally mirror the public Salt signatures. Optional
// scalar fields are pointers so omission remains distinguishable from
// an explicit false/empty value at the provider boundary.
type AutoremoveArgs struct {
	ListOnly *bool `statekit:"name=list_only"`
	Purge    *bool `statekit:"name=purge"`
}
type PackagesArgs struct {
	Name *string `statekit:"name=name"`
	// Pkgs is Salt's canonical vararg name.
	Pkgs []string `statekit:"name=pkgs"`
	// Salt also accepts source mappings for hold/unhold. The APT provider
	// rejects these safely until source-map semantics can be represented.
	Sources []any `statekit:"name=sources"`
}
type PurgeArgs struct {
	Name *string  `statekit:"name=name"`
	Pkgs []string `statekit:"name=pkgs"`
}
type FilePackagesArgs struct {
	Packages []string `statekit:"name=packages"`
}
type OwnerArgs struct {
	Paths []string `statekit:"name=paths"`
}
type SelectionsArgs struct {
	Pattern *string `statekit:"name=pattern"`
	State   *string `statekit:"name=state"`
}
type SetSelectionsArgs struct {
	Path      *string `statekit:"name=path"`
	Selection any     `statekit:"name=selection"`
	Clear     *bool   `statekit:"name=clear"`
	Saltenv   *string `statekit:"name=saltenv"`
}
type InfoArgs struct {
	Names    []string `statekit:"name=names"`
	Failhard *bool    `statekit:"name=failhard"`
}
type ShowArgs struct {
	Names   []string `statekit:"name=names"`
	Filter  *string  `statekit:"name=filter"`
	Refresh *bool    `statekit:"name=refresh"`
}
type UpgradeArgs struct {
	Refresh         *bool `statekit:"name=refresh"`
	DistUpgrade     *bool `statekit:"name=dist_upgrade"`
	ForceConfNew    *bool `statekit:"name=force_conf_new"`
	DownloadOnly    *bool `statekit:"name=download_only"`
	Downloadonly    *bool `statekit:"name=downloadonly"`
	AllowDowngrades *bool `statekit:"name=allow_downgrades"`
	ForceYes        *bool `statekit:"name=force_yes"`
	SkipVerify      *bool `statekit:"name=skip_verify"`
	CacheValidTime  *int  `statekit:"name=cache_valid_time"`
}
type ListUpgradesArgs struct {
	Refresh        *bool `statekit:"name=refresh"`
	DistUpgrade    *bool `statekit:"name=dist_upgrade"`
	CacheValidTime *int  `statekit:"name=cache_valid_time"`
}
type NormalizeNameArgs struct {
	Name string `statekit:"required"`
}
type ParseArchArgs = NormalizeNameArgs
type VersionCmpArgs struct {
	Pkg1        string `statekit:"required"`
	Pkg2        string `statekit:"required"`
	IgnoreEpoch *bool  `statekit:"name=ignore_epoch"`
}

type PathArgs struct {
	Path string `statekit:"required"`
}
type DownloadedArgs struct {
	Root *string `statekit:"name=root"`
}

type aptLongtailFunc struct {
	name      string
	prototype any
}

func (f aptLongtailFunc) Name() string         { return "pkg." + f.name }
func (f aptLongtailFunc) Args() any            { return f.prototype }
func (f aptLongtailFunc) ProviderKind() string { return "pkg" }
func (f aptLongtailFunc) ArgsForProvider(providerName string) (any, error) {
	switch providerName {
	case "apt":
		if f.name == "clean_metadata" || f.name == "list_holds" {
			return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
		}
		return f.prototype, nil
	case "yum", "dnf", "dnf5":
		if p, ok := YumPrototype(f.name); ok {
			return p, nil
		}
		for _, shared := range []string{"normalize_name", "parse_arch", "version_cmp"} {
			if f.name == shared {
				return f.prototype, nil
			}
		}
	}
	return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
}
func (f aptLongtailFunc) ProviderArgsStrict() bool {
	return f.name == "file_list" || f.name == "file_dict" || f.name == "info_installed" || f.name == "owner" || f.name == "clean_metadata" || f.name == "list_holds" || f.name == "services_need_restart"
}
func (f aptLongtailFunc) ProviderCapabilities() []string {
	if f.name == "clean_metadata" {
		return []string{"yumpkg"}
	}
	if f.name == "list_holds" {
		return []string{"yumpkg"}
	}
	if f.name == "services_need_restart" {
		return []string{"aptpkg", "yumpkg"}
	}
	// These public names are shared by aptpkg and yumpkg; execution dispatch
	// remains provider-specific below. Unique APT functions stay APT-only.
	for _, name := range []string{"normalize_name", "parse_arch"} {
		if f.name == name {
			return []string{"aptpkg", "yumpkg"}
		}
	}
	if f.name == "version_cmp" {
		return []string{"aptpkg", "yumpkg"}
	}
	for _, name := range []string{"file_list", "file_dict", "info_installed", "owner"} {
		if f.name == name {
			return []string{"aptpkg", "yumpkg"}
		}
	}
	return []string{"aptpkg"}
}
func (f aptLongtailFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	providerName := p.Name()
	prototype, err := f.ArgsForProvider(providerName)
	if err != nil {
		return nil, err
	}
	if yp, ok := p.(pkgprovider.YumProvider); ok && (providerName == "yum" || providerName == "dnf" || providerName == "dnf5") {
		argMap, err := mapArgs(f.Name(), args, prototype)
		if err != nil {
			return nil, err
		}
		return yp.Yum(ctx, rt, f.name, argMap)
	}
	ap, ok := p.(pkgprovider.AptProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedAPT
	}
	argMap, err := mapArgs(f.Name(), args, prototype)
	if err != nil {
		return nil, err
	}
	return ap.Apt(ctx, rt, f.name, argMap)
}

func mapArgs(name string, args any, prototype any) (map[string]any, error) {
	v := reflect.ValueOf(args)
	if !v.IsValid() {
		return nil, fmt.Errorf("%s: malformed arguments", name)
	}
	expected := reflect.TypeOf(prototype)
	if expected != nil && expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	if expected == nil || expected.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%s: malformed arguments", name)
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() || v.Type().Elem() != expected {
			return nil, fmt.Errorf("%s: malformed arguments", name)
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct || v.Type() != expected {
		return nil, fmt.Errorf("%s: malformed arguments", name)
	}
	m := map[string]any{}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("statekit"), ",")[0]
		if tag == "-" {
			continue
		}
		key := strings.TrimPrefix(tag, "name=")
		if key == "" || key == "required" {
			key = strings.ToLower(t.Field(i).Name)
		}
		f := v.Field(i)
		// Do not manufacture optional nil values at the provider boundary.
		// In particular, a nil compatibility/source slice must not become an
		// explicitly supplied argument with different Salt semantics.
		if (f.Kind() == reflect.Pointer || f.Kind() == reflect.Slice || f.Kind() == reflect.Map || f.Kind() == reflect.Interface) && f.IsNil() {
			continue
		}
		m[key] = f.Interface()
	}
	return m, nil
}

func longtailFunctions() []runtime.ExecFunction {
	return []runtime.ExecFunction{
		aptLongtailFunc{"autoremove", AutoremoveArgs{}}, aptLongtailFunc{"clean_metadata", YumCleanMetadataArgs{}}, aptLongtailFunc{"file_dict", FilePackagesArgs{}}, aptLongtailFunc{"file_list", FilePackagesArgs{}}, aptLongtailFunc{"get_selections", SelectionsArgs{}}, aptLongtailFunc{"hold", PackagesArgs{}}, aptLongtailFunc{"info_installed", InfoArgs{}}, aptLongtailFunc{"list_downloaded", DownloadedArgs{}}, aptLongtailFunc{"list_holds", YumListHoldsArgs{}}, aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}, aptLongtailFunc{"list_upgrades", ListUpgradesArgs{}}, aptLongtailFunc{"normalize_name", NormalizeNameArgs{}}, aptLongtailFunc{"owner", OwnerArgs{}}, aptLongtailFunc{"parse_arch", ParseArchArgs{}}, aptLongtailFunc{"purge", PurgeArgs{}}, aptLongtailFunc{"services_need_restart", struct{}{}}, aptLongtailFunc{"set_selections", SetSelectionsArgs{}}, aptLongtailFunc{"show", ShowArgs{}}, aptLongtailFunc{"unhold", PackagesArgs{}}, aptLongtailFunc{"upgrade", UpgradeArgs{}}, aptLongtailFunc{"upgrade_available", NormalizeNameArgs{}}, aptLongtailFunc{"version_cmp", VersionCmpArgs{}}, aptLongtailFunc{"which", PathArgs{}},
	}
}
