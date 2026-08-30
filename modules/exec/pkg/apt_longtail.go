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

func (f aptLongtailFunc) Name() string                   { return "pkg." + f.name }
func (f aptLongtailFunc) Args() any                      { return f.prototype }
func (f aptLongtailFunc) ProviderCapabilities() []string { return []string{"aptpkg"} }
func (f aptLongtailFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	ap, ok := p.(pkgprovider.AptProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedAPT
	}
	v := reflect.ValueOf(args)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil, fmt.Errorf("%s: nil arguments", f.Name())
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%s: malformed arguments", f.Name())
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
		field := v.Field(i)
		// Do not manufacture optional nil values at the provider boundary.
		// In particular, a nil compatibility/source slice must not become an
		// explicitly supplied argument with different Salt semantics.
		if (field.Kind() == reflect.Pointer || field.Kind() == reflect.Slice || field.Kind() == reflect.Map || field.Kind() == reflect.Interface) && field.IsNil() {
			continue
		}
		m[key] = field.Interface()
	}
	return ap.Apt(ctx, rt, f.name, m)
}

func longtailFunctions() []runtime.ExecFunction {
	return []runtime.ExecFunction{
		aptLongtailFunc{"autoremove", AutoremoveArgs{}}, aptLongtailFunc{"file_dict", FilePackagesArgs{}}, aptLongtailFunc{"file_list", FilePackagesArgs{}}, aptLongtailFunc{"get_selections", SelectionsArgs{}}, aptLongtailFunc{"hold", PackagesArgs{}}, aptLongtailFunc{"info_installed", InfoArgs{}}, aptLongtailFunc{"list_downloaded", DownloadedArgs{}}, aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}, aptLongtailFunc{"list_upgrades", ListUpgradesArgs{}}, aptLongtailFunc{"normalize_name", NormalizeNameArgs{}}, aptLongtailFunc{"owner", struct {
			Paths []string `statekit:"name=paths"`
		}{}}, aptLongtailFunc{"parse_arch", ParseArchArgs{}}, aptLongtailFunc{"purge", PurgeArgs{}}, aptLongtailFunc{"services_need_restart", struct{}{}}, aptLongtailFunc{"set_selections", SetSelectionsArgs{}}, aptLongtailFunc{"show", ShowArgs{}}, aptLongtailFunc{"unhold", PackagesArgs{}}, aptLongtailFunc{"upgrade", UpgradeArgs{}}, aptLongtailFunc{"upgrade_available", NormalizeNameArgs{}}, aptLongtailFunc{"version_cmp", VersionCmpArgs{}}, aptLongtailFunc{"which", PathArgs{}}}
}
