package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	exechosts "github.com/friz-zy/statekit/modules/exec/hosts"
)

func TestFixtureProcessEnvFiltersAmbientOverridesAndCredentials(t *testing.T) {
	ambient := []string{
		"PATH=/first",
		"HOME=/fixture-home",
		"LANG=C.UTF-8",
		"LC_ALL=C",
		"TZ=UTC",
		exechosts.HostsPathEnv + "=/ambient/first",
		"AWS_SECRET_ACCESS_KEY=synthetic",
		"GOOGLE_APPLICATION_CREDENTIALS=/synthetic/credentials.json",
		"STATEKIT_TOKEN=synthetic",
		"PATH=/last",
		exechosts.HostsPathEnv + "=/ambient/second",
		"NOT_ALLOWLISTED=value",
	}
	owned := filepath.Join(exechosts.FixtureHostsRoot, "runner-owned", "hosts")
	got := fixtureProcessEnv(ambient, owned)
	want := []string{
		"PATH=/last",
		"HOME=/fixture-home",
		"LANG=C.UTF-8",
		"LC_ALL=C",
		"TZ=UTC",
		exechosts.HostsPathEnv + "=" + owned,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture environment = %#v, want %#v", got, want)
	}

	hostsEntries := 0
	for _, entry := range got {
		if strings.HasPrefix(entry, exechosts.HostsPathEnv+"=") {
			hostsEntries++
		}
	}
	if hostsEntries != 1 {
		t.Fatalf("fixture hosts path entries = %d, want 1", hostsEntries)
	}
}
