// Compatibility classification for every catalog family.
//
// plans/init.md section 43A forbids blind ports; this manifest makes the
// decision space auditable: every Salt module family ends up exactly one of
// implemented / not_applicable / deferred. Implemented means StateKit ships
// at least one function of that virtual family.
package main

import (
	"sort"
	"strings"
)

// Reason constants for non-implemented families.
const (
	reasonMasterMinion   = "master-minion architecture (StateKit is local-only by design)"
	reasonPlatformWin    = "windows-only"
	reasonPlatformMac    = "macos-only"
	reasonPlatformUnix   = "non-linux unix platform"
	reasonNetworkDevice  = "network-device stack"
	reasonCloudAPI       = "cloud provider API"
	reasonProtocolClient = "requires database/message-broker client protocol"
	reasonDeferred       = "deferred: needs dedicated porting round"
)

var notApplicablePrefixes = []struct {
	prefix string
	reason string
}{
	{"win_", reasonPlatformWin},
	{"mac_", reasonPlatformMac},
	{"darwin", reasonPlatformMac},
	{"aix_", reasonPlatformUnix},
	{"solaris", reasonPlatformUnix},
	{"freebsd", reasonPlatformUnix},
	{"openbsd", reasonPlatformUnix},
	{"netbsd", reasonPlatformUnix},
	{"smartos", reasonPlatformUnix},
	{"zone", reasonPlatformUnix},
	{"smf_", reasonPlatformUnix},
	{"pw_user", reasonPlatformUnix},
	{"pw_group", reasonPlatformUnix},
	{"napalm", reasonNetworkDevice},
	{"junos", reasonNetworkDevice},
	{"nxos", reasonNetworkDevice},
	{"arista", reasonNetworkDevice},
	{"cisco", reasonNetworkDevice},
	{"panos", reasonNetworkDevice},
	{"fortios", reasonNetworkDevice},
	{"netscaler", reasonNetworkDevice},
	{"bigip", reasonNetworkDevice},
	{"vyatta", reasonNetworkDevice},
	{"vyos", reasonNetworkDevice},
	{"netbox", reasonNetworkDevice},
	{"boto", reasonCloudAPI},
	{"cloud", reasonCloudAPI},
	{"azurearm", reasonCloudAPI},
	{"google_", reasonCloudAPI},
	{"gcp_", reasonCloudAPI},
	{"digital_ocean", reasonCloudAPI},
	{"linode", reasonCloudAPI},
	{"softlayer", reasonCloudAPI},
	{"vmware", reasonCloudAPI},
	{"vsphere", reasonCloudAPI},
	{"esxi", reasonCloudAPI},
	{"ec2", reasonCloudAPI},
	{"route53", reasonCloudAPI},
	{"openstack", reasonCloudAPI},
	{"keystone", reasonCloudAPI},
	{"glance", reasonCloudAPI},
	{"heat", reasonCloudAPI},
	{"neutron", reasonCloudAPI},
	{"nova", reasonCloudAPI},
	{"cinder", reasonCloudAPI},
	{"swift", reasonCloudAPI},
	{"mysql", reasonProtocolClient},
	{"postgres", reasonProtocolClient},
	{"redis", reasonProtocolClient},
	{"memcached", reasonProtocolClient},
	{"mongodb", reasonProtocolClient},
	{"influxdb", reasonProtocolClient},
	{"influx", reasonProtocolClient},
	{"elasticsearch", reasonProtocolClient},
	{"kafka", reasonProtocolClient},
	{"rabbitmq", reasonProtocolClient},
	{"snmp", reasonProtocolClient},
	{"ldap3", reasonProtocolClient},
	{"consul", reasonProtocolClient},
	{"etcd", reasonProtocolClient},
	{"vault", reasonProtocolClient},
	{"solr", reasonProtocolClient},
	{"cassandra", reasonProtocolClient},
	{"couchbase", reasonProtocolClient},
	{"sqlite3", reasonProtocolClient},
	{"slack_notify", reasonProtocolClient},
	{"telegram", reasonProtocolClient},
	{"twilio", reasonProtocolClient},
	{"dnsutil", reasonProtocolClient},
	{"dig", reasonProtocolClient},
	{"salt", reasonMasterMinion},
	{"pillar", reasonMasterMinion},
	{"mine", reasonMasterMinion},
	{"publish", reasonMasterMinion},
	{"event", reasonMasterMinion},
	{"minion", reasonMasterMinion},
	{"key", reasonMasterMinion},
	{"beacons", reasonMasterMinion},
	{"schedule", reasonMasterMinion},
	{"proxy", reasonMasterMinion},
	{"rest_", reasonMasterMinion},
	{"saltcheck", reasonMasterMinion},
	{"highstate", reasonMasterMinion},
	{"slsutil", reasonMasterMinion},
	{"state_", reasonMasterMinion},
	{"match", reasonMasterMinion},
	{"grains", reasonMasterMinion},
	{"sdb", reasonMasterMinion},
}

// classifyFamilies buckets every catalog doc into implemented /
// not_applicable / deferred using the shipped-function intersection from
// coverage plus deterministic prefix rules.
func classifyFamilies(docs []ModuleDoc, implementedNames []string) map[string][]string {
	shipped := map[string]bool{}
	for _, name := range implementedNames {
		shipped[strings.SplitN(name, ".", 2)[0]] = true
	}

	// Bridges for StateKit module names that intentionally differ from the
	// Salt source-file family names they implement.
	bridges := map[string]string{
		"cmdmod":     "cmd",
		"localemod":  "locale",
		"useradd":    "user",
		"groupadd":   "group",
		"ini_manage": "ini",
		"mod_random": "random",
		"hosts":      "hosts",
		"mount":      "mount",
	}

	seen := map[string]bool{}
	buckets := map[string][]string{
		"implemented":    {},
		"not_applicable": {},
		"deferred":       {},
	}
	add := func(bucket, label string) {
		if seen[label] {
			return
		}
		seen[label] = true
		buckets[bucket] = append(buckets[bucket], label)
	}

	for _, doc := range docs {
		family := publicModuleName(doc)
		if family == "" {
			continue
		}
		label := family
		if doc.Kind == "state" && !seen[label+"|state"] && seen[label] {
			add("implemented", label)
			continue
		}
		module := family
		if bridged, ok := bridges[family]; ok {
			module = bridged
		}
		covered := shipped[module]
		for _, fn := range doc.Functions {
			if shipped[module] || shipped[module+"."+fn.Function] {
				covered = true
				break
			}
		}
		if covered {
			add("implemented", label)
			continue
		}
		lower := strings.ToLower(family)
		classified := false
		for _, rule := range notApplicablePrefixes {
			if strings.HasPrefix(lower, rule.prefix) {
				add("not_applicable", family+" ("+rule.reason+")")
				classified = true
				break
			}
		}
		if !classified {
			add("deferred", family+" ("+reasonDeferred+")")
		}
	}

	for bucket := range buckets {
		sort.Strings(buckets[bucket])
	}
	return buckets
}
