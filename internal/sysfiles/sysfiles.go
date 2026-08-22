// Package sysfiles provides parsers for the local password, group, and
// shadow databases. They operate on file contents so modules can resolve
// records through the runtime FileSystem abstraction.
package sysfiles

import (
	"strconv"
	"strings"
)

// shadowNumber converts a shadow field to int64; empty or non-numeric values
// map to -1.
func shadowNumber(s string) int64 {
	if s == "" {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// PasswdEntry is one record from /etc/passwd.
type PasswdEntry struct {
	Name  string
	UID   string
	GID   string
	Gecos string
	Home  string
	Shell string
}

// ParsePasswd parses passwd database contents (7 colon-separated fields).
func ParsePasswd(content string) []PasswdEntry {
	var out []PasswdEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 7)
		if len(parts) != 7 {
			continue
		}
		out = append(out, PasswdEntry{
			Name:  parts[0],
			UID:   parts[2],
			GID:   parts[3],
			Gecos: parts[4],
			Home:  parts[5],
			Shell: parts[6],
		})
	}
	return out
}

// GroupEntry is one record from /etc/group.
type GroupEntry struct {
	Name    string
	GID     string
	Members []string
}

// ParseGroup parses group database contents (4 colon-separated fields).
func ParseGroup(content string) []GroupEntry {
	var out []GroupEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) != 4 {
			continue
		}
		members := []string{}
		for _, member := range strings.Split(parts[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				members = append(members, member)
			}
		}
		out = append(out, GroupEntry{Name: parts[0], GID: parts[2], Members: members})
	}
	return out
}

// ShadowEntry is one record from /etc/shadow. Non-numeric optional fields are
// stored as -1 following Salt's linux_shadow behavior.
type ShadowEntry struct {
	Name   string
	Passwd string
	Lstchg int64
	Min    int64
	Max    int64
	Warn   int64
	Inact  int64
	Expire int64
	Flag   int64
}

// ParseShadow parses shadow database contents (9 colon-separated fields).
func ParseShadow(content string) []ShadowEntry {
	var out []ShadowEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 9)
		if len(parts) != 9 {
			continue
		}
		out = append(out, ShadowEntry{
			Name:   parts[0],
			Passwd: parts[1],
			Lstchg: shadowNumber(parts[2]),
			Min:    shadowNumber(parts[3]),
			Max:    shadowNumber(parts[4]),
			Warn:   shadowNumber(parts[5]),
			Inact:  shadowNumber(parts[6]),
			Expire: shadowNumber(parts[7]),
			Flag:   shadowNumber(parts[8]),
		})
	}
	return out
}
