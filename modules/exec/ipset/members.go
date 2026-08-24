package ipset

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Member parts mirror the Python ipaddress objects _parse_member produces:
// plain addresses become ipAddr, networks and range aggregations become
// ipNet values, ports become ints, everything else stays a string.
type ipAddr struct{ addr netip.Addr }

type ipNet struct{ prefix netip.Prefix }

func (n ipNet) contains(a ipAddr) bool {
	if a.addr.Is4() != n.prefix.Addr().Is4() {
		return false
	}
	return n.prefix.Contains(a.addr)
}

// parseMembers ports _parse_members for string slices.
func parseMembers(settype string, members []string) []any {
	out := make([]any, 0, len(members))
	for _, member := range members {
		out = append(out, toSlice(parseMember(settype, member)))
	}
	return out
}

// parseMember ports _parse_member: comma-separated parts typed by the
// set's subtypes; text after the first space rides along as a trailing
// part (comment). Unparseable ip/net parts keep their raw strings like
// upstream's swallowed ValueError.
func parseMember(settype, member string) []any {
	subtypes := strings.Split(strings.Split(settype, ":")[1], ",")

	allParts := strings.SplitN(member, " ", 2)
	parts := strings.Split(allParts[0], ",")

	parsed := []any{}
	for i, subtype := range subtypes {
		part := ""
		if i < len(parts) {
			part = parts[i]
		}
		switch subtype {
		case "ip", "net":
			parsed = append(parsed, parseIPPart(part))
		case "port":
			n, err := strconv.Atoi(part)
			if err != nil {
				// Upstream lets the ValueError propagate.
				parsed = append(parsed, part)
				continue
			}
			parsed = append(parsed, int64(n))
		default:
			parsed = append(parsed, part)
		}
	}
	if len(allParts) > 1 {
		parsed = append(parsed, allParts[1])
	}
	return parsed
}

// parseIPPart mirrors the ipaddress branch: slash form becomes a network,
// dash ranges aggregate into covering networks, bare IPs stay addresses,
// anything unparseable keeps its string shape.
func parseIPPart(part string) any {
	if strings.Contains(part, "/") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return part
		}
		return ipNet{prefix: prefix.Masked()}
	}
	if strings.Contains(part, "-") {
		bounds := strings.SplitN(part, "-", 2)
		start, err1 := netip.ParseAddr(strings.TrimSpace(bounds[0]))
		end, err2 := netip.ParseAddr(strings.TrimSpace(bounds[1]))
		if err1 != nil || err2 != nil || !start.IsValid() || !end.IsValid() {
			return part
		}
		return ipNet{prefix: rangeToPrefix(start, end)}
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(part))
	if err != nil || !addr.IsValid() {
		return part
	}
	return ipAddr{addr: addr}
}

// rangeToPrefix summarizes an address range into the minimal covering
// prefix (the common single-network result of summarize_address_range for
// the shapes ipset entries carry).
func rangeToPrefix(start, end netip.Addr) netip.Prefix {
	var sb, eb []byte
	bits := start.BitLen()
	if start.Is4() {
		s4 := start.As4()
		e4 := end.As4()
		sb, eb = s4[:], e4[:]
	} else {
		s16 := start.As16()
		e16 := end.As16()
		sb, eb = s16[:], e16[:]
	}
	common := 0
	for common < bits {
		byteIdx := common / 8
		bitIdx := uint(7 - common%8)
		if (sb[byteIdx]>>bitIdx)&1 != (eb[byteIdx]>>bitIdx)&1 {
			break
		}
		common++
	}
	masked, _ := end.Prefix(common)
	return masked.Masked()
}

// memberContains ports _member_contains.
func memberContains(member, entry []any) bool {
	if len(member) < len(entry) {
		return false
	}
	for i, entryPart := range entry {
		if !compareMemberParts(member[i], entryPart) {
			return false
		}
	}
	return true
}

// compareMemberParts ports _compare_member_parts including upstream's
// all-items AND semantics over range lists.
func compareMemberParts(memberPart, entryPart any) bool {
	if scalarEqual(memberPart, entryPart) {
		return true
	}

	if entryList, ok := entryPart.([]any); ok {
		for _, item := range entryList {
			if !compareMemberParts(memberPart, item) {
				return false
			}
		}
		return true
	}

	switch m := memberPart.(type) {
	case ipAddr:
		if n, ok := entryPart.(ipNet); ok {
			return n.contains(m)
		}
	case ipNet:
		if a, ok := entryPart.(ipAddr); ok {
			return m.contains(a)
		}
		// Both are networks: unequal networks never contain each other
		// (upstream returns False with a commented-out refinement).
	}
	return false
}

func scalarEqual(a, b any) bool {
	switch av := a.(type) {
	case int64:
		bv, ok := b.(int64)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case ipAddr:
		bv, ok := b.(ipAddr)
		return ok && av.addr == bv.addr
	case ipNet:
		bv, ok := b.(ipNet)
		return ok && av.prefix == bv.prefix
	default:
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
}

func toSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return []any{v}
}
