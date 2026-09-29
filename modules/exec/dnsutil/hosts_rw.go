package dnsutil

// hosts_append / hosts_remove (R10.3b): the pinned Salt mutation
// surface of saltstack/salt/modules/dnsutil.py lines 59-115, ported
// with exact pinned semantics over the R10.3b bounded atomic
// read-modify-publish capability of Runtime.FS
// (runtime.UpdateFileBounded). Every transformation of the hosts file
// renders the COMPLETE replacement content in a pure transform before
// anything is staged or published; publication is one atomic
// namespace operation (never an in-place truncate or append(2) on the
// destination), and any pre-publication failure leaves the file
// byte-identical. Error surfaces are value-free: no path, argument, or
// file-content bytes travel in any error.
//
// Trust boundary (R103B-SEC-05): this is a trusted same-principal
// local mutation API. The caller-selected hostsfile path is a
// PRIVILEGED input — beyond the capability's no-follow walk, original
// path validation, and the documented bounds there is no confinement
// or authorization, and the pinned source performs none either.
// hosts_append may create the target (mode 0644, exactly like the
// pinned fopen(..., "a")); hosts_remove requires an existing file.
// Publication REPLACES the inode: the ordinary permission bits are
// preserved, but owner and group are NOT, and ACLs, extended
// attributes, security labels, and hard links do not carry over.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

var (
	// errArgumentInvalid is the fixed value-free answer for argument
	// shapes the pinned source crashes on or that could inject file
	// structure: a nil entries argument (the pinned AttributeError on
	// None.split), and NUL or line-break bytes inside the hostsfile,
	// ip_addr, or entries arguments (the pinned source performs no
	// validation at all — a safe divergence).
	errArgumentInvalid = errors.New("dnsutil: invalid argument")
	// ErrHostsUpdateFailed is the fixed value-free answer mapping every
	// generic filesystem failure of the bounded update — including the
	// CLEAN-ABORT outcome (a pre-publication failure whose staging
	// cleanup succeeded: the target is byte-identical or absent) —
	// missing file for removal, symlinked or special-file destination,
	// oversized content, capability-absent filesystem, injected fault
	// or fault-seam sentinel, any other foreign filesystem error.
	// The pinned hosts_append instead writes a fresh file after a read
	// error (parse_hosts answers its error STRING, the membership check
	// misfires on it, and fopen(..., "a") creates the file) and the
	// pinned hosts_remove raises the raw IOError — both are replaced
	// by this fail-closed divergence.
	ErrHostsUpdateFailed = errors.New("dnsutil: hosts update failed")
	// ErrHostsUpdateCommittedDurabilityUncertain surfaces the
	// capability's distinct committed-but-durability-uncertain outcome
	// (runtime.ErrUpdateCommittedUncertain: the post-publication
	// parent-directory fsync failed): the new content IS live.
	ErrHostsUpdateCommittedDurabilityUncertain = errors.New("dnsutil: hosts update committed but durability uncertain")
	// ErrHostsUpdateCleanupFailed surfaces the capability's distinct
	// pre-publication cleanup-failure outcome
	// (runtime.ErrUpdateCleanupFailed): the update aborted with the
	// target still UNCHANGED and the staging-file cleanup also failed,
	// so a leftover staging file may remain beside the target. This is
	// an abort outcome, not a commit.
	ErrHostsUpdateCleanupFailed = errors.New("dnsutil: hosts update cleanup failed; target unchanged")
	// ErrHostsUpdateCommittedWithResidue surfaces the capability's
	// distinct staging-residue outcome
	// (runtime.ErrUpdateStagingResidue): the new content IS committed
	// under the target name and this is never a rollback — only a
	// stray staging file remains. The capability answers this sentinel
	// BEFORE the post-publication parent-directory fsync, so crash
	// durability of the live content is unconfirmed here (a weaker
	// guarantee than ErrHostsUpdateCommittedDurabilityUncertain, which
	// is answered only after that fsync was attempted and failed).
	ErrHostsUpdateCommittedWithResidue = errors.New("dnsutil: hosts update committed; staging residue remains")
	// errNoHostsAppend is the internal transform sentinel for the
	// pinned no-op branch (every requested alias already exists); it
	// aborts the transaction before any staging and never escapes as
	// text — the capability boundary answers its fixed cause-free
	// sentinel without inspecting the callback error, so hosts_append
	// recognizes the no-op branch through the transform's captured
	// sentinel, never through errors.Is on the capability error.
	errNoHostsAppend = errors.New("dnsutil: no hosts append")
)

// hostsArgLimits are the argument ceilings enforced before the
// filesystem is touched (R10.3b): the shared R10.3a constants.
const (
	// maxEntriesBytes bounds the entries argument (the shared 1 MiB
	// source ceiling).
	maxEntriesBytes = maxSourceBytes
	// maxIPBytes bounds the ip_addr argument (the 4096-byte cell
	// ceiling).
	maxIPBytes = maxCellBytes
)

// hostsUpdateLimits bounds the read-modify-publish transaction: the
// same 1 MiB ceilings as the R10.3a parsing surface, bounding both the
// existing-content read and the complete replacement.
var hostsUpdateLimits = runtime.UpdateLimits{
	MaxReadBytes:  maxSourceBytes,
	MaxWriteBytes: maxSourceBytes,
}

// forbiddenArgByte reports bytes that could restructure the hosts file
// or cross into the C API: NUL plus every Python str.splitlines()
// boundary (\n, \r, \v, \f, U+001C..U+001E, U+0085, U+2028, U+2029).
// The pinned source performs no argument validation (a safe
// divergence: argument bytes are rejected value-free before the
// filesystem is touched).
func forbiddenArgByte(s string) bool {
	for _, r := range s {
		switch r {
		case 0, '\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029':
			return true
		}
	}
	return false
}

// validateHostsPathArg enforces the hostsfile path ceiling and the
// NUL/line-break rejection before any filesystem access. This is an
// intentional ordering divergence kept for BOTH mutation functions:
// the checks read no file bytes (pure argument validation), so they
// may precede the file open even though the pinned source validates
// nothing.
func validateHostsPathArg(hostsfile string) error {
	if len(hostsfile) > maxPathBytes {
		return errInputTooLarge
	}
	if forbiddenArgByte(hostsfile) {
		return errArgumentInvalid
	}
	return nil
}

// validateEntriesArg enforces the entries ceiling and the
// NUL/line-break rejection. hosts_remove runs it INSIDE the pure
// transform, AFTER the bounded file read — the pinned source order:
// the fopen("r") IOError on a missing file precedes the
// entries.split(",") AttributeError, so the file-read category wins
// over every entries diagnosis. hosts_append keeps it before the
// update because the pinned append calls entries.split(",") BEFORE
// reading the file.
func validateEntriesArg(entries string) error {
	if len(entries) > maxEntriesBytes {
		return errInputTooLarge
	}
	if forbiddenArgByte(entries) {
		return errArgumentInvalid
	}
	return nil
}

// validateHostsArgs is the hosts_append-side combined argument check
// (path, ip_addr, and entries all precede the filesystem, matching the
// pinned split-before-read order of hosts_append).
func validateHostsArgs(hostsfile, ipAddr, entries string, hasIP bool) error {
	if err := validateHostsPathArg(hostsfile); err != nil {
		return err
	}
	if hasIP && len(ipAddr) > maxIPBytes {
		return errInputTooLarge
	}
	if hasIP && forbiddenArgByte(ipAddr) {
		return errArgumentInvalid
	}
	return validateEntriesArg(entries)
}

func containsToken(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// removeFirstToken removes the first occurrence of value, exactly like
// Python list.remove (the full-slice expression keeps the result from
// aliasing the source slice).
func removeFirstToken(tokens []string, value string) []string {
	for i, token := range tokens {
		if token == value {
			return append(tokens[:i:i], tokens[i+1:]...)
		}
	}
	return tokens
}

// mapHostsUpdateError maps a bounded-update failure to the module's
// fixed value-free error classes. The capability's distinct
// committed/cleanup outcomes each keep their own exported module class
// so callers can distinguish them with errors.Is:
// ErrUpdateCommittedUncertain →
// ErrHostsUpdateCommittedDurabilityUncertain (content live, only
// durability uncertain), ErrUpdateCleanupFailed →
// ErrHostsUpdateCleanupFailed (target unchanged, staging cleanup also
// failed), and ErrUpdateStagingResidue →
// ErrHostsUpdateCommittedWithResidue (content live, stray staging
// file, never a rollback — answered before the parent-directory fsync,
// so crash durability of the live content is unconfirmed). Every
// remaining failure — the clean-abort outcome (a pre-publication
// failure whose staging cleanup succeeded: the target is
// byte-identical or absent), the fixed stage-hook sentinel, the fixed
// cause-free transform sentinel, and every foreign filesystem error —
// collapses to ErrHostsUpdateFailed so no errno/path/content bytes can
// escape. Genuine context cancellation is detected by the capability's
// own ctx checks and passes through value-free. Module-internal
// transform classifications (the no-op sentinel, the parser ceilings,
// the argument class) never travel inside the capability error — the
// boundary answers its fixed cause-free sentinel and never inspects
// the callback error — so the module recognizes them through the
// transform's captured sentinel before this mapping runs, never
// through errors.Is here.
func mapHostsUpdateError(err error) error {
	if errors.Is(err, runtime.ErrUpdateCommittedUncertain) {
		return ErrHostsUpdateCommittedDurabilityUncertain
	}
	if errors.Is(err, runtime.ErrUpdateCleanupFailed) {
		return ErrHostsUpdateCleanupFailed
	}
	if errors.Is(err, runtime.ErrUpdateStagingResidue) {
		return ErrHostsUpdateCommittedWithResidue
	}
	for _, known := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrHostsUpdateFailed
}

// ---------------------------------------------------------------------------
// hosts_append

// HostsAppendArgs mirrors the pinned signature
// hosts_append(hostsfile="/etc/hosts", ip_addr=None, entries=None).
type HostsAppendArgs struct {
	Hostsfile *string `statekit:"name=hostsfile"`
	IpAddr    *string `statekit:"name=ip_addr"`
	Entries   *string `statekit:"name=entries"`
}

type hostsAppendFunc struct{}

func (hostsAppendFunc) Name() string { return "dnsutil.hosts_append" }
func (hostsAppendFunc) Args() any    { return HostsAppendArgs{} }

func (hostsAppendFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[HostsAppendArgs](args, "dnsutil.hosts_append")
	if err != nil {
		return nil, err
	}
	// The pinned entries=None head crashes with AttributeError on
	// None.split(","); it maps to the fixed value-free argument error.
	if a.Entries == nil {
		return nil, errArgumentInvalid
	}
	entries := *a.Entries
	path := defaultHostsPath
	if a.Hostsfile != nil {
		path = *a.Hostsfile
	}
	if err := validateHostsArgs(path, pointerString(a.IpAddr), entries, a.IpAddr != nil); err != nil {
		return nil, err
	}

	hostList := splitEntries(entries)
	appendedLine := ""

	// moduleErr carries this module's OWN fixed sentinel out of the
	// pure transform. The capability boundary answers the fixed
	// cause-free ErrUpdateTransform sentinel and never inspects the
	// callback error, so the no-op branch and the parser-ceiling
	// classes are recognized through this captured variable — direct
	// comparison against module-created sentinels, never errors.Is on
	// the capability error.
	var moduleErr error

	// The pure transform: parse the existing content through the
	// R10.3a parse_hosts loop, apply the pinned alias-removal quirk,
	// and render the complete replacement (always a prefix LF, never a
	// terminal LF). Running inside the transaction means the parsed
	// view describes exactly the bytes the transaction read;
	// publication then REPLACES the inode with the rendered
	// replacement, so this is NOT a same-inode guarantee — and it does
	// not protect against a concurrent in-place write to the original
	// inode between the read and the publish (the documented non-CAS
	// ceiling: such a writer is superseded by the publication, not
	// detected).
	transform := func(existing []byte, _ bool) ([]byte, error) {
		hosts, err := parseHostsData(string(existing))
		if err != nil {
			// The R10.3a parser ceilings are inherited (safe
			// divergence: the pinned parse is unbounded).
			moduleErr = err
			return nil, err
		}
		// if ip_addr in hosts: for host in host_list: if host in
		// hosts[ip_addr]: host_list.remove(host). The pinned loop
		// mutates host_list while iterating it, so removing an element
		// skips the next one — the Go loop reproduces the skip exactly
		// (after a removal at i the incremented i reads the element
		// two positions later, and the shrunken list ends the loop
		// early). This is deliberately NOT a clean filter.
		if a.IpAddr != nil {
			if aliases, ok := hosts[*a.IpAddr]; ok {
				for i := 0; i < len(hostList); i++ {
					if containsToken(aliases, hostList[i]) {
						hostList = removeFirstToken(hostList, hostList[i])
					}
				}
			}
		}
		if len(hostList) == 0 {
			moduleErr = errNoHostsAppend
			return nil, errNoHostsAppend
		}
		// "{} {}".format(ip_addr, " ".join(host_list)): a None ip_addr
		// renders as the literal "None" (exactly like Python str.format)
		// while never matching a dict key during the membership check.
		ip := "None"
		if a.IpAddr != nil {
			ip = *a.IpAddr
		}
		appendedLine = "\n" + ip + " " + joinTokens(hostList)
		replacement := make([]byte, 0, len(existing)+len(appendedLine))
		replacement = append(replacement, existing...)
		replacement = append(replacement, appendedLine...)
		if int64(len(replacement)) > hostsUpdateLimits.MaxWriteBytes {
			// The dnsutil input-ceiling class, checked inside the pure
			// transform so the module's fixed value-free error (not the
			// capability's backstop) answers the caller.
			moduleErr = errInputTooLarge
			return nil, errInputTooLarge
		}
		return replacement, nil
	}

	if err := runtime.UpdateFileBounded(rt.FS, ctx, path, hostsUpdateLimits, true, transform); err != nil {
		if moduleErr == errNoHostsAppend {
			// Pinned no-op result, exact text (the only surface that
			// legitimately echoes the path).
			return fmt.Sprintf("No additional hosts were added to %s", path), nil
		}
		if moduleErr != nil {
			// A transform failure aborts before any staging or
			// publication: the module's own fixed value-free class
			// answers (the capability's fixed transform sentinel never
			// carries the class across the boundary).
			return nil, moduleErr
		}
		return nil, mapHostsUpdateError(err)
	}
	// Pinned success result, exact text: a colon, then the line with
	// its leading LF.
	return fmt.Sprintf("The following line was added to %s:%s", path, appendedLine), nil
}

// ---------------------------------------------------------------------------
// hosts_remove

// HostsRemoveArgs mirrors the pinned signature
// hosts_remove(hostsfile="/etc/hosts", entries=None).
type HostsRemoveArgs struct {
	Hostsfile *string `statekit:"name=hostsfile"`
	Entries   *string `statekit:"name=entries"`
}

type hostsRemoveFunc struct{}

func (hostsRemoveFunc) Name() string { return "dnsutil.hosts_remove" }
func (hostsRemoveFunc) Args() any    { return HostsRemoveArgs{} }

func (hostsRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[HostsRemoveArgs](args, "dnsutil.hosts_remove")
	if err != nil {
		return nil, err
	}
	path := defaultHostsPath
	if a.Hostsfile != nil {
		path = *a.Hostsfile
	}
	// Path safety and size bounds run BEFORE the filesystem is touched
	// (an intentional divergence that may precede the file open: the
	// checks read no file bytes). Everything about entries — presence,
	// bounds, byte rejection, and the semantic split — follows the file
	// read, exactly like the pinned source order.
	if err := validateHostsPathArg(path); err != nil {
		return nil, err
	}

	// moduleErr carries this module's OWN fixed sentinel out of the
	// pure transform (see hosts_append): the capability boundary
	// answers its fixed cause-free sentinel and never inspects the
	// callback error, so the argument classes are recognized through
	// the captured variable, never through errors.Is on the capability
	// error.
	var moduleErr error
	var hostList []string

	// The pure transform: entries presence, argument bounds, and the
	// pinned entries.split(',') all happen HERE — after the bounded
	// snapshot read and before anything is staged or published — so a
	// file-read failure (missing file, symlinked destination, oversize
	// content) always precedes every entries diagnosis, including the
	// pinned entries=None AttributeError position (None.split). Entries
	// presence is represented as nil vs *string, so entries=None stays
	// DISTINCT from the empty string: an empty string splits to [""] and
	// keeps the pinned normal-rewrite semantics (a token that never
	// matches, normalization only).
	//
	// Alias-only removal (there is no address parameter) — for each
	// requested entry, membership is tested against comps[1:] but
	// removal takes the FIRST occurrence in the whole token list, so a
	// token serving as both address and alias loses its address
	// occurrence first; a line survives only with more than one token
	// remaining, rejoined with single spaces plus LF. Blank lines and
	// whitespace-prefixed comment lines are preserved verbatim;
	// pre-existing address-only and whitespace-only lines are dropped
	// even without any match.
	transform := func(existing []byte, _ bool) ([]byte, error) {
		if a.Entries == nil {
			// Pinned AttributeError crash position (None.split) — after
			// the file read, exactly like the source.
			moduleErr = errArgumentInvalid
			return nil, errArgumentInvalid
		}
		if err := validateEntriesArg(*a.Entries); err != nil {
			moduleErr = err
			return nil, err
		}
		hostList = splitEntries(*a.Entries)
		var out []byte
		for _, line := range pythonSplitlines(string(existing)) {
			if line == "" || strings.HasPrefix(pythonStrip(line), "#") {
				out = append(out, line...)
				out = append(out, '\n')
				continue
			}
			comps := pythonFields(line)
			// Python tolerates [][1:]; Go panics, so the alias
			// membership of a whitespace-only line (zero tokens) skips
			// straight to the drop rule below.
			if len(comps) > 0 {
				for _, host := range hostList {
					if containsToken(comps[1:], host) {
						comps = removeFirstToken(comps, host)
					}
				}
			}
			if len(comps) > 1 {
				out = append(out, joinTokens(comps)...)
				out = append(out, '\n')
			}
		}
		return out, nil
	}

	// Removal requires an existing file (the pinned fopen(..., "r")
	// raises IOError on a missing file; this port fails closed with the
	// fixed value-free update error) — and that file-read category
	// precedes every entries diagnosis, so missing file + nil entries
	// answers the update-failed class, never the argument class.
	if err := runtime.UpdateFileBounded(rt.FS, ctx, path, hostsUpdateLimits, false, transform); err != nil {
		if moduleErr != nil {
			// The transform failed after the snapshot was read: nothing
			// was staged or published, the target is unchanged, and the
			// module's own fixed value-free class answers.
			return nil, moduleErr
		}
		return nil, mapHostsUpdateError(err)
	}
	// The pinned function returns None; a Python None maps to Go nil.
	return nil, nil
}

// splitEntries is the pinned entries.split(","): no trimming, empty
// elements preserved.
func splitEntries(entries string) []string {
	return strings.Split(entries, ",")
}

// joinTokens is the pinned " ".join(list).
func joinTokens(tokens []string) string { return strings.Join(tokens, " ") }
