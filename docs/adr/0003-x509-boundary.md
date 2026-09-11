# ADR 0003: split the legacy x509 boundary from x509_v2

Status: accepted (porting classification, 2026-08-28; additively amended
by the 2026-09-11 R5.2a addendum, the 2026-09-11 R5.2b addendum and the
2026-09-11 R5.4 addendum below)
Reference revision: references/salt.lock (8b63e700637e)

## Context

The pinned catalog contains two execution sources under the public Salt family
`x509`:

| Source | Catalog functions | Dependency/evidence | Lifecycle |
|---|---:|---|---|
| `salt/modules/x509.py` | 40 | `__virtual__` requires M2Crypto; the source uses ctypes around M2Crypto's X509 context, M2Crypto extension construction, and an OpenSSL CLI workaround for CSR/CRL parsing | Deprecated since Salt 3006 and announced for removal in Salt 3009 |
| `salt/modules/x509_v2.py` | 37 | `__virtual__` requires `cryptography`; local certificate/CSR/CRL/key operations are substantially representable by Go `crypto/x509` and the approved `x/crypto` surface, while PKCS#12 and PKCS#7 serialization are dependency-specific | Modern replacement and the default `x509` implementation in Salt 3008 |

The catalog generator intentionally exposes both source files as
`module: x509` (`source_module` distinguishes them), so a single compatibility
label cannot truthfully describe the legacy and replacement APIs separately.
The old and new implementations also have breaking output and parameter
contracts; treating them as one blind port would hide those differences.

The source gives hard dependency boundaries for the modern implementation:
PKCS#12 needs cryptography 36 (Edwards keys need 37), PKCS#7 needs 37, and
remote signing uses Salt peer communication. The released
`golang.org/x/crypto` version authorized by ADR 0002 (v0.55.0) provides
PKCS#12 decoding but no encoder and has no PKCS#7 serializer. Hand-writing
those container formats without an interop suite would be unsafe.

## Decision

1. **Exclude only the legacy `salt/modules/x509.py` implementation.** Its
   M2Crypto/ctypes ABI and OpenSSL-parser workaround are not a maintainable
   StateKit substrate, and the upstream module is already on a removal path.
   No StateKit function is registered under the legacy-only contract.
2. **Keep `salt/modules/x509_v2.py` planned for a dedicated PKI round.** It is
   not unresolvable: the local key/PEM/certificate/CSR/CRL portions can use
   existing Go crypto primitives. The future round must separately specify
   the exact boundaries for PKCS#12, PKCS#7, broad OpenSSL extension syntax,
   policy merging, and peer signing before implementation.
3. **Do not add a new dependency or invoke a host package installer for this
   classification.** A future PKCS#12/PKCS#7 substrate needs a new ADR or an
   explicitly approved external-tool boundary; crypto container formats will
   not be reimplemented ad hoc.
4. Keep the generated compatibility family `x509` in `planned` for now. This
   is intentional: moving the collapsed label to `excluded` would falsely
   claim that the modern replacement had been rejected. The ADR is the
   source-of-truth split until the catalog model can represent source-level
   family status.

## Consequences

- The R5 boundary phase is complete without a misleading partial x509 port.
- R5.8's `tls` implementation is a separate, deliberately scoped local PKI
  surface; it does not claim to implement all of `x509_v2`.
- The next x509 work item is a modern `x509_v2` contract round, starting with
  the stdlib-portable local subset and a reviewed serialization plan.
- Legacy x509 remains an explicit terminal exclusion; x509_v2 remains
  measurable as planned in `docs/catalog/compatibility.yaml`.
- The docker sandbox was attempted for dependency/interop checks but the
  configured rootless dind runtime cannot start child containers (`runc`
  proc-mount EPERM). No host packages were installed; this does not affect
  the source/dependency classification above.

## Addendum (2026-09-11): R5.2a read-only subset registration

Round R5.2a registered ten read-only functions of the legacy
`salt/modules/x509.py` surface under their canonical public names in
`modules/exec/x509`, on the Go standard library only (`crypto/x509`,
`encoding/pem`, `encoding/asn1`):

`x509.get_pem_entry`, `x509.get_pem_entries`, `x509.get_private_key_size`,
`x509.read_certificate`, `x509.read_certificates`, `x509.read_csr`,
`x509.expired`, `x509.will_expire`, `x509.get_public_key`,
`x509.verify_private_key`.

This addendum interprets, and does not rewrite, decision 1. The
prohibition there targets the legacy-only contract: behavior whose
observable shape is bound to the M2Crypto/ctypes ABI or to the OpenSSL
CLI parser workaround. Every function registered by R5.2a passes a
stronger test than the prohibition's scope:

- Its v1 observable contract (inputs, dict shapes, error shapes) is
  stdlib-expressible: no M2Crypto, pyOpenSSL, ctypes or `openssl` binary
  is reachable, and the registered surface spawns zero processes.
- The same public names exist in `salt/modules/x509_v2.py`, so each
  registered contract is shared with the modern replacement surface that
  decision 2 keeps planned ("starting with the stdlib-portable local
  subset"); none of the ten is a legacy-only contract.

Still excluded until the dedicated v2 round: the write side (`write_pem`,
`create_private_key`, `create_csr`, `create_crl`, `create_certificate`,
`sign_remote_certificate`, `get_signing_policy`, `verify_signature`,
`verify_crl`), `x509.read_crl` (its v1 output shape is parsed OpenSSL CLI
text; it stays pending on that dependency), and the M2Crypto/pyOpenSSL
object-handle contracts such as `get_public_key(asObj=True)`, which are
not serializable over the CLI and remain unexposed. The collapsed `x509`
family label moved from `planned` to `implemented` in
`docs/catalog/compatibility.yaml` because StateKit now ships at least one
function of that public family, per the label semantics; the source-level
split stays authored here, and the x509_v2 round boundary is unchanged.
(The write-side clause of this paragraph is superseded for eight of the
nine listed functions by the R5.2b addendum below; `sign_remote_certificate`
remains excluded.)

## Addendum (2026-09-11, later): R5.2b write-side subset registration

Round R5.2b extends the same interpretation to eight write-side functions
of the legacy `salt/modules/x509.py` surface, registered under their
canonical public names in `modules/exec/x509/write.go`, again on the Go
standard library only (`crypto/x509`, `crypto/rsa`, `crypto/rand`,
`encoding/pem`, `encoding/asn1`):

`x509.write_pem`, `x509.create_private_key`, `x509.create_crl`,
`x509.get_signing_policy`, `x509.create_certificate`, `x509.create_csr`,
`x509.verify_signature`, `x509.verify_crl`.

Like R5.2a, each registration passes the two-part test of the R5.2a
addendum: the v1 observable contract (arguments, defaults, reply
strings, dict shapes, error text) is stdlib-expressible, no M2Crypto,
pyOpenSSL, ctypes or `openssl` binary is reachable (the write surface
spawns zero processes, asserted by `TestWriteSideNoRunnerSpawns`), and
every one of the eight names also exists in
`salt/modules/x509_v2.py`, so no legacy-only contract is registered.
The substrate mapping is library-to-library: where the pinned source
rode M2Crypto's RSA generator, PEM writer, X509 builder and the
pyOpenSSL CRL flow, the port uses `crypto/rsa`, `x509.EncryptPEMBlock`
(the sole stdlib producer of the legacy Proc-Type/DEK-Info envelope),
`x509.CreateCertificate`/`CreateCertificateRequest`/
`CreateRevocationList`, and key-aware `CheckSignature` verification.
Divergences forced by that substrate are documented in the
`modules/exec/x509` package doc and were verified against the pinned
revision at gate time; the material ones are: plain private keys emit
PKCS#8 `PRIVATE KEY` where M2Crypto wrote PKCS#1 (encrypted keys keep
the PKCS#1 + DEK-Info envelope, including the uppercase-hex IV),
`create_crl` defaults its digest to SHA-256 where the pinned pyOpenSSL
fallback was md5, emits the CRL Number 1 that Go requires, and
`sha224` signatures upgrade to SHA-256 because the stdlib exposes no
SHA-224 signature algorithm; `create_certificate` always emits a v3
TBSCertificate (the `version` kwarg cannot lower it), anchors a
dynamic `not_after` at now rather than at `not_before` (the v1 quirk,
kept), and resolves `ca_server` requests to a deterministic
master-surface `UnsupportedError` instead of the excluded
`publish.publish` call; `create_csr` cannot lower the PKCS#10 version;
`verify_crl` uses `CheckSignatureFrom` where the source shelled out to
`openssl crl -CAfile` (an unloadable-but-well-formed PEM CRL is `False`
rather than an error, matching the CLI's failure mode).

Remaining exclusions after R5.2b, stated explicitly:

- `x509.sign_remote_certificate` stays excluded: it is the
  master-minion `publish.publish` surface, which is outside the
  execution-registry substrate by decision 1 and would need its own
  peer-communication ADR (the same boundary the tls and ssh_pki
  families document). `create_certificate(ca_server=...)` reaches it
  only through the deterministic unsupported error above.
- `x509.read_crl` stays pending, not excluded: its v1 output shape is
  parsed `openssl crl -text` CLI output (via `_parse_openssl_crl`),
  which is the OpenSSL-parser workaround decision 1 rejects. A
  stdlib-shape `read_crl` (`x509.ParseRevocationList`) is possible in
  the dedicated v2 round, where `x509_v2.read_crl` already defines the
  modern contract.
- The M2Crypto/pyOpenSSL object-handle contracts (`asObj=True`
  surfaces) remain unexposed, unchanged from R5.2a.

The compatibility label consequences are unchanged from R5.2a: the
collapsed `x509` family was already `implemented`; R5.2b only widens
it, and the regenerated `docs/catalog/coverage.yaml` records the eight
additional implemented names (18 x509 exec names total). The x509_v2
round boundary of decision 2 is untouched.

## Addendum (2026-09-11, final): R5.4 x509_v2 round landed on stdlib

The dedicated v2 round that decision 2 reserved has landed. Round R5.4
registers the six remaining stdlib-portable functions of
`salt/modules/x509_v2.py` under their canonical public names in
`modules/exec/x509/v2.go`, on the Go standard library only
(`crypto/x509`, `encoding/pem`, `encoding/asn1`, `encoding/base64`):

`x509.encode_certificate`, `x509.encode_crl`, `x509.encode_csr`,
`x509.encode_private_key`, `x509.expires`, `x509.read_crl`.

These are decision-2 v2-surface functions, not legacy contracts, so
decision 1 is not implicated: no M2Crypto, pyOpenSSL, ctypes or
`openssl` binary is reachable and the surface spawns zero processes
(asserted by `TestV2NoRunnerNoMutation`). The substrate mapping stays
library-to-library: `cryptography`'s serializers and parsers map onto
`pem.EncodeToMemory`, `x509.Parse*`/`ParseRevocationList` and
`x509.MarshalPKCS8PrivateKey`, and `salt/utils/x509.py`'s
`load_file_or_bytes` maps onto a bounded no-symlink reader with the
same `b64:`/inline-PEM/hex/base64 string interpretation and loader
error text. `encode_private_key` keeps the v2 PKCS#8-always contract
(there is no `cipher` parameter in `x509_v2.encode_private_key`), and
`read_crl` ports the v2 dict shape: issuer keyed by the
`NAME_ATTRS_OID` short names (first value per OID), `%Y-%m-%d %H:%M:%S`
UTC dates, colon-stripped `dec2hex` serial keys, `signature_algorithm`
as the OID `_name` with the dotted-string fallback, and the CRL/entry
extension renderers including the pinned `onysomereasons`
issuingDistributionPoint typo.

Boundaries kept inside decision 3 (no new dependency, no ad hoc
container reimplementation), all deterministic and firing only after
the pinned pre-validations:

- `pkcs7_der`, `pkcs7_pem` and `pkcs12` encodings, PKCS#7-PEM
  certificate inputs, encrypted-PKCS#8 and PKCS#12 key inputs resolve
  to a runtime container `UnsupportedError`: the Go standard library
  cannot serialize or parse those containers.
- `encode_private_key` output encryption (`BestAvailableEncryption`,
  reached via the `passphrase` parameter) and `pkcs12` encoding resolve
  to the same container boundary; plain output is unencrypted PKCS#8.
  Legacy Proc-Type/DEK-Info encrypted *inputs* still decrypt through
  the deprecated `x509.DecryptPEMBlock` with the exact password error
  texts.
- Certificate-profile extension families on a CRL raise the same
  deterministic profile-boundary error the R5.2b round introduced,
  where the source's shared renderer would render them.

This addendum resolves the R5.2b clause that kept `x509.read_crl`
pending: the single canonical registration exposes the v2 cryptography
dict shape, which subsumes the v1 parsed-`openssl crl -text` shape,
while the v1 OpenSSL-CLI parser itself stays excluded by decision 1.
`x509.sign_remote_certificate` remains excluded unchanged: it is the
master-minion `publish.publish` surface and would need its own
peer-communication ADR. With this round the x509 family's actionable
R5 scope is closed: the R5 report records `x509` 19/1 and `x509_v2`
24/1 registered/pending (the pending is `sign_remote_certificate` in
both views, counted once per family view), `docs/catalog/coverage.yaml`
records the six additional implemented names (24 x509 exec names
total), and the catalog regen through `tools/salt-reference` is
byte-identical to the committed state.
