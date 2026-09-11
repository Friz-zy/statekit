# ADR 0003: split the legacy x509 boundary from x509_v2

Status: accepted (porting classification, 2026-08-28; additively amended
by the 2026-09-11 R5.2a addendum below)
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
