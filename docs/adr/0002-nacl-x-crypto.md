# ADR 0002: authorize golang.org/x/crypto for the NaCl family

Status: accepted (2026-08-26)

## Context

The porting constraint froze go.mod ("no new Go dependencies; ADR for
exceptions") after the supply-chain audit of go.sum confirmed a minimal,
fully verified dependency graph. R5 flagged `nacl` as blocked: Salt's
nacl module delegates to PyNaCl/libsodium primitives — crypto_box_seal
(sealed boxes) and crypto_secretbox (XSalsa20-Poly1305) — and none of
these exist in the Go standard library. Reimplementing Salsa20/Poly1305
by hand inside StateKit would mean writing novel cryptographic code, which
is strictly worse than depending on the reference-quality implementation.

The project owner approved using the standard Go crypto library for this
purpose on 2026-08-26 (session decision), unblocking the family.

## Decision

Add `golang.org/x/crypto` as the single authorized extension-library
dependency:

- maintained by the Go team under the same release engineering as the
  standard library;
- the de-facto canonical Go implementation of NaCl primitives
  (golang.org/x/crypto/nacl/box, .../nacl/secretbox, .../curve25519);
- pinned through go.sum checksums like every other module and covered by
  the same OSV/MAL advisory monitoring applied in the R0 audit;
- consumed only by modules/exec/nacl (import surface auditable with
  `go mod why`).

Scope of authorization: NaCl-family primitives needed for wire-compatible
interoperation with PyNaCl/libnacl (sealed boxes, secretboxes, X25519
public keys). Any further dependency requests still require their own ADR.

## Consequences

- go.mod expands beyond gopkg.in/yaml.v3 for the first time since R1;
- go.sum gains x/crypto (and any transitive) checksums — rerun the
  dependency audit procedure from plans/testing.md after the upgrade;
- nacl leaves the pending pool; FIPS-mode refusal stays part of the ported
  contract.
