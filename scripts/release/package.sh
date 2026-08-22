#!/usr/bin/env bash
# Package release binaries into per-platform archives + SHA256SUMS.
#
# Usage: package.sh <version> <dist-dir> <out-dir>
# Expects binaries named statekit-<version>-<os>-<arch>[.exe] in <dist-dir>.
set -euo pipefail

VERSION="$1"
DIST="$2"
OUT="$3"

mkdir -p "$OUT"

for bin in "$DIST"/statekit-"$VERSION"-*; do
    [[ -e "$bin" ]] || { echo "package.sh: no binaries match $DIST/statekit-$VERSION-*" >&2; exit 1; }
    name=$(basename "$bin")
    target=${name#statekit-"$VERSION"-}          # <os>-<arch>[.exe]
    os=${target%%-*}
    ext=""
    if [[ "$target" == *.exe ]]; then
        os=${os%.exe}
        ext=".exe"
    fi
    arch=$(basename "${target%"$ext"}" | cut -d- -f2-)

    staging=$(mktemp -d)
    mkdir -p "$staging/statekit-$VERSION"
    cp "$bin" "$staging/statekit-$VERSION/statekit$ext"
    for doc in README.md LICENSE; do
        [[ -f "$doc" ]] && cp "$doc" "$staging/statekit-$VERSION/"
    done

    tarball="statekit_${VERSION#v}_${os}_${arch}.tar.gz"
    tar -czf "$OUT/$tarball" -C "$staging" "statekit-$VERSION"
    rm -rf "$staging"
    echo "packaged $tarball"
done

(cd "$OUT" && sha256sum ./*.tar.gz > SHA256SUMS)
echo "checksums written to $OUT/SHA256SUMS"
