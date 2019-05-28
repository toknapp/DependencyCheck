#!/bin/sh

set -o nounset -o pipefail -o errexit

TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

TARBALL=$1
shift 1
unzip -q -d "$TMP" "$TARBALL"
$(find "$TMP" -type f -executable) "$@"
