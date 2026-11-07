#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <lambda-dir-name>" >&2
  exit 1
fi

LAMBDA_NAME="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/terraform/build/$LAMBDA_NAME"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp -r "$ROOT/trippycreds" "$BUILD_DIR/trippycreds"
cp "$ROOT/lambdas/$LAMBDA_NAME/handler.py" "$BUILD_DIR/handler.py"
