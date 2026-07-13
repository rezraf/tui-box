#!/bin/sh
set -eu

for target in \
  darwin/amd64 \
  darwin/arm64 \
  linux/amd64 \
  linux/arm64
do
  goos=${target%/*}
  goarch=${target#*/}
  printf 'cross-build: %s/%s (CGO_ENABLED=0)\n' "$goos" "$goarch"
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build ./cmd/tuibox ./cmd/tuiboxd
done
