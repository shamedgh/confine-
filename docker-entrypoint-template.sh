#!/bin/sh
set -e

cp [orig-path] [orig-bak-path]

cp [seccomp-file-path] [orig-binary-path]

exec "$@"
