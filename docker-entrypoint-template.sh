#!/bin/sh
set -e

mv [orig-path] [orig-bak-path]

cp [seccomp-file-path] [orig-binary-path]

[switch-user-cmd]

exec "$@"
