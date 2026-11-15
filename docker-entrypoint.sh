#!/bin/sh
set -eu

data_root=/var/data
storage_root=${STORAGE_ROOT:-$data_root/storage}
mkdir -p "$data_root" "$storage_root"
chown -R dft:dft "$data_root"

case "$storage_root" in
  "$data_root"/*|"$data_root") ;;
  *) chown -R dft:dft "$storage_root" ;;
esac

exec gosu dft "$@"
