#!/bin/sh
set -eu

credentials_file="$1"
username="$(sed -n '1p' "$credentials_file")"
password="$(sed -n '2p' "$credentials_file")"

[ "$username" = "test-user" ] && [ "$password" = "test-password" ]
