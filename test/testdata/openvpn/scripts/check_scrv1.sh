#!/bin/bash
set -eu

credentials_file="$1"
username="$(sed -n '1p' "$credentials_file")"
password="$(sed -n '2p' "$credentials_file")"

[ "$username" = "test-user" ] || exit 1
case "$password" in
SCRV1:*) ;;
*) exit 1 ;;
esac

encoded_password="$(printf '%s' "$password" | cut -d: -f2)"
encoded_response="$(printf '%s' "$password" | cut -d: -f3)"
[ "$(printf '%s' "$encoded_password" | base64 -d)" = "test-password" ] || exit 1
[ "$(printf '%s' "$encoded_response" | base64 -d)" = "31337" ] || exit 1
exit 0
