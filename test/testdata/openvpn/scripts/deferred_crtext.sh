#!/bin/bash
set -eu

credentials_file="$1"
username="$(sed -n '1p' "$credentials_file")"
password="$(sed -n '2p' "$credentials_file")"

[ "$username" = "test-user" ] || exit 1
[ "$password" = "test-password" ] || exit 1

printf '60\ncrtext\nCR_TEXT:E,R:Enter the code\n' > "$auth_pending_file"
exit 2
