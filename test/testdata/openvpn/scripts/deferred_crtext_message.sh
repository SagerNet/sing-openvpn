#!/bin/bash
set -eu

credentials_file="$1"
username="$(sed -n '1p' "$credentials_file")"
password="$(sed -n '2p' "$credentials_file")"

[ "$username" = "test-user" ] || exit 1
[ "$password" = "test-password" ] || exit 1

printf '60\ncrtext\nCR_TEXT::Verification in progress\n' > "$auth_pending_file"
(
    sleep 3
    echo "1" > "$auth_control_file"
) </dev/null >/dev/null 2>&1 &
exit 2
