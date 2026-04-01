#!/bin/bash
set -eu

response="$(base64 -d "$1")"
if [ "$response" = "424242" ]; then
    echo "1" > "$auth_control_file"
else
    echo "0" > "$auth_control_file"
fi
