This directory contains static fixtures for real OpenVPN interoperability tests.

- `pki/ca.crt`, `server.crt`, `server.key`, `client.crt`, `client.key`, `ta.key`
  are copied from the OpenVPN upstream sample keys under
  `/tmp/openvpn/sample/sample-keys`.
- `pki/tls-crypt-v2-server.key` and `pki/tls-crypt-v2-client.key` come from
  OpenVPN upstream unit-test fixtures.
- `pki/static.key` and `pki/tls-crypt.key` intentionally reuse the static key
  format from `ta.key`.
These files are for testing only.
