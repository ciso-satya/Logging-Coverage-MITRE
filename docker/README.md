# docker/

`ca-bundle.crt` is intentionally empty. It is the default value of the `ca_bundle` build secret in
`docker-compose.yml`, so the build works on Windows, macOS and Linux without any extra setup.

Behind a TLS-inspecting corporate proxy, point the build at your proxy's CA bundle instead:

```bash
CA_BUNDLE_FILE=/path/to/corp-ca.pem docker compose up --build -d          # Linux / macOS
$env:CA_BUNDLE_FILE="C:\path\to\corp-ca.pem"; docker compose up --build -d  # Windows PowerShell
```
