# Kestrel Sandbox Labs

Intentionally vulnerable container images that the Kestrel sandbox feature
spawns on demand to test AI-generated exploit payloads in an isolated network.

| Lab kind  | Image tag                  | Vuln class | Endpoint(s)                                     |
|-----------|----------------------------|------------|-------------------------------------------------|
| `xss`     | `kestrel-lab-xss:latest`   | XSS        | `GET /echo?msg=`, `GET /search?q=`, `POST /comment` |

## Building

The labs are built locally so the sandbox manager can `docker run` them
without pulling from a registry.

```sh
# From repo root:
docker build -t kestrel-lab-xss:latest sandbox-labs/xss-flask
```

The first `POST /sandbox/sessions` call for a given lab kind will fail if
the image is missing — error message tells you the exact build command.

## Network

All lab containers attach to the `kestrel_sandbox_net` bridge network
(`internal: true`, no internet egress). The Kestrel backend is the only
other container on that network, so AI payloads can only reach the lab.

## Adding a new lab

1. Create `sandbox-labs/<kind>-<runtime>/` with Dockerfile + minimal app.
2. Add an entry to `backend/app/services/sandbox/catalog.py` describing the
   image tag, exposed port, target paths, and injection-point spec used by
   `payload_adapter.py`.
3. Map the relevant CWE / keyword set to the new kind in
   `backend/app/services/sandbox/classifier.py`.
