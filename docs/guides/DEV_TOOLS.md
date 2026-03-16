# Development & Testing Guide

This provider supports two authentication methods and two test backends.

## Authentication Methods

| Method | Provider Fields | When to Use |
|--------|----------------|-------------|
| **API Key** | `api_key` | UniFi OS hardware (Cloud Key, Dream Machine) and the mock server |
| **Username / Password** | `username` + `password` | Self-hosted UniFi OS Server or legacy Network Application |

These are mutually exclusive — provide one or the other, not both.

```hcl
# API Key auth
provider "unifi" {
  host     = "https://192.168.1.1/proxy/network/integration"
  api_key  = "your-api-key"
  site_id  = "auto"
  insecure = true
}

# Username / Password auth
provider "unifi" {
  host     = "https://localhost:11443/proxy/network/integration"
  username = "admin"
  password = "testpassword123"
  site_id  = "auto"
  insecure = true
}
```

---

## Test Backends

Both backends use the same Terraform configs in `examples/`. Switch between them using `-var-file`:

```bash
terraform plan -var-file=mock.tfvars          # mock API server (API key)
terraform plan -var-file=integration.tfvars   # Docker UniFi OS Server (username/password)
```

### 1. Mock API Server (fast, no Docker needed)

A Flask-based mock with a live web dashboard. Best for rapid development iteration.

**One-time setup:**

```bash
cd devtools/mock-server
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

**Run:**

```bash
# Terminal 1 — start the mock server
cd devtools/mock-server
source .venv/bin/activate
python server.py            # --debug for auto-reload

# Terminal 2 — build and test
make build
cd examples
export TF_CLI_CONFIG_FILE=dev_overrides.tfrc
terraform plan -var-file=mock.tfvars
terraform apply -var-file=mock.tfvars -auto-approve
```

- API: http://localhost:5100
- Dashboard: http://localhost:5100/ui (live updates via SSE)

### 2. Integration Environment (real UniFi OS Server, Docker)

A Docker-based UniFi OS Server instance. Tests against the real v1 API to catch issues the mock can't. Runs as a single privileged container with systemd, bundled MongoDB, and all UniFi services.

**One-time: Build the Docker image**

The image is built from the official UniFi OS Server installer binary. Get the download URL from [ui.com/download/software/unifi-os-server](https://ui.com/download/software/unifi-os-server) (right-click → copy link address).

```bash
export UOS_DOWNLOAD_URL="https://fw-download.ubnt.com/data/unifi-os-server/..."
make integration-build      # ~5 min, cached after first run
```

This uses a Dockerized extraction pipeline — only Docker is needed on your machine.

**Start:**

```bash
make integration-up         # ~2-3 min on first boot
```

**First run only:** The setup wizard must be completed manually:

1. Open https://localhost:11443 (accept the self-signed cert)
2. Create a local admin account: `admin` / `testpassword123`
3. Skip Ubiquiti cloud sign-in (use offline/local mode)
4. Re-run `make integration-up` to create test networks

**Run:**

```bash
make build
cd examples
export TF_CLI_CONFIG_FILE=dev_overrides.tfrc
terraform plan -var-file=integration.tfvars
terraform apply -var-file=integration.tfvars -auto-approve
```

**Teardown:**

```bash
make integration-down       # stops container, removes volumes
```

**Default credentials:**

| Setting  | Value                                            |
|----------|--------------------------------------------------|
| URL      | `https://localhost:11443`                        |
| Username | `admin`                                          |
| Password | `testpassword123`                                |
| Site     | `default`                                        |

**Test networks created by setup:**

| Name      | VLAN | Subnet          |
|-----------|------|-----------------|
| TestLAN   | 10   | 192.168.10.0/24 |
| TestIoT   | 20   | 192.168.20.0/24 |
| TestGuest | 30   | 192.168.30.0/24 |

---

## Var Files

| File | Auth | Backend |
|------|------|---------|
| `examples/mock.tfvars` | API key | Mock server on localhost:5100 |
| `examples/integration.tfvars` | Username/password | Docker UniFi OS Server on localhost:11443 |
| `examples/terraform.tfvars` | *your config* | Your real UniFi controller (gitignored) |

---

## Troubleshooting

**Integration login fails** — Complete the setup wizard manually at https://localhost:11443 with the default credentials, then re-run `make integration-up`.

**UniFi OS Server slow to start** — First boot takes 2-3 minutes as internal services initialize. The setup script waits up to ~7.5 minutes.

**Port conflicts** — Edit `devtools/integration/docker-compose.yml` to change host ports.

**Start fresh** — `make integration-down && make integration-up`

**Image build fails** — Ensure the `UOS_DOWNLOAD_URL` is valid and the installer is for x64 Linux. The URL expires after a while; get a fresh one from [ui.com/download](https://ui.com/download/software/unifi-os-server).
